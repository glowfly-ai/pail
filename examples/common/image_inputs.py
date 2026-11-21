# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""The input hash of one runtime image: what its build reads, and nothing else.

An image is identified by the bytes its build takes from the build context:

  1. its Dockerfile;
  2. the ignore file Docker applies to that Dockerfile (`<Dockerfile>.dockerignore` when it exists, otherwise the
     root `.dockerignore`; the one beside the Dockerfile replaces the root one, it does not add to it);
  3. every file its COPY lines bring in, after the ignore file removed what Docker would not send;
  4. build arguments that change what is built (release identity and build parallelism do not);
  5. the target architecture.

Two hashes are returned. `sha256` covers paths and contents and is the one a recipient compares against an image
label: an extracted delivery does not keep group/other permission bits, so permissions cannot be part of it.
`sha256_with_modes` adds the permission bits and is what the publisher compares between two staged trees before an
image is reused.

A recipe this module cannot read exactly is refused (InputError) instead of guessed: ADD, a variable or a wildcard in
a COPY source, the JSON form, an unknown COPY flag, a source outside the context, a here-document, ONBUILD, a changed
escape character, a symlink inside a source. Directories and empty directories are not recorded; a COPY of a
directory is recorded as the files under it.
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path

SCHEMA_VERSION = 1
# role -> Dockerfile path inside that role's build context (the public layout; the Issuer builds from its own
# reviewed selection, whose root holds Dockerfile.issuer).
ROLES = {
    'microduck': 'examples/microduck/Dockerfile',
    'issuer': 'Dockerfile.issuer',
    'tb3_gate': 'docker/Dockerfile.gate',
}
ARCHITECTURES = ('arm64', 'amd64')
# Not inputs. Release identity travels in labels: the same inputs under another release id are the same image.
# PAIL_BUILD_JOBS is how many compilers run at once, which every builder chooses for its own memory; counting it
# would give the publisher (1 for the gate) and a developer (2) different hashes for the same sources.
NON_INPUT_ARGS = frozenset(('PAIL_VERSION', 'PAIL_SOURCE_SHA256', 'PAIL_ISSUER_INPUT_SHA256', 'PAIL_IMAGE_INPUT_SHA256',
                            'PAIL_BUILD_JOBS'))
COPY_FLAGS = ('--chown=', '--chmod=', '--link')


class InputError(ValueError):
    """The recipe or the context cannot be read exactly; no hash is produced."""


# ---- ignore file (github.com/moby/patternmatcher rules) ----------------------------------------------------------

def _clean(pattern):
    """filepath.Clean, then leading and trailing slashes dropped. '' means the line is skipped."""
    parts = []
    for part in pattern.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return '/'.join(parts)


def _regex(pattern):
    out, i, n = ['^'], 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == '*':
            if i + 1 < n and pattern[i + 1] == '*':
                i += 2
                if i < n and pattern[i] == '/':
                    i += 1
                out.append('.*' if i >= n else '(.*/)?')     # "**" spans any number of directories, zero included
                continue
            out.append('[^/]*')
        elif ch == '?':
            out.append('[^/]')
        elif ch == '[':
            j = pattern.find(']', i + 1)
            if j < 0:
                raise InputError('ignore pattern has an unclosed character class: ' + pattern)
            body = pattern[i + 1:j]
            out.append('[' + ('^' + body[1:] if body.startswith(('!', '^')) else body) + ']')
            i = j
        elif ch == '\\' and i + 1 < n:
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(ch))
        i += 1
    out.append('$')
    return re.compile(''.join(out))


def compile_patterns(lines):
    rules = []
    for line in lines:
        if line.startswith('#'):             # a comment starts in column 1
            continue
        text = line.strip()
        if not text:
            continue
        exclusion = text.startswith('!')
        if exclusion:
            text = text[1:].strip()
        text = _clean(text)
        if not text:                         # blank after cleaning, and the historical "." pattern
            continue
        rules.append((exclusion, _regex(text)))
    return rules


def _ignored(rules, path):
    parts = path.split('/')
    candidates = [path] + ['/'.join(parts[:k]) for k in range(1, len(parts))]
    matched = False
    for exclusion, regex in rules:
        if exclusion != matched:             # an exception is only asked of a path that is currently ignored
            continue
        if any(regex.match(c) for c in candidates):
            matched = not exclusion
    return matched


def ignored(lines, path):
    """True when a context path (posix, relative) is removed by the ignore-file lines."""
    return _ignored(compile_patterns(lines), path)


# ---- Dockerfile ---------------------------------------------------------------------------------------------------

def _instructions(text):
    """Logical lines: continuation joined, comments and blanks dropped."""
    for line in text.splitlines():
        probe = line.strip().lower().replace(' ', '')
        if probe.startswith('#escape='):
            raise InputError('a changed escape character is not supported')
        if not probe.startswith('#') and probe:
            break                            # parser directives only count before the first instruction
    logical, pending = [], ''
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith('#') or (not stripped and not pending):
            continue                         # a comment inside a continued instruction is dropped, as Docker does
        if stripped.endswith('\\'):
            pending += stripped[:-1] + ' '
            continue
        logical.append((pending + stripped).strip())
        pending = ''
    if pending.strip():
        logical.append(pending.strip())
    return [l for l in logical if l]


def copy_sources(dockerfile_text):
    """Context paths named by the COPY lines of a Dockerfile (stage-to-stage copies excluded)."""
    sources = []
    for line in _instructions(dockerfile_text):
        verb = line.split()[0].upper()
        if verb == 'ONBUILD':
            raise InputError('ONBUILD is not supported: ' + line)
        if verb == 'ADD':
            raise InputError('ADD is not supported, use COPY: ' + line)
        if re.search(r'<<-?\s*["\']?\w', line) and verb in ('COPY', 'RUN'):
            raise InputError('a here-document is not supported: ' + line)
        if verb != 'COPY':
            continue
        rest = line[len(line.split()[0]):].strip()
        if rest.startswith('['):
            raise InputError('the JSON form of COPY is not supported: ' + line)
        try:
            tokens = shlex.split(rest)
        except ValueError as exc:
            raise InputError('COPY line cannot be split (%s): %s' % (exc, line)) from None
        flags = [t for t in tokens if t.startswith('--')]
        args = [t for t in tokens if not t.startswith('--')]
        if any(f.startswith('--from') for f in flags):
            continue
        for flag in flags:
            if not flag.startswith(COPY_FLAGS):
                raise InputError('COPY flag is not supported: %s in: %s' % (flag, line))
        if len(args) < 2:
            raise InputError('COPY needs a source and a destination: ' + line)
        for source in args[:-1]:
            if '$' in source:
                raise InputError('a variable in a COPY source is not supported: ' + line)
            if any(c in source for c in '*?['):
                raise InputError('a wildcard in a COPY source is not supported, name the files: ' + line)
            if source.startswith('/') or '..' in source.split('/'):
                raise InputError('COPY source is outside the build context: ' + line)
            clean = _clean(source)
            if not clean:
                raise InputError('COPY of the whole context is not supported, name the sources: ' + line)
            sources.append(clean)
    return sources


# ---- hash ---------------------------------------------------------------------------------------------------------

def _file_row(path):
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': path.stat().st_mode & 0o777}


def _collect(root, source, rules, files):
    start = root / source
    if start.is_symlink():
        raise InputError('a symlink in a COPY source is not supported: ' + source)
    found = 0
    if start.is_file():
        if not _ignored(rules, source):
            files[source] = _file_row(start)
            found = 1
    elif start.is_dir():
        for base, dirs, names in os.walk(start):
            dirs.sort()
            for name in dirs + names:
                if (Path(base) / name).is_symlink():
                    raise InputError('a symlink in a COPY source is not supported: ' +
                                     (Path(base) / name).relative_to(root).as_posix())
            for name in sorted(names):
                path = Path(base) / name
                rel = path.relative_to(root).as_posix()
                if path.is_file() and not _ignored(rules, rel):
                    files[rel] = _file_row(path)
                    found += 1
    if not found:
        raise InputError('COPY source is missing from the build context (absent or removed by the ignore file): ' + source)


def compute(root, role, arch, build_args=None):
    """Input record of one role's image for the build context at `root`."""
    if role not in ROLES:
        raise InputError('unknown role %r (known: %s)' % (role, ', '.join(sorted(ROLES))))
    if arch not in ARCHITECTURES:
        raise InputError('unknown architecture %r (known: %s)' % (arch, ', '.join(ARCHITECTURES)))
    root = Path(root)
    recipe = ROLES[role]
    dockerfile = root / recipe
    if not dockerfile.is_file() or dockerfile.is_symlink():
        raise InputError('Dockerfile of role %s not found in the build context: %s' % (role, recipe))
    dockerfile_bytes = dockerfile.read_bytes()
    ignore_file, ignore_bytes = None, b''
    for candidate in (recipe + '.dockerignore', '.dockerignore'):
        if (root / candidate).is_file():
            ignore_file, ignore_bytes = candidate, (root / candidate).read_bytes()
            break
    rules = compile_patterns(ignore_bytes.decode('utf-8').splitlines())
    files = {}
    sources = copy_sources(dockerfile_bytes.decode('utf-8'))
    for source in sources:
        _collect(root, source, rules, files)
    files = {k: files[k] for k in sorted(files)}
    args = {k: str(v) for k, v in sorted((build_args or {}).items()) if k not in NON_INPUT_ARGS}
    head = {'schema_version': SCHEMA_VERSION, 'role': role, 'arch': arch,
            'dockerfile_sha256': hashlib.sha256(dockerfile_bytes).hexdigest(),
            'ignore_sha256': hashlib.sha256(ignore_bytes).hexdigest() if ignore_file else None,
            'build_args': args}

    def digest(rows):
        return hashlib.sha256(json.dumps(dict(head, files=rows), sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    return dict(head, dockerfile=recipe, ignore_file=ignore_file, files=files, sources=sorted(set(sources)),
                sha256=digest([[p, r['sha256']] for p, r in files.items()]),
                sha256_with_modes=digest([[p, r['sha256'], r['mode']] for p, r in files.items()]))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument('--root', required=True, type=Path, help='build context root')
    ap.add_argument('--role', required=True)
    ap.add_argument('--arch', required=True)
    ap.add_argument('--arg', action='append', default=[], metavar='NAME=VALUE', help='build argument (repeatable)')
    ap.add_argument('--json', action='store_true', help='print the whole record instead of the recipient hash')
    a = ap.parse_args(argv)
    try:
        pairs = {}
        for item in a.arg:
            if '=' not in item:
                raise InputError('--arg needs NAME=VALUE: ' + item)
            name, value = item.split('=', 1)
            pairs[name] = value
        record = compute(a.root, a.role, a.arch, build_args=pairs)
    except (InputError, OSError, UnicodeDecodeError) as exc:
        print('IMAGE_INPUTS_REFUSED: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True) if a.json else record['sha256'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
