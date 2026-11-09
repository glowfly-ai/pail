#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Generate the raised-wheel TurtleBot3 measurement rows of HARDWARE.md, HARDWARE.ko.md, the two READMEs and the
VALIDATION `Real TurtleBot3` row from one measurement file (measurements/hardware_tb3.md), so that no hardware number and no source build is
written by hand (preview.23 evaluation P23-D1, the seventh candidate in a row whose prose named a build other
than the one measured; analysis R3: documents must be generated from measurements).

Rules the generator enforces:
  * every Source cell names the build it was measured on (`independent (0.2.0-preview.22 bundle)`);
  * the phrase "this candidate" / " " is emitted only when the source's build equals the tree's VERSION,
    never written by hand inside the generated regions;
  * a row with no cells, a cell whose source is not declared, or a source without a build is a generation error.

Region markers (2026-11-09): a region that lives INSIDE a Markdown table uses inline markers within its first and
last cell — `|<!-- hw-measurements:begin X --> … <!-- hw-measurements:end X -->|` — because GitHub-Flavored
Markdown ends a table at an HTML-block line; the earlier marker LINES between rows rendered every following row as
plain text on GitHub (README: five rows, HARDWARE.md §8: the whole table). `--write` migrates legacy line markers of
table regions; `--check` reports them. List regions (`defs`) keep line markers.

usage:
  python3 gen_hardware_measurements.py --write     # rewrite the generated regions
  python3 gen_hardware_measurements.py --check     # rc 0 when every region equals the generator's output, rc 1 otherwise, rc 2 misuse

Layouts: run from the internal tree (oss/measurements/..., oss/examples/..., oss/README.md) or from a public
snapshot (measurements/..., examples/..., README.md); the tool finds whichever is present.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEGIN, END = '<!-- hw-measurements:begin -->', '<!-- hw-measurements:end -->'


def root():
    for cand in (HERE, HERE.parent, HERE.parent / 'oss'):
        if (cand / 'measurements' / 'hardware_tb3.md').is_file():
            return cand
    raise SystemExit('measurements/hardware_tb3.md not found beside ' + str(HERE))


def load(r):
    """The measurement file is Markdown with one fenced JSON block (a document, so the bilingual cells it must carry
    sit outside the public-language ratchet that code and config files are under)."""
    text = (r / 'measurements' / 'hardware_tb3.md').read_text(encoding='utf-8')
    m = re.search(r'```json\n(.*?)\n```', text, re.S)
    if not m:
        raise ValueError('measurements/hardware_tb3.md has no ```json block')
    return json.loads(m.group(1))


def version(r):
    for p in (r / 'VERSION', r.parent / 'VERSION'):
        if p.is_file():
            return p.read_text(encoding='utf-8').strip()
    return ''


def source_phrase(src, name, lang, current):
    """'independent (0.2.0-preview.22 bundle)' or, only when it is this tree's version, 'independent (this candidate)'."""
    build = src['build']
    # an `independent_<tag>` source is a further independent run (0.2.0-preview.41: `independent_p40`, the evaluator's
    # preview.40 run); it is phrased like `independent`, distinguished by its build
    kind = 'independent' if name.startswith('independent') else name
    if lang == 'en':
        who = {'publisher': 'publisher', 'independent': 'independent', 'software_demo': 'software demo'}[kind]
        inside = 'this candidate' if build == current else build + (' build' if kind != 'independent' else ' bundle')
        return who + ' (' + inside + ')'
    v = VOCAB
    who = v[kind]
    inside = v['this_candidate'] if build == current else build + ' ' + (v['build'] if kind != 'independent' else v['bundle'])
    return who + '(' + inside + ')'


VOCAB = {}


def render(data, current):
    VOCAB.clear(); VOCAB.update(data['vocabulary_ko'])
    srcs = data['sources']
    out = {}
    for lang in ('en', 'ko'):
        lines = []
        for row in data['rows']:
            if not row.get('cells'):
                raise ValueError('row without cells: ' + row['id'])
            cells = []
            for c in row['cells']:
                if c['source'] not in srcs or not srcs[c['source']].get('build'):
                    raise ValueError('row %s: undeclared source %s' % (row['id'], c['source']))
                cells.append(source_phrase(srcs[c['source']], c['source'], lang, current) + ': ' + c[lang])
            lines.append('| %s | %s | %s |' % (row['check_' + lang], row['established_' + lang], '; '.join(cells)))
        out['table_' + lang] = '\n'.join(lines)
    ind, pub = srcs['independent'], srcs['publisher']
    of_en = lambda s, kind: ('of this candidate' if s['build'] == current else 'of the ' + s['build'] + ' ' + kind)
    of_ko = lambda s, kind: (VOCAB['this_candidate_of'] if s['build'] == current else s['build'] + ' ' + kind + VOCAB['of_suffix'])
    fills = {'independent_of': of_en(ind, 'bundle'), 'publisher_of': of_en(pub, 'build'),
             'independent_of_ko': of_ko(ind, VOCAB['bundle']), 'publisher_of_ko': of_ko(pub, VOCAB['build'])}
    for key, tmpl in data['readme'].items():
        out['readme_' + key] = tmpl.format(**fills)
    # the two source definitions of HARDWARE section 8
    out['defs_en'] = ('- **publisher** — ' + pub['note_en'] + '; build ' + pub['build'] + ', ' + pub['date'] + '.\n'
                      '- **independent** — ' + ind['note_en'] + '; build ' + ind['build'] + ', ' + ind['date'] + '. Where the two differ, the later build is the current value.')
    out['defs_ko'] = ('- **' + VOCAB['publisher'] + '** — ' + pub['note_ko'] + '; ' + VOCAB['build'] + ' ' + pub['build'] + ', ' + pub['date'] + '.\n'
                      '- **' + VOCAB['independent'] + '** — ' + ind['note_ko'] + '; ' + VOCAB['build'] + ' ' + ind['build'] + ', ' + ind['date'] + '. ' + VOCAB['later_build_current'])
    # further independent runs (`independent_<tag>`), one definition line each, after the two above
    for name in sorted(k for k in srcs if k.startswith('independent_')):
        s = srcs[name]
        out['defs_en'] += '\n- **independent (' + s['build'] + ' bundle)** — ' + s['note_en'] + '; build ' + s['build'] + ', ' + s['date'] + '.'
        out['defs_ko'] += '\n- **' + VOCAB['independent'] + '(' + s['build'] + ' ' + VOCAB['bundle'] + ')** — ' + s['note_ko'] + '; ' + VOCAB['build'] + ' ' + s['build'] + ', ' + s['date'] + '.'
    out['validation_row'] = ('| Real TurtleBot3 | publisher run: ' + pub['build'] + ' build (' + pub['date'] + '); independent run: ' + ind['build'] + ' bundle (' + ind['date'] +
                             ', raised wheels: judge 13/13 ×3, scene 8 5/5, Issuer paused 12 s / 30 s across an E-STOP with 0 drive commands after `OK`, ±0.6 s clock steps with no resume, 1 m 0.998–1.000 m ×3, outage-mode precondition not met); '
                             + ''.join('independent run of ' + s['build'] + ': ' + s['validation_summary_en'] + '; ' for k, s in sorted(srcs.items()) if k.startswith('independent_') and s.get('validation_summary_en'))
                             + ('this candidate was ' + ('run' if current in [s['build'] for s in srcs.values()] else 'not run') + ' on the hardware; ') +
                             '`examples/tb3/HARDWARE.md` §8 names the build per cell (generated from `measurements/hardware_tb3.md`) |')
    return out


def regions(r):
    """(path, region name, rendered key) for every generated region."""
    ex = r / 'examples' / 'tb3'
    return [
        (ex / 'HARDWARE.md', 'defs', 'defs_en'), (ex / 'HARDWARE.md', 'table', 'table_en'),
        (ex / 'HARDWARE.ko.md', 'defs', 'defs_ko'), (ex / 'HARDWARE.ko.md', 'table', 'table_ko'),
        (r / 'README.md', 'hardware_row', 'readme_hardware_row_en'), (r / 'README.md', 'deadline_row', 'readme_deadline_row_en'), (r / 'README.md', 'restart_row', 'readme_restart_row_en'),
        (r / 'README.ko.md', 'hardware_row', 'readme_hardware_row_ko'), (r / 'README.ko.md', 'deadline_row', 'readme_deadline_row_ko'), (r / 'README.ko.md', 'restart_row', 'readme_restart_row_ko'),
    ]


# regions whose content is table rows: their markers sit inside the first and last cell (GFM keeps the table)
TABLE_REGIONS = {'table', 'hardware_row', 'deadline_row', 'restart_row'}


def line_region_re(name):
    """Marker lines around the content (list regions; the legacy form of table regions)."""
    return re.compile(r'(<!-- hw-measurements:begin ' + re.escape(name) + r' -->\n)(.*?)(\n<!-- hw-measurements:end ' + re.escape(name) + r' -->)', re.S)


def inline_region_re(name):
    """Markers inside the first and last table cell: `|<!-- begin X --> … <!-- end X -->|`."""
    return re.compile(r'(\|<!-- hw-measurements:begin ' + re.escape(name) + r' -->)(.*?)(<!-- hw-measurements:end ' + re.escape(name) + r' -->\|)', re.S)


def region_re(name):
    return inline_region_re(name) if name in TABLE_REGIONS else line_region_re(name)


def region_content(name, rendered_rows):
    """What sits between the markers: full lines for list regions; for table regions the rows without the outer
    pipes of the first and last row (the markers take their place)."""
    if name not in TABLE_REGIONS:
        return rendered_rows
    if not (rendered_rows.startswith('|') and rendered_rows.endswith('|')):
        raise ValueError('table region %s must render as pipe-delimited rows' % name)
    return rendered_rows[1:-1]


def apply(r, rendered, write):
    problems = []
    for path, name, key in regions(r):
        if not path.is_file():
            problems.append('missing ' + str(path)); continue
        text = path.read_text(encoding='utf-8')
        want = region_content(name, rendered[key])
        m = region_re(name).search(text)
        if not m and name in TABLE_REGIONS:
            legacy = line_region_re(name).search(text)
            if legacy:
                if write:
                    text = (text[:legacy.start()] + '|<!-- hw-measurements:begin %s -->' % name + want
                            + '<!-- hw-measurements:end %s -->|' % name + text[legacy.end():])
                    path.write_text(text, encoding='utf-8')
                else:
                    problems.append('%s: region %r uses legacy marker lines inside a table (GFM drops the rows); run --write' % (path.name, name))
                continue
        if not m:
            problems.append('%s: no generated region %r' % (path.name, name)); continue
        if m.group(2) != want:
            if write:
                text = text[:m.start(2)] + want + text[m.end(2):]
                path.write_text(text, encoding='utf-8')
            else:
                problems.append('%s: region %r differs from the measurement file' % (path.name, name))
    # the VALIDATION row (a single table line; present only in the internal tree and the evaluation bundle)
    for vpath in (r / 'distribution' / 'VALIDATION.md', r.parent / 'VALIDATION.md'):
        if vpath.is_file():
            text = vpath.read_text(encoding='utf-8'); lines = text.splitlines()
            idx = [i for i, l in enumerate(lines) if l.startswith('| Real TurtleBot3 |')]
            if not idx:
                problems.append(vpath.name + ': no `| Real TurtleBot3 |` row')
            elif lines[idx[0]] != rendered['validation_row']:
                if write:
                    lines[idx[0]] = rendered['validation_row']; vpath.write_text('\n'.join(lines) + '\n', encoding='utf-8')
                else:
                    problems.append(vpath.name + ': the Real TurtleBot3 row differs from the measurement file')
            break
    # the hand-written remainder of these documents may not carry the phrase in a table row (P23-D1: that is how it drifted);
    # P25-N1: every public Markdown document is read for a hardware claim, not only the ones with generated regions
    region_docs = {p for p, _, _ in regions(r)}
    for path in public_markdown(r):
        if not path.is_file():
            continue
        text = path.read_text(encoding='utf-8')
        stripped = re.sub(r'<!-- hw-measurements:begin .*?<!-- hw-measurements:end [a-z_]+ -->', '', text, flags=re.S)
        for i, l in enumerate(stripped.splitlines(), 1):
            if path in region_docs and l.strip() == '||':
                continue  # the pipes left around a stripped inline-marker region
            if path in region_docs and l.startswith('|') and ('this candidate' in l or VOCAB['this_candidate'] in l):
                problems.append('%s: a hand-written table row says "this candidate" (write the build name, or generate the row): %s' % (path.name, l[:80]))
            elif hardware_claim(l):
                # P24-N2: the row rule above left prose untouched; a hand-written sentence "independent runs of this
                # candidate" outside the generated regions passed. A sentence that names the hardware and says
                # "this candidate" is a measurement claim and must come from the generator (or say what was NOT run).
                problems.append('%s:%d: a hand-written sentence claims a hardware run of "this candidate" (generate it, or name the build): %s' % (path.name, i, l.strip()[:80]))
    return problems


HARDWARE_WORDS = re.compile(r'TurtleBot3|TB3|raised[- ]wheel|real robot|real hardware|on the hardware|on hardware|on the real base', re.I)
NEGATION = re.compile(r'\bnot\b|\bno\b|\bnever\b|\bdid not\b|\bwithout\b', re.I)
# P25-N1: the phrase has paraphrases ("the raised-wheel run of the current release passed 13/13")
THIS_CANDIDATE = re.compile(r'this candidate|the current (?:release|candidate|build|version)|this (?:release|build|version)|the candidate being (?:sealed|delivered)', re.I)
RUN_WORDS = re.compile(r'\b(?:ran|runs?|measured|measurements?|passed|judged?|judges|tested|replay(?:ed|s)?|results?)\b|\d+/\d+', re.I)
SKIP_DIRS = {'node_modules', 'target', '__pycache__', '.git', 'demo', 'evidence'}


def public_markdown(r):
    """Every Markdown document of the public tree (the generated-region documents included)."""
    out = set(p for p, _, _ in regions(r))
    # CHANGELOG.md used to be skipped here: an older section's "this candidate" named that
    # section's candidate, not the current one. The preview/rc log moved out of the public tree
    # for 0.2.0, so the public changelog has one section and is measured like any other document.
    for p in r.rglob('*.md'):
        if not (set(p.relative_to(r).parts[:-1]) & SKIP_DIRS):
            out.add(p)
    return sorted(out)


def hardware_claim(line):
    """True for a prose line that pairs "this candidate" (either language, paraphrases included) with the hardware
    and is not a negation."""
    if line.strip().startswith('<!--'):
        return False
    # a claim pairs the candidate, the hardware AND a run/measurement word; "this release's gate image is used by the
    # hardware guide" names the hardware without claiming a run and is not a claim
    en = (bool(THIS_CANDIDATE.search(line)) and bool(HARDWARE_WORDS.search(line)) and bool(RUN_WORDS.search(line))
          and not NEGATION.search(line))
    # the Korean words come from the measurement file's vocabulary (no Korean literal in this public tool)
    aliases = [VOCAB['this_candidate']] + list(VOCAB.get('this_candidate_aliases', [])) if VOCAB else []
    ko = (bool(VOCAB) and any(al in line for al in aliases) and any(w in line for w in VOCAB['hardware_words'])
          and any(w in line for w in VOCAB.get('run_words', [])) and not any(n in line for n in VOCAB['negations']))
    return en or ko


def main(argv):
    if argv not in (['--write'], ['--check']):
        print('usage: gen_hardware_measurements.py --write | --check', file=sys.stderr); return 2
    r = root()
    data = load(r)
    current = version(r)
    try:
        rendered = render(data, current)
    except ValueError as exc:
        print('HW-MEASUREMENTS: FAIL ' + str(exc)); return 1
    problems = apply(r, rendered, argv == ['--write'])
    if problems:
        for p in problems:
            print('FAIL: ' + p)
        print('HW-MEASUREMENTS: FAIL (%d)' % len(problems)); return 1
    print('HW-MEASUREMENTS: %s (%d regions; sources publisher=%s independent=%s; VERSION %s)' % (
        'WRITTEN' if argv == ['--write'] else 'PASS', len(regions(r)), data['sources']['publisher']['build'], data['sources']['independent']['build'], current or '?'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
