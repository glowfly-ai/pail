#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Check local file targets in public onboarding Markdown, without network access.

Only root guides, example guides and SDK README files are in scope. Fenced code,
inline code and HTML comments are not links. URL fragments are not checked.
"""
import argparse
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def check(root):
    docs = sorted(set(root.glob('*.md')) | set(root.glob('examples/**/*.md')) |
                  set(root.glob('sdk/**/README*.md')))
    if not docs or not (root / 'README.md').is_file():
        raise ValueError('No public README/documents found')
    checked = 0
    missing = []
    for doc in docs:
        text = doc.read_text(encoding='utf-8')
        text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
        text = re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', text, flags=re.M | re.S)
        # Labels may contain inline code; preserve them until targets extracted.
        targets = re.findall(r'\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\s*\)', text)
        targets += re.findall(r'^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)', text, flags=re.M)
        for target in targets:
            target = target.strip('<>')
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            checked += 1
            dest = (doc.parent / unquote(url.path)).resolve()
            if dest != root and root not in dest.parents:
                missing.append((str(doc.relative_to(root)), target, 'outside public tree'))
            elif not dest.exists():
                missing.append((str(doc.relative_to(root)), target, 'missing target'))
    if checked == 0:
        raise ValueError('No local file links checked')
    for doc, target, reason in missing:
        print('FAIL: %s -> %s (%s)' % (doc, target, reason))
    print('PUBLIC-LINKS: %s (%d failures; %d targets; %d documents)' %
          ('FAIL' if missing else 'PASS', len(missing), checked, len(docs)))
    return 1 if missing else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    try:
        return check(args.root.resolve())
    except (OSError, ValueError) as exc:
        print('PUBLIC-LINKS: CANNOT_CHECK: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
