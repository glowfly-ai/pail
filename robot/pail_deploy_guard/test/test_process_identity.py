# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""`L10` 관측점 : the Python half of the process-identity line.

쌍둥이 둘과 팔이 같다 — 값 · 접힘 · 순서. C++ 은 test_process_identity.cpp,
Go 는 internal/deploysec/identity_test.go 다. 형식이 한 구현에서만 바뀌면 세
배포가 다른 줄을 내는데, 로그를 읽는 쪽에서 그것은 "한 컴포넌트가 줄을 안
낸다"와 구분되지 않는다.
"""

import io
import os
import unittest
from contextlib import redirect_stderr

from pail_deploy_guard import deploy_guard


def _capture(fn):
    buf = io.StringIO()
    with redirect_stderr(buf):
        fn()
    return buf.getvalue()


def _identity_line(out):
    for line in out.splitlines():
        if line.startswith(deploy_guard.IDENTITY_PREFIX):
            return line
    return ''


class ProcessIdentityTest(unittest.TestCase):

    def test_line_carries_real_ids(self):
        """값 팔. 줄의 존재만 재면 하드코딩된 ``uid=10001`` 도 통과하는데,
        하드코딩된 값은 줄이 없는 것보다 나쁘다 — 측정처럼 읽히기 때문이다."""
        out = _capture(lambda: deploy_guard.emit_process_identity('unit'))
        want = '%s uid=%d euid=%d gid=%d egid=%d component=unit' % (
            deploy_guard.IDENTITY_PREFIX, os.getuid(), os.geteuid(),
            os.getgid(), os.getegid())
        self.assertIn(want, out)

    def test_real_and_effective_are_separate_fields(self):
        """접힘 팔. 보통의 실행에서는 uid == euid 라 한 값을 두 번 찍어도 위 팔은
        그대로 통과한다. 여기서는 칸의 **이름**이 따로 있는지를 재는데, 접힘이
        없애는 것이 정확히 그것이다."""
        line = _identity_line(_capture(
            lambda: deploy_guard.emit_process_identity('unit')))
        self.assertTrue(line, 'identity line absent')
        seen = []
        for tok in line.split():
            if '=' in tok:
                seen.append(tok.split('=', 1)[0])
        for key in ('uid', 'euid', 'gid', 'egid'):
            self.assertIn(key, seen, '접힌 칸은 조용하다: %s' % key)
            self.assertEqual(seen.count(key), 1,
                             '같은 이름의 두 칸은 대조되지 않는다: %s' % key)

    def test_identity_precedes_verdict(self):
        """순서 팔. ``enforce`` 의 세 갈래 중 마지막은 ``sys.exit(78)`` 이라 이
        프로세스에서 돌릴 수 없다 — 여기서 재는 것은 검사 가능한 절반이다:
        신원 줄이 판정 줄보다 먼저 나온다. 소스 위치 주장(함수의 첫 문장)은
        러너의 구조 팔이 잰다."""
        old = os.environ.get('PAIL_PROFILE')
        os.environ['PAIL_PROFILE'] = 'dev'
        try:
            out = _capture(lambda: deploy_guard.enforce('unit', ['node']))
        finally:
            if old is None:
                del os.environ['PAIL_PROFILE']
            else:
                os.environ['PAIL_PROFILE'] = old
        i = out.find(deploy_guard.IDENTITY_PREFIX)
        self.assertGreaterEqual(i, 0, 'enforce emitted no identity line:\n%s' % out)
        j = out.find('PAIL PREFLIGHT: profile=')
        self.assertGreaterEqual(j, 0, '이 팔의 전제가 없다 — 판정 줄이 없다:\n%s' % out)
        self.assertLess(i, j, 'identity line comes after the verdict')


if __name__ == '__main__':
    unittest.main()
