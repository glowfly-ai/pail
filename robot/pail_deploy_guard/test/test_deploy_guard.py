# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""SD3-1: evaluate() against the shared truth table
(see spec/ARCHITECTURE.md). The C++ twin reads the same file.
"""

import os
import unittest

from pail_deploy_guard import deploy_guard

MATRIX = os.path.join(os.path.dirname(__file__), 'guard_matrix.tsv')


def _unsentinel(s):
    return '' if s == '<empty>' else s


def _rows():
    with open(MATRIX, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            col = line.split('\t')
            assert len(col) == 8, 'malformed row: %r' % line
            yield col


class TestGuardMatrix(unittest.TestCase):

    def test_matrix(self):
        rows = 0
        for col in _rows():
            rows += 1
            inp = deploy_guard.GuardInput(
                component=col[0],
                profile=_unsentinel(col[1]),
                security_enable=_unsentinel(col[2]),
                security_strategy=_unsentinel(col[3]),
                keystore=_unsentinel(col[4]),
                enclave_provisioned=(col[5] == '1'),
                effective_enclave=_unsentinel(col[6]),
            )
            want = [] if col[7] == '-' else col[7].split(',')
            got = [f[0] for f in deploy_guard.evaluate(inp).fail]
            self.assertEqual(got, want, msg='row: %r' % col)
            for _fid, detail in deploy_guard.evaluate(inp).fail:
                self.assertTrue(detail, msg='empty detail in row: %r' % col)
        self.assertGreaterEqual(rows, 20, 'truth table shrank')

    def test_effective_enclave_from_argv(self):
        cases = [
            (['node', '--ros-args', '-p', 'x:=1'], '/'),
            (['node', '--ros-args', '--enclave', '/pep_gate'], '/pep_gate'),
            (['node', '--enclave', '/a', '--enclave', '/b'], '/b'),
            (['node', '--enclave'], '/'),
        ]
        for argv, want in cases:
            self.assertEqual(deploy_guard.effective_enclave_from_argv(argv), want, msg=argv)

    def test_enclave_override_wins(self):
        argv = ['node', '--ros-args', '--enclave', '/pep_gate']
        self.assertEqual(deploy_guard.effective_enclave('', argv), '/pep_gate')
        self.assertEqual(deploy_guard.effective_enclave('/oem_planner', argv), '/oem_planner')


if __name__ == '__main__':
    unittest.main()
