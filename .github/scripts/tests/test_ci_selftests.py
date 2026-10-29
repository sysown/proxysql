"""Exercise shell failure propagation in the real selftest workflow."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class SelftestFailureTests(unittest.TestCase):
    def test_failed_admin_query_cannot_be_hidden_by_later_success(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci-selftests.yml').read_text())
        step = next(s for s in workflow['jobs']['tests']['steps'] if s.get('name') == 'Self-tests')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'proxysql/src').mkdir(parents=True)
            tools = root / 'tools'
            tools.mkdir()
            mysql = tools / 'mysql'
            mysql.write_text('''#!/usr/bin/env python3
import pathlib,sys
args=' '.join(sys.argv[1:])
if 'SELECT version()' in args:
    print('ERROR: injected Admin query failure',flush=True)
    sys.exit(23)
if 'COREDUMP' in args:
    pathlib.Path('core.test').write_text('test fixture')
print('successful later command',flush=True)
''')
            mysql.chmod(0o755)
            script = step['run'].replace('${{ github.workspace }}', str(root))
            result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                                    env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']),
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
            self.assertNotIn('DONE', result.stdout)


if __name__ == '__main__':
    unittest.main()
