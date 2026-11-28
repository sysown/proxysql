"""Ensure the vendored TLS option patch applies with native and GNU patch."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CONNECTOR = ROOT / 'deps/mariadb-client-library'


class MariaDBTLSPatch(unittest.TestCase):
    def test_mysql_header_patch_applies_without_fuzz(self):
        # The TLS option hunk used to have no leading context. Apple's patch
        # rejects that mid-file hunk even though GNU patch accepts it.
        cases = (
            ('3.3.8', CONNECTOR, 'MARIADB_OPT_SERVER_PLUGINS'),
            ('3.4.11', CONNECTOR / 'patches-3.4.11', 'MARIADB_OPT_MAX_COLUMNS'),
        )
        binaries = {shutil.which(name) for name in ('patch', 'gpatch')}
        if sys.platform == 'darwin':
            binaries.add('/usr/bin/patch')
        self.assertTrue(binaries - {None}, 'at least one patch executable is required')
        for version, patches, previous in cases:
            source_root = f'mariadb-connector-c-{version}-src'
            header = subprocess.check_output([
                'tar', '-xOf', str(CONNECTOR / f'{source_root}.tar.gz'),
                f'{source_root}/include/mysql.h'])
            source = (patches / 'tls_server_name.patch').read_text()
            start = source.index('--- include/mysql.h\n')
            patch = source[start:].split('\n--- ', 1)[0].split('\ndiff --git ', 1)[0] + '\n'

            for binary in sorted(binaries - {None}):
                with self.subTest(version=version, binary=binary), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / 'include').mkdir()
                    target = root / 'include/mysql.h'
                    target.write_bytes(header)
                    result = subprocess.run([binary, '-f', '-F0', '-p0'], cwd=root,
                                            input=patch, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f'MARIADB_OPT_TLS_SERVER_NAME = {previous} + 2',
                                  target.read_text())


if __name__ == '__main__':
    unittest.main()
