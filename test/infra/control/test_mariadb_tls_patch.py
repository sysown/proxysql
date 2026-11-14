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
        archive = CONNECTOR / 'mariadb-connector-c-3.3.8-src.tar.gz'
        header = subprocess.check_output([
            'tar', '-xOf', str(archive),
            'mariadb-connector-c-3.3.8-src/include/mysql.h'])
        source = (CONNECTOR / 'tls_server_name.patch').read_text()
        patch = 'diff --git include/mysql.h include/mysql.h\n' + source.split(
            'diff --git include/mysql.h include/mysql.h\n', 1)[1].split('diff --git ', 1)[0]
        binaries = {shutil.which(name) for name in ('patch', 'gpatch')}
        if sys.platform == 'darwin':
            binaries.add('/usr/bin/patch')
        self.assertTrue(binaries - {None}, 'at least one patch executable is required')
        for binary in sorted(binaries - {None}):
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'include').mkdir()
                target = root / 'include/mysql.h'
                target.write_bytes(header)
                result = subprocess.run([binary, '-f', '-F0', '-p0'], cwd=root,
                                        input=patch, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('MARIADB_OPT_TLS_SERVER_NAME = MARIADB_OPT_SERVER_PLUGINS + 2',
                              target.read_text())


if __name__ == '__main__':
    unittest.main()
