"""Ensure Router compiles against the same vendored OpenSSL as core."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]


class RouterOpenSSLBuild(unittest.TestCase):
    def test_vendored_headers_are_first_and_no_second_openssl_is_linked(self):
        for platform in ('Darwin', 'Linux'):
            with self.subTest(platform=platform):
                result = subprocess.run(
                    [shutil.which('gmake') or 'make', '-s', '-f', 'Makefile', '-f', '-',
                     'inspect-router', 'PROXYSQL40=1', f'UNAME_S={platform}'],
                    cwd=ROOT / 'plugins/mysql_router', text=True, capture_output=True, check=True,
                    input="inspect-router:\n\t@echo 'IDIRS=$(IDIRS)'\n\t@echo 'LDFLAGS=$(PLUGIN_LDFLAGS)'\n")
                values = dict(line.split('=', 1) for line in result.stdout.splitlines())
                self.assertEqual(values['IDIRS'].split()[0], f'-I{ROOT}/deps/libssl/openssl/include')
                self.assertNotIn('-lssl', values['LDFLAGS'].split())
                self.assertNotIn('-lcrypto', values['LDFLAGS'].split())


if __name__ == '__main__':
    unittest.main()
