"""Execute host setup steps with local downloads and real checksum/extraction tools."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


def job(workflow, name):
    return yaml.safe_load((ROOT / '.github/workflows' / workflow).read_text())['jobs'][name]


class HostSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.runner_temp = self.root / 'runner-temp'
        self.runner_temp.mkdir()
        self.archive = self.root / 'fixture.tar.gz'
        payload = b'#!/bin/sh\necho "dbdeployer version 2.4.2"\n'
        with tarfile.open(self.archive, 'w:gz') as archive:
            entry = tarfile.TarInfo('dbdeployer')
            entry.size = len(payload)
            entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(payload))
        self.env = dict(os.environ, PATH=f'{self.bin}:/usr/bin:/bin',
                        RUNNER_TEMP=str(self.runner_temp), GITHUB_PATH=str(self.root / 'github-path'),
                        FIXTURE_ARCHIVE=str(self.archive), REQUESTS=str(self.root / 'requests'))
        self.executable(self.bin / 'curl', '''#!/bin/bash
set -eu
url=""; output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
echo "$url" >> "$REQUESTS"
if [[ "$url" == https://api.github.com/* ]]; then
  echo '{"message":"API rate limit exceeded"}'
  exit 22
fi
if [[ "$url" != https://github.com/ProxySQL/dbdeployer/releases/download/v2.4.2/dbdeployer-2.4.2.linux_amd64.tar.gz ]]; then
  echo "Unexpected download: $url" >&2
  exit 22
fi
if [ "${DOWNLOAD_FAIL:-0}" = 1 ]; then
  echo 'curl: HTTP 503' >&2
  exit 22
fi
cp "$FIXTURE_ARCHIVE" "$output"
''')

    def executable(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def install(self, **overrides):
        step = next(s for s in job('ci-mysqlx.yml', 'e2e-tests')['steps']
                    if s.get('name') == 'Install dbdeployer')
        env = dict(self.env, **step.get('env', {}))
        # Exercise real checksum verification against our local tar fixture.
        env['DBDEPLOYER_SHA256'] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        env.update(overrides)
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']],
                              cwd=self.root, env=env, capture_output=True, text=True)

    def test_install_succeeds_without_release_discovery_api(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bindir = Path((self.root / 'github-path').read_text().strip())
        result = subprocess.run([str(bindir / 'dbdeployer'), '--version'],
                                capture_output=True, text=True, check=True)
        self.assertIn('2.4.2', result.stdout)
        self.assertNotIn('api.github.com', (self.root / 'requests').read_text())
        self.assertFalse(list(self.runner_temp.glob('dbdeployer-install.*')))

    def test_checksum_mismatch_never_installs(self):
        result = self.install(DBDEPLOYER_SHA256='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAILED', result.stdout + result.stderr)
        self.assertFalse((self.root / 'github-path').exists())
        self.assertFalse(list(self.runner_temp.glob('dbdeployer-install.*')))

    def test_download_failure_is_visible_and_never_installs(self):
        result = self.install(DOWNLOAD_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HTTP 503', result.stderr)
        self.assertFalse((self.root / 'github-path').exists())
        self.assertFalse(list(self.runner_temp.glob('dbdeployer-install.*')))

    def test_existing_install_is_checked_without_downloading(self):
        self.executable(self.bin / 'dbdeployer', '#!/bin/sh\necho existing-dbdeployer\n')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('existing-dbdeployer', result.stdout)
        self.assertFalse((self.root / 'requests').exists())

    def test_shuntest_uses_host_abi_compatible_with_build(self):
        shuntest = job('ci-shuntest.yml', 'tests')
        self.assertEqual(shuntest['runs-on'], 'ubuntu-24.04')
        self.assertNotIn('pick-runner', shuntest['needs'])

    def test_shuntest_reports_loader_failure_before_starting_infrastructure(self):
        steps = job('ci-shuntest.yml', 'tests')['steps']
        names = [s.get('name') for s in steps]
        self.assertIn('Verify ProxySQL host runtime', names)
        index = names.index('Verify ProxySQL host runtime')
        self.assertGreater(index, names.index('Restore selected product handoff'))
        self.assertLess(index, names.index('Docker-hoster'))
        binary = self.root / 'proxysql/src/proxysql'
        binary.parent.mkdir(parents=True)
        self.executable(binary, '#!/bin/sh\necho "GLIBC_2.38 not found" >&2\nexit 127\n')
        result = subprocess.run(['bash', '-e', '-c', steps[index]['run']], cwd=self.root,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GLIBC_2.38 not found', result.stderr)


if __name__ == '__main__':
    unittest.main()
