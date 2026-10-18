"""Exercise checkout cleanup after a Docker job leaves protected host files."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
ACTION = 'sysown/proxysql/.github/actions/reclaim-workspace@GH-Actions'
HELPER = ROOT / '.github/actions/reclaim-workspace/reclaim.bash'


def self_hosted_checkout_jobs():
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        # Builds already reclaim before checkout and after Docker builds.
        if path.name == 'ci-builds.yml':
            continue
        doc = yaml.safe_load(path.read_text())
        for name, job in (doc.get('jobs') or {}).items():
            steps = job.get('steps', [])
            runner = str(job.get('runs-on', ''))
            if not ('self-hosted' in runner or 'fromJson' in runner):
                continue
            if any('actions/checkout@' in s.get('uses', '') for s in steps):
                yield path.name, name, steps


class WorkspaceOwnershipTests(unittest.TestCase):
    def test_self_hosted_jobs_reclaim_before_checkout_and_on_failure(self):
        jobs = list(self_hosted_checkout_jobs())
        self.assertGreater(len(jobs), 0)
        for file, job, steps in jobs:
            with self.subTest(file=file, job=job):
                checkout = next(i for i, step in enumerate(steps)
                                if 'actions/checkout@' in step.get('uses', ''))
                guards = [(i, s) for i, s in enumerate(steps) if s.get('uses') == ACTION]
                self.assertTrue(any(i < checkout for i, _ in guards),
                                'Docker-owned files must be reclaimed before checkout')
                self.assertTrue(any(i > checkout and 'always()' in s.get('if', '')
                                    for i, s in guards),
                                'failed jobs must leave the workspace clean for the next job')

    def run_helper(self, workspace, environment='self-hosted'):
        self.assertTrue(HELPER.is_file(), 'missing workspace ownership repair')
        return subprocess.run(['bash', str(HELPER)], capture_output=True, text=True,
                              env={**os.environ, 'GITHUB_WORKSPACE': str(workspace),
                                   'RUNNER_ENVIRONMENT': environment})

    def test_hosted_runner_does_not_touch_the_workspace(self):
        result = self.run_helper('/', 'github-hosted')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_refuses_filesystem_root(self):
        result = self.run_helper('/')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing', result.stderr)

    def test_checkout_can_remove_container_owned_cache_and_database_directory(self):
        if shutil.which('sudo') is None or subprocess.run(
                ['sudo', '-n', 'true'], capture_output=True).returncode:
            self.skipTest('passwordless sudo is needed to reproduce container ownership')
        with tempfile.TemporaryDirectory(prefix='proxysql-checkout-') as directory:
            workspace = Path(directory) / 'checkout'
            workspace.mkdir()
            subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
            cache = workspace / 'test/scripts/lib/__pycache__'
            database = workspace / 'ci_infra_logs/old-job/pgdb1'
            for path in (cache, database):
                path.mkdir(parents=True)
                (path / 'container-output').write_text('fixture')
                path.chmod(0o700)
                subprocess.run(['sudo', '-n', 'chown', '-R', '0:0', str(path)], check=True)
            external = Path(directory) / 'external'
            external.write_text('must not be changed')
            external.chmod(0o600)
            subprocess.run(['sudo', '-n', 'chown', '0:0', str(external)], check=True)
            try:
                dirty = subprocess.run(['git', '-C', str(workspace), 'clean', '-ffdx'],
                                       capture_output=True, text=True)
                self.assertNotEqual(dirty.returncode, 0, 'fixture must reproduce checkout failure')
                # git clean may already have removed unrelated untracked links.
                (workspace / 'external-link').symlink_to(external)
                result = self.run_helper(workspace)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(external.stat().st_uid, 0, 'must not follow external symlinks')
                self.assertEqual(external.stat().st_mode & 0o777, 0o600)
                clean = subprocess.run(['git', '-C', str(workspace), 'clean', '-ffdx'],
                                       capture_output=True, text=True)
                self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
                self.assertFalse(cache.exists())
                self.assertFalse(database.exists())
            finally:
                subprocess.run(['sudo', '-n', 'chown', '-hR',
                                f'{os.getuid()}:{os.getgid()}', directory], check=True)
                subprocess.run(['sudo', '-n', 'chmod', '-R', 'u+rwX', directory], check=True)


if __name__ == '__main__':
    unittest.main()
