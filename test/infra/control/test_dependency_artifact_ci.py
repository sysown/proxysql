"""Exercise dependency CI event gates, change coverage and shell checks."""
import fnmatch
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:
    if os.environ.get('DEPS_ARTIFACT_CI_REQUIRED') == '1':
        raise
    raise unittest.SkipTest('workflow validation requires PyYAML')

from ci_tier_conditions import condition_allows


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / '.github/workflows/CI-dependency-artifacts-checks.yml'
SCRIPTS = (
    'deps/artifacts/prepare.bash',
    'deps/artifacts/build.bash',
    'test/infra/control/dependency-artifacts-smoke.bash',
)


class DependencyArtifactCITests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW.read_text())

    def test_workflow_installs_and_imports_yaml_before_fixture_discovery(self):
        steps = self.workflow['jobs']['fixtures']['steps']
        discovery = next(i for i, step in enumerate(steps)
                         if 'unittest discover' in step.get('run', ''))
        setup = [step['run'] for step in steps[:discovery]
                 if 'pip install' in step.get('run', '')]
        self.assertEqual(len(setup), 1, 'install workflow dependencies before discovery')
        # Keep the Python import real. Replace only package download/installation
        # with a local copy of the installed package, without using the network.
        for installed, install_fails, expected in ((False, False, True),
                                                  (True, True, True),
                                                  (False, True, False)):
            with self.subTest(installed=installed, install_fails=install_fails), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                site = root / 'site'
                site.mkdir()
                package = Path(yaml.__file__).parent
                if installed:
                    shutil.copytree(str(package), str(site / 'yaml'))
                (site / 'pip.py').write_text(
                    'import os, shutil, sys\n'
                    'assert sys.argv[1] == "install"\n'
                    'assert any(arg.startswith("PyYAML") for arg in sys.argv[2:])\n'
                    'if os.environ["INSTALL_FAILS"] == "1": sys.exit(53)\n'
                    'shutil.copytree(' + repr(str(package)) + ', ' + repr(str(site / 'yaml')) + ')\n')
                python = root / 'python3'
                python.write_text('#!/bin/sh\nexec ' + repr(sys.executable) + ' -S "$@"\n')
                python.chmod(0o755)
                env = dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH'],
                           PYTHONPATH=str(site), INSTALL_FAILS='1' if install_fails else '0')
                result = subprocess.run(['bash', '-e', '-c', setup[0]], env=env,
                                        universal_newlines=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode == 0, expected, result.stdout + result.stderr)
                if expected:
                    imported = subprocess.run([str(python), '-c', 'import yaml'], env=env,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertEqual(imported.returncode, 0, imported.stderr)

    def allows(self, job, event, **context):
        values = {
            'github.event_name': event,
            'github.event.pull_request.labels.*.name': [],
            'needs.push-label.result': 'skipped',
            'needs.push-label.outputs.skip': '',
        }
        values.update(context)
        return condition_allows(job.get('if'), 'v30', 'release', event_context=values)

    def test_pr_skip_label_blocks_both_jobs_without_blocking_manual_runs(self):
        for name in ('fixtures', 'source-validation'):
            job = self.workflow['jobs'][name]
            for event, labels, expected in (
                ('pull_request', ['ci:skip'], False),
                ('pull_request', [], True),
                ('workflow_dispatch', [], True),
            ):
                with self.subTest(job=name, event=event, labels=labels):
                    self.assertEqual(self.allows(job, event, **{
                        'github.event.pull_request.labels.*.name': labels,
                    }), expected)

    def test_push_jobs_require_successful_label_lookup_allowing_ci(self):
        for name in ('fixtures', 'source-validation'):
            job = self.workflow['jobs'][name]
            needs = job.get('needs', [])
            if isinstance(needs, str):
                needs = [needs]
            self.assertIn('push-label', needs)
            for result, skip, expected in (
                ('success', 'false', True), ('success', 'true', False),
                ('failure', '', False), ('cancelled', '', False), ('skipped', '', False),
            ):
                with self.subTest(job=name, result=result, skip=skip):
                    self.assertEqual(self.allows(job, 'push', **{
                        'needs.push-label.result': result,
                        'needs.push-label.outputs.skip': skip,
                    }), expected)

    def test_push_label_lookup_only_runs_for_pushes(self):
        self.assertIn('push-label', self.workflow['jobs'])
        job = self.workflow['jobs']['push-label']
        for event, expected in (('push', True), ('pull_request', False),
                                ('workflow_dispatch', False)):
            with self.subTest(event=event):
                self.assertEqual(self.allows(job, event), expected)

    def test_push_and_pr_watch_all_dependency_integration_inputs(self):
        events = self.workflow.get('on', self.workflow.get(True))
        changes = (
            'deps/artifacts/manage.py', 'deps/duckdb/build.mk', 'deps/libssl/build.mk',
            'common_mk/openssl_flags.mk', 'deps/Makefile', 'Makefile',
            'plugins/duckdb/Makefile', 'docker-compose.yml',
            'test/infra/control/test_dependency_artifact_ci.py',
            'test/infra/control/dependency-artifacts-smoke.bash',
            'test/infra/control/test-vendored-openssl-build-contract.bash',
            'test/infra/control/test-vendored-openssl-consumers.bash',
            '.github/workflows/CI-dependency-artifacts.yml',
        )
        for event in ('push', 'pull_request'):
            for change in changes:
                with self.subTest(event=event, change=change):
                    self.assertTrue(any(fnmatch.fnmatchcase(change, pattern)
                                        for pattern in events[event]['paths']))

    def test_shell_syntax_check_rejects_errors_in_every_script(self):
        # Execute the workflow's actual syntax check; bash -n file1 file2 only
        # parses file1, so an invalid later script must still fail this step.
        runs = [step['run'] for step in self.workflow['jobs']['fixtures']['steps']
                if 'bash -n' in step.get('run', '')]
        self.assertEqual(len(runs), 1)
        script = runs[0]
        if not script.lstrip().startswith('for '):
            script = next(line.strip() for line in script.splitlines() if 'bash -n' in line)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for invalid in (None,) + SCRIPTS:
                for relative in SCRIPTS:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('if\n' if relative == invalid else 'true\n')
                with self.subTest(invalid=invalid):
                    result = subprocess.run(['bash', '-e', '-c', script], cwd=root,
                                            universal_newlines=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertEqual(result.returncode == 0, invalid is None,
                                     result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
