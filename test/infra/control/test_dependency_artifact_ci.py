"""Exercise dependency CI event gates, change coverage and shell checks."""
import fnmatch
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:
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

    def test_runtime_fixture_suite_can_skip_optional_workflow_dependencies(self):
        result = subprocess.run(
            [sys.executable, '-S', '-m', 'unittest', 'discover', '-s',
             str(ROOT / 'test/infra/control'), '-p', 'test_dependency_artifact_ci.py', '-v'],
            universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('workflow validation requires PyYAML', result.stderr)

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

    def test_openssl_bridge_make_failure_reports_captured_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'deps/libssl').mkdir(parents=True)
            openssl = root / 'deps/libssl/openssl'
            (root / 'deps/Makefile').write_text(
                f'OPENSSL_VERSION := 3.5.7\nSSL_PATH := {openssl}\n'
                f'SSL_IDIR := {openssl}/include\nSSL_LDIR := {openssl}\n'
                f'LIB_SSL_PATH := {openssl}/libssl.a\n'
                f'LIB_CRYPTO_PATH := {openssl}/libcrypto.a\n'
                f'OPENSSL_STATIC_LIBS := {openssl}/libssl.a {openssl}/libcrypto.a\n'
                'ifeq ($(MAKECMDGOALS),libssl)\n'
                '$(error fixture OpenSSL bridge failure)\nendif\n'
                'dependency-source-openssl:\n\t@true\n')
            result = subprocess.run(
                ['bash', str(ROOT / 'test/infra/control/test-vendored-openssl-build-contract.bash')],
                env=dict(os.environ, OPENSSL_BUILD_CONTRACT_ROOT=tmp),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('fixture OpenSSL bridge failure', result.stderr)
            self.assertIn('ERROR:', result.stderr)


if __name__ == '__main__':
    unittest.main()
