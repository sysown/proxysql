"""Exercise the unit runner with real child processes and stub coverage tools."""
import os
import json
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).with_name('run-unit-tests-asan-coverage.bash')


class UnitRunnerTimeoutTests(unittest.TestCase):
    runner_name = RUNNER.name
    expected_summary = '1 passed, 1 failed'
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.control = self.root / 'test/infra/control'
        self.control.mkdir(parents=True)
        for name in [RUNNER.name, 'run-tests-isolated.bash',
                     'unit-test-execution.bash', 'asan-detection.bash']:
            shutil.copy2(RUNNER.with_name(name), self.control / name)
        self.units = self.root / 'test/tap/tests/unit'
        self.units.mkdir(parents=True)
        (self.root / 'lib').mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, body in [('lcov', ':'), ('genhtml', ':'),
                           ('ldconfig', 'echo libprotobuf.so')]:
            self.executable(self.bin / name, body)

    def executable(self, path, body):
        path.write_text('#!/usr/bin/env bash\n' + body + '\n')
        path.chmod(0o755)

    def run_suite(self, timeout='1'):
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                   UNIT_TEST_TIMEOUT_SECONDS=timeout, SKIP_PROXYSQL='1',
                   TAP_GROUP='unit-tests-g1', INFRA_ID='timeout-regression',
                   INFRA_TYPE='', COVERAGE='0', TEST_PY_TAP_EXCL='')
        groups = self.root / 'test/tap/groups'
        groups.mkdir(exist_ok=True)
        (groups / 'groups.json').write_text(json.dumps(
            {p.name: ['unit-tests-g1'] for p in self.units.glob('*-t')}))
        process = subprocess.Popen(['bash', str(self.control / self.runner_name)],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=15)
            stdout = stdout.replace('>>> PASSED:', 'PASS:').replace('>>> FAILED:', 'FAIL:')
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        finally:
            # Also bound failing test runs against a runner without timeouts.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    def test_timeout_kills_term_resistant_process_group_and_continues(self):
        pidfile = self.root / 'child.pid'
        self.executable(self.units / 'a-hang-t',
                        "trap '' TERM\n"
                        "bash -c 'trap \"\" TERM; while :; do sleep 1; done' &\n"
                        f'echo $! > "{pidfile}"\nwait')
        self.executable(self.units / 'b-pass-t', 'exit 0')
        result = self.run_suite()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('TIMEOUT: a-hang-t', result.stdout)
        self.assertIn('PASS: b-pass-t', result.stdout)
        self.assertIn(self.expected_summary, result.stdout)
        child_pid = int(pidfile.read_text())
        # A killed grandchild may remain as a zombie until the container's init
        # reaps it; only a running process would indicate failed group cleanup.
        stat = Path(f'/proc/{child_pid}/stat')
        self.assertTrue(not stat.exists() or stat.read_text().split()[2] == 'Z')

    def test_zero_exit_sanitizer_report_is_failure(self):
        self.executable(self.units / 'sanitizer-t',
                        "echo 'WARNING: ThreadSanitizer: use of an invalid mutex' >&2\nexit 0")
        result = self.run_suite()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('FAIL: sanitizer-t', result.stdout)
        self.assertIn('WARNING: ThreadSanitizer:', result.stdout)

    def test_log_capture_failure_is_fatal(self):
        self.executable(self.units / 'log-failure-t', 'exit 0')
        if self.runner_name == 'run-tests-isolated.bash':
            log_dir = self.root / 'ci_infra_logs/timeout-regression/unit-test-logs'
        else:
            log_dir = self.root / 'unit-test-logs'
        (log_dir / 'log-failure-t.log').mkdir(parents=True)
        result = self.run_suite()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('FAIL: log-failure-t', result.stdout)

    def test_nonzero_exit_is_preserved(self):
        self.executable(self.units / 'failure-t', 'exit 7')
        result = self.run_suite()
        self.assertEqual(result.returncode, 1)
        self.assertIn('failure-t (rc=7)', result.stdout)

    def test_unbounded_timeout_is_rejected(self):
        self.executable(self.units / 'pass-t', 'exit 0')
        result = self.run_suite(timeout='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('UNIT_TEST_TIMEOUT_SECONDS', result.stderr)


class IsolatedUnitRunnerTimeoutTests(UnitRunnerTimeoutTests):
    runner_name = 'run-tests-isolated.bash'
    expected_summary = '1/2 passed, 1 failed'


if __name__ == '__main__':
    unittest.main()
