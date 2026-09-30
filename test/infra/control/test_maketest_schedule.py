"""Keep simulator compilation out of PR CI while preserving nightly builds."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class MakeTestScheduleTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / '.github/workflows/CI-maketest.yml').read_text())

    def test_only_nightly_and_manual_triggers(self):
        events = self.workflow.get('on', self.workflow.get(True, {}))
        self.assertEqual(set(events), {'schedule', 'workflow_dispatch'})
        self.assertEqual(events['schedule'], [{'cron': '17 2 * * *'}])
        tier = events['workflow_dispatch']['inputs']['tier']
        self.assertEqual(tier['default'], 'v4.0')
        self.assertEqual(set(tier['options']), {'v4.0', 'v3.1', 'v3.0'})

    def test_builds_are_independent_of_the_pr_producer(self):
        self.assertEqual(set(self.workflow['jobs']), {'builds'})
        job = self.workflow['jobs']['builds']
        self.assertNotIn('needs', job)
        targets = job['strategy']['matrix']['target']
        self.assertEqual(set(targets), {
            'testaurora', 'testgalera', 'testgrouprep',
            'testreadonly', 'testreplicationlag', 'testall',
        })
        self.assertEqual(len(targets), 6)
        checkout = next(step for step in job['steps'] if 'actions/checkout@' in step.get('uses', ''))
        self.assertEqual(checkout['with']['ref'], '${{ github.sha }}')
        self.assertNotIn('coverage', job['name'])

    def test_build_exit_status_logs_and_cleanup(self):
        """Compile failures survive tee, and both paths clean up the container."""
        script = next(step['run'] for step in self.workflow['jobs']['builds']['steps']
                      if step.get('name') == 'Build simulator configuration')
        for build_rc in (0, 23):
            with self.subTest(build_rc=build_rc), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'proxysql').mkdir()
                (root / 'proxysql/Makefile').write_text('all:\n\ttrue\n')
                (root / 'proxysql/docker-compose.yml').write_text('command: original\n')
                bin_dir = root / 'bin'
                bin_dir.mkdir()
                commands = {
                    'git': '#!/bin/sh\necho v4.0.0-1-gabcdef0\n',
                    'make': '#!/bin/sh\necho "Unexpected host packaging invocation" >&2\nexit 99\n',
                    'docker': '''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['DOCKER_CALLS'], 'a') as out:
    out.write(json.dumps(sys.argv[1:]) + '\\n')
if 'run' in sys.argv:
    print('compiler stdout')
    print('compiler stderr', file=sys.stderr)
    sys.exit(int(os.environ['BUILD_RC']))
''',
                }
                for name, content in commands.items():
                    command = bin_dir / name
                    command.write_text(content)
                    command.chmod(0o755)
                env = dict(os.environ, PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],
                           DOCKER_CALLS=str(root / 'calls'), BUILD_RC=str(build_rc),
                           GITHUB_ACTIONS='true', GITHUB_SHA='a'*40, GITHUB_RUN_ID='123',
                           GITHUB_RUN_ATTEMPT='1', TARGET='testall')
                result = subprocess.run(['bash', '-c', script], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, build_rc, result.stdout+result.stderr)
                calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
                self.assertEqual(len(calls), 2)
                self.assertIn('ubuntu22_dbg_build', calls[0])
                self.assertIn('run', calls[0])
                self.assertIn('down', calls[1])
                self.assertIn('compiler stdout', (root / 'build.log').read_text())
                self.assertIn('compiler stderr', (root / 'build.log').read_text())


if __name__ == '__main__':
    unittest.main()
