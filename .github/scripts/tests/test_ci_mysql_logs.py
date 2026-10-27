"""Keep deployment evidence after both successful and failed GR startup."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.github/scripts/ci_collect_mysql_logs.py'


class MySQLLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.container = self.root / 'container'
        self.container.mkdir()
        self.output = self.root / 'mysql-deployment'
        self.requests = self.root / 'requests'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURE_ROOT=str(self.container), REQUESTS=str(self.requests))
        docker = self.bin / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
a=sys.argv[1:]
with open(os.environ['REQUESTS'],'a') as f:f.write(json.dumps(a)+'\\n')
root=pathlib.Path(os.environ['FIXTURE_ROOT'])
if a[0]=='ps':
    print('abc infra-dbdeployer-mysql84-gr-ci-gr-v31-123')
    print('def infra-dbdeployer-mysql84-gr-ci-gr-v31-1234')
elif a[0]=='logs':
    print('2026-10-27T20:34:34Z Using MySQL version: 8.4.8')
    print('2026-10-27T20:34:35Z Installing and starting node 2')
    print('MySQL initialization stderr',file=sys.stderr)
elif a[0]=='inspect': print('{"Status":"exited","ExitCode":1}')
elif a[0]=='cp':
    source=root/a[1].split(':',1)[1].lstrip('/')
    if not source.exists():sys.exit(1)
    if source.is_dir():shutil.copytree(source,a[2])
    else:shutil.copyfile(source,a[2])
elif a[0]=='exec':
    if os.environ.get('STOPPED'):sys.exit(1)
    if 'find' in a:
        for p in root.rglob('*'):
            if p.is_file():print('/'+str(p.relative_to(root)))
    else:print('mysqld process I/O and wait channel')
elif a[0] in ('top','stats'):print('container process/resource snapshot')
else:sys.exit(2)
''')
        docker.chmod(0o755)
        for relative, content in {
            'root/sandboxes/logs/deploy.log': 'deploying node 2\n',
            'root/sandboxes/group_sp_msb_8_4_8/node1/data/msandbox.err': 'node1 ready\n',
            'root/sandboxes/group_sp_msb_8_4_8/node2/data/msandbox.err': 'node2 initializing\n',
            'root/sandboxes/group_sp_msb_8_4_8/node2/init_db': 'mysqld --initialize-insecure\n',
            'root/sandboxes/group_sp_msb_8_4_8/node2/my.sandbox.cnf': 'innodb_buffer_pool_size=128M\n',
            'root/sandboxes/group_sp_msb_8_4_8/node2/data/ibdata1': 'DO NOT COPY DATABASE DATA',
        }.items():
            path = self.container / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def collect(self, **extra):
        result = subprocess.run([sys.executable, str(SCRIPT), '--infra-id', 'ci-gr-v31-123',
                                 '--output', str(self.output)], env=dict(self.env, **extra),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return [json.loads(line) for line in self.requests.read_text().splitlines()]

    def test_live_deployment_logs_survive_container_deletion(self):
        calls = self.collect()
        import shutil
        shutil.rmtree(self.container)
        self.assertEqual((self.output / 'abc/root/sandboxes/logs/deploy.log').read_text(), 'deploying node 2\n')
        self.assertEqual((self.output / 'abc/root/sandboxes/group_sp_msb_8_4_8/node2/data/msandbox.err').read_text(), 'node2 initializing\n')
        self.assertIn('Installing and starting node 2', (self.output / 'abc/deployment.log').read_text())
        self.assertIn('MySQL initialization stderr', (self.output / 'abc/deployment.log').read_text())
        self.assertIn('ExitCode', (self.output / 'abc/state.json').read_text())
        self.assertTrue((self.output / 'host.txt').is_file())
        self.assertFalse(list(self.output.rglob('ibdata1')))
        self.assertFalse((self.output / 'def').exists(), 'must not inspect another job')
        self.assertTrue(any(c[:2] == ['logs', '--timestamps'] for c in calls))

    def test_exited_container_still_yields_mysql_error_and_deployer_logs(self):
        self.collect(STOPPED='1')
        self.assertIn('node2 initializing', (self.output / 'abc/root/sandboxes/group_sp_msb_8_4_8/node2/data/msandbox.err').read_text())
        self.assertIn('deploying node 2', (self.output / 'abc/root/sandboxes/logs/deploy.log').read_text())
        self.assertTrue((self.output / 'collection.json').is_file())

    def test_log_timeout_preserves_partial_output_and_continues_collecting(self):
        spec = importlib.util.spec_from_file_location('mysql_logs', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real_run = subprocess.run

        def transport(command, **kwargs):
            if command[:2] == ['docker', 'logs']:
                raise subprocess.TimeoutExpired(command, 15, output=b'partial deployment output\n')
            return real_run(command, **kwargs)

        with patch.dict(os.environ, self.env), patch.object(module.subprocess, 'run', side_effect=transport):
            module.collect('ci-gr-v31-123', self.output)
        self.assertIn('partial deployment output', (self.output / 'abc/deployment.log').read_text())
        self.assertIn('node2 initializing', (self.output / 'abc/root/sandboxes/group_sp_msb_8_4_8/node2/data/msandbox.err').read_text())
        records = json.loads((self.output / 'collection.json').read_text())
        self.assertTrue(any('error' in record for record in records))

    def test_every_gr_workflow_collects_before_cleanup_and_uploads_on_success(self):
        files = sorted((ROOT / '.github/workflows').glob('ci-mysql*-gr-g*.yml'))
        self.assertEqual(len(files), 12)
        for path in files:
            with self.subTest(workflow=path.name):
                steps = yaml.safe_load(path.read_text())['jobs']['tests']['steps']
                names = [s.get('name') for s in steps]
                self.assertIn('Save MySQL deployment diagnostics', names)
                self.assertLess(names.index('Save MySQL deployment diagnostics'), names.index('Cleanup'))
                collect = steps[names.index('Save MySQL deployment diagnostics')]
                self.assertEqual(collect['if'], 'always()')
                self.assertTrue(collect['continue-on-error'])
                upload = steps[names.index('Archive MySQL deployment diagnostics')]
                self.assertNotIn('failure()', upload['if'])
                self.assertIn('!cancelled()', upload['if'])
                self.assertIn('/mysql-deployment/', upload['with']['path'])
                self.assertEqual(upload['with']['retention-days'], 3)


if __name__ == '__main__':
    unittest.main()
