"""Keep infrastructure evidence across services, job outcomes and teardown."""
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
SCRIPT = ROOT / '.github/scripts/ci_collect_infra_logs.py'
sys.path.insert(0, str(SCRIPT.parent))


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
import json, os, pathlib, shutil, sys, tarfile
a=sys.argv[1:]
with open(os.environ['REQUESTS'],'a') as f:f.write(json.dumps(a)+'\\n')
root=pathlib.Path(os.environ['FIXTURE_ROOT'])
if a[0]=='ps':
    print('abc\\ndef')
elif a[0]=='logs':
    print('2026-10-27T20:34:34Z Using '+os.environ.get('FLAVOR','MySQL')+' version: '+os.environ.get('VERSION','8.4.8'))
    print('2026-10-27T20:34:35Z Installing and starting node 2')
    print('MySQL initialization stderr',file=sys.stderr)
elif a[0]=='inspect':
    for identifier, project in [('abc',os.environ.get('PROJECT','infra-dbdeployer-mysql84-gr-ci-gr-v31-123')),('def','unrelated-ci-gr-v31-1234')]:
        if identifier in a[3:]:print(json.dumps(dict(id=identifier,project=project,name='/'+identifier,mounts=[],networks={},state={'Status':'running' if os.environ.get('RUNNING') else 'exited','ExitCode':1})))
elif a[0]=='cp':
    source=root/a[1].split(':',1)[1].lstrip('/')
    if not source.exists():sys.exit(1)
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:archive.add(source,arcname=source.name)
elif a[0]=='exec':
    if os.environ.get('STOPPED'):sys.exit(1)
    if 'find' in a:
        if os.environ.get('BIG_FIND'):
            sys.stdout.write('x'*(2*1024*1024));sys.exit(0)
        for p in root.rglob('*'):
            if p.is_file() and (p.suffix!='.conf' or '*.conf' in a):print('/'+str(p.relative_to(root)))
        if os.environ.get('PARTIAL_FIND'):sys.exit(1)
    else:print('mysqld process I/O and wait channel')
elif a[0] in ('top','stats'):print('container process/resource snapshot')
elif a[0]=='compose' and a[-2:]==['ps','-aq']:print('abc')
elif a[0]=='rm' or (a[0]=='compose' and 'down' in a):
    shutil.rmtree(root)
    print('original docker stdout')
    sys.exit(int(os.environ.get('REMOVE_STATUS','0')))
else:sys.exit(2)
''')
        docker.chmod(0o755)
        for relative, content in {
            'var/log/service/engine.log': 'generic service log\n',
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

    def collect(self, extra_args=(), **extra):
        result = subprocess.run([sys.executable, str(SCRIPT), '--infra-id', 'ci-gr-v31-123',
                                 '--output', str(self.output), *extra_args], env=dict(self.env, **extra),
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
        self.assertTrue(any(c[:4] == ['logs', '--timestamps', '--tail', '20000'] for c in calls))

    def test_collection_is_independent_of_service_type(self):
        for service in ('mysql', 'mariadb', 'postgresql', 'clickhouse', 'valkey', 'future-service'):
            with self.subTest(service=service):
                self.output = self.root / service
                self.collect(PROJECT='infra-' + service + '-ci-gr-v31-123')
                self.assertIn('generic service log', (self.output / 'abc/var/log/service/engine.log').read_text())
                self.assertTrue((self.output / 'abc/deployment.log').is_file())

    def test_missing_optional_find_roots_do_not_discard_discovered_logs(self):
        self.collect(PARTIAL_FIND='1')
        self.assertIn('node2 initializing', (self.output / 'abc/root/sandboxes/group_sp_msb_8_4_8/node2/data/msandbox.err').read_text())

    def test_ownership_includes_workspace_and_network_peers_but_not_other_jobs(self):
        spec = importlib.util.spec_from_file_location('infra_logs', SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        states = [
            dict(id='a', project='app', mounts=[{'Source':str(self.root/'checkout/subdir')}], networks={'backend':{},'host':{}}),
            dict(id='b', project='postgres', mounts=[], networks={'backend':{}}),
            dict(id='c', project='postgres', mounts=[], networks={'replication':{}}),
            dict(id='d', project='sidecar', mounts=[], networks={'replication':{}}),
            dict(id='e', project='unrelated', mounts=[], networks={'host':{}}),
            dict(id='f', project='other', mounts=[{'Source':str(self.root/'checkout-other')}], networks={}),
        ]
        selected = module.selected_containers(states, '', self.root/'checkout')
        self.assertEqual({s['id'] for s in selected}, {'a','b','c','d'})
        peers = [dict(id='b',project='suite',mounts=[],networks={}),
                 dict(id='a',project='suite',mounts=[{'Source':str(self.root/'checkout')}],networks={})]
        self.assertEqual({s['id'] for s in module.selected_containers(peers,'',self.root/'checkout')},{'a','b'})
        self.assertEqual(len(module.selected_containers(states, '', self.root/'checkout', True)), 6)

    def test_docker_hook_saves_logs_before_harness_removal_and_preserves_exit_status(self):
        hook = ROOT/'.github/scripts/ci_docker_diagnostics.py'
        for args,status in [(['rm','-f','abc'],23),(['compose','-p','suite','down','-v'],0)]:
            with self.subTest(args=args):
                # Each operation gets an independent fixture filesystem.
                self.output = self.root / ('capture-'+args[0])
                self.container.mkdir(exist_ok=True)
                log = self.container/'var/log/service/engine.log'
                log.parent.mkdir(parents=True,exist_ok=True);log.write_text('before harness removal\n')
                env=dict(self.env,CI_INFRA_DIAGNOSTICS_ROOT=str(self.output),REMOVE_STATUS=str(status))
                code='from ci_docker_diagnostics import wrapper_main;wrapper_main('+repr(str(self.bin/'docker'))+','+repr(args)+')'
                result=subprocess.run([sys.executable,'-c','import sys;sys.path.insert(0,'+repr(str(hook.parent))+');'+code],
                                      env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,status,result.stderr)
                self.assertEqual(result.stdout,'original docker stdout\n')
                self.assertFalse(self.container.exists())
                self.assertIn('before harness removal',(self.output/'abc/var/log/service/engine.log').read_text())

    def test_docker_global_value_options_do_not_bypass_teardown_capture(self):
        from ci_docker_diagnostics import removal_targets
        for option in ('-l','--log-level','--tlscacert','--tlscert','--tlskey'):
            with self.subTest(option=option):
                targets,prefix=removal_targets('/usr/bin/docker',[option,'value','rm','-f','abc'])
                self.assertEqual(targets,['abc'])
                self.assertEqual(prefix,['/usr/bin/docker',option,'value'])

    def test_collection_lock_wait_is_bounded(self):
        import ci_docker_diagnostics as hook
        with patch.object(hook.fcntl,'flock',side_effect=BlockingIOError),patch.object(hook.time,'monotonic',side_effect=[0,1,2]),patch.object(hook.time,'sleep'):
            self.assertFalse(hook.acquire_collection_lock(object()))

    def test_overwrites_do_not_consume_additional_file_or_byte_budget(self):
        from ci_collect_infra_logs import FileBudget
        self.output.mkdir()
        budget=FileBudget(self.output)
        target=self.output/'service.log'
        self.assertTrue(budget.save(target,b'first snapshot'))
        count=budget.files
        self.assertTrue(budget.save(target,b'new'))
        self.assertEqual(budget.files,count)
        self.assertEqual(budget.bytes,3)

    def test_existing_service_files_refresh_at_file_and_byte_caps(self):
        self.collect()
        spec=importlib.util.spec_from_file_location('infra_logs',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        source=self.container/'var/log/service/engine.log'
        target=self.output/'abc/var/log/service/engine.log'
        count=len([p for p in self.output.rglob('*') if p.is_file()])
        source.write_text('new\n')
        with patch.dict(os.environ,self.env),patch.object(module,'MAX_FILES',count):
            module.collect('ci-gr-v31-123',self.output)
        self.assertEqual(target.read_text(),'new\n')
        source.write_text('ok\n')
        total=sum(p.stat().st_size for p in self.output.rglob('*') if p.is_file() and p.name!='collection.json')
        with patch.dict(os.environ,self.env),patch.object(module,'MAX_TOTAL_BYTES',total):
            module.collect('ci-gr-v31-123',self.output)
        self.assertEqual(target.read_text(),'ok\n')

    def test_live_postgresql_configuration_is_collected_alongside_logs(self):
        for name in ('postgresql.conf','pg_hba.conf'):
            source=self.container/'home/pguser/sandboxes/primary/data'/name
            source.parent.mkdir(parents=True,exist_ok=True);source.write_text('postgres configuration\n')
        self.collect()
        for name in ('postgresql.conf','pg_hba.conf'):
            self.assertIn('postgres configuration',(self.output/'abc/home/pguser/sandboxes/primary/data'/name).read_text())

    def test_probe_listing_is_bounded(self):
        self.collect(BIG_FIND='1')
        records=json.loads((self.output/'collection.json').read_text())
        listing=next(r for r in records if 'find' in r.get('command',[]))
        self.assertTrue(listing.get('truncated'))

    def test_file_budget_applies_to_metadata_and_command_outputs(self):
        spec=importlib.util.spec_from_file_location('infra_logs',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.dict(os.environ,self.env),patch.object(module,'MAX_FILES',3):
            module.collect('ci-gr-v31-123',self.output)
        self.assertLessEqual(len([p for p in self.output.rglob('*') if p.is_file()]),3)

    def test_output_cannot_escape_runner_temp_or_follow_an_output_symlink(self):
        spec=importlib.util.spec_from_file_location('infra_logs',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        runner_temp=self.root/'runner-temp';runner_temp.mkdir()
        outside=self.root/'outside'
        with patch.dict(os.environ,RUNNER_TEMP=str(runner_temp)):
            with self.assertRaises(ValueError):module.collect('',outside)
            (runner_temp/'linked').symlink_to(outside)
            with self.assertRaises(ValueError):module.collect('',runner_temp/'linked')
            safe=runner_temp/'safe';safe.mkdir()
            target=self.root/'keep.txt';target.write_text('preserve')
            (safe/'collection.json').symlink_to(target)
            with self.assertRaises(ValueError):module.collect('',safe)
            self.assertEqual(target.read_text(),'preserve')
        self.assertFalse(outside.exists())

    def test_timeout_partial_file_is_counted_in_payload_budget(self):
        spec=importlib.util.spec_from_file_location('infra_logs',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        large=self.container/'var/log/service/large.log';large.write_bytes(b'x'*2048)
        real_run=subprocess.run
        real_read=Path.read_text
        def read(path,*args,**kwargs):
            return '' if str(path).startswith('/proc/') else real_read(path,*args,**kwargs)
        def transport(command,**kwargs):
            if command[:2]==['docker','logs']:
                kwargs['stdout'].write(b'p'*512)
                raise subprocess.TimeoutExpired(command,1)
            return real_run(command,**kwargs)
        with patch.dict(os.environ,self.env),patch.object(module,'MAX_TOTAL_BYTES',1536),patch.object(module.subprocess,'run',side_effect=transport),patch.object(Path,'read_text',read):
            module.collect('ci-gr-v31-123',self.output)
        self.assertEqual((self.output/'abc/deployment.log').stat().st_size,512)
        payload=[p for p in self.output.rglob('*') if p.is_file() and p.name!='collection.json']
        self.assertLessEqual(sum(p.stat().st_size for p in payload),1536)

    def test_exited_mariadb_replication_galera_and_postgresql_layouts(self):
        for flavor,version,project,relative in [
            ('MariaDB','10.11.14','infra-dbdeployer-mariadb10', 'root/sandboxes/rsandbox_10_11_14/master/data/msandbox.err'),
            ('MariaDB','10.11.14','infra-dbdeployer-mariadb10-galera', 'root/sandboxes/galera_msb_10_11_14/node2/data/msandbox.err'),
            ('PostgreSQL','17.10','infra-dbdeployer-pgsql17-repl', 'home/pguser/sandboxes/postgresql_repl_16710/primary/postgresql.log'),
        ]:
            with self.subTest(project=project):
                path = self.container/relative; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('service initialization detail\n')
                self.output = self.root/project
                self.collect(STOPPED='1', FLAVOR=flavor, VERSION=version, PROJECT=project+'-ci-gr-v31-123')
                self.assertIn('service initialization detail', (self.output/'abc'/relative).read_text())

    def test_host_sandbox_logs_and_streamed_log_size_limits(self):
        spec = importlib.util.spec_from_file_location('infra_logs', SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        huge = self.container/'var/log/service/large.log'
        huge.write_bytes(b'x'*10000)
        sandbox = self.root/'native/single/data'; sandbox.mkdir(parents=True)
        (sandbox/'msandbox.err').write_text('native service detail\n')
        with patch.dict(os.environ,self.env), patch.object(module,'MAX_FILE_BYTES',1024):
            module.collect('ci-gr-v31-123', self.output, host_log_root=self.root/'native')
        self.assertEqual((self.output/'abc/var/log/service/large.log').stat().st_size,1024)
        self.assertIn('native service detail',(self.output/'host-sandboxes/single/data/msandbox.err').read_text())
        self.assertTrue(any(record.get('truncated') for record in json.loads((self.output/'collection.json').read_text())))

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

    def test_slow_first_service_cannot_starve_other_container_logs(self):
        spec = importlib.util.spec_from_file_location('infra_logs', SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        real_run = subprocess.run
        clock = [0]

        def transport(command, **kwargs):
            if command[1] in ('logs','top') and 'abc' in command:
                clock[0] += kwargs['timeout']
                raise subprocess.TimeoutExpired(command, kwargs['timeout'])
            return real_run(command, **kwargs)

        with patch.dict(os.environ,dict(self.env,RUNNING='1')), patch.object(module.subprocess,'run',side_effect=transport), patch.object(module.time,'monotonic',side_effect=lambda:clock[0]):
            module.collect('',self.output,all_containers=True,timeout=20)
        self.assertIn('Installing and starting', (self.output/'def/deployment.log').read_text())

    def test_full_budget_keeps_previous_evidence_and_still_saves_manifest(self):
        spec = importlib.util.spec_from_file_location('infra_logs', SCRIPT)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.output.mkdir()
        retained=self.output/'previous-service.log';retained.write_bytes(b'x'*1024)
        with patch.dict(os.environ,dict(self.env,STOPPED='1')), patch.object(module,'MAX_TOTAL_BYTES',1024):
            module.collect('ci-gr-v31-123',self.output)
        self.assertEqual(retained.read_bytes(),b'x'*1024)
        self.assertTrue((self.output/'collection.json').is_file())

    def test_all_infrastructure_jobs_collect_before_teardown(self):
        checked = []
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            workflow = yaml.safe_load(path.read_text())
            for job_name, job in workflow.get('jobs', {}).items():
                steps = job.get('steps', [])
                runs = '\n'.join(s.get('run', '') for s in steps)
                if not (any(marker in runs for marker in ('ensure-infras.bash','destroy-infras.bash','stop-proxysql-isolated.bash')) or path.name.startswith('ci-3p-')
                        or any(s.get('name') == 'Cleanup sandbox' for s in steps)):
                    continue
                if not steps:
                    continue
                with self.subTest(workflow=path.name, job=job_name):
                    captures = [i for i,s in enumerate(steps) if s.get('uses') == './ci-control/.github/actions/infrastructure-diagnostics' and s.get('with',{}).get('phase') != 'setup']
                    self.assertEqual(len(captures), 1)
                    index = captures[0]
                    self.assertEqual(steps[index]['if'], '${{ !cancelled() }}')
                    self.assertNotIn('timeout-minutes',steps[index])
                    self.assertTrue(steps[index]['continue-on-error'])
                    cleanups = [i for i,s in enumerate(steps) if 'stop-proxysql-isolated.bash' in s.get('run', '')
                                or 'destroy-infras.bash' in s.get('run', '') or s.get('name') == 'Cleanup sandbox']
                    self.assertTrue(all(index < i for i in cleanups))
                    setups = [i for i,s in enumerate(steps) if s.get('with',{}).get('phase') == 'setup'
                              and s.get('uses') == './ci-control/.github/actions/infrastructure-diagnostics']
                    self.assertEqual(len(setups),1)
                    self.assertLess(setups[0],index)
                    checkout = next(i for i,s in enumerate(steps) if s.get('with',{}).get('path') == 'ci-control')
                    self.assertLess(checkout,setups[0])
                    checked.append((path.name,job_name))
        self.assertEqual(len(checked), 74)
        action = yaml.safe_load((ROOT / '.github/actions/infrastructure-diagnostics/action.yml').read_text())
        upload = next(s for s in action['runs']['steps'] if 'upload-artifact@' in s.get('uses', ''))
        self.assertEqual(upload['if'], "${{ inputs.phase == 'collect' && !cancelled() }}")
        self.assertEqual(upload['with']['retention-days'], 3)
        self.assertIn('runner.temp', str(upload['with']['path']))


if __name__ == '__main__':
    unittest.main()
