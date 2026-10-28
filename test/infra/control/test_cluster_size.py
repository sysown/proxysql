"""Exercise cluster launch, advertised endpoints and scheduler polling together."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
CONTROL = ROOT / 'test/infra/control'


class ClusterSizeTests(unittest.TestCase):
    def exercise(self, override=None, skip=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = root / 'test/infra/control'
            control.mkdir(parents=True)
            for name in ('start-proxysql-isolated.bash', 'env-isolated.bash',
                         'asan-detection.bash', 'docker-fs-helper.bash', 'check_all_nodes.bash'):
                shutil.copy2(CONTROL / name, control / name)
            for name in ('src/obj', 'lib/obj', 'bin', 'launched', 'polled', 'nodes'):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / 'src/proxysql').touch()
            daemon = root / 'bin/proxysql'
            daemon.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, re, sys
a=sys.argv[1:]; data=a[a.index('-D')+1]
match=re.search(r'-node(\d+)$',data); index=match.group(1) if match else '0'
root=pathlib.Path(os.environ['CLUSTER_FIXTURE_ROOT'])
(root/'launched'/index).write_text(json.dumps({'args':a,'nodes':os.environ.get('PROXYSQL_CLUSTER_NODES')}))
''')
            docker = root / 'bin/docker'
            docker.write_text('''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
a=sys.argv[1:]; root=pathlib.Path(os.environ['CLUSTER_FIXTURE_ROOT'])
if a[0]=='run' and '-d' in a:
    env=os.environ.copy()
    for i,arg in enumerate(a):
        if arg=='-e':
            key,_,value=a[i+1].partition('=');env[key]=value
    command=a[-1].replace('/usr/bin/proxysql',str(root/'bin/proxysql')).replace('/var/lib/proxysql',str(root/'nodes'))
    subprocess.run(['bash','-c',command],env=env,check=True)
elif a[0]=='exec':
    sys.stdin.read()
print('fixture-container')
''')
            mysql = root / 'bin/mysql'
            mysql.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
a=sys.argv[1:]; port=a[a.index('-P')+1];sys.stdin.read()
(pathlib.Path(os.environ['CLUSTER_FIXTURE_ROOT'])/'polled'/port).touch()
''')
            for path in (daemon, docker, mysql):
                path.chmod(0o755)
            env = dict(os.environ, CLUSTER_FIXTURE_ROOT=str(root), WORKSPACE=str(root),
                       PATH=str(root/'bin')+os.pathsep+os.environ['PATH'], INFRA_ID='cluster-size-test',
                       SKIP_CLUSTER_START='1' if skip else '0')
            env.pop('PROXYSQL_CLUSTER_NODES', None)
            if override is not None:
                env['PROXYSQL_CLUSTER_NODES'] = str(override)
            expected_peers = 0 if skip else (6 if override is None else override)
            result = subprocess.run(['bash', str(control/'start-proxysql-isolated.bash')],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual({int(p.name) for p in (root/'launched').iterdir()},
                             set(range(expected_peers+1)))
            for path in (root/'launched').iterdir():
                self.assertEqual(json.loads(path.read_text())['nodes'], str(expected_peers))
            result = subprocess.run(['bash', '-c', 'source "$1"; printf "ENDPOINTS=%s\\n" "$TAP_CLUSTER_NODES"',
                                     'fixture', str(control/'env-isolated.bash')],
                                    env=env, capture_output=True, text=True, check=True)
            expected = ','.join(f'proxysql:{6032+i*10}' for i in range(expected_peers+1)) if expected_peers else ''
            self.assertIn('ENDPOINTS='+expected+'\n', result.stdout)
            # The scheduler runs inside the primary container, which receives
            # the effective peer count even when SKIP_CLUSTER_START overrides it.
            env['PROXYSQL_CLUSTER_NODES'] = str(expected_peers)
            subprocess.run(['bash', str(control/'check_all_nodes.bash')], env=env, check=True)
            deadline = time.monotonic()+3
            while len(list((root/'polled').iterdir())) < expected_peers+1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual({int(p.name) for p in (root/'polled').iterdir()},
                             {6032+i*10 for i in range(expected_peers+1)})

    def test_default_is_seven_total_instances(self):
        self.exercise()

    def test_explicit_cluster_size_is_preserved(self):
        self.exercise(3)
        self.exercise(9)

    def test_zero_and_skip_modes_start_only_primary(self):
        self.exercise(0)
        self.exercise(9, skip=True)


if __name__ == '__main__':
    unittest.main()
