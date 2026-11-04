#!/usr/bin/env python3
"""Run real package/tarball upload bodies against an offline, stateful gh fake.

Catches missing asset-list pagination, wrong replacement IDs/order, and errors
that must stop the shell before it deletes or uploads another asset. No real gh
executable or network endpoint is used. Fixtures reproduce the release smoke's
51 assets with the target at position 39, plus a target beyond page size 100.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
FAKE_GH = r'''
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import parse_qs, urlparse

state_file = Path(os.environ['FAKE_GH_STATE'])
state = json.loads(state_file.read_text())
args = sys.argv[1:]

def save():
    state_file.write_text(json.dumps(state))

def fail(message):
    save()
    print(message, file=sys.stderr)
    sys.exit(1)

if not args or args[0] != 'api':
    fail('unexpected gh command: ' + repr(args))
method = 'GET'
for option in ['-X', '--method']:
    if option in args:
        method = args[args.index(option) + 1]
endpoint = next((a for a in args if a.startswith(('repos/', 'https://uploads.github.com/'))), '')
state['calls'].append({'method': method, 'endpoint': endpoint})
save()
if method == 'GET':
    if endpoint.split('?')[0] != 'repos/sysown/proxysql/releases/77/assets':
        fail('unexpected asset-list endpoint')
    if '--jq' not in args:
        fail('asset lookup must select the matching name and ID')
    page_size = int(parse_qs(urlparse(endpoint).query).get('per_page', ['30'])[0])
    pages = [state['assets'][i:i + page_size] for i in range(0, len(state['assets']), page_size)] or [[]]
    if '--paginate' not in args:
        pages = pages[:1]
    query = args[args.index('--jq') + 1]
    for index, page in enumerate(pages):
        if state.get('failure') == 'get-first' or (state.get('failure') == 'get-next' and index == 1):
            fail('simulated asset-list failure')
        result = subprocess.run([os.environ['FAKE_GH_JQ'], '-r', query],
                                input=json.dumps(page), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode:
            fail(result.stderr)
        print(result.stdout, end='', flush=True)
    save()
elif method == 'DELETE':
    prefix = 'repos/sysown/proxysql/releases/assets/'
    if not endpoint.startswith(prefix):
        fail('unexpected deletion endpoint')
    if state.get('failure') == 'delete':
        fail('simulated delete failure')
    asset_id = int(endpoint[len(prefix):])
    if not any(a['id'] == asset_id for a in state['assets']):
        fail('deleted nonexistent asset')
    state['assets'] = [a for a in state['assets'] if a['id'] != asset_id]
    save()
elif method == 'POST':
    parsed = urlparse(endpoint)
    if parsed.netloc != 'uploads.github.com' or parsed.path != '/repos/sysown/proxysql/releases/77/assets':
        fail('unexpected upload endpoint')
    name = parse_qs(parsed.query)['name'][0]
    if any(a['name'] == name for a in state['assets']):
        fail('HTTP 422 ReleaseAsset already_exists: ' + name)
    if state.get('failure') == 'upload':
        fail('simulated upload failure')
    if '--input' not in args:
        fail('upload did not select the local artifact')
    content = Path(args[args.index('--input') + 1]).read_text()
    state['assets'].append({'id': 900001, 'name': name, 'size': len(content),
                            'state': 'uploaded', 'uploaded_content': content})
    save()
else:
    fail('unexpected mutation method: ' + method)
'''


def upload_body(workflow):
    lines = workflow.read_text().splitlines()
    start = lines.index('    - name: Upload to release')
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == '      run: |')
    body = []
    for line in lines[run + 1:]:
        if line.strip() and not line.startswith('        '):
            break
        body.append(line[8:] if line else '')
    script = '\n'.join(body).replace('${{ github.repository }}', 'sysown/proxysql')
    if '${{' in script:
        raise AssertionError('unhandled GitHub expression in upload body')
    return script + '\n'


class UploadPaginationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jq = shutil.which('jq')
        if cls.jq is None:
            raise RuntimeError('this offline gh fake requires the local jq command')
        directory = ROOT / '.github/workflows'
        cls.workflows = sorted(directory.glob('CI-package-amd64-*.yml')) + sorted(directory.glob('CI-package-arm64-*.yml'))
        if not cls.workflows:
            raise AssertionError('no producer workflows found')
        cls.package = directory / 'CI-package-amd64-debian12.yml'
        cls.tarball = directory / 'CI-package-amd64-tarball.yml'

    def run_upload(self, workflow, name, position=38, count=51, failure=None, extra_names=()):
        # Literal target position/ID expectations are independent of the upload code.
        assets = [{'id': i + 1, 'name': 'unrelated-%03d.deb' % i,
                   'size': 17, 'state': 'uploaded'} for i in range(count)]
        if position is not None:
            assets[position] = {'id': 77739, 'name': name, 'size': 3, 'state': 'uploaded'}
        original = [a.copy() for a in assets]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary_dir = directory / 'binaries'
            binary_dir.mkdir()
            (binary_dir / name).write_text('replacement artifact')
            for extra in extra_names:
                (binary_dir / extra).write_text('later artifact')
            fake_bin = directory / 'fake-bin'
            fake_bin.mkdir()
            fake = fake_bin / 'gh'
            fake.write_text('#!' + sys.executable + '\n' + FAKE_GH)
            fake.chmod(0o755)
            state_file = directory / 'state.json'
            state_file.write_text(json.dumps({'assets': assets, 'calls': [], 'failure': failure}))
            environment = os.environ.copy()
            environment.update({'PATH': str(fake_bin) + os.pathsep + os.defpath,
                                'RELEASE_ID': '77', 'FAKE_GH_STATE': str(state_file),
                                'FAKE_GH_JQ': self.jq})
            body = upload_body(workflow)
            syntax = subprocess.run(['bash', '-n'], input=body, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            result = subprocess.run(['bash', '-c', body], cwd=str(directory), env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=15)
            return result, json.loads(state_file.read_text()), original

    def assert_replaced(self, result, state, original, name):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        matches = [a for a in state['assets'] if a['name'] == name]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['id'], 900001)
        self.assertEqual(matches[0]['uploaded_content'], 'replacement artifact')
        self.assertEqual([a for a in state['assets'] if a['name'] != name],
                         [a for a in original if a['name'] != name])
        self.assertEqual([c['method'] for c in state['calls']], ['GET', 'DELETE', 'POST'])
        self.assertEqual(state['calls'][1]['endpoint'], 'repos/sysown/proxysql/releases/assets/77739')

    def test_asset_39_of_51_is_replaced_before_upload(self):
        name = 'proxysql_3.0.12-debian12_amd64.deb'
        self.assert_replaced(*self.run_upload(self.package, name), name)

    def test_every_producer_replaces_an_asset_beyond_100(self):
        # Removing pagination from any single producer must fail this behavior check.
        for workflow in self.workflows:
            with self.subTest(workflow=workflow.name):
                name = ('proxysql-3.0.12-linux-amd64.tar.gz' if '-tarball.yml' in workflow.name
                        else 'proxysql_3.0.12-debian12_amd64.deb')
                self.assert_replaced(*self.run_upload(workflow, name, position=238, count=251), name)

    def test_first_page_replacement_preserves_unrelated_assets(self):
        name = 'proxysql_3.0.12-debian12_amd64.deb'
        self.assert_replaced(*self.run_upload(self.package, name, position=0), name)

    def test_missing_asset_is_uploaded_without_deletion(self):
        name = 'proxysql_3.0.12-debian12_amd64.deb'
        result, state, original = self.run_upload(self.package, name, position=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state['assets'][:-1], original)
        self.assertEqual(state['assets'][-1]['name'], name)
        self.assertEqual([c['method'] for c in state['calls']], ['GET', 'POST'])

    def test_id_hash_and_tarball_checksum_sidecars_are_replaced(self):
        cases = [(self.package, 'proxysql_3.0.12-debian12_amd64.id-hash'),
                 (self.tarball, 'proxysql-3.0.12-linux-amd64.tar.gz.sha256')]
        for workflow, name in cases:
            with self.subTest(artifact=name):
                self.assert_replaced(*self.run_upload(workflow, name, position=138, count=151), name)

    def test_asset_list_failure_prevents_mutations(self):
        result, state, original = self.run_upload(self.package, 'proxysql_3.0.12-debian12_amd64.deb', failure='get-first')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['assets'], original)
        self.assertEqual([c['method'] for c in state['calls']], ['GET'])

    def test_later_page_error_prevents_mutation_even_after_match(self):
        result, state, original = self.run_upload(self.package, 'proxysql_3.0.12-debian12_amd64.deb',
                                                position=0, count=251, failure='get-next')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['assets'], original)
        self.assertEqual([c['method'] for c in state['calls']], ['GET'])

    def test_delete_failure_prevents_upload(self):
        result, state, original = self.run_upload(self.package, 'proxysql_3.0.12-debian12_amd64.deb',
                                                position=0, failure='delete')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['assets'], original)
        self.assertEqual([c['method'] for c in state['calls']], ['GET', 'DELETE'])

    def test_upload_failure_stops_before_next_artifact(self):
        name = 'proxysql_3.0.12-debian12_amd64.deb'
        result, state, original = self.run_upload(self.package, name, position=0, failure='upload',
                                                extra_names=('proxysql_3.0.12-debian12_amd64.id-hash',))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['assets'], [a for a in original if a['name'] != name])
        self.assertEqual([c['method'] for c in state['calls']], ['GET', 'DELETE', 'POST'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
