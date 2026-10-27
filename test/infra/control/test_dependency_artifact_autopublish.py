"""Reviewed-history promotion and idempotent per-signature releases."""
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from test_dependency_artifact_bundles import fixture_tree

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deps/artifacts'))


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class GitHub:
    """A release API boundary that preserves uploaded bytes across retries."""
    def __init__(self):
        self.releases = {}
        self.writes = []
        self.fail_upload_once = False
        self.race = None
        self.real_run = subprocess.run

    def run(self, args, **kwargs):
        if args[0] != 'gh':
            return self.real_run(args, **kwargs)
        output, error, status = '', '', 0
        if args[1] == 'api':
            tag = args[2].split('/releases/tags/', 1)[1]
            if tag in self.releases:
                output = json.dumps(self.releases[tag]['release'])
            else:
                error, status = 'gh: Not Found (HTTP 404)', 1
        else:
            operation, tag = args[2:4]
            self.writes.append((operation, tag))
            if operation == 'create':
                if self.race is not None:
                    self.releases[tag] = self.race
                    self.race = None
                    error, status = 'already_exists (HTTP 422)', 1
                else:
                    self.releases[tag] = {
                        'release': {'draft': True, 'tag_name': tag,
                                    'target_commitish': args[args.index('--target') + 1]},
                        'assets': {}}
            elif operation == 'upload':
                state = self.releases[tag]
                if not state['release']['draft']:
                    raise AssertionError('attempted to replace a published asset')
                paths = [Path(a) for a in args[4:] if Path(a).is_file()]
                for path in paths:
                    if path.name in state['assets'] and '--clobber' not in args:
                        raise AssertionError('retry did not explicitly replace draft assets')
                    state['assets'][path.name] = path.read_bytes()
                    if self.fail_upload_once:
                        self.fail_upload_once = False
                        error, status = 'interrupted upload', 1
                        break
            elif operation == 'edit':
                if '--draft=false' not in args or '--prerelease' not in args or '--latest=false' not in args:
                    raise AssertionError('release publication policy lost')
                self.releases[tag]['release']['draft'] = False
            else:
                raise AssertionError(args)
        return subprocess.CompletedProcess(args, status, output, error)

    def open(self, url, **kwargs):
        prefix = 'https://github.com/sysown/proxysql/releases/download/'
        if not url.startswith(prefix):
            raise AssertionError('download outside canonical store: ' + url)
        tag, asset = url[len(prefix):].split('/')
        state = self.releases.get(tag)
        if state is None or state['release']['draft'] or asset not in state['assets']:
            raise HTTPError(url, 404, 'missing', {}, None)
        return Response(state['assets'][asset], url)


class AutomaticPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / 'source'
        self.root.mkdir()
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        for name in ('identity.py', 'bundles.py', 'manage.py', 'prepare.bash'):
            self.write('deps/artifacts/' + name, name + '\n')
        self.write('common_mk/openssl_flags.mk', 'OPENSSL_VERSION := 3.5.7\n')
        self.write('deps/libssl/build.mk', 'OPENSSL_CONFIGURE_FLAGS := no-shared no-tests -fPIC\n')
        self.write('deps/libssl/verify-source.bash', '# verified openssl source\n')
        self.write('deps/libssl/openssl-3.5.7.tar.gz', 'verified source\n')
        self.write_checksum('deps/libssl/openssl-3.5.7.tar.gz')
        self.source = self.commit()
        self.git('update-ref', 'refs/remotes/origin/v3.0', self.source)
        self.env = dict(os.environ, GITHUB_REPOSITORY='sysown/proxysql',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/v3.0',
                        GITHUB_SHA=self.source, GITHUB_RUN_ATTEMPT='1')
        self.candidates = self.directory / 'candidates'
        self.candidates.mkdir()
        self.identity = importlib.import_module('identity')
        self.bundles = importlib.import_module('bundles')
        self.store = importlib.import_module('store')
        self.github = GitHub()

    def api(self):
        try:
            return importlib.import_module('publication')
        except ModuleNotFoundError:
            self.fail('automatic publication API has not been implemented')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root)] + list(args),
                                       stderr=subprocess.PIPE).decode().strip()

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def write_checksum(self, relative):
        archive = self.root / relative
        Path(str(archive) + '.sha256').write_text(
            hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')

    def commit(self):
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'reviewed source')
        return self.git('rev-parse', 'HEAD')

    def candidate(self, name='dependency-candidate-a1-tier-build-openssl',
                  settings=None, provenance=None, license_text=None, version='3.5.7',
                  identity_update=None):
        directory = self.candidates / name
        directory.mkdir()
        tree = self.directory / ('tree-' + name)
        fixture_tree(tree, 'openssl')
        (tree / 'include/openssl/opensslv.h').write_text(''.join(
            '# define OPENSSL_VERSION_' + key + ' ' + value + '\n'
            for key, value in zip(('MAJOR', 'MINOR', 'PATCH'), version.split('.'))))
        if license_text:
            (tree / 'LICENSE').write_text(license_text)
        digest = lambda p: hashlib.sha256((self.root / p).read_bytes()).hexdigest()
        identity = {
            'format_version': 1, 'dependency': 'openssl', 'eligible': True,
            'version': version,
            'source_sha256': digest('deps/libssl/openssl-' + version + '.tar.gz'),
            'recipe_sha256': digest('deps/libssl/build.mk'),
            'verifier_sha256': digest('deps/libssl/verify-source.bash'),
            'helper': {n: digest('deps/artifacts/' + n)
                       for n in ('identity.py', 'bundles.py', 'manage.py', 'prepare.bash')},
            'settings': settings or ['no-shared', 'no-tests', '-fPIC'],
            'flags': {n: '' for n in self.identity.FLAGS},
            'custom_paths': {n: '' for n in ('CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH')},
            'toolchain': {'os': 'Linux', 'arch': 'x86_64', 'distro': ['ubuntu', '24.04'],
                          'libc': ['glibc', '2.39'], 'runtime': 'a' * 64,
                          'cc': {'command': ['gcc'], 'version': 'gcc 13', 'target': 'x86_64-linux-gnu', 'macros': 'b' * 64},
                          'cxx': {'command': ['g++'], 'version': 'g++ 13', 'target': 'x86_64-linux-gnu', 'macros': 'c' * 64}}}
        identity.update(identity_update or {})
        entry = self.bundles.create_bundle('openssl', tree, identity, directory / 'bundle.tar.gz')
        entry.update(url=self.store.asset_url('openssl', entry['fingerprint'], 'bundle.tar.gz'),
                     provenance={'commit': provenance or self.source, 'run': '123', 'image': '', 'profile': ''})
        (directory / 'entry.json').write_text(json.dumps(entry))
        return directory, entry

    def matrix(self):
        return self.api().publication_matrix(self.candidates, self.source, self.root, self.env)

    def publish(self, directory, entry):
        api = self.api()
        with patch.object(api.subprocess, 'run', side_effect=self.github.run), \
                patch.object(api, 'urlopen', side_effect=self.github.open), \
                patch.object(self.store, 'urlopen', side_effect=self.github.open):
            return api.publish_candidate(directory, 'openssl', entry['fingerprint'], self.source,
                                         self.root, 'sysown/proxysql', self.env)

    def test_same_identity_is_deduplicated_without_requiring_same_binary_bytes(self):
        first, entry = self.candidate()
        self.candidate('dependency-candidate-a1-other-build-openssl', license_text='different valid output')
        self.assertEqual({'include': [{'dependency': 'openssl', 'fingerprint': entry['fingerprint'],
                                       'artifact': 'dependency-candidate-a1-other-build-openssl'}]}, self.matrix())

    def test_old_attempt_artifacts_are_ignored(self):
        directory = self.candidates / 'dependency-candidate-a2-other-build-openssl'
        directory.mkdir()
        (directory / 'entry.json').write_text('not JSON')
        self.assertEqual({'include': []}, self.matrix())

    def test_pull_requests_and_foreign_repositories_cannot_publish(self):
        self.candidate()
        for changes in ({'GITHUB_EVENT_NAME': 'pull_request'},
                        {'GITHUB_REPOSITORY': 'attacker/proxysql'},
                        {'GITHUB_REF': 'refs/heads/feature'}):
            with self.subTest(changes=changes):
                with patch.dict(self.env, changes), self.assertRaises(ValueError):
                    self.matrix()

    def test_unreviewed_source_or_candidate_provenance_is_rejected(self):
        self.write('unreviewed', 'branch\n')
        unreviewed = self.commit()
        self.candidate(provenance=unreviewed)
        with self.assertRaisesRegex(ValueError, 'reviewed|protected|ancestor'):
            self.matrix()
        self.source = unreviewed
        self.env['GITHUB_SHA'] = unreviewed
        with self.assertRaisesRegex(ValueError, 'reviewed|protected|ancestor'):
            self.matrix()

    def test_version_and_focused_source_hash_must_match_reviewed_commit(self):
        directory, entry = self.candidate()
        entry['identity']['version'] = '9.9.9'
        entry['fingerprint'] = self.identity.fingerprint(entry['identity'])
        entry['url'] = self.store.asset_url('openssl', entry['fingerprint'], 'bundle.tar.gz')
        (directory / 'entry.json').write_text(json.dumps(entry))
        with self.assertRaisesRegex(ValueError, 'version|reviewed|source'):
            self.matrix()

    def test_incomplete_toolchain_cannot_be_promoted_even_when_payload_matches(self):
        self.candidate(identity_update={'toolchain': {}})
        with self.assertRaisesRegex(ValueError, 'toolchain'):
            self.matrix()

    def test_malformed_workflow_run_is_rejected_as_invalid_input(self):
        event = self.directory / 'event.json'
        event.write_text('{"workflow_run":null}')
        self.env.update(GITHUB_EVENT_NAME='workflow_run', GITHUB_EVENT_PATH=str(event))
        with self.assertRaises(ValueError):
            self.matrix()

    def test_cached_candidate_from_older_reviewed_commit_is_accepted(self):
        self.candidate()
        self.write('unrelated.md', 'unrelated source change\n')
        self.source = self.commit()
        self.git('update-ref', 'refs/remotes/origin/v3.0', self.source)
        self.env['GITHUB_SHA'] = self.source
        self.assertEqual(1, len(self.matrix()['include']))

    def test_workflow_run_binds_upstream_source_but_uses_current_attempt(self):
        self.candidate()
        event = self.directory / 'event.json'
        payload = {'workflow_run': {'event': 'push', 'head_branch': 'v3.0', 'head_sha': self.source,
                                    'head_repository': {'full_name': 'sysown/proxysql'}, 'run_attempt': 8}}
        event.write_text(json.dumps(payload))
        self.env.update(GITHUB_EVENT_NAME='workflow_run', GITHUB_EVENT_PATH=str(event))
        self.assertEqual(1, len(self.matrix()['include']))
        payload['workflow_run']['head_repository']['full_name'] = 'attacker/proxysql'
        event.write_text(json.dumps(payload))
        with self.assertRaises(ValueError):
            self.matrix()

    def test_corrupt_candidate_and_noncanonical_url_are_rejected(self):
        directory, entry = self.candidate()
        entry['url'] = 'https://attacker.invalid/bundle.tar.gz'
        (directory / 'entry.json').write_text(json.dumps(entry))
        with self.assertRaises(ValueError):
            self.matrix()
        entry['url'] = self.store.asset_url('openssl', entry['fingerprint'], 'bundle.tar.gz')
        (directory / 'entry.json').write_text(json.dumps(entry))
        (directory / 'bundle.tar.gz').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            self.matrix()

    def test_new_bundle_publishes_pair_and_existing_valid_winner_is_not_overwritten(self):
        directory, entry = self.candidate()
        self.assertEqual('published', self.publish(directory, entry)['status'])
        tag = self.store.release_tag('openssl', entry['fingerprint'])
        original = copy.deepcopy(self.github.releases[tag])
        other, replacement = self.candidate('dependency-candidate-a1-other-build-openssl', license_text='different')
        self.assertNotEqual(entry['sha256'], replacement['sha256'])
        self.github.writes = []
        self.assertEqual('existing', self.publish(other, replacement)['status'])
        self.assertEqual([], self.github.writes)
        self.assertEqual(original, self.github.releases[tag])

    def test_interrupted_draft_is_recovered_on_retry(self):
        directory, entry = self.candidate()
        self.github.fail_upload_once = True
        with self.assertRaises(ValueError):
            self.publish(directory, entry)
        tag = self.store.release_tag('openssl', entry['fingerprint'])
        self.assertTrue(self.github.releases[tag]['release']['draft'])
        self.assertEqual('published', self.publish(directory, entry)['status'])
        self.assertFalse(self.github.releases[tag]['release']['draft'])
        self.assertEqual({'entry.json', 'bundle.tar.gz'}, set(self.github.releases[tag]['assets']))

    def test_tag_creation_race_accepts_valid_published_winner(self):
        directory, entry = self.candidate()
        self.github.race = {'release': {'draft': False},
                            'assets': {'entry.json': (directory / 'entry.json').read_bytes(),
                                       'bundle.tar.gz': (directory / 'bundle.tar.gz').read_bytes()}}
        self.assertEqual('existing', self.publish(directory, entry)['status'])
        self.assertEqual(['create'], [op for op, tag in self.github.writes])

    def test_dispatch_can_publish_two_reviewed_versions_without_colliding(self):
        first_directory, first = self.candidate()
        self.assertEqual('published', self.publish(first_directory, first)['status'])
        self.write('common_mk/openssl_flags.mk', 'OPENSSL_VERSION := 3.5.8\n')
        self.write('deps/libssl/openssl-3.5.8.tar.gz', 'new verified source\n')
        self.write_checksum('deps/libssl/openssl-3.5.8.tar.gz')
        self.source = self.commit()
        self.git('update-ref', 'refs/remotes/origin/v3.0', self.source)
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_SHA=self.source)
        directory, second = self.candidate('dependency-candidate-a1-next-build-openssl', version='3.5.8')
        self.assertEqual('published', self.publish(directory, second)['status'])
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(2, len(self.github.releases))


if __name__ == '__main__':
    unittest.main()
