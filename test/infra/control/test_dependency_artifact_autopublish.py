"""Reviewed-source candidates, immutable winners and interrupted draft recovery."""
import importlib
import json
from pathlib import Path
import subprocess
from unittest.mock import Mock, patch
import unittest

import test_dependency_artifact_make as fixture
import test_dependency_artifact_store as store_fixture


class GitHub:
    def __init__(self):
        self.releases, self.writes, self.fail_upload = {}, [], False
        self.real_run = subprocess.run

    def run(self, args, **kwargs):
        if args[0] != 'gh':
            return self.real_run(args, **kwargs)
        if args[1] == 'api':
            state = self.releases.get(args[2].split('/')[-1])
            missing = state is None or state['draft']
            return subprocess.CompletedProcess(args, int(missing), '', 'HTTP 404' if missing else '')
        operation, tag = args[2:4]
        state = self.releases.get(tag)
        output, error, status = '', '', 0
        if operation == 'view':
            if state is None:
                error, status = 'release not found', 1
            else:
                output = json.dumps(dict(isDraft=state['draft'], tagName=tag))
        elif operation == 'download':
            (Path(args[args.index('--dir') + 1]) / 'bundle.tar.gz').write_bytes(state['bundle.tar.gz'])
        else:
            self.writes.append(operation)
            if operation == 'create':
                self.releases[tag] = dict(draft=True)
            elif operation == 'upload':
                assert state['draft'], 'completed releases must never be overwritten'
                assert '--clobber' in args
                for name in ('entry.json', 'bundle.tar.gz'):
                    path = next(Path(arg) for arg in args if Path(arg).name == name)
                    state[name] = path.read_bytes()
                    if self.fail_upload:
                        self.fail_upload = False
                        error, status = 'interrupted upload', 1
                        break
            elif operation == 'edit':
                assert '--draft=false' in args
                state['draft'] = False
            else:
                raise AssertionError(args)
        return subprocess.CompletedProcess(args, status, output, error)

    def remote_entry(self, dependency, identity, environ):
        store = importlib.import_module('store')
        tag = store.release_tag(dependency, importlib.import_module('identity').fingerprint(identity))
        state = self.releases[tag]
        assert not state['draft']
        return store.checked_entry(json.loads(state['entry.json']), dependency, identity, remote=True)


class AutomaticPublicationTests(unittest.TestCase):
    def setUp(self):
        fixture.PreparationTests.setUp(self)
        self.publisher = importlib.import_module('publish')
        self.store = importlib.import_module('store')
        for args in [('init', '-q'), ('config', 'user.name', 'Test'),
                     ('config', 'user.email', 'test@example.invalid')]:
            self.git(*args)
        self.source = self.commit()
        self.env.update(GITHUB_REPOSITORY='sysown/proxysql', GITHUB_EVENT_NAME='push',
                        GITHUB_REF='refs/heads/v3.0', GITHUB_SHA=self.source, GITHUB_RUN_ATTEMPT='1')
        self.candidates = self.root / 'candidates'
        self.candidates.mkdir()
        self.github = GitHub()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root)] + list(args),
                                       stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        self.git('add', 'deps', 'common_mk')
        self.git('commit', '-qm', 'reviewed source')
        sha = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/v3.0', sha)
        return sha

    def candidate(self, suffix='first', provenance=None, license_text='fixture license'):
        directory = self.candidates / ('dependency-candidate-a1-' + suffix + '-openssl')
        directory.mkdir()
        identity = self.identity.build_identity('openssl', self.root, self.env)
        version = self.identity.configuration('openssl', self.root)['version']
        tree = self.root / 'template' / ('openssl-' + version)
        (tree / 'LICENSE').write_text(license_text)
        entry = self.bundles.create_bundle('openssl', tree, identity, directory / 'bundle.tar.gz')
        entry.update(url=self.store.asset_url('openssl', entry['fingerprint'], 'bundle.tar.gz'),
                     provenance={'commit': provenance or self.source})
        (directory / 'entry.json').write_text(json.dumps(entry))
        return directory, entry

    def matrix(self):
        return self.publisher.publication_matrix(self.candidates, self.source, self.root, self.env)

    def publish(self, directory, entry, remote=None):
        with patch.object(self.publisher.subprocess, 'run', side_effect=self.github.run), \
                patch.object(self.store, 'remote_entry', side_effect=remote or self.github.remote_entry):
            return self.publisher.publish_candidate(directory, 'openssl', entry['fingerprint'],
                                                     self.source, self.root, self.store.REPOSITORY, self.env)

    def test_current_attempt_deduplicates_keys_and_accepts_older_reviewed_producer(self):
        self.candidate()
        self.candidate('second', license_text='different valid output')
        (self.candidates / 'dependency-candidate-a2-invalid').mkdir()
        (self.root / 'deps/unrelated').write_text('unrelated core change')
        self.source = self.commit()
        self.env['GITHUB_SHA'] = self.source
        self.assertEqual(1, len(self.matrix()['include']))

    def test_pr_foreign_and_unreviewed_sources_cannot_publish(self):
        directory, entry = self.candidate()
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_REPOSITORY', 'foreign/repo'), ('GITHUB_REF', 'refs/heads/topic')]:
            with self.subTest(key=key), patch.dict(self.env, {key: value}), self.assertRaises(ValueError):
                self.publish(directory, entry)
        (self.root / 'deps/unreviewed').write_text('unreviewed source')
        self.git('add', 'deps/unreviewed')
        self.git('commit', '-qm', 'unreviewed')
        unreviewed = self.git('rev-parse', 'HEAD')
        self.source = unreviewed
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_SHA=unreviewed)
        with self.assertRaises(ValueError):
            self.matrix()
        self.assertEqual([], self.github.writes)

    def test_wrong_version_source_hash_and_unreviewed_provenance_are_rejected(self):
        directory, original = self.candidate()
        for field, value in [('version', '9.9.9'), ('recipe_sha256', 'a' * 64)]:
            entry = json.loads(json.dumps(original))
            entry['identity'][field] = value
            entry['fingerprint'] = self.identity.fingerprint(entry['identity'])
            entry['url'] = self.store.asset_url('openssl', entry['fingerprint'], 'bundle.tar.gz')
            (directory / 'entry.json').write_text(json.dumps(entry))
            with self.assertRaisesRegex(ValueError, 'inputs.*reviewed source'):
                self.matrix()
        original['provenance']['commit'] = 'a' * 40
        (directory / 'entry.json').write_text(json.dumps(original))
        with self.assertRaises(ValueError):
            self.matrix()

    def test_published_winner_is_preserved_even_when_candidate_bytes_differ(self):
        directory, entry = self.candidate()
        self.assertEqual('published', self.publish(directory, entry)['status'])
        other, replacement = self.candidate('second', license_text='different valid output')
        self.assertNotEqual(entry['sha256'], replacement['sha256'])
        self.github.writes.clear()
        self.assertEqual('existing', self.publish(other, replacement)['status'])
        self.assertEqual([], self.github.writes)

    def test_two_versions_publish_under_independent_release_keys(self):
        first, entry = self.candidate()
        self.publish(first, entry)
        store_fixture.AutomaticStoreTests.install_version(self, '3.5.8')
        self.source = self.commit()
        self.env['GITHUB_SHA'] = self.source
        second, upgraded = self.candidate('upgraded')
        self.assertEqual('published', self.publish(second, upgraded)['status'])
        self.assertNotEqual(entry['fingerprint'], upgraded['fingerprint'])
        self.assertEqual(2, len(self.github.releases))
        for candidate in (entry, upgraded):
            tag = self.store.release_tag('openssl', candidate['fingerprint'])
            self.assertEqual(candidate, json.loads(self.github.releases[tag]['entry.json']))

    def test_tag_creation_race_reuses_published_winner(self):
        directory, entry = self.candidate()
        self.publish(directory, entry)
        tag = self.store.release_tag('openssl', entry['fingerprint'])
        original = self.github.run
        def race(args, **kwargs):
            if args[:3] == ['gh', 'release', 'create']:
                return subprocess.CompletedProcess(args, 1, '', 'already_exists')
            return original(args, **kwargs)
        state = dict(isDraft=False, tagName=tag)
        self.github.writes.clear()
        with patch.object(self.publisher, 'release_state', side_effect=[None, state, state]), \
                patch.object(self.github, 'run', side_effect=race) as run:
            self.assertEqual('existing', self.publish(directory, entry)['status'])
        self.assertTrue(any(call[0][0][:3] == ['gh', 'release', 'create'] for call in run.call_args_list))
        self.assertEqual([], self.github.writes)

    def test_published_metadata_retries_availability_but_not_integrity_errors(self):
        directory, entry = self.candidate()
        for unavailable in (None, self.store.Unavailable('not visible yet')):
            fetch = Mock(side_effect=[unavailable, entry])
            with self.subTest(unavailable=unavailable), patch('time.sleep') as sleep:
                self.publish(directory, entry, remote=fetch)
                self.assertEqual(2, fetch.call_count)
                sleep.assert_called_once_with(2)
        fetch = Mock(return_value=None)
        with patch('time.sleep') as sleep, self.assertRaisesRegex(ValueError, 'metadata is unavailable'):
            self.publish(directory, entry, remote=fetch)
        self.assertEqual(3, fetch.call_count)
        self.assertEqual(2, sleep.call_count)
        fetch = Mock(side_effect=ValueError('invalid metadata'))
        with patch('time.sleep') as sleep, self.assertRaisesRegex(ValueError, 'invalid metadata'):
            self.publish(directory, entry, remote=fetch)
        self.assertEqual(1, fetch.call_count)
        sleep.assert_not_called()

    def test_interrupted_draft_is_discovered_and_completed_without_recreating_release(self):
        directory, entry = self.candidate()
        self.github.fail_upload = True
        with self.assertRaisesRegex(ValueError, 'interrupted upload'):
            self.publish(directory, entry)
        tag = self.store.release_tag('openssl', entry['fingerprint'])
        self.assertTrue(self.github.releases[tag]['draft'])
        rest = self.github.run(['gh', 'api', 'repos/sysown/proxysql/releases/tags/' + tag])
        self.assertEqual(1, rest.returncode, 'REST tags cannot discover an interrupted draft')
        self.github.writes.clear()
        self.assertEqual('published', self.publish(directory, entry)['status'])
        self.assertEqual(['upload', 'edit'], self.github.writes)
        self.assertFalse(self.github.releases[tag]['draft'])


if __name__ == '__main__':
    unittest.main()
