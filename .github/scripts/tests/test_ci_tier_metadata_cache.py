"""Immutable metadata reuse must not cross producer attempts or jobs."""
import io
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import GitHubAPI, load_manifest
from ci_tier_plan import make_plan
import ci_tier_runtime as runtime


class MetadataCacheTests(unittest.TestCase):
    name = 'ci-manifest-t1-a1-b2-a1'

    def archive(self, value, filename='manifest.json'):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr(zipfile.ZipInfo(filename, date_time=(2020, 1, 1, 0, 0, 0)), json.dumps(value))
        return stream.getvalue()

    def request(self, path, *args, **kwargs):
        self.requests.append(path)
        if kwargs.get('raw'):
            return self.archive(self.value, self.filename)
        raw = self.archive(self.value, self.filename)
        return {'artifacts': [dict(id=9, name=self.selected_name, expired=self.expired,
                                  digest='sha256:'+hashlib.sha256(raw).hexdigest() if self.has_digest else None)]}

    def setUp(self):
        self.requests = []
        self.value = {'checks': []}
        self.selected_name = self.name
        self.filename = 'manifest.json'
        self.has_digest = True
        self.expired = False

    def test_new_clients_reuse_archive_after_fresh_metadata_verification(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            first = GitHubAPI('owner/repo', cache_dir=folder).json_artifact(2, self.name, 'manifest.json')
            first['checks'].append('caller mutation')
            second = GitHubAPI('owner/repo', cache_dir=folder).json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(second, {'checks': []})
            self.assertEqual(len(self.requests), 3)
            self.assertEqual(sum(path.endswith('/zip') for path in self.requests), 1)

    def test_repository_run_attempt_and_filename_do_not_share_entries(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            for repo, run, name, filename in [('a/repo', 2, self.name, 'manifest.json'),
                    ('b/repo', 2, self.name, 'manifest.json'), ('a/repo', 3, self.name, 'manifest.json'),
                    ('a/repo', 2, 'ci-manifest-t1-a1-b2-a2', 'manifest.json'),
                    ('a/repo', 2, self.name, 'other.json')]:
                self.selected_name = name
                self.filename = filename
                GitHubAPI(repo, cache_dir=folder).json_artifact(run, name, filename)
            self.assertEqual(len(self.requests), 10)

    def test_mutable_selection_is_always_read_fresh(self):
        self.selected_name = 'ci-tier-selection'
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.selected_name, 'manifest.json')
            self.value = {'checks': ['changed']}
            self.assertEqual(api.json_artifact(2, self.selected_name, 'manifest.json'), self.value)
            self.assertEqual(len(self.requests), 4)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_corrupt_cache_fails_closed_without_fetching_a_replacement(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.name, 'manifest.json')
            entry, = Path(folder).iterdir()
            entry.write_text('{broken')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                api.json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 3)

    def test_forged_cached_archive_cannot_change_check_ids(self):
        self.value = {'checks': [{'check_id': 100}]}
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.name, 'manifest.json')
            entry, = Path(folder).iterdir()
            entry.write_bytes(self.archive({'checks': [{'check_id': 999}]}))
            with self.assertRaisesRegex(ValueError, 'checksum'):
                api.json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 3)

    def test_artifacts_without_a_digest_are_not_cached(self):
        self.has_digest = False
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.name, 'manifest.json')
            self.value = {'checks': ['changed']}
            self.assertEqual(api.json_artifact(2, self.name, 'manifest.json'), self.value)
            self.assertEqual(len(self.requests), 4)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_cached_artifact_is_not_accepted_after_expiration(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.name, 'manifest.json')
            self.expired = True
            with self.assertRaisesRegex(ValueError, 'live artifact'):
                api.json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 3)

    def test_changed_live_digest_does_not_accept_the_old_cache(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            api.json_artifact(2, self.name, 'manifest.json')
            self.value = {'checks': ['changed']}
            with self.assertRaisesRegex(ValueError, 'checksum'):
                api.json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 3)

    def test_cached_manifest_still_checks_producer_binding(self):
        producer = dict(repository='owner/repo', sha='a'*40, control_sha='b'*40,
                        trigger_id=1, trigger_attempt=1, build_id=2, build_attempt=1)
        self.value = make_plan(producer, dict(tiers=['v40'], mode='normal'), {'consumers': []})
        with tempfile.TemporaryDirectory() as folder, patch.object(GitHubAPI, 'request', side_effect=self.request):
            api = GitHubAPI('owner/repo', cache_dir=folder)
            self.assertEqual(load_manifest(producer, api)['sha'], 'a'*40)
            with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                load_manifest(dict(producer, sha='c'*40), api)
            self.assertEqual(len(self.requests), 3)

    def test_runtime_cache_is_scoped_to_the_current_job_attempt(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                'RUNNER_TEMP': folder, 'GITHUB_RUN_ID': '10', 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_JOB': 'test', 'SOURCE_ARTIFACTS_TOKEN': ''}), \
                patch.object(GitHubAPI, 'request', side_effect=self.request):
            runtime.api_for({'repository': 'owner/repo'}).json_artifact(2, self.name, 'manifest.json')
            runtime.api_for({'repository': 'owner/repo'}).json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 3)
            for key, value in [('GITHUB_JOB', 'other'), ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_RUN_ID', '11')]:
                with patch.dict(os.environ, {key: value}):
                    runtime.api_for({'repository': 'owner/repo'}).json_artifact(2, self.name, 'manifest.json')
            self.assertEqual(len(self.requests), 9)


if __name__ == '__main__':
    unittest.main()
