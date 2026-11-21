"""The optional app token serves only this repository's artifact reads."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_tier_artifacts
from ci_tier_artifacts import GitHubAPI

ENV = {'CI_READ_TOKEN': 'ghs_read', 'GITHUB_REPOSITORY': 'owner/repo', 'GH_TOKEN': 'job'}


class ReadTokenTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.failing = set()

    def request(self, path, method='GET', payload=None, raw=False, *, token=None, **kwargs):
        self.calls.append((path, method, token))
        if token in self.failing:
            raise RuntimeError(f'GitHub API {method} {path}: exit 1 HTTP 401 after 1 attempts')
        return {'artifacts': [{'id': 1, 'name': 'a'}]}

    def run_artifacts(self, env, api):
        with patch.dict(os.environ, env, clear=True), \
                patch.object(ci_tier_artifacts, 'github_request', side_effect=self.request):
            return api.artifacts(7)

    def test_artifact_listing_uses_the_read_token(self):
        self.run_artifacts(ENV, GitHubAPI('owner/repo'))
        self.assertEqual([token for *_, token in self.calls], ['ghs_read'])

    def test_writes_never_use_the_read_token(self):
        with patch.dict(os.environ, ENV, clear=True), \
                patch.object(ci_tier_artifacts, 'github_request', side_effect=self.request):
            GitHubAPI('owner/repo').request('repos/owner/repo/check-runs/1', 'PATCH', {})
            GitHubAPI('owner/repo').request('repos/owner/repo/actions/runs/7')
        self.assertEqual([token for *_, token in self.calls], [None, None])

    def test_explicit_token_and_other_repositories_ignore_it(self):
        self.run_artifacts(ENV, GitHubAPI('owner/repo', token='source'))
        self.run_artifacts(ENV, GitHubAPI('other/repo'))
        self.assertEqual([token for *_, token in self.calls], ['source', None])

    def test_absent_token_uses_the_job_token(self):
        self.run_artifacts({'GITHUB_REPOSITORY': 'owner/repo'}, GitHubAPI('owner/repo'))
        self.assertEqual([token for *_, token in self.calls], [None])

    def test_failed_read_falls_back_to_the_job_token(self):
        self.failing.add('ghs_read')
        records = self.run_artifacts(ENV, GitHubAPI('owner/repo'))
        self.assertEqual(records[0]['name'], 'a')
        self.assertEqual([token for *_, token in self.calls], ['ghs_read', None])

    def test_failed_download_falls_back_to_the_job_token(self):
        used = []

        def parts(url, token, target, size, workers, deadline):
            used.append(token)
            if token == 'ghs_read':
                raise RuntimeError('Artifact download failed (HTTP 401)')
            Path(target).write_bytes(b'x' * size)

        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, ENV, clear=True), \
                patch.object(ci_tier_artifacts, 'download_parts', side_effect=parts):
            target = Path(folder) / 'a.zip'
            GitHubAPI('owner/repo').download('repos/owner/repo/actions/artifacts/1/zip', target, 4)
            self.assertEqual(target.read_bytes(), b'xxxx')
        self.assertEqual(used, ['ghs_read', 'job'])


if __name__ == '__main__':
    unittest.main()
