from pathlib import Path
import unittest
import yaml
from ci_tier_conditions import condition_allows

ROOT = Path(__file__).resolve().parents[3]

class SkipLabelTests(unittest.TestCase):
    def workflows(self, event):
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            doc = yaml.safe_load(path.read_text())
            if event in (doc.get('on', doc.get(True, {})) or {}):
                yield path.name, doc

    def allowed(self, job, **context):
        defaults = {
            'github.event_name': 'pull_request',
            'github.event.pull_request': True,
            'github.event.pull_request.head.repo.fork': False,
            'github.event.pull_request.head.repo.full_name': 'sysown/proxysql',
            'github.repository': 'sysown/proxysql',
            'github.ref': 'refs/pull/1/merge',
            'github.event.pull_request.labels.*.name': [],
            'github.event.action': 'synchronize',
            'github.event.label.name': '',
            'github.event.workflow_run.display_title': 'feature CI-builds abc123',
            'github.event.workflow_run.event': 'pull_request',
            'github.event.workflow_run.head_repository.full_name': 'sysown/proxysql',
            'needs.push-label.result': 'skipped',
            'needs.push-label.outputs.skip': '',
        }
        defaults.update(context)
        defaults.setdefault('github.event.workflow_run', defaults['github.event_name'] == 'workflow_run' or any(k.startswith('github.event.workflow_run.') for k in context))
        return condition_allows(job.get('if'), 'v30', 'release', event_context=defaults)

    def test_legacy_build_completion_does_not_duplicate_legacy_trigger_fanout(self):
        for name, doc in self.workflows('workflow_run'):
            if name == 'CI-builds.yml':
                continue
            for jid, job in doc['jobs'].items():
                with self.subTest(workflow=name, job=jid):
                    self.assertFalse(self.allowed(job, **{
                        'github.event_name': 'workflow_run',
                        'github.event.workflow_run.event': 'workflow_run',
                    }))
                    self.assertTrue(self.allowed(job, **{
                        'github.event_name': 'workflow_run',
                        'github.event.workflow_run.event': 'push',
                    }))

    def test_label_blocks_all_direct_pr_jobs(self):
        for name, doc in self.workflows('pull_request'):
            for jid, job in doc['jobs'].items():
                if jid == 'push-label':
                    continue
                for fork in (False, True):
                    with self.subTest(workflow=name, job=jid, fork=fork):
                        self.assertFalse(self.allowed(job, **{
                            'github.event.pull_request.labels.*.name': ['pg-compat', 'ci:skip'],
                            'github.event.pull_request.head.repo.fork': fork,
                        }))

    def test_unlabelled_pr_routes_remain_available(self):
        for name, doc in self.workflows('pull_request'):
            for jid, job in doc['jobs'].items():
                if jid == 'push-label':
                    continue
                with self.subTest(workflow=name, job=jid):
                    # Global dependency promotion intentionally excludes PRs;
                    # their build jobs still populate their own exact caches.
                    expected = (name, jid) != ('CI-dependency-artifacts.yml', 'publish')
                    self.assertEqual(expected, self.allowed(job, **{
                        'github.event.pull_request.labels.*.name': ['pg-compat'],
                        'github.event.pull_request.head.repo.fork': name == 'CI-builds-fork.yml',
                    }))

    def test_skipped_trigger_blocks_entire_cascade(self):
        found = 0
        for name, doc in self.workflows('workflow_run'):
            events = doc.get('on', doc.get(True))
            self.assertEqual(events['workflow_run']['workflows'], ['CI-trigger'] if name == 'CI-builds.yml' else ['CI-trigger', 'CI-builds'])
            for jid, job in doc['jobs'].items():
                found += 1
                with self.subTest(workflow=name, job=jid):
                    self.assertFalse(self.allowed(job, **{
                        'github.event_name': 'workflow_run',
                        'github.event.workflow_run.display_title': '[ci:skip] feature CI-builds abc123',
                    }))
                    self.assertTrue(self.allowed(job, **{'github.event_name': 'workflow_run'}))
                    if 'workflow_dispatch' in events:
                        self.assertTrue(self.allowed(job, **{
                            'github.event_name': 'workflow_dispatch',
                            'github.event.workflow_run': False,
                            'github.event.workflow_run.display_title': '',
                        }))
        self.assertGreater(found, 60)

    def test_trigger_title_carries_label_decision(self):
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-builds.yml').read_text())
        self.assertTrue(doc['run-name'].startswith("${{ contains(github.event.pull_request.labels.*.name, 'ci:skip') && '[ci:skip] ' || '' }}"))

    def test_existing_failure_and_fork_restrictions_remain(self):
        for name, doc in self.workflows('workflow_run'):
            for job in doc['jobs'].values():
                context = {'github.event.workflow_run.conclusion': 'failure'}
                if name == 'CI-builds.yml':
                    context = {'github.event.workflow_run.head_repository.full_name': 'someone/fork'}
                with self.subTest(workflow=name):
                    self.assertFalse(self.allowed(job, **context))
        trigger = yaml.safe_load((ROOT / '.github/workflows/CI-builds.yml').read_text())
        self.assertFalse(self.allowed(trigger['jobs']['run'], **{
            'github.event.pull_request.head.repo.fork': True,
        }))

    def test_skip_label_event_has_a_separate_concurrency_group(self):
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-pg-compat.yml').read_text())
        group = doc['concurrency']['group']
        base = '${{ github.workflow }}-${{ github.event.pull_request.number || github.ref_name }}'
        self.assertTrue(group.startswith(base))
        suffix = group[len(base):]
        self.assertTrue(suffix.startswith('${{'))
        self.assertTrue(suffix.endswith('}}'))
        self.assertTrue(condition_allows(suffix, 'v30', 'release', event_context={
            'github.event.action': 'labeled', 'github.event.label.name': 'ci:skip',
        }))
        self.assertFalse(condition_allows(suffix, 'v30', 'release', event_context={
            'github.event.action': 'synchronize', 'github.event.label.name': '',
        }))
        self.assertFalse(condition_allows(suffix, 'v30', 'release', event_context={
            'github.event.action': 'labeled', 'github.event.label.name': 'pg-compat',
        }))

    def test_manual_and_scheduled_pg_compat_remain_available(self):
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-pg-compat.yml').read_text())
        for event in ['schedule', 'workflow_dispatch']:
            self.assertTrue(self.allowed(doc['jobs']['pg-compat'], **{'github.event_name': event}))

if __name__ == '__main__':
    unittest.main()
