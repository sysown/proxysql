from pathlib import Path
import json
import os
import subprocess
import tempfile
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
            'github.event.pull_request.labels.*.name': [],
            'github.event.action': 'synchronize',
            'github.event.label.name': '',
            'github.event.workflow_run.display_title': 'feature CI-trigger abc123',
            'needs.push-label.result': 'skipped',
            'needs.push-label.outputs.skip': '',
        }
        defaults.update(context)
        return condition_allows(job.get('if'), 'v30', 'release', event_context=defaults)

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
                    self.assertTrue(self.allowed(job, **{
                        'github.event.pull_request.labels.*.name': ['pg-compat'],
                        'github.event.pull_request.head.repo.fork': name == 'CI-builds-fork.yml',
                    }))

    def test_skipped_trigger_blocks_entire_cascade(self):
        found = 0
        for name, doc in self.workflows('workflow_run'):
            events = doc.get('on', doc.get(True))
            self.assertEqual(events['workflow_run']['workflows'], ['CI-trigger'])
            for jid, job in doc['jobs'].items():
                found += 1
                with self.subTest(workflow=name, job=jid):
                    self.assertFalse(self.allowed(job, **{
                        'github.event_name': 'workflow_run',
                        'github.event.workflow_run.display_title': '[ci:skip] feature CI-trigger abc123',
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
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-trigger.yml').read_text())
        self.assertTrue(doc['run-name'].startswith("${{ contains(github.event.pull_request.labels.*.name, 'ci:skip') && '[ci:skip] ' || '' }}"))

    def test_lint_push_gate_requires_successful_lookup(self):
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-lint-groups-json.yml').read_text())
        for result, skip, expected in [('success', 'true', False), ('success', 'false', True), ('failure', '', False), ('cancelled', '', False)]:
            with self.subTest(result=result, skip=skip):
                self.assertEqual(self.allowed(doc['jobs']['lint'], **{
                    'github.event_name': 'push',
                    'needs.push-label.result': result,
                    'needs.push-label.outputs.skip': skip,
                }), expected)

    def test_existing_failure_and_fork_restrictions_remain(self):
        for name, doc in self.workflows('workflow_run'):
            for job in doc['jobs'].values():
                context = {'github.event.workflow_run.conclusion': 'failure'}
                if name == 'CI-builds.yml':
                    context = {'github.event.workflow_run.head_repository.full_name': 'someone/fork'}
                with self.subTest(workflow=name):
                    self.assertFalse(self.allowed(job, **context))
        trigger = yaml.safe_load((ROOT / '.github/workflows/CI-trigger.yml').read_text())
        self.assertFalse(self.allowed(trigger['jobs']['run'], **{
            'github.event.pull_request.head.repo.fork': True,
        }))

    def test_push_lookup_executes_filter_and_propagates_api_failure(self):
        doc = yaml.safe_load((ROOT / '.github/workflows/CI-lint-groups-json.yml').read_text())
        script = doc['jobs']['push-label']['steps'][0]['run']
        def pr(label='ci:skip', ref='feature', repo='sysown/proxysql', state='open'):
            return {'state': state, 'head': {'ref': ref, 'repo': {'full_name': repo}},
                    'labels': [{'name': label}]}
        cases = [
            ([pr()], 'branch', 0, 'skip=true'),
            ([pr(label='CI:SKIP')], 'branch', 0, 'skip=true'),
            ([pr(label='ci:v3.0')], 'branch', 0, 'skip=false'),
            ([pr(ref='unrelated'), pr(repo='someone/fork'), pr(state='closed')], 'branch', 0, 'skip=false'),
            ([], 'branch', 0, 'skip=false'),
            ([pr()], 'tag', 0, 'skip=false'),
            ([pr()], 'branch', 1, None),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            # Exercise the actual workflow shell and jq expression. Only the
            # HTTP transport is replaced; no credentials or network required.
            gh = directory / 'gh'
            gh.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *"--paginate"* ]]
[[ "$*" == *"head=sysown:feature"* ]]
if [[ "$API_FAILURE" == 1 ]]; then exit 1; fi
while [[ "$1" != --jq ]]; do shift; done
jq -r "$2" "$API_RESPONSE"
''')
            gh.chmod(0o755)
            for response, ref_type, failure, expected in cases:
                with self.subTest(response=response, ref_type=ref_type, failure=failure):
                    output = directory / 'output'
                    output.write_text('')
                    fixture = directory / 'response'
                    fixture.write_text(json.dumps(response))
                    env = dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH'],
                               GH_REPO='sysown/proxysql', HEAD_REF='feature', REF_TYPE=ref_type,
                               GITHUB_OUTPUT=str(output), API_RESPONSE=str(fixture),
                               API_FAILURE=str(failure))
                    result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
                    if failure:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(output.read_text(), '')
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output.read_text().strip(), expected)

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
