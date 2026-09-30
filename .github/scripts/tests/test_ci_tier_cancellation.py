"""Cancellation must follow PR provenance, not workflow_run's default-branch SHA."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_cancel_superseded import cancel_superseded, cancel_if_superseded

REPO = 'sysown/proxysql'
OLD, CURRENT, NEWER = 'a'*40, 'b'*40, 'c'*40


def pr(sha=CURRENT):
    return dict(number=42, head=dict(sha=sha, ref='feature/test', repo=dict(full_name=REPO)))


def run(identifier, sha=OLD, event='pull_request', **changes):
    row = dict(id=identifier, event=event, status='in_progress', head_sha=sha,
               head_branch='feature/test', head_repository=dict(full_name=REPO),
               pull_requests=[dict(number=42)], path='.github/workflows/CI-trigger.yml',
               display_title='CI-trigger')
    row.update(changes)
    return row


class API:
    repository = REPO

    def __init__(self, runs, current=None):
        self.runs = {row['id']: copy.deepcopy(row) for row in runs}
        self.pr = current or pr()
        self.cancelled = []
        self.reads = 0
        self.advance_on_read = None
        self.complete_on_cancel = False

    def pages(self, path, key):
        status = path.split('status=')[1]
        return [copy.deepcopy(row) for row in self.runs.values() if row['status'] == status]

    def request(self, path, method='GET'):
        if path == f'repos/{REPO}/pulls/42':
            self.reads += 1
            if self.reads == self.advance_on_read:
                self.pr = pr(NEWER)
            return copy.deepcopy(self.pr)
        identifier = int(path.split('/runs/')[1].split('/')[0])
        if method == 'POST':
            assert path.endswith('/cancel')
            if self.complete_on_cancel:
                self.runs[identifier]['status'] = 'completed'
                raise RuntimeError('already completed')
            self.cancelled.append(identifier)
        return copy.deepcopy(self.runs[identifier])


class CancellationTests(unittest.TestCase):
    def test_old_direct_and_cascade_runs_cancel_but_new_head_is_preserved(self):
        origin = run(10, status='completed')
        child = run(11, sha='d'*40, event='workflow_run', head_branch='v3.0',
                    pull_requests=[], display_title='feature/test CI-tests '+OLD+' trigger=10/1')
        api = API([origin, child, run(12), run(13, CURRENT), run(14, CURRENT, event='push')])
        self.assertEqual(set(cancel_superseded(api, 42, CURRENT, 99)), {11, 12})
        self.assertEqual(set(api.cancelled), {11, 12})

    def test_other_pr_fork_branch_and_manual_runs_are_preserved(self):
        rows = [run(1, pull_requests=[dict(number=43)]),
                run(2, head_repository=dict(full_name='someone/proxysql')),
                run(3, head_branch='other'), run(4, event='workflow_dispatch'),
                run(5, event='schedule'), run(6, event='pull_request_target'),
                run(7, pull_requests=[])]
        api = API(rows)
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [])

    def test_title_alone_cannot_claim_another_prs_cascade(self):
        other = run(10, status='completed', pull_requests=[dict(number=43)])
        child = run(11, event='workflow_run', display_title='feature/test CI-tests '+OLD+' trigger=10/1')
        api = API([other, child])
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [])

    def test_same_branch_push_cascade_is_cancelled_but_manual_origin_is_preserved(self):
        push = run(10, event='push', status='completed', pull_requests=[])
        manual = run(20, event='workflow_dispatch', status='completed')
        push_child = run(11, event='workflow_run', display_title='CI-tests trigger=10/1')
        manual_child = run(21, event='workflow_run', display_title='CI-tests trigger=20/1')
        api = API([push, manual, push_child, manual_child])
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [11])

    def test_cascade_requires_a_real_ci_trigger_and_an_exact_title_suffix(self):
        other = run(10, status='completed', path='.github/workflows/unrelated.yml')
        child = run(11, event='workflow_run', display_title='CI-tests trigger=10/1')
        malformed = run(12, event='workflow_run', display_title='CI-tests trigger=10/1 extra')
        api = API([other, child, malformed])
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [])

    def test_all_active_states_and_same_branch_push_are_cancelled(self):
        states = ['queued', 'in_progress', 'pending', 'waiting', 'requested']
        api = API([run(i+1, status=state) for i, state in enumerate(states)] + [run(20, event='push')])
        self.assertEqual(set(cancel_superseded(api, 42, CURRENT, 99)), {1, 2, 3, 4, 5, 20})

    def test_delayed_event_cannot_cancel_a_newer_commit(self):
        api = API([run(1), run(2, NEWER)], current=pr(NEWER))
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [])

    def test_head_advancing_during_sweep_stops_further_cancellations(self):
        api = API([run(1), run(2)])
        api.advance_on_read = 3
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [1])

    def test_completed_run_racing_cancel_is_harmless(self):
        api = API([run(1)])
        api.complete_on_cancel = True
        self.assertEqual(cancel_superseded(api, 42, CURRENT, 99), [])

    def test_late_old_consumer_cancels_itself_before_artifact_work(self):
        api = API([run(7, event='workflow_run')])
        context = dict(repository=REPO, event='pull_request', sha=OLD, pull_requests=[dict(number=42)])
        with self.assertRaisesRegex(RuntimeError, 'superseded'):
            cancel_if_superseded(context, api, 7)
        self.assertEqual(api.cancelled, [7])

    def test_current_consumer_and_manual_historical_run_are_preserved(self):
        for event, sha in [('pull_request', CURRENT), ('workflow_dispatch', OLD), ('push', OLD)]:
            with self.subTest(event=event):
                api = API([])
                context = dict(repository=REPO, event=event, sha=sha, pull_requests=[dict(number=42)])
                cancel_if_superseded(context, api, 7)
                self.assertEqual(api.cancelled, [])


if __name__ == '__main__':
    unittest.main()
