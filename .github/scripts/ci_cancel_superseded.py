#!/usr/bin/env python3
"""Cancel superseded CI, following workflow_run's immutable trigger identity."""
import json
import os
import re
import time

from ci_tier_artifacts import GitHubAPI

ACTIVE = ('queued', 'in_progress', 'pending', 'waiting', 'requested')
TRIGGER = re.compile(r' trigger=([1-9][0-9]*)/([1-9][0-9]*)$')
TRIGGER_PATHS = {'.github/workflows/CI-trigger.yml', '.github/workflows/CI-builds.yml'}
# Events whose origin run may legitimately start a CI cascade. `workflow_dispatch`
# is excluded on purpose: a manual dispatch is an explicit request for that commit
# and must never be swept away by a later push.
CASCADE_EVENTS = ('pull_request', 'push')
CANCEL_ATTEMPTS = 3
sleep = time.sleep  # replaced by the tests


class StateChanged(Exception):
    """The branch head or PR state changed; the sweep must stop."""


def cancel_run(api, run_id, still_current=lambda: True):
    path = f'repos/{api.repository}/actions/runs/{run_id}'
    if api.request(path)['status'] == 'completed':
        return False
    # GitHubAPI never replays a failed POST, because most writes are not safe
    # to repeat. Cancelling a run is: asking twice has the same effect as
    # asking once. A transient error must not fail the whole sweep -- GitHub
    # has answered HTTP 502 to a cancellation that did take effect.
    for attempt in range(CANCEL_ATTEMPTS):
        # Checked before every POST, retries included: the head or the PR
        # state may change during the status read or the backoff.
        if not still_current():
            raise StateChanged
        try:
            api.request(path + '/cancel', 'POST')
            break
        except RuntimeError:
            # A run may finish between the status check and the cancellation.
            if api.request(path)['status'] == 'completed':
                return False
            if attempt == CANCEL_ATTEMPTS - 1:
                raise
            sleep(5 * 2 ** attempt)
    print(f'Cancellation requested: {api.repository}/actions/runs/{run_id}')
    return True


def resolve_origin(api, run, origins):
    """Map a workflow_run back to the source-event workflow that caused it.

    workflow_run rows carry the default branch's SHA, not the commit that was
    tested, so provenance has to come from the trigger id embedded in the
    display title. Only recognized source-event entry workflows are followed.
    """
    if run.get('event') != 'workflow_run':
        return run
    match = TRIGGER.search(run.get('display_title', ''))
    if not match:
        return None
    trigger_id = int(match.group(1))
    if trigger_id not in origins:
        origins[trigger_id] = api.request(f'repos/{api.repository}/actions/runs/{trigger_id}')
    origin = origins[trigger_id]
    if (origin.get('event') not in CASCADE_EVENTS
            or origin.get('path') not in TRIGGER_PATHS):
        return None
    return origin


def sweep(api, still_current, superseded, exclude_run_id):
    """Cancel active runs whose cascade origin is superseded.

    `still_current()` is re-checked immediately before each cancellation
    request (see cancel_run) rather than once up front: a queued cascade lists hundreds of workflows
    and the branch head (or the PR state) may change while the sweep runs, so
    a delayed sweeper must never reach a cancellation the new state forbids.
    """
    origins = {}
    cancelled = []
    seen = set()
    for status in ACTIVE:
        for run in api.pages(f'repos/{api.repository}/actions/runs?status={status}', 'workflow_runs'):
            run_id = run['id']
            if run_id == exclude_run_id or run_id in seen:
                continue
            seen.add(run_id)
            origin = resolve_origin(api, run, origins)
            if origin is None:
                continue
            if not superseded(origin):
                continue
            try:
                if cancel_run(api, run_id, still_current):
                    cancelled.append(run_id)
            except StateChanged:
                return cancelled
    return cancelled


def cancel_superseded(api, pr_number, event_head_sha, exclude_run_id):
    pr_path = f'repos/{api.repository}/pulls/{pr_number}'
    current = api.request(pr_path)
    if current['head']['sha'] != event_head_sha:
        return []  # A delayed synchronize event must not cancel newer work.
    head = current['head']
    if not head.get('repo'):
        # The PR's source repository was deleted: GitHub returns head.repo
        # as null and no run can be matched to the PR's source.
        return []

    def head_sha_now():
        return api.request(pr_path)['head']['sha']

    def belongs(run):
        same_source = (run.get('head_repository') or {}).get('full_name') == head['repo']['full_name']
        same_branch = run.get('head_branch') == head['ref']
        if not same_source or not same_branch:
            return False
        if run.get('event') == 'push':
            return True
        return run.get('event') == 'pull_request' and any(
            pr.get('number') == pr_number for pr in run.get('pull_requests', []))

    return sweep(api, lambda: head_sha_now() == event_head_sha,
                 lambda run: belongs(run) and run.get('head_sha') != event_head_sha,
                 exclude_run_id)


def cancel_closed_pr(api, pr_number, exclude_run_id):
    """Cancel all CI of a PR that was merged or closed, its last head included.

    Nothing else stops it: the superseded sweep only fires on a new head, so
    every PR merged or closed with CI still queued used to leave its whole
    ~100-workflow cascade in the shared runner pool, ahead of the open PRs.
    A merged PR's code is tested again by the push cascade of the branch it
    was merged into; a closed one needs no results at all.

    GitHub empties a run's `pull_requests` once the PR is no longer open, so
    the run cannot be matched by PR number. It is matched by the PR's source
    repository and branch instead, and a run still attached to another open
    PR from the same branch is left to that PR. Only `pull_request` origins
    are swept: push CI on the same branch is not this PR's work.
    """
    pr_path = f'repos/{api.repository}/pulls/{pr_number}'
    head = api.request(pr_path)['head']
    if not head.get('repo'):
        # The PR's source repository was deleted (head.repo is null). Its runs
        # cannot be told apart from another source's runs on a branch of the
        # same name, so leave them alone.
        return []

    def still_closed():
        # A reopened PR wants its CI again; stop at once.
        return api.request(pr_path)['state'] == 'closed'

    def belongs(run):
        return (run.get('event') == 'pull_request'
                and (run.get('head_repository') or {}).get('full_name') == head['repo']['full_name']
                and run.get('head_branch') == head['ref']
                and all(pr.get('number') == pr_number for pr in run.get('pull_requests', [])))

    if not still_closed():
        return []  # Reopened before this delayed event was handled.
    return sweep(api, still_closed, belongs, exclude_run_id)


def cancel_superseded_push(api, branch, event_after, exclude_run_id):
    """Cancel CI cascades started by older pushes to the same branch.

    Every push to a long-lived branch (v3.0, a release line) starts a fresh
    ~100-workflow cascade. Without this sweep the older cascades simply queue
    behind the newer one, so the branch accumulates work for commits it no
    longer points at -- which is what saturates the shared runner pool.

    Scope is deliberately narrow: only runs that are part of a CI-trigger
    cascade on this exact branch. Direct `push` runs of unrelated workflows
    (CI-package-build, and any release or deploy workflow added later) are
    NOT superseded CI and must be left running, so a direct origin has to
    name a recognized entry workflow just as a workflow_run child does.

    Manual dispatches are excluded: workflow_dispatch is an explicit request
    for that commit.
    """
    ref_path = f'repos/{api.repository}/commits/{branch}'

    def head_sha_now():
        return api.request(ref_path)['sha']

    def belongs(run):
        return (run.get('event') == 'push'
                and run.get('head_branch') == branch
                and run.get('path') in TRIGGER_PATHS)

    return sweep(api, lambda: head_sha_now() == event_after,
                 lambda run: belongs(run) and run.get('head_sha') != event_after,
                 exclude_run_id)


def cancel_if_superseded(context, api, current_run_id):
    """Stop late-starting automatic PR work before registration/artifact access."""
    if context['event'] != 'pull_request' or not context.get('pull_requests'):
        return
    for pr in context['pull_requests']:
        current = api.request(f"repos/{api.repository}/pulls/{pr['number']}")
        if current['head']['sha'] == context['sha']:
            return
    cancel_run(api, current_run_id)
    raise RuntimeError('PR commit was superseded; cancelled this workflow before starting CI work')


def main():
    name = os.environ['GITHUB_EVENT_NAME']
    event = json.loads(open(os.environ['GITHUB_EVENT_PATH']).read())
    api = GitHubAPI(os.environ['GITHUB_REPOSITORY'])
    run_id = int(os.environ['GITHUB_RUN_ID'])
    # Both sweeps must run from a trusted context: `pull_request_target`
    # executes base-branch code, and `push` only ever fires on a branch the
    # actor can already write to. Neither checks out the tested code.
    if name == 'pull_request_target' and event.get('action') == 'closed':
        cancelled = cancel_closed_pr(api, event['number'], run_id)
    elif name == 'pull_request_target':
        cancelled = cancel_superseded(api, event['number'],
                                      event['pull_request']['head']['sha'], run_id)
    elif name == 'push':
        # A branch deletion carries no CI cascade to prune.
        if event.get('deleted'):
            print('Push deleted the branch; nothing to sweep')
            return
        cancelled = cancel_superseded_push(api, event['ref'].split('refs/heads/')[-1],
                                           event['after'], run_id)
    else:
        raise ValueError(f'cancellation sweep does not support the {name} event')
    print(f'Requested cancellation of {len(cancelled)} superseded runs')


if __name__ == '__main__':
    main()
