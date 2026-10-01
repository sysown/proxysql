#!/usr/bin/env python3
"""Cancel superseded CI, following workflow_run's immutable trigger identity."""
import json
import os
import re

from ci_tier_artifacts import GitHubAPI

ACTIVE = ('queued', 'in_progress', 'pending', 'waiting', 'requested')
TRIGGER = re.compile(r' trigger=([1-9][0-9]*)/([1-9][0-9]*)$')
TRIGGER_PATH = '.github/workflows/CI-trigger.yml'
# Events whose origin run may legitimately start a CI cascade. `workflow_dispatch`
# is excluded on purpose: a manual dispatch is an explicit request for that commit
# and must never be swept away by a later push.
CASCADE_EVENTS = ('pull_request', 'push')


def cancel_run(api, run_id):
    path = f'repos/{api.repository}/actions/runs/{run_id}'
    if api.request(path)['status'] == 'completed':
        return False
    try:
        api.request(path + '/cancel', 'POST')
    except RuntimeError:
        # A run may finish between the status check and the cancellation.
        if api.request(path)['status'] != 'completed':
            raise
        return False
    print(f'Cancellation requested: {api.repository}/actions/runs/{run_id}')
    return True


def resolve_origin(api, run, origins):
    """Map a workflow_run back to the CI-trigger run that actually caused it.

    workflow_run rows carry the default branch's SHA, not the commit that was
    tested, so provenance has to come from the trigger id embedded in the
    display title. Anything without a real CI-trigger origin is left alone.
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
            or origin.get('path') != TRIGGER_PATH):
        return None
    return origin


def sweep(api, head_sha_now, head_sha, belongs, exclude_run_id):
    """Cancel active runs whose cascade origin predates this branch's head.

    The head is re-read immediately before each cancellation rather than once
    up front: a queued cascade lists hundreds of workflows and the head may
    advance while the sweep runs, so a delayed sweeper must never reach a
    cancellation for a commit that is no longer the branch head.
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
            if not belongs(origin) or origin.get('head_sha') == head_sha:
                continue
            # Re-read the head immediately before each cancellation, not just
            # before listing potentially hundreds of workflows.
            if head_sha_now() != head_sha:
                return cancelled
            if cancel_run(api, run_id):
                cancelled.append(run_id)
    return cancelled


def cancel_superseded(api, pr_number, event_head_sha, exclude_run_id):
    pr_path = f'repos/{api.repository}/pulls/{pr_number}'
    current = api.request(pr_path)
    if current['head']['sha'] != event_head_sha:
        return []  # A delayed synchronize event must not cancel newer work.
    head = current['head']

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

    return sweep(api, head_sha_now, event_head_sha, belongs, exclude_run_id)


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
    name TRIGGER_PATH just as a workflow_run child does.

    Manual dispatches are excluded: workflow_dispatch is an explicit request
    for that commit.
    """
    ref_path = f'repos/{api.repository}/commits/{branch}'

    def head_sha_now():
        return api.request(ref_path)['sha']

    def belongs(run):
        return (run.get('event') == 'push'
                and run.get('head_branch') == branch
                and run.get('path') == TRIGGER_PATH)

    return sweep(api, head_sha_now, event_after, belongs, exclude_run_id)


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
    if name == 'pull_request_target':
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
