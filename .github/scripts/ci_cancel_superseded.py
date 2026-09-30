#!/usr/bin/env python3
"""Cancel superseded PR CI, following workflow_run's immutable trigger identity."""
import json
import os
import re

from ci_tier_artifacts import GitHubAPI

ACTIVE = ('queued', 'in_progress', 'pending', 'waiting', 'requested')
TRIGGER = re.compile(r' trigger=([1-9][0-9]*)/([1-9][0-9]*)$')


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


def cancel_superseded(api, pr_number, event_head_sha, exclude_run_id):
    pr_path = f'repos/{api.repository}/pulls/{pr_number}'
    current = api.request(pr_path)
    if current['head']['sha'] != event_head_sha:
        return []  # A delayed synchronize event must not cancel newer work.
    head = current['head']

    def belongs(run):
        same_source = (run.get('head_repository') or {}).get('full_name') == head['repo']['full_name']
        same_branch = run.get('head_branch') == head['ref']
        if not same_source or not same_branch:
            return False
        if run.get('event') == 'push':
            return True
        return run.get('event') == 'pull_request' and any(
            pr.get('number') == pr_number for pr in run.get('pull_requests', []))

    origins = {}
    cancelled = []
    seen = set()
    for status in ACTIVE:
        for run in api.pages(f'repos/{api.repository}/actions/runs?status={status}', 'workflow_runs'):
            run_id = run['id']
            if run_id == exclude_run_id or run_id in seen:
                continue
            seen.add(run_id)
            origin = run
            if run.get('event') == 'workflow_run':
                match = TRIGGER.search(run.get('display_title', ''))
                if not match:
                    continue
                trigger_id = int(match[1])
                if trigger_id not in origins:
                    origins[trigger_id] = api.request(f'repos/{api.repository}/actions/runs/{trigger_id}')
                origin = origins[trigger_id]
                if (origin.get('event') not in ('pull_request', 'push')
                        or origin.get('path') != '.github/workflows/CI-trigger.yml'):
                    continue
            if not belongs(origin) or origin.get('head_sha') == event_head_sha:
                continue
            # Re-read the head immediately before each cancellation, not just
            # before listing potentially hundreds of workflows.
            if api.request(pr_path)['head']['sha'] != event_head_sha:
                return cancelled
            if cancel_run(api, run_id):
                cancelled.append(run_id)
    return cancelled


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
    if os.environ['GITHUB_EVENT_NAME'] != 'pull_request_target':
        raise ValueError('cancellation sweep requires a trusted pull_request_target event')
    event = json.loads(open(os.environ['GITHUB_EVENT_PATH']).read())
    cancelled = cancel_superseded(GitHubAPI(os.environ['GITHUB_REPOSITORY']),
                                 event['number'], event['pull_request']['head']['sha'],
                                 int(os.environ['GITHUB_RUN_ID']))
    print(f'Requested cancellation of {len(cancelled)} superseded runs')


if __name__ == '__main__':
    main()
