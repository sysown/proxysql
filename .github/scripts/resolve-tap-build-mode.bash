#!/usr/bin/env bash
set -euo pipefail

emit_normal() {
    echo "CI TAP build mode: normal ($1)" >&2
    printf '%s\n' normal
}

if [[ "${TRUSTED:-false}" != true ]]; then
    emit_normal 'untrusted caller'; exit 0
fi
if [[ -z "${TRIGGER_JSON:-}" ]]; then
    emit_normal 'direct dispatch'; exit 0
fi

pr_number=$(jq -r '.event.workflow_run.pull_requests[0].number // empty' <<<"${TRIGGER_JSON}") \
    || { echo 'invalid trigger JSON' >&2; exit 1; }
if [[ -z "$pr_number" ]]; then
    emit_normal 'non-PR trigger'; exit 0
fi

labels=$("${GH_BIN:-gh}" api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" \
    --jq '.labels[].name') \
    || { echo "unable to read labels for PR #${pr_number}" >&2; exit 1; }
if grep -Fxq 'ci:asan' <<<"${labels}"; then
    echo "CI TAP build mode: asan (PR #${pr_number} has ci:asan)" >&2
    printf '%s\n' asan
else
    emit_normal "PR #${pr_number} has no ci:asan"
fi
