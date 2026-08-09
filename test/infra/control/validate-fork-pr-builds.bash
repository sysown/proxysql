#!/usr/bin/env bash
set -euo pipefail

base_ref=${1:?usage: $0 <base-ref> <gh-actions-ref>}
actions_ref=${2:?usage: $0 <base-ref> <gh-actions-ref>}
base_builds=$(git show "$base_ref:.github/workflows/CI-builds.yml")
fork_builds=$(git show "$base_ref:.github/workflows/CI-builds-fork.yml")
reusable_builds=$(git show "$actions_ref:.github/workflows/ci-builds.yml")

grep -Fq 'github.event.workflow_run.head_repository.full_name == github.repository' <<<"$base_builds"
grep -Fq 'pull_request:' <<<"$fork_builds"
grep -Fq 'contents: read' <<<"$fork_builds"
grep -Fq 'trusted: false' <<<"$fork_builds"
grep -Fq 'trusted:' <<<"$reusable_builds"
grep -Fq 'inputs.trusted' <<<"$reusable_builds"
! grep -Fq 'allow-unsafe-pr-checkout: true' <<<"$base_builds$fork_builds$reusable_builds"
