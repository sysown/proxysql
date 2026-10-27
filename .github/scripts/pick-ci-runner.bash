#!/usr/bin/env bash
# Choose a pool; this observes demand and does not reserve a runner.
set -uo pipefail
diagnostic="$(mktemp)"
trap 'rm -f "$diagnostic"' EXIT
hosted="${HOSTED_RUNNER:-ubuntu-22.04}"
printf -v choice '"%s"' "$hosted"
if [ "${ELIGIBLE:-}" = "true" ]; then
  POOL="${POOL_SIZE:-6}"
  demand=0; err=0
  ids=$( gh api --paginate "repos/${REPO}/actions/runs?status=in_progress&per_page=100" --jq '.workflow_runs[].id' 2>"$diagnostic" ) || err=1
  if [ "$err" = "0" ]; then
    for rid in ${ids:-}; do
      [ "$demand" -ge "$POOL" ] && break
      n=$(gh api --paginate "repos/${REPO}/actions/runs/${rid}/jobs?per_page=100" --jq '[.jobs[]|select(.status=="in_progress" and (([.labels[]]|index("proxysql-ci")) != null))]|length' 2>/dev/null |
        awk '{total += $1} END {print total+0}') || { echo ">>> WARNING: could not read jobs for run ${rid}; assuming pool is full"; n="${POOL}"; }
      demand=$(( demand + ${n:-0} ))
    done
    free=$(( POOL - demand ))
    echo ">>> self-hosted pool: demand=${demand}/${POOL} free=${free} (in-progress on pool)"
    if [ "${free}" -ge 1 ]; then
      choice='["self-hosted","proxysql-ci"]'; echo ">>> capacity available -> self-hosted"
    else
      printf -v choice '"%s"' "$hosted"; echo ">>> pool at/over capacity -> spill to GitHub-hosted"
    fi
  else
    echo ">>> WARNING: could not read runs:"; sed 's/^/    /' "$diagnostic"
    if [[ "${HOSTED_ON_LOOKUP_FAILURE:-false}" == true ]]; then
      printf -v choice '"%s"' "$hosted"
    else
      choice='["self-hosted","proxysql-ci"]'
    fi
    echo ">>> capacity lookup failed -> ${choice}"
  fi
else
  echo ">>> not eligible for self-hosted -> GitHub-hosted"
fi
echo "runson=${choice}" >> "$GITHUB_OUTPUT"
echo ">>> decision: runson=${choice}"
