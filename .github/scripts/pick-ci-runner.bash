#!/usr/bin/env bash
# Choose a pool; this observes demand and does not reserve a runner.
set -uo pipefail
diagnostic="$(mktemp)"
switched="$(mktemp -u)"
trap 'rm -f "$diagnostic" "$switched"' EXIT
exec 3>&1
# GH_TOKEN can be the read-only app token, which has its own rate limit. After
# its first failed lookup, use FALLBACK_TOKEN (the job token) for the rest.
api() {
  local out
  if [ ! -e "$switched" ]; then
    out=$(gh api "$@") && { printf '%s\n' "$out"; return 0; }
    [ -n "${FALLBACK_TOKEN:-}" ] && [ "$FALLBACK_TOKEN" != "${GH_TOKEN:-}" ] || return 1
    echo ">>> WARNING: lookup with the read token failed; using the job token" >&3
    : > "$switched"
  fi
  out=$(GH_TOKEN="$FALLBACK_TOKEN" gh api "$@") && printf '%s\n' "$out"
}
hosted="${HOSTED_RUNNER:-ubuntu-22.04}"
printf -v choice '"%s"' "$hosted"
if [ "${ELIGIBLE:-}" = "true" ]; then
  POOL="${POOL_SIZE:-6}"
  demand=0; err=0
  ids=$( api --paginate "repos/${REPO}/actions/runs?status=in_progress&per_page=100" --jq '.workflow_runs[].id' 2>"$diagnostic" ) || err=1
  if [ "$err" = "0" ]; then
    # Listing the jobs of every in-progress run cost one API call per run, for
    # every context job: thousands of calls per hour while several pipelines run,
    # all from the repository's shared GITHUB_TOKEN quota. Read at most
    # MAX_SCAN runs, spread evenly over the list, and scale their pool jobs up
    # to all runs. The choice was already an estimate: it reserves nothing.
    MAX_SCAN="${MAX_SCAN_RUNS:-20}"
    read -r -a runs <<< "$(echo ${ids:-})"
    total=${#runs[@]}
    stride=$(( (total + MAX_SCAN - 1) / MAX_SCAN )); [ "$stride" -lt 1 ] && stride=1
    scanned=0
    for (( i = 0; i < total; i += stride )); do
      rid=${runs[$i]}
      [ "$demand" -ge "$POOL" ] && break
      n=$(api --paginate "repos/${REPO}/actions/runs/${rid}/jobs?per_page=100" --jq '[.jobs[]|select(.status=="in_progress" and (([.labels[]]|index("proxysql-ci")) != null))]|length' 2>/dev/null |
        awk '{total += $1} END {print total+0}') || { echo ">>> WARNING: could not read jobs for run ${rid}; assuming pool is full"; n="${POOL}"; }
      demand=$(( demand + ${n:-0} ))
      scanned=$(( scanned + 1 ))
    done
    if [ "$stride" -gt 1 ] && [ "$demand" -lt "$POOL" ] && [ "$scanned" -gt 0 ]; then
      echo ">>> sampled ${scanned}/${total} in-progress runs: ${demand} pool jobs"
      demand=$(( (demand * total + scanned - 1) / scanned ))
    fi
    free=$(( POOL - demand ))
    echo ">>> self-hosted pool: demand=${demand}/${POOL} free=${free} (in-progress on pool)"
    if [ "${free}" -ge 1 ]; then
      choice='["self-hosted","proxysql-ci"]'; echo ">>> capacity available -> self-hosted"
    else
      printf -v choice '"%s"' "$hosted"; echo ">>> pool at/over capacity -> spill to GitHub-hosted"
    fi
  else
    echo ">>> WARNING: could not read runs:"; sed 's/^/    /' "$diagnostic"
    # This knob applies to runs-listing failures. Failed jobs lookups above
    # conservatively assume the pool is full and always spill to hosted.
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
