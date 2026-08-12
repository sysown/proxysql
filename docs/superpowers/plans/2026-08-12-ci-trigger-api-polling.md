# Resilient CI Trigger API Polling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `CI-trigger` tolerate up to five consecutive minutes of transient GitHub API failures without confusing a polling failure with an unsuccessful `CI-builds` conclusion.

**Architecture:** Keep the existing `CI-trigger` → `CI-builds` → downstream fan-out topology. Replace `gh run watch --exit-status` with JSON discovery and status polling through one bounded retry helper; successful API calls reset the helper's error window, while confirmed completed conclusions retain their current pass/fail semantics.

**Tech Stack:** GitHub Actions YAML, Bash, GitHub CLI (`gh`), GNU `timeout`, `jq`, PyYAML, ShellCheck.

## Global Constraints

- Modify only `.github/workflows/ci-trigger.yml` and the directly associated design and implementation-plan documentation.
- Preserve the current `GH-Actions` branch topology, workflow permissions, downstream conditions, and 240-minute trigger timeout.
- Set the consecutive API-error tolerance to exactly 300 seconds.
- Bound each GitHub CLI polling call to at most 30 seconds.
- Retry failed calls after 5, 10, 20, then at most 30 seconds between later attempts.
- Continue discovery every 20 seconds when the API call succeeds but the expected run is not visible.
- Continue status polling every 30 seconds while the discovered run is not completed.
- Fail immediately only after GitHub confirms a completed conclusion other than `success`; never infer a build conclusion from a GitHub CLI failure.
- Do not change ProxySQL source, build selection, or downstream workflows.

---

### Task 1: Replace ambiguous workflow watching with bounded JSON polling

**Files:**
- Modify: `.github/workflows/ci-trigger.yml:17-49`
- Reference: `docs/superpowers/specs/2026-08-12-ci-trigger-api-polling-design.md`
- Test: temporary fake-`gh` harness under `/tmp/proxysql-ci-trigger-polling-test/` (do not commit)

**Interfaces:**
- Consumes: the existing `GH_TOKEN`, `${{ github.repository }}`, `${{ github.event.after || github.sha }}`, `${{ github.event.pull_request.head.sha || github.sha }}`, and `${{ github.sha }}` values.
- Produces: the same `CI-trigger` job conclusion consumed by all existing `workflow_run[completed]` workflows; the conclusion is `success` only after the selected `CI-builds` run is confirmed complete with conclusion `success`.

- [ ] **Step 1: Build a deterministic red test for the current one-error behavior**

Create `/tmp/proxysql-ci-trigger-polling-test/` with `mktemp -d` or an explicit validated temporary path. Add a fake executable named `gh` that returns one matching table row for `run list` and then returns this single failure for `run watch`:

```bash
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  *"run list"*)
    printf 'in_progress\t\tfeature/test CI-builds test-sha\tCI-builds\tv3.0\tworkflow_run\t42\t1m\t2026-08-12T00:00:00Z\n'
    ;;
  *"run watch"*)
    echo 'failed to get run: Get "https://api.github.com/repos/sysown/proxysql/actions/runs/42": tls: failed to verify certificate' >&2
    exit 1
    ;;
  *)
    echo "unexpected fake gh arguments: $*" >&2
    exit 2
    ;;
esac
```

Extract the first `run` block from `.github/workflows/ci-trigger.yml` with this script, replace the four GitHub expressions with `test-sha` and `sysown/proxysql`, put the fake executable first in `PATH`, and execute the extracted Bash. Keep the current five-second sleeps intact for this one red run.

```python
import yaml
from pathlib import Path

workflow = Path('.github/workflows/ci-trigger.yml')
output = Path('/tmp/proxysql-ci-trigger-polling-test/trigger-step.sh')
script = yaml.safe_load(workflow.read_text())['jobs']['trigger']['steps'][0]['run']
for old, new in {
    '${{ github.event.after || github.sha }}': 'test-sha',
    '${{ github.event.pull_request.head.sha || github.sha }}': 'test-sha',
    '${{ github.sha }}': 'test-sha',
    '${{ github.repository }}': 'sysown/proxysql',
}.items():
    script = script.replace(old, new)
output.write_text(script)
```

Expected: exit code `1`, with `CI-builds run ... did not complete successfully` even though the fake failure represents transport rather than a completed build conclusion. This reproduces the defect before editing production workflow code.

- [ ] **Step 2: Replace the first trigger step with the bounded poller**

Use `apply_patch` to replace the current table parsing and `gh run watch` block. Keep the existing step name and token. The new Bash must follow this structure:

```bash
set -euo pipefail

readonly API_ERROR_WINDOW_SECONDS="${CI_API_ERROR_WINDOW_SECONDS:-300}"
readonly API_CALL_TIMEOUT_SECONDS="${CI_API_CALL_TIMEOUT_SECONDS:-30}"
readonly API_RETRY_INITIAL_SECONDS="${CI_API_RETRY_INITIAL_SECONDS:-5}"
readonly API_RETRY_MAX_SECONDS="${CI_API_RETRY_MAX_SECONDS:-30}"
readonly DISCOVERY_POLL_SECONDS="${CI_DISCOVERY_POLL_SECONDS:-20}"
readonly STATUS_POLL_SECONDS="${CI_STATUS_POLL_SECONDS:-30}"
readonly INITIAL_DELAY_SECONDS="${CI_INITIAL_DELAY_SECONDS:-5}"
readonly GH_BIN="${GH_BIN:-gh}"
readonly REPOSITORY="${{ github.repository }}"

RUNNAME1="${{ github.event.after || github.sha }}"
RUNNAME2="${{ github.event.pull_request.head.sha || github.sha }}"
RUNNAME3="${{ github.sha }}"
GH_RESPONSE=""

gh_poll() {
  local operation="$1"
  shift

  local deadline=$((SECONDS + API_ERROR_WINDOW_SECONDS))
  local delay="${API_RETRY_INITIAL_SECONDS}"
  local attempt=1
  local response=""
  local status=0

  while true; do
    local remaining=$((deadline - SECONDS))
    if ((remaining <= 0)); then
      echo "::error::GitHub API polling failed for ${API_ERROR_WINDOW_SECONDS} consecutive seconds while ${operation}"
      return 1
    fi

    local call_timeout="${API_CALL_TIMEOUT_SECONDS}"
    if ((call_timeout > remaining)); then
      call_timeout="${remaining}"
    fi

    if response=$(timeout --signal=KILL "${call_timeout}s" "${GH_BIN}" "$@" 2>&1); then
      GH_RESPONSE="${response}"
      return 0
    else
      status=$?
    fi

    remaining=$((deadline - SECONDS))
    if ((remaining <= 0)); then
      echo "::error::GitHub API polling failed for ${API_ERROR_WINDOW_SECONDS} consecutive seconds while ${operation}; last exit ${status}"
      printf '%s\n' "${response}"
      return 1
    fi

    local sleep_for="${delay}"
    if ((sleep_for > remaining)); then
      sleep_for="${remaining}"
    fi
    echo "::warning::GitHub API call failed while ${operation} (attempt ${attempt}, exit ${status}); retrying in ${sleep_for}s"
    printf '%s\n' "${response}"
    sleep "${sleep_for}"

    if ((delay < API_RETRY_MAX_SECONDS)); then
      delay=$((delay * 2))
      if ((delay > API_RETRY_MAX_SECONDS)); then
        delay="${API_RETRY_MAX_SECONDS}"
      fi
    fi
    attempt=$((attempt + 1))
  done
}

echo "Get CI-builds run id for '${RUNNAME1}|${RUNNAME2}|${RUNNAME3}' ..."
sleep "${INITIAL_DELAY_SECONDS}"

RUNID=""
while [[ -z "${RUNID}" ]]; do
  gh_poll "discovering CI-builds" -R "${REPOSITORY}" run list \
    --workflow CI-builds --limit 100 \
    --json databaseId,displayTitle,status

  for expected_sha in "${RUNNAME1}" "${RUNNAME2}" "${RUNNAME3}"; do
    [[ -n "${expected_sha}" ]] || continue
    RUNID=$(jq -r --arg sha "${expected_sha}" \
      'first(.[] | select(.displayTitle | contains($sha)) | .databaseId) // empty' \
      <<<"${GH_RESPONSE}")
    [[ -z "${RUNID}" ]] || break
  done

  if [[ -z "${RUNID}" ]]; then
    echo "CI-builds run is not visible yet; retrying in ${DISCOVERY_POLL_SECONDS}s"
    sleep "${DISCOVERY_POLL_SECONDS}"
  fi
done

echo "Found CI-builds run ${RUNID}; waiting for its confirmed conclusion"
while true; do
  gh_poll "querying CI-builds run ${RUNID}" -R "${REPOSITORY}" run view "${RUNID}" \
    --json status,conclusion

  run_status=$(jq -r '.status // empty' <<<"${GH_RESPONSE}")
  run_conclusion=$(jq -r '.conclusion // empty' <<<"${GH_RESPONSE}")
  if [[ -z "${run_status}" ]]; then
    echo "::error::GitHub API returned no status for CI-builds run ${RUNID}"
    exit 1
  fi

  if [[ "${run_status}" != "completed" ]]; then
    echo "CI-builds run ${RUNID} is ${run_status}; polling again in ${STATUS_POLL_SECONDS}s"
    sleep "${STATUS_POLL_SECONDS}"
    continue
  fi

  if [[ "${run_conclusion}" == "success" ]]; then
    echo "CI-builds run ${RUNID} completed successfully"
    break
  fi

  echo "::error::CI-builds run ${RUNID} completed with conclusion '${run_conclusion:-unknown}'"
  exit 1
done
```

Do not alter the second housekeeping step in this task.

- [ ] **Step 3: Verify transient recovery with a fake GitHub CLI**

Update the temporary fake `gh` executable to the following scenario-driven implementation so `run list` and `run view` return JSON and maintain separate call counters in the temporary directory:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${FAKE_SCENARIO:?FAKE_SCENARIO is required}"
: "${FAKE_STATE_DIR:?FAKE_STATE_DIR is required}"

if [[ "$*" == *"run list"* ]]; then
  kind="list"
elif [[ "$*" == *"run view"* ]]; then
  kind="view"
else
  echo "unexpected fake gh arguments: $*" >&2
  exit 2
fi

counter_file="${FAKE_STATE_DIR}/${kind}.count"
count=0
if [[ -f "${counter_file}" ]]; then
  read -r count <"${counter_file}"
fi
count=$((count + 1))
printf '%s\n' "${count}" >"${counter_file}"

tls_error() {
  echo 'Get "https://api.github.com/": tls: failed to verify certificate' >&2
  exit 1
}

matching_run='[{"databaseId":42,"displayTitle":"feature/test CI-builds test-sha","status":"in_progress"}]'

case "${FAKE_SCENARIO}:${kind}:${count}" in
  transient-success:list:1|reset-window:list:1|reset-window:list:3)
    tls_error
    ;;
  transient-success:list:2|reset-window:list:4|missing-then-visible:list:2|confirmed-build-failure:list:1)
    printf '%s\n' "${matching_run}"
    ;;
  reset-window:list:2|missing-then-visible:list:1)
    printf '[]\n'
    ;;
  transient-success:view:1)
    printf '{"status":"in_progress","conclusion":""}\n'
    ;;
  transient-success:view:2)
    tls_error
    ;;
  transient-success:view:3|reset-window:view:1|missing-then-visible:view:1)
    printf '{"status":"completed","conclusion":"success"}\n'
    ;;
  confirmed-build-failure:view:1)
    printf '{"status":"completed","conclusion":"failure"}\n'
    ;;
  continuous-api-failure:*)
    tls_error
    ;;
  *)
    echo "unexpected scenario call: ${FAKE_SCENARIO}:${kind}:${count}" >&2
    exit 2
    ;;
esac
```

Extract the updated first `run` block as in Step 1. Before each scenario, remove only the two counter files under the validated temporary state directory. Execute the script with these overrides so the test completes quickly:

```bash
GH_BIN=/tmp/proxysql-ci-trigger-polling-test/gh \
CI_API_ERROR_WINDOW_SECONDS=4 \
CI_API_CALL_TIMEOUT_SECONDS=1 \
CI_API_RETRY_INITIAL_SECONDS=1 \
CI_API_RETRY_MAX_SECONDS=1 \
CI_DISCOVERY_POLL_SECONDS=1 \
CI_STATUS_POLL_SECONDS=1 \
CI_INITIAL_DELAY_SECONDS=0 \
FAKE_SCENARIO=transient-success \
FAKE_STATE_DIR=/tmp/proxysql-ci-trigger-polling-test/state \
bash /tmp/proxysql-ci-trigger-polling-test/trigger-step.sh
```

Run these response sequences:

```text
transient-success:
  run list #1 -> TLS error, exit 1
  run list #2 -> [{"databaseId":42,"displayTitle":"feature/test CI-builds test-sha","status":"in_progress"}]
  run view #1 -> {"status":"in_progress","conclusion":""}
  run view #2 -> TLS error, exit 1
  run view #3 -> {"status":"completed","conclusion":"success"}
  expected -> exit 0, two retry warnings, confirmed success message

reset-window:
  run list #1 -> TLS error, exit 1
  run list #2 -> []
  run list #3 -> TLS error, exit 1
  run list #4 -> matching run JSON
  run view #1 -> completed/success JSON
  expected -> exit 0; each successful list response starts a fresh error window

missing-then-visible:
  run list #1 -> []
  run list #2 -> matching run JSON
  run view #1 -> completed/success JSON
  expected -> exit 0 and a normal discovery-wait message, no API-error warning
```

- [ ] **Step 4: Verify the two terminal failure modes remain distinct**

Run the same extracted script against:

```text
continuous-api-failure:
  every gh call -> TLS error, exit 1
  expected -> exit 1 after the reduced four-second budget with
              "GitHub API polling failed"

confirmed-build-failure:
  run list -> matching run JSON
  run view -> {"status":"completed","conclusion":"failure"}
  expected -> immediate exit 1 with
              "completed with conclusion 'failure'"
```

Assert that neither continuous API failure nor its log says the CI-builds run completed unsuccessfully. This is the key error-classification regression check.

- [ ] **Step 5: Validate the final workflow statically**

Run:

```bash
python3 - <<'PY'
import yaml
from pathlib import Path

path = Path('.github/workflows/ci-trigger.yml')
data = yaml.safe_load(path.read_text())
assert data['jobs']['trigger']['timeout-minutes'] == 240
steps = data['jobs']['trigger']['steps']
assert len(steps) == 2
script = steps[0]['run']
assert 'gh run watch' not in script
assert '--json status,conclusion' in script
assert '${CI_API_ERROR_WINDOW_SECONDS:-300}' in script
print('workflow YAML and polling invariants: ok')
PY
```

Extract the first step again, replace GitHub expressions with literal test values, and run:

```bash
shellcheck -s bash /tmp/proxysql-ci-trigger-polling-test/trigger-step.sh
git diff --check
git diff -- .github/workflows/ci-trigger.yml
```

Expected: the YAML/invariant script prints `ok`; ShellCheck and `git diff --check` exit `0`; the diff contains only the intended trigger-step rewrite.

- [ ] **Step 6: Commit the workflow change**

```bash
git add .github/workflows/ci-trigger.yml
git commit -m "fix(ci): retry transient trigger polling failures"
```

### Task 2: Audit the complete branch and prepare hosted verification

**Files:**
- Verify: `.github/workflows/ci-trigger.yml`
- Verify: `docs/superpowers/specs/2026-08-12-ci-trigger-api-polling-design.md`
- Verify: `docs/superpowers/plans/2026-08-12-ci-trigger-api-polling.md`

**Interfaces:**
- Consumes: the committed workflow from Task 1 and the approved design constraints.
- Produces: a clean branch ready for a PR targeting `GH-Actions`, plus an explicit post-merge verification procedure.

- [ ] **Step 1: Re-run the complete deterministic verification from a clean state**

Remove and recreate only `/tmp/proxysql-ci-trigger-polling-test/`, then rerun all five fake-`gh` scenarios from Task 1. Re-run the YAML invariant check, ShellCheck, and `git diff --check`.

Expected: three recovery scenarios exit `0`; the continuous API and confirmed build failure scenarios exit `1` with their distinct expected messages; all static checks exit `0`.

- [ ] **Step 2: Audit scope and history**

```bash
git status --short
git diff --check origin/GH-Actions...HEAD
git diff --stat origin/GH-Actions...HEAD
git diff --name-only origin/GH-Actions...HEAD
git log --oneline origin/GH-Actions..HEAD
```

Expected changed files:

```text
.github/workflows/ci-trigger.yml
docs/superpowers/plans/2026-08-12-ci-trigger-api-polling.md
docs/superpowers/specs/2026-08-12-ci-trigger-api-polling-design.md
```

Expected commits: the design commit, the plan commit, and the workflow implementation commit only.

- [ ] **Step 3: Record the hosted verification gate**

After the branch is pushed and merged into `GH-Actions`, retrigger a PR with an empty commit. Verify:

```bash
gh pr checks 6035 --repo sysown/proxysql
gh run list --repo sysown/proxysql --workflow CI-trigger.yml --limit 10
gh run list --repo sysown/proxysql --workflow CI-builds.yml --limit 10
```

Acceptance requires the exact-head `CI-builds` run to complete successfully, `CI-trigger` to propagate that conclusion, and downstream `workflow_run[completed]` suites to start rather than skip. A live TLS error is not required; the deterministic fake-`gh` scenarios provide that coverage.
