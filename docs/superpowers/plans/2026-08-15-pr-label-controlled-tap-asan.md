# PR-label-controlled TAP ASAN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ci:asan` select an ASAN-instrumented standard TAP build in the existing CI-builds handoff, without adding label triggers or changing individual fan-out workflows.

**Architecture:** Add a small, independently tested shell resolver on the `GH-Actions` branch. The reusable `ci-builds.yml` invokes it before its build matrix, then passes its `normal` or `asan` result to the existing standard TAP build. The ASAN cache key is distinct, while artifact handoff names remain unchanged so downstream consumers receive the selected artifact transparently.

**Tech Stack:** GitHub Actions reusable workflows, GitHub CLI REST API, Bash, `jq`, Actions cache/artifacts.

## Global Constraints

- Make implementation changes on the `GH-Actions` branch; `v3.0` continues to call that reusable workflow.
- The only selecting label is exactly `ci:asan`.
- Do not add `labeled` or `unlabeled` trigger types; an empty commit starts a fresh label-selected run.
- For direct dispatches, pushes, fork/untrusted callers, and PRs without `ci:asan`, select `normal` mode.
- A trusted PR-backed run whose label lookup fails must fail; it must not silently choose normal mode.
- Keep `CI-unit-tests-asan-coverage` unchanged.
- Apply ASAN only to the `ubuntu24-tap-genai-gcov` handoff in this change. MySQLX and the other nonstandard variants remain follow-up work.
- Preserve existing build-handoff artifact names. Add an `_asan` suffix only to the Actions cache key, not artifact names.

---

## File Structure

- `.github/scripts/resolve-tap-build-mode.bash` — receives trusted status and the serialized triggering GitHub context; prints `normal` or `asan` to stdout and writes its reason to stderr.
- `.github/scripts/tests/test-resolve-tap-build-mode.bash` — hermetic Bash tests for normal, labeled, untrusted, non-PR, and label-query-failure cases.
- `.github/workflows/ci-builds.yml` — checks out the trusted control script, exposes its result as a job output, passes it into the build matrix, isolates ASAN caches, and injects sanitizer flags only in the standard TAP matrix leg.
- `doc/GH-Actions/README.md` — documents the opt-in label, the explicit empty-commit rerun behavior, and the scope boundary.

## Task 1: Add a tested central build-mode resolver

**Files:**
- Create: `.github/scripts/resolve-tap-build-mode.bash`
- Create: `.github/scripts/tests/test-resolve-tap-build-mode.bash`

**Interfaces:**
- Consumes: `TRUSTED` (`true` or `false`), optional `TRIGGER_JSON`, `GITHUB_REPOSITORY`, and optional `GH_BIN` (defaults to `gh`).
- Produces: exactly `normal` or `asan` on stdout; diagnostic reason on stderr; nonzero only when a trusted PR-backed label lookup cannot be completed.
- Uses: `gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" --jq '.labels[].name'` to retrieve current PR labels.

- [ ] **Step 1: Write the resolver tests first**

Create a Bash test file that makes a temporary executable `gh` stub and invokes the resolver through its public environment interface. Include these assertions:

```bash
assert_mode() {
    local expected="$1"; shift
    local actual
    actual=$("$@")
    test "$actual" = "$expected" || {
        echo "expected $expected, got $actual" >&2
        exit 1
    }
}

pr_trigger='{"event":{"workflow_run":{"pull_requests":[{"number":42}]}}}'
non_pr_trigger='{"event":{"workflow_run":{"pull_requests":[]}}}'

assert_mode normal env TRUSTED=false TRIGGER_JSON="$pr_trigger" \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true GITHUB_REPOSITORY=sysown/proxysql \
    GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$non_pr_trigger" \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='bug' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode normal env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='ci:asan-extra' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
assert_mode asan env TRUSTED=true TRIGGER_JSON="$pr_trigger" GH_LABELS='bug ci:asan' \
    GITHUB_REPOSITORY=sysown/proxysql GH_BIN="$stub" "$resolver"
```

Make the stub emit each space-separated `GH_LABELS` entry on its own line (for example, `tr ' ' '\n' <<<"${GH_LABELS:-}"`), matching `gh api --jq '.labels[].name'`; it exits nonzero when `GH_STUB_FAIL=1`. Assert that the failure case exits nonzero; this is the guard against a false-green normal build.

- [ ] **Step 2: Run the new test to confirm it fails before the resolver exists**

Run:

```bash
bash .github/scripts/tests/test-resolve-tap-build-mode.bash
```

Expected: failure because `.github/scripts/resolve-tap-build-mode.bash` does not yet exist.

- [ ] **Step 3: Implement the resolver**

Implement the following control flow in `.github/scripts/resolve-tap-build-mode.bash`:

```bash
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
```

Mark the resolver and test executable.

- [ ] **Step 4: Run the resolver test suite**

Run:

```bash
bash .github/scripts/tests/test-resolve-tap-build-mode.bash
```

Expected: all seven cases pass: untrusted, direct dispatch, non-PR, ordinary PR, near-matching label, labeled PR, and API failure.

- [ ] **Step 5: Commit the tested resolver**

```bash
git add .github/scripts/resolve-tap-build-mode.bash \
  .github/scripts/tests/test-resolve-tap-build-mode.bash
git commit -m "ci: resolve TAP ASAN mode from PR label"
```

## Task 2: Route the central TAP handoff through the selected build mode

**Files:**
- Modify: `.github/workflows/ci-builds.yml`
- Test: `.github/scripts/tests/test-resolve-tap-build-mode.bash`

**Interfaces:**
- Consumes: `resolve-tap-mode.outputs.mode`, constrained to `normal` or `asan` by Task 1.
- Produces: the existing `ci-builds-handoff-${SHA}-ubuntu24-tap-genai-gcov-{src,test}` artifacts, containing the normal or ASAN binary for that run.
- Preserves: all fan-out `HANDOFF_VARIANT: ubuntu24-tap-genai-gcov` references and `CI-unit-tests-asan-coverage`.

- [ ] **Step 1: Add the mode-resolution job before `builds`**

Add `resolve-tap-mode` with one `mode` job output. Check out only the trusted `GH-Actions` control script—not PR code—then run it with serialized caller context:

```yaml
resolve-tap-mode:
  runs-on: ubuntu-24.04
  outputs:
    mode: ${{ steps.resolve.outputs.mode }}
  steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
    with:
      ref: GH-Actions
      path: ci-control
      sparse-checkout: |
        .github/scripts/resolve-tap-build-mode.bash
  - id: resolve
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      TRUSTED: ${{ inputs.trusted }}
      TRIGGER_JSON: ${{ inputs.trigger }}
    run: |
      mode="$(ci-control/.github/scripts/resolve-tap-build-mode.bash)"
      printf 'mode=%s\n' "$mode" >> "$GITHUB_OUTPUT"
```

Set `GITHUB_REPOSITORY` through the standard Actions environment and run
`chmod +x ci-control/.github/scripts/resolve-tap-build-mode.bash` immediately
before invoking it.

- [ ] **Step 2: Prove the resolver is still correct after workflow wiring**

Run:

```bash
bash .github/scripts/tests/test-resolve-tap-build-mode.bash
```

Expected: all resolver cases remain green. Inspect the workflow diff to confirm the control checkout is pinned to `GH-Actions`, so a PR cannot alter label-selection behavior.

- [ ] **Step 3: Make the build job depend on the resolver and isolate ASAN caches**

Add `needs: resolve-tap-mode` to `builds`. Expose its output in the job environment and append a suffix only for sanitizer cache entries:

```yaml
env:
  TAP_BUILD_MODE: ${{ needs.resolve-tap-mode.outputs.mode }}
  BLDCACHE: ${{ inputs.trigger && fromJson(inputs.trigger).event.workflow_run.head_sha || github.sha }}_${{ matrix.dist }}${{ matrix.type }}${{ needs.resolve-tap-mode.outputs.mode == 'asan' && '_asan' || '' }}
  MATRIX: '(${{ matrix.dist }},${{ matrix.type }},${{ needs.resolve-tap-mode.outputs.mode }})'
```

Keep the `ci-builds-handoff-*` artifact name expressions unchanged. This prevents a cached normal binary from satisfying an ASAN build for the same SHA while retaining fan-out compatibility.

- [ ] **Step 4: Inject ASAN only for the standard handoff variant**

Replace the current `matrix.type =~ "-asan"` condition in the `Build` step with an explicit selected-mode guard before the GenAI and GCOV injections:

```bash
if [[ "${TAP_BUILD_MODE}" = 'asan' && "${{ matrix.dist }}${{ matrix.type }}" = 'ubuntu24-tap-genai-gcov' ]]; then
  sed -i "/command/i \\      - WITHASAN=1" docker-compose.yml
  sed -i "/command/i \\      - TEST_WITHASAN=1" docker-compose.yml
fi
```

Emit the selected mode and the matrix variant at the top of the Build step. Do not add flags to `ubuntu22-tap-mysqlx`, `ubuntu22-tap`, or non-TAP matrix entries in this implementation.

- [ ] **Step 5: Lint the workflow and run the script tests**

Run:

```bash
bash .github/scripts/tests/test-resolve-tap-build-mode.bash
docker run --rm -v "$PWD:/repo:ro" -w /repo rhysd/actionlint:1.7.7 \
  .github/workflows/ci-builds.yml
```

Expected: resolver tests pass and actionlint reports no workflow syntax or expression errors.

- [ ] **Step 6: Commit the central build selection**

```bash
git add .github/workflows/ci-builds.yml
git commit -m "ci: select TAP ASAN build from PR label"
```

## Task 3: Document and validate the opt-in contract

**Files:**
- Modify: `doc/GH-Actions/README.md`
- Test: a labeled and an unlabeled CI run on an internal PR.

**Interfaces:**
- Documents: the exact `ci:asan` label, the empty-commit rerun rule, normal behavior for dispatch/push, and the standard-variant-only scope.
- Depends on: Tasks 1 and 2.

- [ ] **Step 1: Add a concise “Opt-in TAP ASAN” section**

Document these exact rules:

```markdown
- Add `ci:asan` to an internal PR, then push an empty commit to request an
  ASAN standard-TAP integration run.
- Removing or adding the label alone does not start CI.
- Without the label, push builds, and manual dispatches use the normal build.
- The label replaces the normal `ubuntu24-tap-genai-gcov` handoff for that
  commit; it does not run a second fan-out.
- Unit ASAN coverage and MySQLX behavior are unchanged.
```

- [ ] **Step 2: Validate an unlabeled PR run**

On an internal PR without `ci:asan`, push a commit and verify:

```text
CI TAP build mode: normal
```

The build must publish the existing `ubuntu24-tap-genai-gcov` handoffs, and a representative existing consumer such as `CI-mysql84-g1` must restore them successfully.

- [ ] **Step 3: Validate the labeled replacement run**

Add `ci:asan`, push an empty commit, and verify:

```text
CI TAP build mode: asan
WITHASAN=1
TEST_WITHASAN=1
```

Confirm the artifact names remain `ci-builds-handoff-<sha>-ubuntu24-tap-genai-gcov-{src,test}` and the same representative fan-out workflow restores them.

- [ ] **Step 4: Validate failure behavior and unchanged workflows**

Temporarily make the resolver’s `gh api` call fail in a branch-only test run. Confirm a trusted PR-backed `ci-builds` run fails in `resolve-tap-mode`, before the build matrix starts. Confirm `CI-unit-tests-asan-coverage` still runs under its existing trigger regardless of `ci:asan`.

- [ ] **Step 5: Commit documentation**

```bash
git add doc/GH-Actions/README.md
git commit -m "docs(ci): explain label-selected TAP ASAN runs"
```
