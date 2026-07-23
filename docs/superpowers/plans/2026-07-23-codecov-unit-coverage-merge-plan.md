# ProxySQL Codecov Unit-Coverage Merge Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Codecov load `codecov.yml` for both checkout layouts so TAP and unit-test reports merge while Codecov outages remain non-blocking.

**Architecture:** Keep the existing LCOV producers and server-side `fixes: proxysql/::` rule. Add explicit `codecov_yml_path` inputs to the root-checkout unit workflow and the nested-checkout TAP workflows, plus a lightweight shell contract validator that catches future regressions.

**Tech Stack:** GitHub Actions YAML, Codecov Action v4, Bash, Git worktrees, `actionlint` when available.

---

### Task 1: Add the workflow contract validator

**Files:**
- Create: `test/infra/control/validate-codecov-workflows.bash`

- [ ] **Step 1: Write the failing validator**

Create an executable Bash validator that accepts a workflow directory and an expected configuration path. It must find every `codecov/codecov-action@v4` step and require the same step to contain `codecov_yml_path` with the expected value and `fail_ci_if_error: false`.

```bash
#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_ROOT="${1:-.github/workflows}"
EXPECTED_CONFIG="${2:-codecov.yml}"

mapfile -t WORKFLOWS < <(
    rg -l --glob '*.yml' --glob '*.yaml' \
        '^[[:space:]]*uses:[[:space:]]*codecov/codecov-action@v4' \
        "${WORKFLOW_ROOT}" | sort
)

if [ "${#WORKFLOWS[@]}" -eq 0 ]; then
    echo "ERROR: no Codecov workflows found under ${WORKFLOW_ROOT}" >&2
    exit 1
fi

for workflow in "${WORKFLOWS[@]}"; do
    awk -v file="${workflow}" -v expected="${EXPECTED_CONFIG}" '
        function finish_step() {
            if (!has_codecov) {
                return
            }
            if (!has_config) {
                printf "%s: missing codecov_yml_path: %s\n", file, expected > "/dev/stderr"
                bad = 1
            }
            if (!has_nonblocking) {
                printf "%s: Codecov upload must keep fail_ci_if_error: false\n", file > "/dev/stderr"
                bad = 1
            }
        }

        /^[[:space:]]*-[[:space:]]/ {
            if (in_step) {
                finish_step()
            }
            in_step = 1
            has_codecov = 0
            has_config = 0
            has_nonblocking = 0
        }

        /uses:[[:space:]]*codecov\/codecov-action@v4/ {
            has_codecov = 1
        }
        /codecov_yml_path:/ && index($0, expected) {
            has_config = 1
        }
        /fail_ci_if_error:[[:space:]]*false/ {
            has_nonblocking = 1
        }

        END {
            if (in_step) {
                finish_step()
            }
            exit bad
        }
    ' "${workflow}"
done

echo "Codecov workflow contract OK: ${#WORKFLOWS[@]} workflow(s), config=${EXPECTED_CONFIG}"
```

- [ ] **Step 2: Run it against the current `v3.0` worktree to verify RED**

Run:

```bash
chmod +x test/infra/control/validate-codecov-workflows.bash
test/infra/control/validate-codecov-workflows.bash .github/workflows codecov.yml
```

Expected: FAIL with a missing `codecov_yml_path` diagnostic, because the current unit workflow has no explicit configuration path.

- [ ] **Step 3: Run the shell syntax check**

Run:

```bash
bash -n test/infra/control/validate-codecov-workflows.bash
```

Expected: exit 0.

### Task 2: Fix the root-checkout unit-test upload

**Files:**
- Modify: `.github/workflows/CI-unit-tests-asan-coverage.yml`

- [ ] **Step 1: Add the explicit Codecov configuration path**

In the existing `Upload coverage to Codecov` step, add this input immediately under `with:`:

```yaml
        codecov_yml_path: codecov.yml
```

Leave `files: coverage/lcov.info`, `flags: unit-tests`, `use_oidc: true`, and `fail_ci_if_error: false` unchanged.

- [ ] **Step 2: Run the validator and verify GREEN for the unit workflow**

Run:

```bash
test/infra/control/validate-codecov-workflows.bash .github/workflows codecov.yml
```

Expected: PASS for the one Codecov workflow present in the `v3.0` checkout.

### Task 3: Fix all nested-checkout TAP uploads on `GH-Actions`

**Files:**
- Modify: all 43 `.github/workflows/*.yml` files on the `GH-Actions` workflow branch that use `codecov/codecov-action@v4`.

- [ ] **Step 1: Create an isolated worktree for the workflow branch**

From the `v3.0` worktree, run:

```bash
git worktree add ../fix-codecov-unit-coverage-gh-actions \
    -b fix/codecov-unit-coverage-gh-actions origin/GH-Actions
```

- [ ] **Step 2: Confirm the validator is RED on the workflow branch**

Run the validator from the `v3.0` worktree against the absolute `.github/workflows` path in the workflow worktree:

```bash
test/infra/control/validate-codecov-workflows.bash \
    /data/rene/proxysql3/proxysql/.worktrees/fix-codecov-unit-coverage-gh-actions/.github/workflows \
    proxysql/codecov.yml
```

Expected: FAIL because the 43 TAP upload steps do not explicitly load the config.

- [ ] **Step 3: Add the nested configuration path to every TAP upload step**

For each Codecov workflow, add this input immediately under its `with:` line:

```yaml
        codecov_yml_path: proxysql/codecov.yml
```

Use this mechanical rewrite only after confirming every target has the same
`uses`/`with` structure. The negative lookahead prevents duplicate inputs if
the command is accidentally run twice. Do not alter flags, files, OIDC, or
failure behavior.

```bash
while IFS= read -r workflow; do
    perl -0pi -e \
        's{(^([ \t]*)uses:[ \t]*codecov/codecov-action\@v4[^\n]*\n\2with:\n)(?!\2  codecov_yml_path:)}{$1$2  codecov_yml_path: proxysql/codecov.yml\n}mg' \
        "${workflow}"
done < <(
    rg -l --glob '*.yml' --glob '*.yaml' \
        '^[[:space:]]*uses:[[:space:]]*codecov/codecov-action@v4' \
        .github/workflows | sort
)
```

- [ ] **Step 4: Run the validator against all 43 workflows**

Run:

```bash
test/infra/control/validate-codecov-workflows.bash \
    /data/rene/proxysql3/proxysql/.worktrees/fix-codecov-unit-coverage-gh-actions/.github/workflows \
    proxysql/codecov.yml
```

Expected: PASS and report 43 workflows.

- [ ] **Step 5: Commit the workflow-branch changes**

Run in the `GH-Actions` worktree:

```bash
git add .github/workflows
git commit -m "fix(ci): load Codecov config for TAP uploads"
```

### Task 4: Verify syntax and regression contract

**Files:**
- Test: `.github/workflows/CI-unit-tests-asan-coverage.yml`
- Test: all modified `GH-Actions` workflows
- Test: `test/infra/control/validate-codecov-workflows.bash`

- [ ] **Step 1: Run Bash syntax checks**

Run:

```bash
bash -n test/infra/control/validate-codecov-workflows.bash
```

Expected: exit 0.

- [ ] **Step 2: Run `actionlint` when installed**

Run:

```bash
if command -v actionlint >/dev/null 2>&1; then
    actionlint .github/workflows/CI-unit-tests-asan-coverage.yml
    actionlint /data/rene/proxysql3/proxysql/.worktrees/fix-codecov-unit-coverage-gh-actions/.github/workflows/*.yml
else
    echo "actionlint not installed; YAML contract validation completed"
fi
```

Expected: no workflow errors; if unavailable, the explicit validator remains the required local check.

- [ ] **Step 3: Confirm the diff is limited to the approved scope**

Run in each worktree:

```bash
git diff --check HEAD^ HEAD
git status --short
```

Expected: only the approved validator/spec/plan and Codecov workflow edits are present; no user files from the original checkout appear.

### Task 5: Verify the remote behavior

- [ ] **Step 1: Run the unit coverage workflow on the patched branch**

Dispatch or allow the `CI-unit-tests-asan-coverage` workflow to run for the commit. Verify its log contains `codecov_yml_path: codecov.yml`, a non-empty `coverage/lcov.info`, and a queued Codecov upload.

- [ ] **Step 2: Run at least one TAP workflow on the patched `GH-Actions` branch**

Verify its log contains `codecov_yml_path: proxysql/codecov.yml` and a queued Codecov upload for a `tap-*` flag.

- [ ] **Step 3: Confirm Codecov merged results**

Query the Codecov totals API for the commit and the `unit-tests` flag:

```bash
SHA="$(git rev-parse HEAD)"
curl -fsSL \
  "https://api.codecov.io/api/v2/github/sysown/repos/proxysql/totals/?sha=${SHA}&flag=unit-tests" \
  | jq '.totals'
curl -fsSL \
  "https://api.codecov.io/api/v2/github/sysown/repos/proxysql/totals/?sha=${SHA}&path=lib/" \
  | jq '.totals'
```

Expected: the unit flag has nonzero sessions, and the `lib/` total reflects combined TAP and unit coverage rather than only the 12% unit-test baseline. Codecov upload/API failures must remain warnings in the test workflow because `fail_ci_if_error` stays false.

- [ ] **Step 4: Commit the `v3.0` changes**

Run in the `v3.0` worktree:

```bash
git add .github/workflows/CI-unit-tests-asan-coverage.yml \
    test/infra/control/validate-codecov-workflows.bash \
    docs/superpowers/specs/2026-07-23-codecov-unit-coverage-merge-design.md \
    docs/superpowers/plans/2026-07-23-codecov-unit-coverage-merge-plan.md
git commit -m "fix(ci): merge unit and TAP Codecov coverage"
```
