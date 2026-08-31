# Pre-push CI Lint Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one repository-owned lint suite authoritative for both GitHub Actions and a pre-push hook, then activate that hook locally.

**Architecture:** A fail-fast Bash runner owns the existing CI lint command list. GitHub Actions and `.githooks/pre-push` both delegate to it, while a shell contract test exercises hook success and failure using a temporary Git repository and fake runner.

**Tech Stack:** Bash, Git hooks, Python 3 repository linters, GitHub Actions YAML.

---

### Task 1: Add a failing pre-push hook contract test

**Files:**
- Create: `test/infra/control/test-pre-push-lint-hook.bash`

- [ ] **Step 1: Write the hook contract test**

Create an executable Bash test that requires the tracked hook and shared runner,
checks that the workflow delegates to the runner, and exercises pass/fail
propagation in a temporary Git repository:

```bash
#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
hook="${repo_root}/.githooks/pre-push"
runner="${repo_root}/test/infra/control/run-ci-lint.bash"
workflow="${repo_root}/.github/workflows/CI-lint-groups-json.yml"

fail() {
  echo "pre-push lint hook contract: FAIL: $*" >&2
  exit 1
}

[[ -x "${hook}" ]] || fail "${hook} must exist and be executable"
[[ -x "${runner}" ]] || fail "${runner} must exist and be executable"
grep -Fq "test/infra/control/run-ci-lint.bash" "${workflow}" \
  || fail "CI lint workflow must invoke the shared runner"

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT
git -C "${fixture}" init -q
mkdir -p "${fixture}/.githooks" "${fixture}/test/infra/control" "${fixture}/nested"
cp "${hook}" "${fixture}/.githooks/pre-push"

cat > "${fixture}/test/infra/control/run-ci-lint.bash" <<'RUNNER'
#!/usr/bin/env bash
printf '%s\n' "${PWD}" > "${LINT_HOOK_PROBE}"
exit "${LINT_HOOK_STATUS}"
RUNNER
chmod +x "${fixture}/test/infra/control/run-ci-lint.bash"

probe="${fixture}/probe"
(
  cd "${fixture}/nested"
  LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=0 \
    "${fixture}/.githooks/pre-push" origin example.invalid
) || fail "hook must return success when the lint runner succeeds"
[[ "$(<"${probe}")" == "${fixture}" ]] \
  || fail "hook must execute the lint runner from the worktree root"

if (
  cd "${fixture}/nested"
  LINT_HOOK_PROBE="${probe}" LINT_HOOK_STATUS=23 \
    "${fixture}/.githooks/pre-push" origin example.invalid
); then
  fail "hook must return non-zero when the lint runner fails"
fi

echo "pre-push lint hook contract: OK"
```

- [ ] **Step 2: Make the test executable**

Run:

```bash
chmod +x test/infra/control/test-pre-push-lint-hook.bash
```

- [ ] **Step 3: Run the test and verify RED**

Run:

```bash
test/infra/control/test-pre-push-lint-hook.bash
```

Expected: exit 1 with `.githooks/pre-push must exist and be executable`.

- [ ] **Step 4: Commit the failing contract test**

```bash
git add test/infra/control/test-pre-push-lint-hook.bash
git commit -m "test: define pre-push lint hook contract"
```

### Task 2: Centralize the complete CI lint suite

**Files:**
- Create: `test/infra/control/run-ci-lint.bash`
- Modify: `.github/workflows/CI-lint-groups-json.yml`

- [ ] **Step 1: Add the canonical fail-fast lint runner**

Create this executable script:

```bash
#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
cd "${repo_root}"

run_check() {
  local label="$1"
  shift
  echo ">>> ${label}"
  "$@"
}

run_check "Lint groups.json format" \
  python3 test/tap/groups/lint_groups_json.py
run_check "Check AI TAP shard split" \
  python3 test/tap/groups/test_ai_group_shards.py
run_check "Check TAP Makefile dependency graph" \
  python3 test/tap/groups/test_makefile_dependencies.py
run_check "Check binlog reader infrastructure contract" \
  python3 test/tap/groups/test_binlog_reader_infra.py
run_check "Check every TAP source is registered in groups.json" \
  python3 test/tap/groups/check_groups.py --source
run_check "Check cluster simulator coverage contract" \
  test/infra/control/test-cluster-simulator-coverage.bash
run_check "Check coverage collector invariants" \
  test/infra/control/validate-coverage-gcov-toolchain.bash
run_check "Check package CI verification hook" \
  test/infra/control/test-package-ci-verification.bash
run_check "Check package install verifier" \
  test/infra/control/test-verify-package-install.bash
run_check "Check group infra/workflow coverage (warn-only)" \
  python3 test/tap/groups/lint_group_coverage.py

echo ">>> CI lint suite: OK"
```

- [ ] **Step 2: Make the runner executable**

```bash
chmod +x test/infra/control/run-ci-lint.bash
```

- [ ] **Step 3: Make GitHub Actions invoke the shared runner**

Keep checkout and the `GH-Actions` fetch step unchanged. Replace the ten
individual validation steps with:

```yaml
      - name: Run repository CI lint suite
        run: test/infra/control/run-ci-lint.bash
```

- [ ] **Step 4: Run the shared runner and confirm the existing failure**

Run:

```bash
test/infra/control/run-ci-lint.bash
```

Expected: exit 1 at `Lint groups.json format`, reporting that
`mysql_resultset_framer_traffic_unit-t` must precede
`mysql_server_version_by_interface_unit-t`. This proves the shared entry point
reproduces CI before the data fix.

### Task 3: Add and document the tracked pre-push hook

**Files:**
- Create: `.githooks/pre-push`
- Create: `.githooks/README.md`

- [ ] **Step 1: Add the tracked pre-push hook**

```bash
#!/usr/bin/env bash

set -euo pipefail

if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "pre-push lint: unable to determine the Git worktree root" >&2
  exit 1
fi

runner="${repo_root}/test/infra/control/run-ci-lint.bash"
if [[ ! -x "${runner}" ]]; then
  echo "pre-push lint: missing executable runner: ${runner}" >&2
  exit 1
fi

echo ">>> Running repository CI lint suite before push"
cd "${repo_root}"
exec "${runner}"
```

- [ ] **Step 2: Make the hook executable**

```bash
chmod +x .githooks/pre-push
```

- [ ] **Step 3: Document activation and bypass behavior**

Create `.githooks/README.md`:

````markdown
# Repository Git hooks

Enable the tracked hooks once per clone:

```bash
git config core.hooksPath .githooks
```

The pre-push hook runs the same complete lint suite as
`.github/workflows/CI-lint-groups-json.yml` and blocks the push on failure.
Use `git push --no-verify` only when intentionally bypassing local verification.
````

- [ ] **Step 4: Run the contract test and verify GREEN**

Run:

```bash
test/infra/control/test-pre-push-lint-hook.bash
```

Expected: `pre-push lint hook contract: OK`.

- [ ] **Step 5: Commit the shared runner and hook**

```bash
git add .github/workflows/CI-lint-groups-json.yml .githooks \
  test/infra/control/run-ci-lint.bash
git commit -m "ci: run lint suite before pushes"
```

### Task 4: Fix the current lint violation and activate the hook

**Files:**
- Modify: `test/tap/groups/groups.json`
- Local Git configuration: `core.hooksPath`

- [ ] **Step 1: Apply the canonical groups.json formatter**

Run:

```bash
python3 test/tap/groups/lint_groups_json.py --fix
```

Expected: the `mysql_server_version_by_interface_unit-t` entry moves after
`mysql_resultset_framer_traffic_unit-t`; inspect the diff and retain no unrelated
rewrites.

- [ ] **Step 2: Run the complete shared lint suite**

```bash
test/infra/control/run-ci-lint.bash
```

Expected: every check passes and the final line is `>>> CI lint suite: OK`.

- [ ] **Step 3: Activate the tracked hooks for this repository**

```bash
git config core.hooksPath .githooks
git config --get core.hooksPath
```

Expected: `.githooks`.

- [ ] **Step 4: Run the installed pre-push hook directly**

```bash
"$(git rev-parse --show-toplevel)/.githooks/pre-push" origin "$(git remote get-url origin)" </dev/null
```

Expected: the complete lint suite passes and exits 0.

- [ ] **Step 5: Commit the lint correction**

```bash
git add test/tap/groups/groups.json
git commit -m "test: keep TAP group registry sorted"
```

### Task 5: Final verification and publication

**Files:**
- Verify only; no expected source changes.

- [ ] **Step 1: Verify the complete implementation**

```bash
test/infra/control/test-pre-push-lint-hook.bash
test/infra/control/run-ci-lint.bash
git diff --check origin/v3.0...HEAD
git status --short
```

Expected: both scripts pass, `git diff --check` is silent, and the worktree is
clean.

- [ ] **Step 2: Push through the installed hook**

```bash
git push
```

Expected: the pre-push hook runs the full suite successfully before Git updates
`origin/feature/mysql-server-version-by-interface`.

- [ ] **Step 3: Verify GitHub state**

```bash
gh pr checks 6151
```

Expected: a new lint workflow run is present; monitor it to completion and
confirm `lint` passes. Investigate any other newly failing checks separately
rather than conflating them with the lint gate.
