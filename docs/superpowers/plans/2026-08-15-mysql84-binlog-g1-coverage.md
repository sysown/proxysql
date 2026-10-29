# MySQL 8.4 Binlog Reader Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the existing MySQL 8.4 binlog-reader TAP group under GCOV and upload its explicit LCOV result to Codecov.

**Architecture:** Add a v3.0 caller whose name mirrors `mysql84-binlog-g1`, then add its reusable `GH-Actions` implementation.  The reusable workflow follows `ci-mysql84-g5.yml`: use the existing GCOV build handoff, start the group-specific binlog topology, collect one LCOV file, require it, and upload only it.

**Tech Stack:** GitHub Actions reusable workflows, Docker Compose test infrastructure, Bash, fastcov LCOV, Codecov Action v4.

## Global Constraints

- Keep `TAP_GROUP` exactly `mysql84-binlog-g1`.
- Use `infra-dbdeployer-mysql84-binlog` through the group environment; do not emulate binlog readers in a generic MySQL group.
- Use `COVERAGE=1` and upload only the explicit `.info` file with `plugins: noop` and `disable_search: true`.
- Preserve Codecov availability as non-blocking, but fail the job when no LCOV is generated.

---

### Task 1: Add the v3.0 group-named caller

**Files:**
- Create: `.github/workflows/CI-mysql84-binlog-g1.yml`
- Test: `test/infra/control/validate-codecov-workflows.bash`

**Interfaces:**
- Consumes: the reusable workflow `sysown/proxysql/.github/workflows/ci-mysql84-binlog-g1.yml@GH-Actions`.
- Produces: the `CI-mysql84-binlog-g1` check for CI-trigger workflow completions.

- [ ] **Step 1: Write the failing workflow-presence check**

Run:

```bash
test -f .github/workflows/CI-mysql84-binlog-g1.yml
```

Expected: FAIL because the group-named caller does not exist.

- [ ] **Step 2: Create the caller**

Create a `workflow_dispatch` and `workflow_run` caller named
`CI-mysql84-binlog-g1`, use the same successful-`CI-trigger` guard and
`write-all` permission contract as `CI-mysql84-g5.yml`, and delegate with:

```yaml
uses: sysown/proxysql/.github/workflows/ci-mysql84-binlog-g1.yml@GH-Actions
```

- [ ] **Step 3: Verify the caller is present and valid**

Run:

```bash
test -f .github/workflows/CI-mysql84-binlog-g1.yml
python3 - <<'PY'
import yaml
yaml.safe_load(open('.github/workflows/CI-mysql84-binlog-g1.yml'))
PY
```

Expected: both commands exit zero.

- [ ] **Step 4: Commit the caller**

```bash
git add .github/workflows/CI-mysql84-binlog-g1.yml
git commit -m "ci: add mysql84 binlog coverage caller"
```

### Task 2: Add the GH-Actions reusable coverage workflow

**Files:**
- Create: `.github/workflows/ci-mysql84-binlog-g1.yml` on a branch based on `GH-Actions`
- Test: `test/infra/control/validate-codecov-workflows.bash`

**Interfaces:**
- Consumes: `trigger` JSON from the v3.0 caller and build handoffs named with the real triggering SHA.
- Produces: `ci_infra_logs/ci-mysql84-binlog-g1/coverage-report/ci-mysql84-binlog-g1.info` and a Codecov upload named `tap-mysql84-binlog-g1-coverage`.

- [ ] **Step 1: Write the failing workflow-presence check**

Run on the `GH-Actions` checkout:

```bash
test -f .github/workflows/ci-mysql84-binlog-g1.yml
```

Expected: FAIL because the reusable binlog coverage workflow does not exist.

- [ ] **Step 2: Create the reusable workflow from the GCOV TAP template**

Copy the proven checkout, build-handoff, binary-verification, GHCR login,
cleanup and Codecov settings from `ci-mysql84-g5.yml`.  Replace each group
value with `mysql84-binlog-g1`, including `INFRA_ID`, `TAP_GROUP`, artifact
paths and Codecov name.  Set `COVERAGE=1` in the test step.

Add the LCOV gate before upload:

```yaml
- name: Require non-empty binlog coverage LCOV
  if: ${{ !cancelled() }}
  run: test -s proxysql/ci_infra_logs/ci-mysql84-binlog-g1/coverage-report/ci-mysql84-binlog-g1.info
```

Configure Codecov to upload that exact `.info` file with `plugins: noop`,
`disable_search: true`, `root_dir: proxysql`, `use_oidc: true`, name
`tap-mysql84-binlog-g1-coverage`, and flag `integration-tests`.

- [ ] **Step 3: Verify static workflow contracts**

Run on the `GH-Actions` checkout:

```bash
test/infra/control/validate-codecov-workflows.bash .github/workflows/ci-mysql84-binlog-g1.yml codecov.yml
python3 - <<'PY'
import yaml
yaml.safe_load(open('.github/workflows/ci-mysql84-binlog-g1.yml'))
PY
```

Expected: both commands exit zero.

- [ ] **Step 4: Commit and open the linked reusable-workflow PR**

```bash
git add .github/workflows/ci-mysql84-binlog-g1.yml
git commit -m "ci: add mysql84 binlog coverage workflow"
git push -u origin ci/mysql84-binlog-g1-coverage
```

Open a PR against `GH-Actions` and merge it before relying on the v3.0 caller.

### Task 3: Validate the real binlog workload and update the v3.0 PR

**Files:**
- Modify: existing v3.0 coverage PR branch only if validation reveals a group or workflow contract defect.
- Test: `test/tap/tests/test_binlog_reader-t.cpp`

**Interfaces:**
- Consumes: the binlog group environment and the new reusable workflow contract.
- Produces: a passing real binlog-reader TAP run and non-empty local LCOV data.

- [ ] **Step 1: Run the focused real workload**

Run:

```bash
INFRA_ID=coverage-mysql84-binlog \
TAP_GROUP=mysql84-binlog-g1 \
TEST_PY_TAP_INCL=test_binlog_reader-t \
COVERAGE=1 \
test/infra/control/run-tests-isolated.bash
```

Expected: the existing TAP passes while exercising the actual reader processes supplied by the binlog infrastructure.

- [ ] **Step 2: Verify coverage output**

Run:

```bash
test -s ci_infra_logs/coverage-mysql84-binlog/coverage-report/coverage-mysql84-binlog.info
```

Expected: exit zero; an empty or missing report is a coverage-collection defect, not an acceptable skipped upload.

- [ ] **Step 3: Run registration and workflow validation**

Run:

```bash
python3 test/tap/groups/lint_groups_json.py
python3 test/tap/groups/check_groups.py --source
test/infra/control/validate-codecov-workflows.bash
```

Expected: all commands exit zero.

- [ ] **Step 4: Commit any v3.0 validation-driven correction and push the existing PR**

```bash
git add .github/workflows/CI-mysql84-binlog-g1.yml
git commit -m "ci: run mysql84 binlog TAP coverage"
git push
```
