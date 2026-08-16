# GCOV Collector Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TAP coverage conversion use GCOV 11, matching the Ubuntu 22 coverage build, so Codecov receives daemon-side FFTO coverage.

**Architecture:** Keep ProxySQL's GCC 11 coverage build unchanged. The Ubuntu 24 CI-base image gains `gcov-11`; the standalone and multi-group raw-GCOV conversion paths select it explicitly with fastcov's `-g` option and fail instead of silently writing an empty report when it is unavailable.

**Tech Stack:** Docker, Ubuntu APT, Bash, fastcov, GCOV, GitHub Actions test infrastructure.

## Global Constraints

- Coverage build compiler remains GCC/GCOV 11.4.
- Raw `.gcda` conversion must invoke `fastcov -g gcov-11`.
- LCOV-only combination must remain toolchain-agnostic.
- A missing compatible GCOV binary is a CI failure, not a warning.
- Verify using real MySQL FFTO TAP traffic, not a synthetic packet helper.

---

### Task 1: Add a regression check for the coverage-toolchain contract

**Files:**
- Create: `test/infra/control/validate-coverage-gcov-toolchain.bash`
- Test: `test/infra/control/validate-coverage-gcov-toolchain.bash`

**Interfaces:**
- Consumes: `test/infra/docker-base/Dockerfile`, `test/infra/control/run-tests-isolated.bash`, and `test/infra/control/run-multi-group.bash`.
- Produces: exit status 0 only when the image installs `gcov-11` and both raw-data fastcov call sites specify `-g gcov-11`.

- [ ] **Step 1: Write the failing regression check**

Create an executable Bash script that resolves the repository root from its own path and checks these exact conditions:

```bash
#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dockerfile="${root}/test/infra/docker-base/Dockerfile"
runner="${root}/test/infra/control/run-tests-isolated.bash"
multi="${root}/test/infra/control/run-multi-group.bash"

rg -q '^[[:space:]]*gcov-11[[:space:]\\]*$' "${dockerfile}"
test "$(rg -c 'fastcov -b .* -g gcov-11' "${runner}")" -eq 1
test "$(rg -c 'fastcov -b .* -g gcov-11' "${multi}")" -eq 1
```

- [ ] **Step 2: Run the check and verify it fails**

Run:

```bash
bash test/infra/control/validate-coverage-gcov-toolchain.bash
```

Expected: nonzero exit because `gcov-11` is absent and neither conversion command selects it.

- [ ] **Step 3: Commit the failing-test addition**

```bash
git add test/infra/control/validate-coverage-gcov-toolchain.bash
git commit -m "test(ci): assert GCOV collector compatibility"
```

### Task 2: Use the compiler-matching GCOV for raw coverage conversion

**Files:**
- Modify: `test/infra/docker-base/Dockerfile:8-33`
- Modify: `test/infra/control/run-tests-isolated.bash:391-400`
- Modify: `test/infra/control/run-multi-group.bash:361-378`
- Test: `test/infra/control/validate-coverage-gcov-toolchain.bash`

**Interfaces:**
- Consumes: `gcov-11` supplied by the CI-base Docker image.
- Produces: `fastcov` LCOV conversion from GCC 11 `.gcda` data, or an immediate nonzero CI exit with an explicit missing-tool message.

- [ ] **Step 1: Install the matching reader in CI-base**

Add `gcov-11` to the `apt-get install` list in `test/infra/docker-base/Dockerfile`, adjacent to `lcov`:

```dockerfile
    lcov \\
    gcov-11 \\
    && pip3 install --break-system-packages fastcov \\
```

- [ ] **Step 2: Make standalone conversion fail clearly and use GCOV 11**

Immediately before the standalone `fastcov` invocation in the exit trap, add:

```bash
if ! command -v gcov-11 >/dev/null 2>&1; then
    echo ">>> ERROR: gcov-11 is required to decode GCC 11 coverage data" >&2
    exit 1
fi
```

Then change the command to:

```bash
fastcov -b -g gcov-11 -j$(nproc) -l \\
```

Keep the existing source exclusions and report path unchanged.

- [ ] **Step 3: Make multi-group conversion fail clearly and use GCOV 11**

Inside the per-group `docker run ... bash -c` block, replace the conditional fastcov wrapper with:

```bash
set -e
command -v gcov-11 >/dev/null 2>&1 || {
    echo ">>> ERROR: gcov-11 is required to decode GCC 11 coverage data" >&2
    exit 1
}
cd "${GCOV_DIR}"
fastcov -b -g gcov-11 -j4 -l \\
    -e /usr deps \\
    -d . -o "${GROUP_INFO}" >> "${COVERAGE_LOG}" 2>&1
```

Remove the outer warning-only fallback for that raw-data conversion command so the coverage workflow cannot continue after an empty per-group report.

- [ ] **Step 4: Run the regression check and verify it passes**

Run:

```bash
bash test/infra/control/validate-coverage-gcov-toolchain.bash
```

Expected: exit 0.

- [ ] **Step 5: Build and inspect the CI-base image**

Run:

```bash
docker build -t proxysql-ci-base:gcov11 test/infra/docker-base
docker run --rm proxysql-ci-base:gcov11 bash -lc 'gcov-11 --version && fastcov --help | grep -F -- "-g GCOV"'
```

Expected: GCOV 11 is available and fastcov supports selecting a GCOV executable.

- [ ] **Step 6: Commit the compatibility fix**

```bash
git add test/infra/docker-base/Dockerfile test/infra/control/run-tests-isolated.bash test/infra/control/run-multi-group.bash test/infra/control/validate-coverage-gcov-toolchain.bash
git commit -m "fix(ci): use matching GCOV for TAP coverage"
```

### Task 3: Prove end-to-end coverage with real FFTO traffic

**Files:**
- Test: existing `test/tap/tests/test_ffto_mysql-t.cpp`
- Test: generated `ci_infra_logs/<infra-id>/coverage-report/<infra-id>.info`

**Interfaces:**
- Consumes: the rebuilt `proxysql-ci-base:latest`, GCC 11 ProxySQL coverage binary, and isolated legacy MySQL infrastructure.
- Produces: a passing TAP test and nonzero LCOV lines for `lib/MySQLFFTO.cpp`.

- [ ] **Step 1: Rebuild/tag the fixed CI-base image for the isolated scripts**

```bash
docker build -t proxysql-ci-base:latest test/infra/docker-base
```

- [ ] **Step 2: Build the existing GCC 11 coverage binary and the one TAP executable**

```bash
WITHGCOV=1 PROXYSQL40=1 make ubuntu22-tap-genai-gcov
docker run --rm -v "$PWD:/opt/proxysql" proxysql/packaging:build-ubuntu22-v4.0.0 \\
  bash -lc 'cd /opt/proxysql/test/tap/tests && WITHGCOV=1 PROXYSQL40=1 PROXYSQL31=1 PROXYSQLFFTO=1 make test_ffto_mysql-t'
```

- [ ] **Step 3: Run only real FFTO TAP traffic under coverage**

```bash
export INFRA_ID=gcov11-ffto
export TAP_GROUP=legacy-g4
export INFRA_TYPE=infra-mysql57
export COVERAGE=1
test/infra/control/ensure-infras.bash
TEST_PY_TAP_INCL=test_ffto_mysql-t test/infra/control/run-tests-isolated.bash
```

Expected: `test_ffto_mysql-t` passes, including its fast-forward-session and query-digest assertions.

- [ ] **Step 4: Assert that LCOV records FFTO execution**

```bash
info="ci_infra_logs/${INFRA_ID}/coverage-report/${INFRA_ID}.info"
awk '/^SF:.*lib\/MySQLFFTO\.cpp$/{seen=1} seen && /^LH:/{print; exit}' "${info}"
test -s "${info}"
```

Expected: a nonzero `LH:` value for `lib/MySQLFFTO.cpp`.

- [ ] **Step 5: Tear down only the isolated test resources**

```bash
INFRA_ID="${INFRA_ID}" TAP_GROUP=legacy-g4 INFRA_TYPE=infra-mysql57 \\
  test/infra/control/destroy-infras.bash
```

- [ ] **Step 6: Commit any verification-only script changes, if created**

```bash
git status --short
```

Expected: no generated coverage artifacts or infrastructure logs are staged or committed.
