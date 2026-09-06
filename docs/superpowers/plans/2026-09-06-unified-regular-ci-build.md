# Unified Regular CI Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the overlapping regular TAP builders with one Ubuntu 24 full-plugin build and one complete handoff consumed by group-based CI workflows.

**Architecture:** `GH-Actions` first gains an additive `ubuntu24-tap-full` producer and generic full-handoff consumer while legacy variants remain available. `v3.0` then registers `mysqlx-g1` and converts thin callers. A final `GH-Actions` cleanup removes old regular variants only after real consumer runs prove the full handoff works. Sanitizer and platform-specific profiles are out of scope.

**Tech Stack:** GitHub reusable workflows, zstd workflow artifacts, Bash, Python group linting, TAP isolated infrastructure.

**Spec:** `docs/superpowers/specs/2026-09-06-unified-regular-ci-build-design.md`

## Global Constraints

- The regular producer builds every in-tree plugin and every TAP/unit binary exactly once with `PROXYSQL40=1`.
- The handoff is complete and generic; no producer or consumer may retain/delete/enumerate test binaries by plugin filename family.
- Consumers select only `tap_group` and infrastructure; they do not compile ProxySQL.
- Keep ASAN/gcov, TSAN, clang, package, third-party-language, and OS-specific build profiles separate.
- Reusable workflow changes target `GH-Actions`; callers and `groups.json` changes target `v3.0`.
- Every commit has a detailed body explaining behavior, compatibility, and verification.

---

### Task 1: Add full-handoff contract checks on `GH-Actions`

**Files:**
- Create: `test/infra/control/test-ci-builds-full-handoff.bash`
- Modify: `test/infra/control/run-ci-lint.bash`
- Modify: `.github/workflows/ci-builds.yml`

**Interfaces:**
- Consumes: `ci-builds.yml` matrix and artifact upload naming.
- Produces: a CI lint that proves one `ubuntu24-tap-full` producer publishes one complete handoff and has no plugin-specific test pruning.

- [ ] **Step 1: Write the failing contract test**

```bash
#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workflow="${root}/.github/workflows/ci-builds.yml"

grep -Fq "dist: 'ubuntu24'" "${workflow}"
grep -Fq "type: '-tap-full'" "${workflow}"
grep -Fq 'ci-builds-handoff-${{ env.SHA }}-ubuntu24-tap-full' "${workflow}"
! grep -Fq "! -name 'mysqlx_*_unit-t'" "${workflow}"
! grep -Fq 'SKIP_GENAI_UNIT_TESTS=1' "${workflow}"
```

- [ ] **Step 2: Run the contract test and verify RED**

Run: `test/infra/control/test-ci-builds-full-handoff.bash`

Expected: non-zero because `ubuntu24-tap-full` and its complete handoff do not exist yet.

- [ ] **Step 3: Implement only the generic builder contract**

Add this full producer alongside the three existing regular matrix legs:

```yaml
- dist: 'ubuntu24'
  type: '-tap-full'
```

Make the new build command set `PROXYSQL40=1` without
`SKIP_GENAI_UNIT_TESTS`. Do not remove or alter a legacy leg in this task.
Replace plugin-specific unit deletion with a generic executable check:

```bash
test "${TAP_COUNT}" -gt 0
test "${UNIT_COUNT}" -gt 0
```

Pack `src/`, `test/`, required plugin/runtime files, and optional coverage metadata
into one `full-handoff.tar.zst`; upload it as
`ci-builds-handoff-${SHA}-ubuntu24-tap-full`.

- [ ] **Step 4: Wire the check into CI lint and verify GREEN**

Add this exact invocation to `test/infra/control/run-ci-lint.bash`:

```bash
run_check "Check complete regular CI build handoff" \
  test/infra/control/test-ci-builds-full-handoff.bash
```

Run:

```bash
test/infra/control/test-ci-builds-full-handoff.bash
test/infra/control/run-ci-lint.bash
```

Expected: both exit 0.

- [ ] **Step 5: Commit the additive producer**

```bash
git add .github/workflows/ci-builds.yml test/infra/control/test-ci-builds-full-handoff.bash test/infra/control/run-ci-lint.bash
git commit -m "ci(builds): add complete regular test handoff" \
  -m "Add the Ubuntu 24 full-plugin producer and a single generic artifact containing all runtime, TAP, unit, and plugin outputs. Keep legacy variants during consumer migration."
```

### Task 2: Add one generic full-handoff unit-group consumer on `GH-Actions`

**Files:**
- Create: `.github/workflows/ci-unit-group.yml`

**Interfaces:**
- Consumes: `trigger`, `tap_group`, and `ci-builds-handoff-${SHA}-ubuntu24-tap-full`.
- Produces: a reusable workflow that downloads and verifies the complete handoff, derives unit binaries exclusively from `groups.json`, and executes them in the Ubuntu 24 build image required by their ABI/runtime dependencies.

- [ ] **Step 1: Write the failing workflow-contract test**

```bash
grep -Fq 'tap_group:' .github/workflows/ci-unit-group.yml
grep -Fq 'ci-builds-handoff-${SHA}-ubuntu24-tap-full' .github/workflows/ci-unit-group.yml
grep -Fq 'groups.json' .github/workflows/ci-unit-group.yml
! grep -Eq 'mysqlx_\*|plugin_\*|genai_\*' .github/workflows/ci-unit-group.yml
```

- [ ] **Step 2: Run the contract test and verify RED**

Run: the workflow-contract check on the `v3.0` branch after it fetches this
`GH-Actions` candidate.

Expected: non-zero because the reusable consumer does not exist.

- [ ] **Step 3: Implement the reusable consumer**

Define required inputs:

```yaml
trigger: { type: string }
tap_group: { type: string, required: true }
```

Resolve only `ci-builds-handoff-${SHA}-ubuntu24-tap-full`, download it through
the triggering CI-builds run artifact list with the existing bounded retry
pattern, and unpack it into `proxysql/`. Parse `groups.json` for `tap_group`,
require every selected test to be an executable under `test/tap/tests/unit/`,
and fail if the group selects nothing. Run that list in
`proxysql/packaging:build-ubuntu24-v4.0.0`; this preserves the protobuf and
other build-image runtime contract without compiling. Validate both:

```bash
test -x test/tap/tests/unit/plugin_manager_unit-t
test -x src/proxysql
```

The consumer has no infrastructure lifecycle because only unit groups are
accepted; integration groups continue to use their existing infrastructure
workflows until Task 4 converts them.

- [ ] **Step 4: Run contract/lint checks and verify GREEN**

Run:

```bash
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/ci-unit-group.yml"))'
```

Expected: both exit 0.

- [ ] **Step 5: Commit the generic consumer**

```bash
git add .github/workflows/ci-unit-group.yml
git commit -m "ci: add generic full-handoff unit consumer" \
  -m "Provide one reusable unit-group runner that restores the complete regular build artifact and selects tests exclusively through groups.json."
```

### Task 3: Register `mysqlx-g1` and add its thin caller on `v3.0`

**Files:**
- Modify: `test/tap/groups/groups.json`
- Create: `.github/workflows/CI-mysqlx-g1.yml`
- Create: `test/tap/groups/test_mysqlx_group_registration.py`
- Modify: `.github/workflows/CI-mysqlx.yml`

**Interfaces:**
- Consumes: `ci-unit-group.yml@GH-Actions`, `mysqlx-g1`, `mysqlx-e2e-g1`, and `mysqlx-soak-g1`.
- Produces: group-based MySQLX unit execution; E2E/soak retain their infrastructure-specific runners until Task 4 converts their handoff.

- [ ] **Step 1: Write the failing registration test**

```python
def test_mysqlx_and_plugin_units_have_mysqlx_g1():
    groups = json.load(open(GROUPS))
    selected = {name for name, tags in groups.items() if "mysqlx-g1" in tags}
    assert "mysqlx_connection_unit-t" in selected
    assert "plugin_manager_unit-t" in selected
    assert "test_mysqlx_e2e_handshake-t" not in selected
```

- [ ] **Step 2: Run it and verify RED**

Run: `python3 test/tap/groups/test_mysqlx_group_registration.py`

Expected: failure because `mysqlx-g1` is absent.

- [ ] **Step 3: Add group membership and the caller**

Add `mysqlx-g1` to every `mysqlx_*_unit-t` and `plugin_*_unit-t` currently
executed by the bespoke `CI-mysqlx` unit loop, preserving
`@proxysql_min_version` metadata. Do not remove any existing group membership.

Create `CI-mysqlx-g1.yml` following `CI-ai-g1.yml`, but call:

```yaml
uses: sysown/proxysql/.github/workflows/ci-unit-group.yml@GH-Actions
with:
  trigger: ${{ toJson(github) }}
  tap_group: mysqlx-g1
```

Leave `CI-mysqlx.yml`'s E2E and soak lifecycle unchanged in this task; Task 4
moves their handoff resolver while retaining their explicit infrastructure.

- [ ] **Step 4: Run registration and group checks**

Run:

```bash
python3 test/tap/groups/test_mysqlx_group_registration.py
python3 test/tap/groups/lint_groups_json.py
python3 test/tap/groups/check_groups.py --source
python3 test/tap/groups/lint_group_coverage.py --strict
```

Expected: all exit 0; no new missing-workflow group.

- [ ] **Step 5: Commit the MySQLX migration**

```bash
git add test/tap/groups/groups.json test/tap/groups/test_mysqlx_group_registration.py .github/workflows/CI-mysqlx-g1.yml .github/workflows/CI-mysqlx.yml
git commit -m "ci(mysqlx): run unit coverage through mysqlx-g1" \
  -m "Register MySQLX and plugin chassis units in mysqlx-g1 and replace bespoke filename loops with the generic full-handoff group consumer. Preserve E2E and soak infrastructure groups."
```

### Task 4: Convert regular callers to the full handoff and prove it in CI

**Files:**
- Modify: `.github/workflows/ci-ai-gcov.yml`
- Modify: `.github/workflows/ci-mysqlx.yml`
- Modify: relevant `ci-*.yml` consumers that restore `ubuntu22-tap` or `ubuntu24-tap-genai-gcov`
- Modify: `test/infra/control/test-ci-builds-full-handoff.bash`

**Interfaces:**
- Consumes: the complete full handoff and generic consumer.
- Produces: no enabled regular consumer requests a retired regular variant.

- [ ] **Step 1: Extend the contract test to fail on legacy enabled consumers**

```bash
for workflow in .github/workflows/ci-*.yml; do
  grep -Eq 'ubuntu22-tap|ubuntu22-tap-mysqlx|ubuntu24-tap-genai-gcov' "$workflow" && exit 1 || true
done
```

Scope the assertion only to enabled regular consumer paths; leave ASAN/TSAN
and other intentionally distinct profiles out of the scan.

- [ ] **Step 2: Run it and verify RED**

Run: `test/infra/control/test-ci-builds-full-handoff.bash`

Expected: failure naming current legacy consumers.

- [ ] **Step 3: Switch consumers**

Change each regular reusable consumer to resolve only
`ubuntu24-tap-full`. Replace repeated artifact-resolution code with the generic
consumer where test behavior is standard; retain coverage upload and special
infrastructure steps only where required. Do not add test-family filenames to
the build or consumer workflow.

- [ ] **Step 4: Verify real workflow runs**

Trigger or observe one `CI-builds` run for the branch, then require successful
check runs for:

```text
one non-plugin regular TAP group
CI-ai-g1
CI-mysqlx-g1
CI-mysqlx E2E
CI-mysqlx soak
```

Record each run URL, artifact size, producer elapsed time, consumer elapsed
time, and whether any consumer compiled ProxySQL.

- [ ] **Step 5: Commit consumer conversion**

```bash
git add .github/workflows test/infra/control/test-ci-builds-full-handoff.bash
git commit -m "ci: consume one regular full build handoff" \
  -m "Move enabled regular TAP consumers to the Ubuntu 24 complete artifact. Consumers select groups and infrastructure only; they never rebuild ProxySQL or enumerate plugin binaries."
```

### Task 5: Retire obsolete regular build variants after proof

**Files:**
- Modify: `.github/workflows/ci-builds.yml`
- Modify: `.github/workflows/CI-builds.yml`
- Modify: `test/infra/control/test-ci-builds-full-handoff.bash`
- Modify: documentation that names retired regular variants

**Interfaces:**
- Consumes: successful Task 4 workflow evidence.
- Produces: CI-builds has exactly one regular TAP matrix leg and no enabled
  third-party workflow depends on `debian12-dbg`.

- [ ] **Step 1: Make retirement contract assertions fail first**

```bash
! grep -Fq "dist: 'ubuntu22'" .github/workflows/ci-builds.yml
! grep -Fq "type: '-tap-mysqlx'" .github/workflows/ci-builds.yml
! grep -Fq "dist: 'debian12'" .github/workflows/ci-builds.yml
```

- [ ] **Step 2: Run the assertions and verify RED**

Run: `test/infra/control/test-ci-builds-full-handoff.bash`

Expected: failure while legacy matrix legs remain.

- [ ] **Step 3: Remove only proven-unused variants**

Remove `ubuntu22-tap`, `ubuntu22-tap-mysqlx`, and `debian12-dbg` from the
regular matrix. Before deleting Debian, verify every `CI-3p-*` workflow is
disabled or has been converted to the full handoff. Preserve manually
dispatched or platform-specific builders not covered by the design.

- [ ] **Step 4: Run final static and real-CI verification**

Run:

```bash
test/infra/control/test-ci-builds-full-handoff.bash
test/infra/control/run-ci-lint.bash
python3 test/tap/groups/lint_groups_json.py
python3 test/tap/groups/check_groups.py --source
python3 test/tap/groups/lint_group_coverage.py --strict
git diff --check
```

Then require a final successful producer and the Task 4 consumer set.

- [ ] **Step 5: Commit retirement and record measurements**

```bash
git add .github/workflows test/infra/control docs
git commit -m "ci(builds): retire duplicate regular TAP builders" \
  -m "Remove the Ubuntu 22 general/MySQLX and Debian debug regular matrix legs after all enabled consumers proved they run from the single Ubuntu 24 full handoff. Record observed build and compressed artifact measurements."
```

## Plan Self-Review

- **Spec coverage:** Tasks 1–2 establish the generic full artifact and group
  consumer; Task 3 provides `mysqlx-g1`; Task 4 migrates all regular consumers;
  Task 5 retires the old matrix only after CI evidence. Separate profiles remain
  explicitly out of scope.
- **No placeholders:** every task names files, commands, expected RED/GREEN
  conditions, and commit scope.
- **Interface consistency:** the producer artifact is consistently named
  `ci-builds-handoff-${SHA}-ubuntu24-tap-full`; consumers consistently require
  `trigger`, `tap_group`, and `infra_id`.
