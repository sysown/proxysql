# PR 6151 TAP Disk-Safety and Conflict-Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove disk-configuration mutation from PR 6151's TAP coverage and merge the current `v3.0` base without losing either side's changes.

**Architecture:** Keep all feature verification in configuration-startup, runtime-variable, listener, and cluster paths. Add a narrow lint contract preventing the new interface TAP from executing disk save or restore commands, then merge `origin/v3.0` with a merge commit and resolve the four overlapping files semantically.

**Tech Stack:** Bash contract tests, C++ TAP, Markdown, Git, GitHub CLI.

---

## Task 1: Define and satisfy the disk-safety contract

**Files:**

- Create: `test/infra/control/validate-interface-tap-disk-safety.bash`
- Modify: `test/infra/control/run-ci-lint.bash`
- Modify: `test/tap/tests/mysql-server_version_by_interface-t.cpp`

- [ ] **Step 1: Add a validator rejecting disk save and restore commands in the interface TAP**

The validator must inspect `test/tap/tests/mysql-server_version_by_interface-t.cpp` case-insensitively and fail if it finds `SAVE ... TO DISK` or `LOAD ... FROM DISK`.

- [ ] **Step 2: Run the validator and verify RED**

Run: `test/infra/control/validate-interface-tap-disk-safety.bash`

Expected: non-zero with the existing `SAVE MYSQL VARIABLES TO DISK` and `LOAD MYSQL VARIABLES FROM DISK` lines reported.

- [ ] **Step 3: Remove disk mutation while retaining runtime fallback coverage**

Delete the save, disk-table assertion, disk restore, and restored-session assertions. Keep the runtime update to `{}`, `LOAD MYSQL VARIABLES TO RUNTIME`, and fallback handshake assertion. Remove the now-unused `admin_variable_equals` helper and reduce the TAP plans by four assertions.

- [ ] **Step 4: Wire the validator into the canonical lint runner and verify GREEN**

Run: `test/infra/control/validate-interface-tap-disk-safety.bash`

Expected: `interface TAP disk-safety contract: OK` and exit zero.

- [ ] **Step 5: Commit the test remediation**

Commit message: `test: forbid disk writes in interface version TAP`

## Task 2: Correct the feature documentation

**Files:**

- Modify: `docs/superpowers/specs/2026-08-30-mysql-server-version-by-interface-design.md`
- Modify: `docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md`

- [ ] **Step 1: Remove disk-persistence claims**

State that the normal variable getter supports established persistence machinery, but this feature TAP intentionally does not execute disk save or restore commands. Rewrite Task 6 as runtime reload and ordinary cluster synchronization coverage.

- [ ] **Step 2: Scan PR additions for forbidden executable commands**

Run a case-insensitive scan over added TAP source lines. Documentation may describe the prohibition; executable TAP code must contain no disk save or restore query.

- [ ] **Step 3: Commit the documentation correction**

Commit message: `docs: remove TAP disk persistence coverage`

## Task 3: Merge current v3.0 and resolve conflicts

**Files:**

- Modify: `.github/workflows/CI-lint-groups-json.yml`
- Modify: `lib/MySQL_Session.cpp`
- Modify: `test/tap/groups/groups.json`
- Modify: `test/tap/tests/unit/Makefile`

- [ ] **Step 1: Merge the fetched base**

Run: `git merge --no-ff origin/v3.0`

Expected: conflicts only in the four known files.

- [ ] **Step 2: Resolve semantically**

Preserve current base workflow/session/test registrations and PR 6151's centralized lint runner, per-interface version selection, TAP group entry, and unit targets. Keep JSON entries sorted.

- [ ] **Step 3: Verify the index has no unresolved paths and commit the merge**

Run: `git diff --name-only --diff-filter=U`

Expected: no output.

## Task 4: Verify and publish

**Files:** None.

- [ ] **Step 1: Run focused builds and tests**

Build and run the per-interface parser unit test, protocol unit test for stable and `PROXYSQL31`, and the self-launched per-interface TAP under `PROXYSQL31`.

- [ ] **Step 2: Run repository checks**

Run the canonical CI lint runner and `git diff --check`.

- [ ] **Step 3: Verify conflict and disk-safety state**

Confirm no unmerged paths, no merge conflict against `origin/v3.0`, and no forbidden executable disk commands in PR-added TAP code.

- [ ] **Step 4: Push normally**

Run: `git push origin feature/mysql-server-version-by-interface`

Expected: the pre-push lint hook passes and the PR becomes mergeable without force-pushing.
