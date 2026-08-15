# Final GCOV Dump Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve daemon-side coverage from every TAP test by dumping ProxySQL's in-memory GCOV counters exactly once after each isolated TAP group.

**Architecture:** `run-tests-isolated.bash` already has an EXIT trap that runs after the TAP suite and before ProxySQL is stopped. The trap will issue `PROXYSQL GCOV DUMP`, then decode the resulting GCDA files. The obsolete per-TAP-test dump in `proxysql-tester.py` will be removed because GCC 13 ignores later dumps unless counters are reset. Deliberate dump/decode/reset stages for non-TAP modes remain unchanged.

**Tech Stack:** Bash, Python TAP harness, GCC 13 GCOV, fastcov/LCOV.

## Global Constraints

- Generate real TAP traffic without changing functional tests.
- Dump the long-running ProxySQL process once per isolated TAP group.
- Collect coverage on successful, failed, and timed-out test runs.
- Preserve the original test exit status unless coverage collection itself is the only failure.

---

### Task 1: Add the daemon-dump regression validator

**Files:**
- Create: `test/infra/control/test-final-gcov-dump.bash`
- Create: `test/infra/control/dump-proxysql-gcov.bash`
- Create: `test/infra/control/coverage-exit-status.bash`
- Create: `test/infra/control/fixtures/record-mysql-argv.bash`
- Modify: `test/infra/control/validate-coverage-gcov-toolchain.bash`
- Modify: `.github/workflows/CI-lint-groups-json.yml`

- [x] Write a validator requiring the final dump to precede `fastcov`, forbidding per-test dumps, bounding the admin call, and requiring dump failures to propagate.
- [x] Run it and confirm that the current pipeline fails the assertions.
- [x] Wire the validator into the existing lightweight CI lint workflow.

### Task 2: Dump daemon counters once at group exit

**Files:**
- Modify: `test/infra/control/run-tests-isolated.bash`
- Modify: `test/scripts/bin/proxysql-tester.py`

- [x] Remove the dump after each TAP executable.
- [x] Issue one admin dump in the coverage EXIT trap before GCDA decoding.
- [x] Record dump failure without skipping the remaining diagnostic collection.
- [x] Return the test failure when tests failed; otherwise return the coverage failure.
- [x] Run the validator until it passes.

### Task 3: Verify and publish

**Files:**
- Verify all modified files.

- [x] Run the coverage validators, Bash syntax checks, Python compilation, and `git diff --check`.
- [x] Review the final diff against `origin/v3.0` for unrelated changes.
- [ ] Commit and push the focused fix to PR #6062.
- [ ] Inspect the resulting GitHub Actions coverage run and compare daemon-side line coverage with the previous upload.
