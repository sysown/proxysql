# MySQL Transaction Error Fixes Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Preserve transaction routing after statement errors and reject invalid SET TRANSACTION on the correct statement without losing transactions.
**Architecture:** Reuse a small transaction-persistence updater on both query completion paths. Validate next-transaction characteristics before committing tracked state and preserve the backend on recoverable 1568 errors.
**Tech Stack:** C++17, MySQL C API, existing TAP and isolated infrastructure.
**Spec:** docs/superpowers/specs/2026-11-10-mysql-transaction-errors-design.md

## Global Constraints

- Preserve #6481's uncertainty latch and autocommit defaults.
- Apply MySQL correctness fixes on all tiers; no PostgreSQL changes.
- Keep SESSION/LOCAL SETs valid, with no permanent hostgroup lock.
- Use existing isolated test infrastructure; no manually started containers.

## Review Focus

- Prepared-statement cleanup must not clear unknown transaction state.
- autocommit=0 without an actual transaction must permit SET TRANSACTION.
- Uncertainty after an unrelated error must use backend validation.
- Both list characteristics must remain unchanged after rejection.
- COMMIT/ROLLBACK must reach the original backend and release routing persistence.

### Task 1: Regression coverage

**Files:** create test/tap/tests/reg_test_6611_6612_transaction_errors-t.cpp; register test/tap/groups/groups.json.
**Interfaces:** ordinary C API operations and PROXYSQL INTERNAL SESSION observations; no production-only test hooks.
- [x] Write end-to-end checks for both issues, prepared/text DML, SET forms/scopes, uncertain/idle states and actual data durability.
- [x] Build and run against unfixed ProxySQL; observe expected routing, error timing and data assertions fail.

### Task 2: Implement and verify

**Files:** lib/MySQL_Session.cpp, include/MySQL_Session.h (only if a shared helper needs declaration).
**Interfaces:** existing IsActiveTransaction(), backend server_status, SQL_NEXT_* tracked values and request cleanup.
- [x] Share persistence updates on success and error without recomputing the uncertainty latch.
- [x] Reject unscoped SETs before mutation in known transactions; preserve the original backend for uncertain SET validation and recoverable 1568.
- [x] Build debug core with the normal top-level build flags.
- [x] Run new regressions and existing reg_test_6420_parsersql_set_transaction-t, reg_test_6469_set_transaction_characteristics-t and mysql-set_transaction-t where available.
- [x] Review the diff and cleanup test state. Commit production changes separately from tests; leave branch for user review.

## Verification results

- Baseline regression: expected routing, delayed-error and lost-data assertions failed before production changes.
- Initial fix: 179/179 protocol assertions passed.
- Stale IN_TRANS after backend rollback: four added cases failed before the uncertainty guard correction.
- DO/constant SELECT pooling: eight added assertions failed before retaining pending characteristics across nontransactional statements.
- Final debug build: passed with `make PROXYSQL31=1 DEPS_PATH=/data/rene/development/proxysql3/proxysql/deps -o build_deps_debug_default debug -j4` (existing dependency libraries used read-only; core built in this worktree).
- Final protocol suite: mysql-set_transaction-t (48), reg_test_6420_parsersql_set_transaction-t (20), reg_test_6469_set_transaction_characteristics-t (37), and reg_test_6611_6612_transaction_errors-t (206): 311/311 assertions passed through run-tests-isolated.bash's host execution path against a private native debug proxy and existing MySQL 8.4.8 backends. Parser 0/1 and SET algorithms 2/3 covered.
- Local test linking required libstdc++ ahead of the debug core archive under GCC 15. Existing #6469 fixture needed session sql_generate_invisible_primary_key=ON on Group Replication; no repository fixture or server-global setting changed.
- TAP lint could not run because clang-tidy is unavailable. git diff --check passed.
- OpenCode/DeepSeek performed a bounded read-only source review. The author reviewed the final hold-consumption changes and resolved the unverified suspicions against source and protocol evidence.
- Test-specific credentials, proxy data, temporary schemas/users and test objects were removed. Branch is retained for review; no merge or push requested.
