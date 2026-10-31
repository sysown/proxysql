# PR 6151 Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every actionable review finding on PR 6151 while preserving the approved per-interface version contract.

**Architecture:** Compute and validate the initial-handshake payload in an unnarrowed type before populating MySQL's 24-bit header. Make test fixtures own temporary resources with RAII, and strengthen the shared lint runner so local pushes and CI execute the same behavioral contracts with explicit prerequisites.

**Tech Stack:** C++17, MySQL wire protocol, TAP, Bash, GitHub Actions, Markdownlint

---

## Task 1: Reject unrepresentable initial handshakes

**Files:**

- Modify: `test/tap/tests/unit/protocol_unit-t.cpp`
- Modify: `lib/MySQL_Protocol.cpp`

- [ ] **Step 1: Add a scalar-path regression test**

  Add `test_initial_handshake_rejects_oversized_payload()`. Set
  `mysql_thread___server_version` to a string of `0xFFFFFF` bytes, configure a
  `MySQL_Protocol` with a null stream pointer, and assert that
  `generate_pkt_initial_handshake()` returns false before allocating or
  dereferencing the stream. Restore the thread-local globals afterward and add
  the assertion to both TAP plan counts.

- [ ] **Step 2: Run the regression test and verify RED**

  Run:

  ```bash
  make -C test/tap/tests/unit protocol_unit-t PROXYSQL31=1
  ./test/tap/tests/unit/protocol_unit-t
  ```

  Expected: the new test process fails or crashes because the payload length is
  narrowed to 24 bits before the oversized version is copied.

- [ ] **Step 3: Validate before narrowing**

  In `generate_pkt_initial_handshake()`, measure the selected version and auth
  plugin once. Compute the fixed payload overhead as `size_t`, reject when the
  version length exceeds the remaining space below `0xFFFFFF`, and only then
  assign the checked result to `myhdr.pkt_length`. Log an actionable error and
  return false without allocating a packet.

- [ ] **Step 4: Verify GREEN on both feature tiers**

  Run:

  ```bash
  make -C test/tap/tests/unit protocol_unit-t PROXYSQL31=1
  ./test/tap/tests/unit/protocol_unit-t
  make -C test/tap/tests/unit protocol_unit-t PROXYSQL31=
  ./test/tap/tests/unit/protocol_unit-t
  ```

  Expected: all TAP assertions pass in both builds.

## Task 2: Give test resources deterministic ownership

**Files:**

- Modify: `test/tap/tests/mysql-server_version_by_interface-t.cpp`
- Modify: `test/tap/tests/reg_test_4300-dollar_quote_check-t.cpp`
- Modify: `test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp`

- [ ] **Step 1: Confirm the static-analysis failures**

  Verify the reported patterns still exist:

  ```bash
  rg -n 'proxysql-svbi-|mysql_real_connect|/tmp/proxysql\.sock' \
    test/tap/tests/mysql-server_version_by_interface-t.cpp \
    test/tap/tests/reg_test_4300-dollar_quote_check-t.cpp \
    test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp
  ```

  Expected: predictable runtime-directory construction, failed-connect return
  paths, and test-only `/tmp` map keys are present.

- [ ] **Step 2: Add secure RAII runtime-directory ownership**

  Add a local non-copyable `TemporaryRuntimeDirectory` that calls `mkdtemp()`
  with `proxysql-svbi-XXXXXX`, exposes the resulting path, and removes that exact
  tree with the non-throwing `std::filesystem::remove_all(path, error_code)` in
  its destructor. Construct it before `prepare_runtime()`, stop deleting and
  recreating the directory inside `prepare_runtime()`, and remove manual final
  cleanup.

- [ ] **Step 3: Close failed MySQL handles**

  Guard every `mysql_init()` result touched in the edited dollar-quote test.
  When `mysql_real_connect()` fails, capture/print the error, call
  `mysql_close()`, and then return failure.

- [ ] **Step 4: Remove misleading temporary-path tokens**

  Replace the two `/tmp/proxysql.sock` strings used only as parser/resolver map
  keys with `/run/proxysql.sock`. Keep the exact-match assertions unchanged.

- [ ] **Step 5: Build the affected TAP tests**

  Run:

  ```bash
  make -C test/tap/tests/unit mysql_server_version_by_interface_unit-t PROXYSQL31=1
  ./test/tap/tests/unit/mysql_server_version_by_interface_unit-t
  make -C test/tap/tests mysql-server_version_by_interface-t reg_test_4300-dollar_quote_check-t PROXYSQL31=1
  ```

  Expected: both builds succeed and the unit test passes.

## Task 3: Strengthen the shared lint contract

**Files:**

- Modify: `test/infra/control/test-pre-push-lint-hook.bash`
- Modify: `test/infra/control/run-ci-lint.bash`
- Modify: `test/infra/control/validate-coverage-gcov-toolchain.bash`
- Modify: `.githooks/README.md`
- Modify: `.github/workflows/CI-lint-groups-json.yml`

- [ ] **Step 1: Extend the pre-push contract test and verify RED**

  Add assertions that the canonical runner invokes this contract test and emits
  a clear `envsubst`/gettext installation message when run with a PATH that has
  `dirname` but no `envsubst`. Canonicalize the fixture expectation with
  `pwd -P`.

  Run:

  ```bash
  test/infra/control/test-pre-push-lint-hook.bash
  ```

  Expected: failure because the runner neither checks `envsubst` nor invokes the
  hook contract.

- [ ] **Step 2: Add the prerequisite and contract invocation**

  At the top of the lint runner, fail before any Python checks when `envsubst`
  is unavailable and name `gettext`/`gettext-base` in the error. Add the hook
  contract as a `run_check` entry. The contract's nested runner execution exits
  during prerequisite checking, so it does not recurse.

- [ ] **Step 3: Anchor coverage-toolchain wiring checks**

  Require a workflow line whose YAML key is `run:` and whose command is the
  shared runner. Require a real `run_check` continuation naming
  `validate-coverage-gcov-toolchain.bash`; comments and arbitrary strings must
  no longer satisfy either check.

- [ ] **Step 4: Document and harden CI permissions**

  Document that local execution requires `envsubst` from `gettext` on macOS or
  `gettext-base` on Debian/Ubuntu. Add `permissions: contents: read` to the lint
  workflow.

- [ ] **Step 5: Verify the shell contracts**

  Run:

  ```bash
  test/infra/control/test-pre-push-lint-hook.bash
  test/infra/control/validate-coverage-gcov-toolchain.bash
  ```

  Expected: both scripts exit successfully.

## Task 4: Correct reviewed documentation

**Files:**

- Modify: `docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md`

- [ ] **Step 1: Fix Markdown hierarchy and socket-version text**

  Change every task heading directly below the document H1 from `### Task` to
  `## Task`. Change the planned socket mapping from
  `8.4.1-interface-socket` to the implemented `8.1.4-interface-socket`.

- [ ] **Step 2: Verify the documentation contract**

  Run:

  ```bash
  ! rg '^### Task' docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md
  rg -n 'proxysql\.sock -> 8\.1\.4-interface-socket' docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md
  ```

  Expected: no invalid task headings and one corrected socket mapping.

## Task 5: Full verification and delivery

**Files:**

- Verify all modified files

- [ ] **Step 1: Run formatting and diff checks**

  Run:

  ```bash
  git diff --check
  git status --short
  ```

  Expected: no whitespace errors; only intended files are modified.

- [ ] **Step 2: Run the complete pre-push lint suite**

  Run:

  ```bash
  test/infra/control/run-ci-lint.bash
  ```

  Expected: `CI lint suite: OK`.

- [ ] **Step 3: Re-run focused feature tests**

  Run the protocol and catalog unit binaries plus the self-launched
  `mysql-server_version_by_interface-t` through the repository's isolated TAP
  harness when the ProxySQL binary is available.

- [ ] **Step 4: Commit and push**

  Commit the review remediations, push the feature branch through the pre-push
  gate, and inspect PR checks and review threads. Report any non-actionable
  analyzer findings separately with their technical reason.
