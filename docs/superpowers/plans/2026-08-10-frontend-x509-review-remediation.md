# Frontend X.509 PR Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the actionable lint, CodeRabbit, and SonarCloud findings on PR 6028 without changing the approved authentication semantics.

**Architecture:** Keep certificate evidence immutable for a physical frontend connection, but isolate ASN.1 URI extraction and policy subchecks into small helpers. Keep certificate generation in TAP code while replacing shell command construction with argument-vector process execution. Refactor only the large test flows and policy evaluator flagged on new code.

**Tech Stack:** C++17, OpenSSL X.509 APIs, nlohmann JSON, RE2, ProxySQL TAP, `wexecvp`, Python groups.json lint.

## Global Constraints

- `require_x509` production behavior remains compiled only under `PROXYSQL31` and therefore `PROXYSQL40`.
- Stable v3.0 must not recognize, log, or enforce `require_x509`.
- Certificate policy runs before pass-through allowlist, cache, metrics, or probing.
- `COM_CHANGE_USER` reuses immutable evidence from the original TLS handshake and never renegotiates TLS.
- The normal pass-through TAP plan remains 40; only its unavailable-trusted-fixture fallback changes from 11 skips to 10.
- Authentication failures exposed to clients remain generic error 1045.

---

### Task 1: Establish RED quality and regression baselines

**Files:**

- Modify: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Modify: `test/tap/tests/test_frontend_x509_passthrough-t.cpp`
- Inspect: `test/tap/groups/groups.json`

**Interfaces:**

- Consumes: existing certificate fixture and isolated TAP runner.
- Produces: failing coverage for first-SPIFFE-SAN selection and the trusted-fixture fallback assertion count.

- [ ] Add a SPIFFE certificate fixture containing two URI SANs and assert that the first SPIFFE URI is the identity used for authentication.
- [ ] Run the focused PROXYSQL31 TAP against the current implementation and record the expected failure caused by last-match overwrite.
- [ ] Run `python3 test/tap/groups/lint_groups_json.py` and record the expected unsorted-key failure.
- [ ] Exercise the pass-through test with trusted certificate signing unavailable and record the plan mismatch caused by 11 fallback skips.

### Task 2: Harden certificate evidence extraction and lifecycle

**Files:**

- Modify: `include/MySQL_Data_Stream.h`
- Modify: `lib/mysql_data_stream.cpp`
- Test: `test/tap/tests/test_frontend_x509_auth-t.cpp`

**Interfaces:**

- Produces: `reset_frontend_certificate_evidence()` and bounded first-match SPIFFE URI extraction from `ASN1_STRING`.

- [ ] Replace `strstr`/`strdup` over ASN.1 storage with `ASN1_STRING_get0_data`, `ASN1_STRING_length`, bounded prefix comparison, exact allocation/copy, and explicit NUL termination.
- [ ] Stop after the first matching SPIFFE URI and reject embedded-NUL URI values.
- [ ] Reset/free SAN and PROXYSQL31 evidence at data-stream initialization so any future stream reuse cannot retain prior-client evidence.
- [ ] Rebuild and rerun the focused X.509 TAP until the new first-SAN regression is GREEN.

### Task 3: Simplify policy evaluation and secure COM_CHANGE_USER cleanup

**Files:**

- Modify: `lib/MySQL_Protocol.cpp`
- Test: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Test: `test/tap/tests/reg_test_3504-change_user-t.cpp`

**Interfaces:**

- Produces: small `require_x509` and SPIFFE evaluation helpers used by `evaluate_frontend_certificate_policy`.

- [ ] Extract the `require_x509` type/evidence check without changing fail-closed results or diagnostics.
- [ ] Extract the context/type/regex SPIFFE check without changing exact/regex matching.
- [ ] Replace the new direct `free(password)` rejection cleanup with `cleanse_and_free_password(password)`; leave pre-existing packet-buffer ownership unchanged.
- [ ] Clean-build and run the X.509 and COM_CHANGE_USER TAPs in PROXYSQL31.

### Task 4: Remove unsafe test-fixture process and temporary-directory patterns

**Files:**

- Modify: `test/tap/tests/frontend_x509_test_utils.h`
- Modify: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Modify: `test/tap/tests/test_frontend_x509_passthrough-t.cpp`

**Interfaces:**

- Produces: non-copyable `temporary_certificate_directory` rooted below `REGULAR_INFRA_DATADIR`; `run_openssl(const std::vector<std::string>&)` using `wexecvp`.

- [ ] Delete copy and move construction/assignment for the owning temporary-directory class and rename its header guard to a non-reserved identifier.
- [ ] Build the `mkdtemp` template beneath the isolated infra data directory passed by the callers.
- [ ] Replace shell quoting and `system()` with explicit OpenSSL argument vectors passed to `wexecvp`, capturing stdout/stderr for diagnostics.
- [ ] Rebuild and run both X.509 TAP binaries to prove certificate generation and cleanup remain functional.

### Task 5: Resolve TAP quality findings without changing behavior

**Files:**

- Modify: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Modify: `test/tap/tests/test_frontend_x509_passthrough-t.cpp`

**Interfaces:**

- Produces: focused setup/behavior/cleanup helper functions; explicit lambda captures.

- [ ] Split each flagged `main()` into setup, behavior-matrix, and cleanup helpers while retaining literal TAP expectations and ordering.
- [ ] Explicitly capture only the admin connection and command-line object in the two pass-through lambdas.
- [ ] Change the trusted-fixture fallback from 11 skips to 10 and keep `plan(40)`.
- [ ] Rerun normal and unavailable-trusted-fixture paths and verify both emit exactly 40 TAP results.

### Task 6: Fix lint and documentation review findings

**Files:**

- Modify: `test/tap/groups/groups.json`
- Modify: `docs/superpowers/plans/2026-08-10-frontend-x509-authentication.md`
- Modify: `docs/superpowers/specs/2026-08-10-frontend-x509-proxysql31-gating-design.md` if its lint output requires it.

**Interfaces:**

- Produces: sorted group keys and valid fenced examples.

- [ ] Run the groups lint fixer, inspect that it only sorts keys, then rerun lint.
- [ ] Indent fenced preprocessor examples consistently within their list items and add any missing language tags.
- [ ] Run the repository Markdown lint command used by CI or the closest locally available equivalent.

### Task 7: Full verification and GitHub handoff

**Files:**

- Verify all changed files.

**Interfaces:**

- Produces: fresh Stable and PROXYSQL31 build/test evidence suitable for pushing to PR 6028.

- [ ] Run `git diff --check`, groups lint, focused test compilation, and static checks for banned `system()`/unbounded ASN.1 operations.
- [ ] Clean-build Stable DEBUG, run the tier-gate and COM_CHANGE_USER regressions, and verify feature symbols remain absent.
- [ ] Clean-build PROXYSQL31 DEBUG and run frontend X.509, X.509/pass-through, COM_CHANGE_USER, and tier-gate TAPs.
- [ ] Commit the scoped remediation, push only after verification, and rerun/recheck PR checks; rerun the unrelated Aurora job without modifying cluster code.
