# Auth Methods RSA Version Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `test_auth_methods-t` select the correct RSA full-authentication expectations from the runtime ProxySQL version boundary at 3.1.

**Architecture:** Read and parse the ProxySQL Admin `SELECT @@version` result once, then pass the derived RSA capability through the existing authentication expectation functions. Keep the legacy failure oracle below 3.1 and recognize the RSA packet exchange at or above 3.1.

**Tech Stack:** C++11, MariaDB/MySQL C API, TAP test helpers.

## Global Constraints

- ProxySQL versions 3.1 and newer support non-TLS `caching_sha2_password` RSA full authentication.
- ProxySQL versions below 3.1 retain the legacy expected-failure behavior.
- The runtime ProxySQL version, not the TAP binary's compile flags, determines the expectation.
- Do not push the branch without explicit user approval.

---

### Task 1: Runtime version capability and authentication oracle

**Files:**
- Modify: `test/tap/tests/test_auth_methods-t.cpp`

**Interfaces:**
- Produces: `parse_proxysql_version(const std::string&, int&, int&) -> bool`.
- Produces: `supports_caching_sha2_rsa(int, int) -> bool`.
- Consumes: ProxySQL Admin `SELECT @@version` result and the derived `supports_rsa` flag.

- [ ] **Step 1: Write failing boundary tests**

Add TAP assertions with literal expectations for `2.7`, `3.0`, `3.1`, `4.0.11-113-g...`, and malformed input before defining the new helpers.

- [ ] **Step 2: Run the focused build and verify RED**

Run `make -C test/tap/tests test_auth_methods-t` with the branch's normal feature flags. Expect compilation to fail because the version helpers do not exist yet.

- [ ] **Step 3: Implement runtime detection and capability plumbing**

Implement strict leading major/minor parsing, query `SELECT @@version` on the Admin connection, and fail with a diagnostic on query/result/parse errors. Apply the derived boolean only to the pre-3.1 non-TLS hashed SHA-2 exception, expected success/failure counts, and RSA full-auth packet classification.

- [ ] **Step 4: Run focused verification and verify GREEN**

Rebuild `test_auth_methods-t`, run it against the local test environment, and confirm the TAP plan and all assertions pass. Run `git diff --check` and inspect the focused diff.

- [ ] **Step 5: Leave the verified changes local until publication is approved**

Report the exact files changed, ProxySQL version detected, commands run, and test results. Commit and push only after explicit user approval.
