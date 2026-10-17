# Mixed user-variable SET correction

**Goal:** Track the initialization statements in sysown/proxysql#6479 using
ProxySQL's existing execution model: parsed SETs update desired frontend state
and return OK locally; backend synchronization happens only when needed by a
subsequent query. Only unsupported/unparsed SETs follow the existing forwarding
and hostgroup-locking fallback policy.

**Correction:** The first PR revision incorrectly forwarded parsed SETs and
committed frontend/backend maps after backend OK. The backend wait_timeout reset
and warning fallback added to compensate for that design are removed. The same
forwarding behavior in the earlier literal user-variable path is corrected too.

**Scope:** Retain the narrow mixed-SET allowlist for max_execution_time and
wait_timeout, ordered repeated assignments, scope checks, and atomic resource
preflight. Use the existing system-variable and user-variable synchronization
paths. wait_timeout remains frontend-only. ParserSQL 1.1.1 already exposes the
required AST; no dependency release is needed.

- [x] Reproduce unwanted forwarding: new no-backend and attached-transaction
      regression assertions fail on the original PR binary.
- [x] Commit validated frontend state locally after query-rule routing checks.
- [x] Remove asynchronous pending-SET state, post-OK commit helper, warning
      fallback, and reset-before-pooling workaround.
- [x] Cover mixed SET interception on MySQL and MariaDB. Only backend inspection
      of max_execution_time depends on backend support.
- [x] Build and run parser, state, digest, and integration checks.


**Required evidence:** Parsed pure/mixed SET creates no backend; SET does not
change an attached backend or transaction status; the next query synchronizes
changed values; backend wait_timeout stays at its original value; unsupported
mixed SET falls back without partial frontend commits; repeated values and
counters remain correct; cross-hostgroup replay and client isolation pass.

## Verification

- Native core and server builds passed using the committed ParserSQL 1.1.1.
- Parser adapter: 268 checks; user-variable state: 74; digest fallback: 92.
- Integration: 71 checks each against MySQL 8.0.46, MariaDB 10.11, and
  MySQL with global multiplexing disabled (213 integration checks).
- Five new interception/transaction assertions failed against the original
  PR binary and passed with local handling. Deferred replay rejection and
  unchanged-value replay counters are also covered.
- Resource-limit fixtures now explicitly materialize their desired state before
  sampling fallback-only counters. Exact 64 KiB coverage uses bounded individual
  assignments that fit the existing conservative replay packet budget.
- Independent read-only review found no blocking correctness issues.

GitHub CI must run on the correction; these local results do not establish that
remote CI is green. Publication and linked task updates are performed after the
verified correction is committed.

The final no-multiplexing repeat reproduced the previously observed baseline
COM_CHANGE_USER test failure: it unconditionally required the same physical
backend ID. That assertion now follows the existing COM_RESET_CONNECTION test:
require exact reuse with multiplexing, and permit replacement without it while
still verifying cleared frontend diagnostics and a NULL backend value.
