# PostgreSQL native backend review fixes

> **For agentic workers:** Use systematic debugging and test-driven development for each task; coordinate independent work with dispatching-parallel-agents. Run one independent review of the combined changes before pushing.

**Goal:** Resolve issues #6249–#6253 in PR #5882 with regression coverage.

**Architecture:** Preserve the existing transaction-poison recovery path and libpq TLS policy. Keep Unix-socket connections on libpq until native Unix transport exists. Native cancellation must retain the original peer endpoint instead of resolving DNS again.

**Tech Stack:** C++17, OpenSSL, libpq, TAP, isolated PostgreSQL 16 infrastructure.

**Spec:** GitHub issues #6249, #6250, #6251, #6252, #6253 and the review of PR #5882 at b7ddfbfad.

## Constraints and review focus

- Work on the existing PR branch; preserve the default-off native flag.
- Build with PROXYSQL31=1 and debug flags consistently; coordinate shared build artifacts.
- Preserve both backend modes, frontend wire ordering, transaction recovery, and connection teardown.
- Validate TLS with and without CA configuration and incompatible protocol bounds.
- Preserve Unix socket paths and default/nondefault ports without changing TCP selection.
- Cancellation must fail against an unavailable original endpoint without trying a different server.
- No unrelated refactoring or changes to the user's primary checkout.

## Task 1 — #6249: aborted transaction after DISCARD ALL

Files: lib/PgSQL_Session.cpp; test/tap/tests/pgsql-discard_all_txn_block-t.cpp.

- [x] Extend the existing integration test: after BEGIN and rejected DISCARD ALL, SELECT and INSERT must return 25P02, ROLLBACK must leave no row, and a subsequent transaction must work. Cover both backend modes and COMMIT-as-rollback recovery.
- [x] Run the extended test on b7ddfbfad and record the expected failures.
- [x] Preserve poisoned transaction state when the rejection destroys the backend, reusing the existing recovery implementation.
- [x] Rebuild and run the DISCARD, transaction-recovery, and native transaction tests.
- [x] Commit with the issue reference.

## Task 2 — #6250: REQUIRE with a configured CA

Files: lib/PgSQL_Connection.cpp (TLS context/handshake only); test/tap/tests/unit/pgsql_native_tls_verify_modes_unit-t.cpp.

- [x] Add REQUIRE-with-CA tests, with a real handshake that rejects an untrusted certificate and accepts a trusted certificate; retain REQUIRE-without-CA behavior.
- [x] Run the regression against the current production library and record the failure.
- [x] Enable chain verification when a CA is loaded, including REQUIRE; preserve verification errors and cleanup.
- [x] Run the TLS verification tests and native TLS integration tests.
- [x] Commit with the issue reference.

## Task 3 — #6251: configured TLS protocol bounds

Files: lib/PgSQL_Connection.cpp (TLS context only); native TLS unit tests.

- [x] Add table-driven tests for an unset range, TLSv1.3 minimum, TLSv1.2 maximum, and exact TLSv1.2 pin; prove incompatible peers fail negotiation.
- [x] Record failing configured-bound assertions against the original implementation.
- [x] Apply parsed per-server minimum/maximum values through OpenSSL and handle configuration errors.
- [x] Run the TLS tests and commit with the issue reference.

## Task 4 — #6252: Unix socket compatibility

Files: lib/PgSQL_Connection.cpp (protocol selection only); a focused regression test registered in the existing test harness.

- [x] Add coverage for filesystem socket paths, supported abstract sockets, default and nondefault ports, and unchanged TCP selection.
- [x] Confirm native-mode Unix connection failure before the change.
- [x] Select libpq per connection for Unix sockets, retaining the original socket host and port semantics.
- [x] Run the regression and a live Unix-socket connection through ProxySQL; commit with the issue reference.

## Task 5 — #6253: cancellation endpoint

Files: include/PgSQL_Connection.h; lib/PgSQL_Connection.cpp (cancel args/sender); callers in lib/PgSQL_Session.cpp and lib/PgSQL_HostGroups_Manager.cpp if needed; cancellation regression tests.

- [x] Add a regression with distinct connected and configured-host endpoints: only the original peer receives the exact PID/secret packet. Also cover unavailable original endpoint and invalid capture.
- [x] Confirm the original implementation sends to the wrong endpoint or cannot honor the captured endpoint.
- [x] Snapshot the connected peer while its socket is valid into the owned kill arguments, then connect directly to that address in the cancellation thread.
- [x] Run cancellation regressions plus the existing native cancel test; commit with the issue reference.

## Integration and delivery

- [x] Build the combined debug binary and run the affected unit and integration tests through run-tests-isolated.bash.
- [x] Review the combined diff independently; address material findings and run relevant tests.
- [x] Prepare verified production and regression commits for feature/pgsql-native-backend-protocol, with all five issue references and review evidence. Publication target: PR #5882.

## Verification results

- Regression-before-fix evidence: transaction abort/durability failures in both backend modes; configured-CA and protocol-bound handshake failures; three Unix-socket endpoint failures; all four original-peer cancellation failures.
- Debug build: `PROXYSQL31=1 make debug -j6 NPROCS=6` passed.
- All 18 affected unit binaries passed; final expanded TLS suite passed all 25 assertions. Unix and cancellation endpoint suites each passed four assertions.
- Isolated integration: DISCARD 60 assertions (58 passed and two existing TODO assertions for ParameterStatus ordering), Unix sockets 10, native cancellation 10, TLS 15, transactions 21, query differential 33, portals 13, poisoned recovery 17, and poisoned extended queries 11.
- All 40 new DISCARD assertions passed, including durable writes before and after rejection and ROLLBACK/COMMIT recovery in both backend modes.
- Independent combined code review and final TLS mapping review found no actionable defects.
