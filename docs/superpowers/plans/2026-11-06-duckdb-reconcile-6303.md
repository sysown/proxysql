# Reconcile MySQL replica branch with #6303 and #6280

> **For agentic workers:** Use superpowers:executing-plans inline in the existing isolated worktree.

**Goal:** Retain the MySQL replica subsystem and useful result improvements, adopt PR #6303's richer shared result foundation, and remove the unapproved custom SQL translator.
**Base:** e23f3ec12; dependency origin/v3.0-6283 at 7479dae6a; current main e2f317aba.
**Architecture:** Merge the result PR into this current-main-based feature branch, preserve newer mainline guards, use its DuckDBColumnType/protocol-aware converter and both frontend metadata paths, and layer supported native MySQL temporal/fallback/length behavior on that single foundation. Remove mysql_compatibility mode and its lexer instead of inventing a replacement parser. New syntax work waits for vendored ParserSQL support.
**Spec:** #6280 implementation constraints; #6283/#6303 result contract; #6289 replica acceptance; #6298 core framework / #6282 DuckDB adapter boundary.

## Constraints

- Never reset, rewrite or force-push existing history; preserve pre-reconciliation branch tip under a local backup ref.
- Keep inherited mainline security/configuration guards, the replica engine/API, atomic checkpoints, RESET ownership and crash recovery.
- No custom parser/lexer or new downstream SQL recognition. Inherited pre-branch guards remain; new compatibility syntax work is deferred to ParserSQL.
- Do not implement prepared frontend protocol in DuckDB. #6298 owns state machines/encoding/lifecycle; #6282 adapts native DuckDB once the contract exists. #6281 remains blocked by ParserSQL68/69.
- Preserve default external-access policy and test both wire protocols. Any #6303 safety/conversion features must survive integration.
- A new draft PR targets v3.0 and declares dependency on #6303. Direct stacking on its old head would include1080 unrelated mainline commits. PR contents include the dependency until it merges.

## Review focus

- Merge must keep newer mainline SET/config guards rather than restoring old permission behavior.
- Native UUID/time variants/ENUM/BIT/TIMESTAMPTZ conversions and PostgreSQL typed metadata/BYTEA/booleans from #6303 remain intact.
- Preserve useful MySQL temporal metadata, exceptional scalar fallback, UTF-8 and observed byte lengths using the common type descriptor.
- Wrapper output preserves column ordering/labels/execute-once; unsupported RETURNING cannot silently NULL or commit hidden writes.
- Removing unpublished compatibility variables/tests/build rules must not leave active custom grammar recognition or misleading public docs.

### Task 1: Merge result foundation and preserve useful deltas

- [x] Backup current tip; merge #6303 without committing, resolve overlapping result/session headers/sources/tests by contract.
- [x] Use #6303's protocol-aware result schema/conversion and metadata serializers; preserve native MySQL temporal fields, fallback and accurate UTF-8/length information.
- [x] Keep selective, positional result wrapping based on DuckDB descriptions rather than SQL text recognition; preserve safety on both protocols.
- [x] Update/adapt focused tests to the unified API, observe failures before adding missing preserved behavior, build and run them.

### Task 2: Remove custom translator and align roadmap

- [x] Remove new lexer, opt-in variable, listener/TLS wiring and tests; retain native DuckDB SQL and existing mainline discovery/config guards.
- [x] Update public doc/duckdb and handoff/specs to record native-only compatibility pending ParserSQL, #6289 status/remaining reconnect work and result-PR integration.
- [x] Prepared statements: #6298 core prerequisite, #6282 adapter only. Include issue mapping, acceptance gaps and clear next steps.

### Task 3: Verify, review and prepare PR

- [x] Run merged result/session suites, both wire suites, typed direct/routed tests, applier live/recovery and affected Admin/listener units. Record skips/errors honestly.
- [x] Read-only code review; fix material findings and rerun relevant tests.
- [x] Commit reconciliation; prepare a focused new draft PR linked to #6289/#6280 and dependent on #6303, without editing #6303 or issue comments.

## Validation and review (2026-11-06)

- Plugin and affected unit/live targets build with PROXYSQL40, DuckDB1.4.5,
  MariaDBConnector/C3.3.8 plus this branch's decoder patch.
- Eight unit binaries:400 TAP checks, seven explicit optional ICU skips.
- Default external-access-disabled MySQL77/PG84 checks, four ICU skips each.
  Signed ICU enabled in a private test instance:77/84 assertions, no skips.
- Typed direct+routed30; Admin22; live applier31 and recovery19, each with
  MySQL8.4.8 NONE and CRC32 checksums. No new throughput measurements.
- Regression-first checks exposed missing temporal metadata and exceptional
  scalar fallback before porting those deltas to the shared API. Default
  100000-row TIMESTAMPTZ fixture uses numeric epoch instants to avoid an ICU
  arithmetic dependency. Live UTC fixture now compares to DuckDB's own VARCHAR
  cast rather than assuming the host/session timezone is UTC.
- Read-only code/docs review found no material issues; corrected stale comments,
  unit counts/date and transaction-status documentation. Documented manual
  cleanup of the unpublished retired configuration key.

DBTrail research additionally identified unsupported InnoDB referential actions:
MySQL8.4 documents that cascaded child changes are not logged, while our metadata
admission/targetDDL has no FK policy. Documented as an unenforced limitation and
immediate #6289 follow-up (metadata-based rejection and live coverage), before
network reconnect. No FK production fix or runtime reproduction is claimed.

Reconciliation committed as `86796b8b8`; draft PR: https://github.com/sysown/proxysql/pull/6591 (base v3.0, dependency #6303).
