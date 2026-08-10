# Prepared-Statement Memory Test Hardening Design

## Status

Approved for implementation on 2026-08-10.

## Context

`test_prepare_statement_memory_usage-t` measures the global
`prepare_statement_metadata_memory` and `prepare_statement_backend_memory`
counters immediately before and after preparing a statement. The test assumes
that no other prepared-statement state changes during that interval.

That assumption is not valid in the shared TAP infrastructure. In the failed
`CI-mysql84-g8` run, backend statements created by the preceding
`test_noise_injection-t` were still being released. Five unrelated
`ref_count_server` values decreased while the memory test prepared `SELECT 1`.
The target statement was installed correctly, but the unrelated releases were
larger than its allocation, so both global counters decreased and the test
failed.

## Goals

- Preserve coverage of both prepared-statement memory metrics.
- Reject samples affected by unrelated prepared-statement activity.
- Preserve coverage of new statements and connection-local statement reuse.
- Replace the fixed post-close sleep with state-based synchronization.
- Keep the change confined to the TAP test and its documentation.

## Non-goals

- Change prepared-statement accounting or cleanup in ProxySQL.
- Reorder CI tests or move the test to another group.
- Flush shared connection pools or otherwise mutate infrastructure-wide state.
- Replace memory-metric assertions with cache-table-only assertions.

## Considered Approaches

### 1. Guard each memory sample with prepared-statement snapshots

Capture `stats_mysql_prepared_statements_info` around the memory reads and
accept a measurement only when every statement other than the target is
unchanged. Retry contaminated attempts within a bounded deadline.

This is the selected approach because it detects the exact source of the race
without weakening the original memory-metric contract.

### 2. Wait for global counters to become stable before measuring

This is simpler, but a cleanup can begin after the stability check and before
the prepare completes. It reduces the race window without closing it.

### 3. Reorder or regroup the tests

Moving the memory test away from `test_noise_injection-t` would avoid the
observed ordering, but other tests can leave the same shared state behind. It
would hide this occurrence rather than make the test correct.

## Detailed Design

### Stable samples

The test will represent a memory sample as:

- metadata memory;
- backend memory; and
- a complete, ordered snapshot of
  `stats_mysql_prepared_statements_info`.

A stable sample is read using a snapshot-memory-snapshot sequence. The two
snapshots must match. If they differ, the read is retried within a bounded
deadline. This prevents a memory value from being paired with statement state
that was already changing while it was read.

Snapshots include every exposed field and are keyed by `global_stmt_id`:
schema, username, digest, client and server reference counts, column and
parameter counts, and query text.

### Uncontaminated measurements

For each prepare operation, the test will:

1. Obtain a stable sample before the prepare.
2. Prepare the target query and keep the `MYSQL_STMT` open.
3. Obtain a stable sample after the prepare.
4. Remove the target query from both statement snapshots.
5. Accept the measurement only when the remaining snapshots are identical.

If unrelated state changed, the attempt is diagnostic-only: it emits no TAP
assertions, closes the statement, waits for its client reference to settle,
and retries.

New-statement retries use a fresh, process-unique query each time so a
contaminated attempt cannot turn the next attempt into a cache-reuse check.
The two accepted new queries are retained for the later reuse checks.

Reuse retries use the same accepted query. Once its client reference has
returned to zero, preparing it again must increase metadata memory for the
client mapping while leaving backend memory unchanged on the same frontend and
backend connection.

### State-based close synchronization

After `mysql_stmt_close`, the test will poll the target row until its
`ref_count_client` is zero. A fixed deadline prevents a hang. This replaces the
current `usleep(10000)`, which assumes processing completes within ten
milliseconds.

### TAP behavior and diagnostics

The test retains four checks with three assertions each:

1. first new statement: metadata increases; backend does not decrease;
2. second new statement: metadata increases; backend does not decrease;
3. reuse first statement: metadata increases; backend is unchanged;
4. reuse second statement: metadata increases; backend is unchanged.

Retries do not emit TAP assertions. Each logical check emits exactly three
assertions after it obtains a clean result or exhausts its deadline, preserving
the existing twelve-test plan. Contamination and timeout diagnostics identify
which unrelated statement rows changed.

All query and result errors remain terminal for the affected logical check and
are reported through TAP rather than silently retried.

## Validation

The failed `CI-mysql84-g8` run provides the RED case: the existing test failed
while archived statement snapshots showed unrelated server references
decreasing.

Implementation validation will include:

- building the focused TAP binary from the current `v3.0` base;
- running the existing `mysql84-g8` ordering with `test_noise_injection-t`
  followed by `test_prepare_statement_memory_usage-t` where practical;
- running the hardened test in a clean isolated MySQL 8.4 infrastructure;
- checking TAP output remains exactly 12 passing assertions;
- running repository diff and whitespace checks.

The implementation is successful only if accepted memory samples retain the
original comparison semantics and unrelated statement changes cause retry or
an explicit bounded failure, never a false memory regression.
