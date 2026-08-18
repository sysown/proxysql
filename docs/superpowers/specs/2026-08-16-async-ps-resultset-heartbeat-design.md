# Async Prepared-Statement Resultset Heartbeat Design

## Purpose

Prevent the MySQL worker watchdog from aborting ProxySQL while an asynchronous
prepared statement is making legitimate progress converting a very large
buffered resultset into client-protocol packets. The fix must preserve the
existing watchdog threshold and resultset-processing behavior, and must not
refresh the heartbeat for every row or packet.

## Root cause

The worker refreshes `atomic_curtime` before entering `process_all_sessions()`.
The asynchronous prepared-statement result path can then remain inside
`process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT()` while it converts
millions of buffered rows. Under AddressSanitizer, the 4 GB result used by
`test_ps_large_result-t` can keep that loop busy beyond the watchdog's fatal
missing-heartbeat window even though rows are still being processed.

The older prepared-statement result path already refreshes the worker
heartbeat after each 256 MiB of copied resultset data. Commit `868f70903`
introduced that cadence specifically to prevent large-result processing from
being mistaken for a stuck worker. The later incremental asynchronous path
uses `MySQL_ResultSet::add_row(MYSQL_ROWS *)`, which updates `resultset_size`
but does not carry forward the heartbeat boundary check.

## Design

Add the established 256 MiB progress-boundary check to
`MySQL_ResultSet::add_row(MYSQL_ROWS *)`:

1. Generate the client-protocol packet as today and obtain its byte length.
2. Compare the previous and resulting `resultset_size` buckets using the same
   `0xFFFFFFF` boundary already used by `init_with_stmt()`.
3. Only when the packet crosses a boundary, obtain the current monotonic time
   and store it in the owning MySQL worker's `atomic_curtime`.
4. Update `resultset_size`, `num_rows`, and the packet sequence exactly as
   today.

The boundary comparison executes for each converted row because that is where
the byte progress becomes known. The comparatively expensive clock read and
heartbeat write execute only once per 256 MiB of output. For the 4 GB TAP
result, this produces roughly sixteen progress heartbeats instead of ten
million row-level updates.

The heartbeat access will be guarded by the existing resultset ownership
pointers. The intended non-mirrored prepared-statement path always has an
owning client data stream, session, and worker; the guard avoids introducing a
new crash if the method is reused in a context without those objects.

## Safety and scope

The heartbeat represents bounded forward progress: the row loop has a fixed
upper bound and `resultset_size` increases only after a row has been converted.
If processing becomes stuck on a row, no boundary is crossed and the watchdog
still fires. The change therefore does not turn the heartbeat into an
unconditional keepalive and does not mask a stalled worker.

The preliminary linked-list traversal remains unchanged. It only locates and
counts buffered rows. The subsequent multi-GB packet-conversion work is the
path that bypasses the codebase's existing byte-based heartbeat policy.

This change does not alter:

- watchdog timeouts or `restart_on_missing_heartbeats`;
- resultset fetch suspension or throttling thresholds;
- row-loop bounds, packet generation, or byte accounting;
- MariaDB coroutine allocation ownership or the retained-last-row behavior;
- non-prepared-statement result processing.

## Verification

The existing failing ASAN execution of `test_ps_large_result-t` is the
end-to-end regression test. After the change:

- the affected source must compile cleanly;
- focused available tests for prepared-statement result processing must pass;
- `test_ps_large_result-t` must complete under the label-selected ASAN build
  without watchdog missed-heartbeat termination;
- the TAP must still fetch all 10,000,000 rows and report the 4 GB result as
  successful;
- no AddressSanitizer finding may be suppressed or ignored.

## Non-goals

Cooperatively batching or yielding the row-conversion loop could improve event
loop fairness, but it would require redesigning MariaDB coroutine-buffer
ownership and partial-row-list retention. That is separate from restoring the
existing watchdog progress contract and is outside this fix.
