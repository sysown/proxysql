# PostgreSQL request completion boundary

Approved design: finish the current request cleanup and nonblocking client write before choosing another session. Stop before a buffered next request can reclaim capacity ahead of an existing waiter.

Spec: ../specs/2026-10-25-pgsql-scheduler-contract.md

## Task 1: Implement and verify the boundary

Add failing coverage for output attempted before returning, no completion-only continuation, durable buffered work and paused queued work. Keep actual native/libpq waiter ordering and partial-write coverage. Remove the special epilogue resume state; in the completed-request tail, return Runnable only for buffered next-command work after writeout. Other existing Runnable outcomes for backend dispatch and retry remain valid. Preserve established-only checkout and allocation ownership. Respect response-throttle pauses when draining queued work and computing the next poll deadline. Build with the existing feature/compiler flags, run the focused scheduler/waiter/timeout/allocation tests and the wire-order check, then commit.

Expected: current code fails the new boundary and pause assertions; implementation passes them and all focused checks.

## Task 2: Measure the approved condition and document

Capture an immutable candidate. Compare only SELECT 1, plaintext, localhost, five hundred clients, ten pre-established backends, sixteen pgbench jobs, one native worker. Use the existing immutable c94fbe056 control and an order-balanced comparison to avoid repeating the previous run-order mistake. Require unchanged ConnOK and ConnERR throughout warmup and measurement; collect TPS, CPU/query, p95/p99 and one-second pool samples. No build or profiler runs during measurement.

Expected: all runs retain the fixed pool and produce auditable results. Report the measured difference even if the proposal does not recover performance.

Update the scheduling diagrams and report, obtain an independent review of the final code, commit documentation and push the existing PR branch without rewriting history. Preserve René Cannaò identity and detailed commit messages without measurements.

Review focus: queued buffered requests without new POLLIN, client output backpressure/throttling, cancellation and teardown, extended-query Sync/portal ownership, waiter priority and unavailable pool behavior. No additional workload matrix.
