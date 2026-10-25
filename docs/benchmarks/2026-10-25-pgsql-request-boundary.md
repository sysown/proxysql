# PostgreSQL request-boundary handoff benchmark

The handler now completes request cleanup and attempts the nonblocking client reply write before returning to the worker. An already-buffered next command yields to existing backend waiters; a client with no next command needs no completion-only continuation. The special epilogue-resume flag is removed. Buffered next-command work respects reply-throttle pauses and remains runnable without another readable socket event.

[Scheduling diagrams and protocol boundary](../superpowers/specs/2026-10-25-pgsql-scheduler-contract.md).

## Comparison

Only one workload/configuration was measured: `SELECT 1`, no TLS on either leg, localhost on lon104, 500 clients, 10 pre-established backends, 16 pgbench jobs, native backend protocol, and one ProxySQL worker. ProxySQL is bound to CPU 0; pgbench to CPUs 2,4,6,8,10,12,14,16. Governor: performance. Parser, command statistics and query digest statistics are disabled; free_connections_pct is 100 and connection max age is zero. No active query rules.

Each instance received a fixed-pool prewarm, twenty-second warmup and sixty-second measured run. The order was old/new/new/old. Both versions use the same release build flags. No profiler or build ran during throughput measurement. Transaction latency logs were written to tmpfs and compressed after measurement.

| Version | Commit | Mean TPS | Mean CPU µs/query | Mean p95 ms | Mean p99 ms |
|---|---|---:|---:|---:|---:|
| Pre-write completion continuation | `c94fbe056` | 42,640.03 | 23.3875 | 12.615 | 16.792 |
| Writeout before waiter handoff | `4facb95bf` | 41,959.82 | 23.7760 | 12.703 | 17.069 |

Across the two runs per version, throughput changed **-1.60%** and CPU time per query changed **+1.66%**. These are fresh-instance measurements, not a same-process causal toggle or a statistical confidence interval. Percentile columns are the arithmetic means of each run's nearest-rank percentile, not pooled percentiles.

| Run order | Version | TPS | CPU µs/query | p95 ms | p99 ms |
|---:|---|---:|---:|---:|---:|
| 1 | previous | 42,939.55 | 23.2280 | 12.539 | 16.709 |
| 2 | latest | 42,506.19 | 23.4666 | 12.540 | 16.881 |
| 3 | latest | 41,413.45 | 24.0855 | 12.865 | 17.257 |
| 4 | previous | 42,340.51 | 23.5471 | 12.691 | 16.875 |

The patch did **not** recover the performance regression in this comparison. Mean userspace CPU increased from 7.1400 to 7.5099 µs/query; system CPU changed from 16.2475 to 16.2662 µs/query. Most of the measured increase is therefore userspace CPU. The connection pool stayed fully occupied in the sampled interior window; these results do not locate the remaining instruction-level cause. No rollback or additional scheduling experiment was performed.

## Pool and correctness checks

Every run retained the same ten backends: ConnOK stayed at ten, ConnERR stayed at zero, and ConnUsed + ConnFree stayed at ten in every measurement snapshot. The prewarm-to-warmup comparison also showed no new connections. All runs had zero failed transactions, all five hundred clients completed requests, and the digest map remained empty. There were sixty-two snapshots per run, including the measurement boundaries.

| Version | Mean ConnUsed | Mean ConnFree | Observed ConnFree range |
|---|---:|---:|---|
| previous | 10.000 | 0.000 | 0–0 |
| latest | 10.000 | 0.000 | 0–0 |

Pool distribution uses snapshots five through fifty-five inclusive. Idle snapshots before/after measurement are excluded from these averages; connection-creation checks cover every snapshot. CPU/query uses process CPU ticks and backend query-counter deltas over the same interior window.

## Verification

- Coherent release build with `-O2 -fno-omit-frame-pointer -ggdb` and the existing development feature defines.
- Scheduler contract: seventeen assertions, including output before return, no completion-only continuation, retained short writes, queued work without new input, throttle pause deadlines and teardown. The new boundary/pause checks first failed on the old implementation.
- Allocation ownership: forty-seven assertions; worker timeout: fourteen; worker waiter: sixty-five. All passed.
- Real PostgreSQL wire checks with native and libpq backends: releasing client A receives sequence values `[1,3]`, waiting client B receives `[2]`; A’s buffered second query cannot bypass B. The sole backend remains established.
- Repository CI lint passed locally. All four Mermaid diagrams parsed.
- Independent read-only review found no actionable code issue. It did not independently execute tests or evaluate benchmark measurements.

## Artifacts

On lon104, `/home/rene/pg-network-bench/request-boundary-summary.json` and `request-boundary-binaries.json` identify the results and immutable binaries. Raw per-transaction logs, runtime settings, pool samples and per-client completion counts remain under these result directories:

- `/home/rene/pg-network-bench/results/request-boundary-plain500-b10-select1-previous-20261025T151725Z`
- `/home/rene/pg-network-bench/results/request-boundary-plain500-b10-select1-latest-20261025T151901Z`
- `/home/rene/pg-network-bench/results/request-boundary-plain500-b10-select1-latest-20261025T152037Z`
- `/home/rene/pg-network-bench/results/request-boundary-plain500-b10-select1-previous-20261025T152213Z`

Immutable benchmark binaries (debug sections stripped only; allocated sections verified unchanged):

| Version | SHA-256 |
|---|---|
| previous | `436bc799f928854b1e11efcfb8b96a13282183e2082182584e58f3dbb0ff4b18` |
| latest | `22765bc25b210239e120f807edae6961e408db3c1b08b387a1f2cd6f11e83ece` |

The earlier same-process diagnostic isolated the cost of the pre-write yield path. This benchmark evaluates the implemented replacement with waiter ordering retained; it does not substitute the diagnostic yield-disable switch for a production scheduler. No other workload, TLS condition, client count or backend cap was benchmarked in this comparison.
