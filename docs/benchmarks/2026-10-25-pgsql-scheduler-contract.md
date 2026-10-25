# PostgreSQL scheduler contract: implementation and focused benchmark

**Superseded scheduler boundary:** the later [request-boundary implementation and benchmark](2026-10-25-pgsql-request-boundary.md) completes client writeout before waiter handoff and records the new comparison. This report retains the earlier results.

The explicit scheduler contract is implemented and committed. It fixes the demonstrated ordering problem: an existing backend waiter executes before the releasing client's next buffered query. This benchmark did **not** show a throughput improvement. The candidate was 1.48% slower in this single comparison.

## Measured results

| Metric | Committed control `9dfe548bc` | Candidate `c94fbe056` |
|---|---:|---:|
| TPS | 43,346.14 | 42,702.92 |
| Mean latency, ms | 11.529 | 11.703 |
| p95 latency, ms | 12.297 | 12.582 |
| p99 latency, ms | 16.767 | 16.878 |
| Proxy process CPU, microseconds/query | 23.014 | 23.348 |
| User CPU, microseconds/query | 7.202 | 7.091 |
| System CPU, microseconds/query | 15.812 | 16.257 |
| Successful measured transactions | 2,494,892 | 2,458,514 |
| Clients completing transactions | 500 | 500 |
| Failed transactions | 0 | 0 |
| ConnOK before / after | 10 / 10 | 10 / 10 |
| ConnERR | 0 | 0 |
| ConnUsed, steady sample min / mean / max | 10 / 10 / 10 | 10 / 10 / 10 |
| ConnFree, steady sample min / mean / max | 0 / 0 / 0 | 0 / 0 / 0 |

Each run has 62 pool snapshots, with samples taken every second during measurement plus the boundaries. The steady pool summary uses 40 samples between ten and fifty seconds. Backend count remained ten throughout, with no backend creation during warmup or measurement. These are sampled pool-accounting values; they do not prove that every backend is executing a query continuously.

The 1.48% TPS difference is a single-run observation, not a measured distribution of run-to-run variance. CPU/query increased 1.45%. User CPU/query fell slightly while system CPU/query rose; this accounting does not identify the cause without further profiling.

## Exact workload and controls

- Native PostgreSQL backend protocol, localhost TCP on lon104, no containers, TLS disabled on both legs and verified through client connection information and backend `pg_stat_ssl`.
- `SELECT 1`, pgbench simple protocol, 500 clients, 16 jobs on CPUs `2,4,6,8,10,12,14,16`.
- One ProxySQL worker on CPU zero; CPU governor `performance`.
- Ten backend connections established before warmup, maximum ten, `free_connections_pct=100`, `connection_max_age_ms=0`.
- Parsing disabled (`query_processor_parser=0`), `commands_stats=false`, `query_digests=false`; no active query rules. Digest map remained empty.
- Twenty-second warmup and sixty-second pgbench measurement for each build. TPS excludes initial frontend connection time, as reported by pgbench. CPU/query uses process ticks and backend-query deltas between samples five and fifty-five.
- Full transaction latency logs written to tmpfs, compressed only after measurement. Percentiles use nearest rank across every successful measured transaction. Logged counts match pgbench completion counts.
- Matching compiler, dependency tree, build path, feature defines and `-O2 -fno-omit-frame-pointer -ggdb` flags. No timing hooks or perf collection in these throughput runs. Only debug sections were stripped from immutable executables; loaded sections were compared before and after stripping.

The control is the committed PR state immediately before this work, including earlier review fixes. It is not the older pre-review or clean upstream build. The candidate includes the explicit checkout/step contract, safe handoff/continuations, allocation ownership changes and retryable-send correction. This comparison does not isolate their individual costs.

## Implementation

- `run_step()` reports waiting for I/O, waiting for a backend, established connection unavailable, runnable continuation, or close. Consumed work clears `to_process`; the old dispatched-session vector and linear membership searches are removed.
- Established-only acquisition cannot create, warm or evict connections, park a session, impose retry delay or count an ordinary checkout failure. Recovery and deadlines retain the normal acquisition path.
- A released backend triggers a safe yield after request, transaction and protocol cleanup and before client writeout or another buffered command. The worker serves an eligible waiter after the handler returns, then resumes the releasing session through its existing epilogue.
- Continuations are queued once, drained with a bounded snapshot, retained across readiness resets, canceled on teardown and protected from idle-worker migration. Remaining continuation work prevents a blocking poll.
- Retryable plaintext send errors retain output even after `POLLOUT`. The regression trace showed a successful partial send followed by `EAGAIN` being treated as fatal in the preceding implementation.
- Allocation exceptions stay inside the C++ boundary around libpq parsing. Notice callbacks return to libpq for cleanup, sticky failure prevents completion/reuse, and COPY buffers have scoped ownership.

[Scheduling documentation: previous order, current order, and proposed request boundary](../superpowers/specs/2026-10-25-pgsql-scheduler-contract.md). This document also records the subsequent same-process yield investigation. The benchmark tables above remain the initial comparison, not measurements of the proposed scheduling boundary.

## Verification

The complete affected library and executable build passed. Focused TAP checks passed: scheduler contract 13, allocation ownership 47, worker timeout 14 and worker waiter 65 assertions, totaling 139. The repository CI lint command passed locally.

A wire-level test sends two queries from client A in one write while client B waits for the sole backend. A sequence records execution order:

| Build / backend | Client A sequence values | Client B sequence value |
|---|---|---|
| Control / native | 1, 2 | 3 |
| Candidate / native | 1, 3 | 2 |
| Candidate / libpq | 1, 3 | 2 |

Both candidate checks preserve all response completions and retain their one backend. The partial-write test resumes output without new readable bytes and verifies exact delivery through repeated writable events. Incompatible pool misses preserve the free connection and leave waiter, retry, poll and failure state unchanged. The allocation checks exercise actual libpq notice and COPY cleanup, including failures, sticky state and successful notice bytes.

An independent read-only review found no confirmed correctness defects. Its incompatible-pool test gap was added; its subsequent review accepted the retryable-send correction. This is focused validation, not a claim that the full protocol, TLS, platform or multiworker CI matrix has passed. Those configurations were not benchmarked in this task.

## Commits and evidence

Meaningful changes remain separate commits: `2bf7f2b8f` (design and plan), `9cad112f8` (explicit checkout and step outcomes), `e82be040a` (allocation ownership), and `c94fbe056` (safe handoff, continuations and partial output). Existing history is preserved.

On lon104, under `/home/rene/pg-network-bench/`:

- Control run: `results/scheduler-contract-plain500-b10-select1-previous-20261025T133000Z`.
- Candidate run: `results/scheduler-contract-plain500-b10-select1-latest-20261025T133158Z`.
- `scheduler-contract-comparison.json`, `scheduler-contract-binaries.json` and `scheduler-contract-evidence.tar.gz` contain the audited comparison, binary provenance, pool samples, settings and verification logs.
- `benchmark-scheduler-contract.py`, `check-scheduler-handoff.py` and `capture-scheduler-binary.py` retain the exact benchmark, ordering probe and binary capture procedures. Raw compressed transaction logs remain in each run directory.

Control executable SHA-256: `b5f1b80312812dba8bbfa94016569a7b0f1b44df869e88d3b5947b2023b60198`.

Candidate executable SHA-256: `436bc799f928854b1e11efcfb8b96a13282183e2082182584e58f3dbb0ff4b18`.
