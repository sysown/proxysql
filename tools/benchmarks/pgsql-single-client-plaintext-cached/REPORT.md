# Single-client plaintext comparison

Optimized ProxySQL source commit de5cfbba7de79151cf8c9e847b9d293d65a29b57 versus PgBouncer 1.26.1. This reuses the unchanged executables from the preceding TLS comparison, with encryption disabled on both hops. Binary hashes and source identity are retained in the per-case metadata.

## Conditions

Fresh unprofiled runs on lon104 over localhost TCP: one persistent frontend client, one pgbench thread pinned to CPU 2, one proxy worker/core pinned to CPU 0, performance governor, ten backend connections established before warmup and retained throughout, TLS disabled on both frontend and backend hops, simple query protocol, twenty seconds warmup followed by sixty seconds measured. The preparation step uses concurrent sleepers solely to establish the backend pool; it is outside warmup and measurement.

ProxySQL uses its native backend implementation with commands_stats=false, query_digests=false, full free-connection retention and no maximum connection age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10 and reserve_pool_size=0. All workload and administrative connections are plaintext. Both PgBouncer TLS modes are disabled. ProxySQL disables frontend TLS, backend TLS and the per-user TLS requirement. Frontend conninfo and backend pg_stat_ssl=false are checked before warmup.

The scalar workload is SELECT 1. The resultset workload is the existing generated 42-row query with approximately 4 KB of PostgreSQL response data. Exact query snapshots match between proxies. Each case is a single fresh run; the table is an initial comparison rather than a repeated-run confidence estimate.

## Shared optimizations

Result accumulation-buffer reuse and the removal of diagnostic worker timing calls apply to both transports. Deferred I/O and session ordering are also shared; inline pool handoff chiefly matters when backends are scarce, which this single-client pool does not exercise. Borrowed-token classification and bounded tokenizer copies can benefit either transport when their processing paths are enabled; command statistics and digests remain disabled here, so those changes are not isolated by these runs. The latest completed-handshake cache is inside encrypted-stream paths and provides no plaintext-path optimization.

The earlier matched plaintext timing-hook experiment also observed a gain with a different backend-pool setting. Its original report and comparison are preserved as historical context; those measurements are not part of the fresh results below.

This comparison measures the current optimized plaintext build against PgBouncer. It does not compare against an unoptimized ProxySQL build or attribute a speedup to an individual patch.

## Throughput

| Workload | Optimized ProxySQL TPS | PgBouncer TPS | ProxySQL relative |
|---|---:|---:|---:|
| SELECT 1 | 10,983.58 | 12,779.02 | -14.05% |
| 4KB / 42 rows | 5,395.83 | 6,608.28 | -18.35% |

## Latency and proxy CPU

Latency percentiles use every successful transaction, recorded on tmpfs during measurement. Means below use the complete raw-log average rather than the rounded pgbench summary. CPU figures cover only each proxy process, using the central measurement interval.

| Workload | Proxy | Mean (µs) | p50 (µs) | p95 (µs) | p99 (µs) | User CPU/query (µs) | Kernel CPU/query (µs) | Total CPU/query (µs) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| SELECT 1 | ProxySQL | 88.77 | 82 | 118 | 125 | 12.00 | 25.02 | 37.02 |
| SELECT 1 | PgBouncer | 76.12 | 74 | 101 | 111 | 5.63 | 22.31 | 27.95 |
| 4KB / 42 rows | ProxySQL | 182.22 | 167 | 255 | 293 | 20.99 | 36.08 | 57.07 |
| 4KB / 42 rows | PgBouncer | 148.50 | 135 | 199 | 236 | 9.62 | 29.36 | 38.98 |

## Pool and correctness checks

Every case reports zero failed transactions and keeps the same ten backend connections. ProxySQL ConnOK stays ten and ConnERR stays zero in every snapshot. PgBouncer retains the same backend process identities and reports no server connection creation or close in the steady connection log. No profiling or source timing hooks are enabled. All isolated instances stop after their runs.

| Workload | Proxy | Used/active range | Free/idle range | Other retained states | Successful transactions |
|---|---|---:|---:|---:|---:|
| SELECT 1 | ProxySQL | 1–1 | 9–9 | 0–0 | 658,898 |
| SELECT 1 | PgBouncer | 0–1 | 0–10 | 0–9 | 766,605 |
| 4KB / 42 rows | ProxySQL | 0–1 | 9–10 | 0–0 | 323,693 |
| 4KB / 42 rows | PgBouncer | 0–1 | 0–10 | 0–9 | 396,427 |

Spare backend connections are expected here: a single client has at most one workload query outstanding. Pool counters may also include maintenance activity. PgBouncer other retained states comprise sv_used, sv_tested and sv_login; its active/idle columns alone do not cover the retained pool. Every snapshot totals the configured backend count across all states.

Independent verification streamed all 2,145,623 transaction records, checked their client identity and uncompressed log hashes, and checked the exact nearest-rank p50/p95/p99 boundaries. The ProxySQL and PgBouncer executable hashes match their captured provenance. The original staged work remains unchanged.

## Artifacts

- comparison.json: complete results, latency metadata, pool ranges and commit-description mapping.
- one-client-plain-series-20261024T195452Z/: execution order, summaries and independent verification.
- Per-case directories: query, plaintext transport proof, settings, binary identity, pool snapshots, pgbench output and latency/log-hash metadata.
- benchmark-one-plain-proxysql.py and benchmark-one-plain-pgbouncer.py: reproduction scripts.
- historical-timing-hooks-REPORT.md and historical-plaintext-timing-hooks.json: prior shared-path optimization evidence under different conditions.

Large transactions.*.gz files remain in their original per-case /home/rene/pg-network-bench/results/ directories on lon104; they are excluded from Git. Their uncompressed hashes are retained in latency-percentiles.json.

## Earlier TLS reference

These TLS measurements were recorded earlier with the same binaries, client/core bindings, query text and backend-pool settings. They are references, not contemporaneous paired transport trials or evidence isolating any optimization. No additional TLS benchmark was run.

| Workload | Proxy | Earlier TLS TPS | Fresh plaintext TPS | Difference |
|---|---|---:|---:|---:|
| SELECT 1 | ProxySQL | 7,592.28 | 10,983.58 | +44.67% |
| SELECT 1 | PgBouncer | 7,708.86 | 12,779.02 | +65.77% |
| 4KB / 42 rows | ProxySQL | 4,242.53 | 5,395.83 | +27.18% |
| 4KB / 42 rows | PgBouncer | 4,069.41 | 6,608.28 | +62.39% |
