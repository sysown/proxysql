# Single-client TLS comparison

Cached ProxySQL source commit de5cfbba7de79151cf8c9e847b9d293d65a29b57 versus PgBouncer 1.26.1. The ProxySQL executable is unchanged from the handshake-cache experiment. Its original build commit is preserved; the active source/evidence commit messages were rewritten into detailed prose without numerical figures. commit-description-rewrite.json records old/new identities and identical tree verification.

## Conditions

Fresh unprofiled runs on lon104 over localhost TCP: one persistent frontend client, one pgbench thread pinned to CPU 2, one proxy worker/core pinned to CPU 0, performance governor, ten backend connections established before warmup and retained throughout, TLSv1.3 AES-256-GCM on both hops, simple query protocol, twenty seconds warmup followed by sixty seconds measured. The preparation step uses concurrent sleepers solely to establish the backend pool; it is outside warmup and measurement.

ProxySQL uses its native backend implementation with commands_stats=false, query_digests=false, full free-connection retention and no maximum connection age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10 and reserve_pool_size=0. Administrative monitoring is plaintext for both products; every workload client requires TLS. PgBouncer allows plaintext only to keep administrative monitoring from performing repeated TLS handshakes.

The scalar workload is SELECT 1. The resultset workload is the existing generated 42-row query with approximately 4 KB of PostgreSQL response data. Exact query snapshots match between proxies. Each case is a single fresh run; the table is an initial comparison rather than a repeated-run confidence estimate.

## Throughput

| Workload | Cached ProxySQL TPS | PgBouncer TPS | ProxySQL relative |
|---|---:|---:|---:|
| SELECT 1 | 7,592.28 | 7,708.86 | -1.51% |
| 4KB / 42 rows | 4,242.53 | 4,069.41 | +4.25% |

## Latency and proxy CPU

Latency percentiles use every successful transaction, recorded on tmpfs during measurement. Means below use the complete raw-log average rather than the rounded pgbench summary. CPU figures cover only each proxy process, using the central measurement interval.

| Workload | Proxy | Mean (µs) | p50 (µs) | p95 (µs) | p99 (µs) | User CPU/query (µs) | Kernel CPU/query (µs) | Total CPU/query (µs) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| SELECT 1 | ProxySQL | 128.87 | 125 | 165 | 198 | 25.89 | 29.67 | 55.56 |
| SELECT 1 | PgBouncer | 127.13 | 122 | 160 | 192 | 23.44 | 32.03 | 55.47 |
| 4KB / 42 rows | ProxySQL | 232.72 | 214 | 313 | 361 | 42.07 | 40.99 | 83.06 |
| 4KB / 42 rows | PgBouncer | 242.47 | 231 | 337 | 364 | 36.72 | 42.67 | 79.40 |

## Pool and correctness checks

Every case reports zero failed transactions and keeps the same ten backend connections. ProxySQL ConnOK stays ten and ConnERR stays zero in every snapshot. PgBouncer retains the same backend process identities and reports no server connection creation or close in the steady connection log. No profiling or source timing hooks are enabled. All isolated instances stop after their runs.

| Workload | Proxy | Used/active range | Free/idle range | Other retained states | Successful transactions |
|---|---|---:|---:|---:|---:|
| SELECT 1 | ProxySQL | 0–1 | 9–10 | 0–0 | 455,435 |
| SELECT 1 | PgBouncer | 0–1 | 0–10 | 0–9 | 462,426 |
| 4KB / 42 rows | ProxySQL | 0–1 | 9–10 | 0–0 | 254,495 |
| 4KB / 42 rows | PgBouncer | 0–1 | 0–10 | 0–9 | 244,107 |

Spare backend connections are expected here: a single client has at most one workload query outstanding. Pool counters may also include maintenance activity. PgBouncer other retained states comprise sv_used, sv_tested and sv_login; its active/idle columns alone do not cover the retained pool. Every snapshot totals the configured backend count across all states.

Independent verification streamed all 1,416,463 transaction records, checked their client identity and uncompressed log hashes, and checked the exact nearest-rank p50/p95/p99 boundaries. The ProxySQL and PgBouncer executable hashes match their captured provenance. The original staged work remains unchanged.

## Artifacts

- comparison.json: complete results, latency metadata, pool ranges and commit-description mapping.
- one-client-tls-series-20261024T133402Z/: execution order, summaries and independent verification.
- Per-case directories: query, TLS proof, settings, binary identity, pool snapshots, pgbench output and latency/log-hash metadata.
- benchmark-one-tls-proxysql.py and benchmark-one-tls-pgbouncer.py: reproduction scripts.

Large transactions.*.gz files remain in their original per-case /home/rene/pg-network-bench/results/ directories on lon104; they are excluded from Git. Their uncompressed hashes are retained in latency-percentiles.json.
