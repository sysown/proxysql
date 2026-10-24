# Cached frontend TLS handshake: first benchmark

An isolated cache experiment on optimized f3163c864. Code commit: bd2353e922cb5cb13e5f6941f1079fd1685511ff, branch optimization/pgsql-tls-handshake-cache. No scheduler or BIO-counter optimization is combined with this change.

## Result

500 clients, 10 pre-established retained backends, localhost TCP on lon104, 42-row / 4063-byte response, TLSv1.3 AES-256-GCM on both hops, one proxy worker pinned to CPU 0, 16 pgbench jobs pinned to CPUs 2,4,6,8,10,12,14,16, performance governor, native backend protocol, commands_stats=false and query_digests=false. Twenty seconds warmup, sixty seconds pgbench measurement, one-second pool snapshots and complete transaction logs on tmpfs. Administrative monitoring uses plaintext.

The before column reuses the recorded 2026-10-23T11:45:39Z unprofiled f3163c864 run. The patched run was recorded at 2026-10-24T12:57:11Z. This is a preliminary comparison across runs at different times, rather than a contemporaneous paired A/B or a confidence interval. It does not establish that the entire observed difference was caused by the cache. No baseline was rerun.

| Metric | Recorded f3163c864 | Cached TLS handshake | Change |
|---|---:|---:|---:|
| TPS | 17,626.93 | 19,199.90 | +8.92% |
| Mean latency (ms) | 28.349 | 26.026 | -8.19% |
| p50 latency (ms) | 28.142 | 25.855 | -8.13% |
| p95 latency (ms) | 29.186 | 26.854 | -7.99% |
| p99 latency (ms) | 34.842 | 32.267 | -7.39% |
| User CPU/query (µs) | 31.371 | 28.616 | -8.78% |
| Kernel CPU/query (µs) | 25.177 | 23.284 | -7.52% |
| Total proxy CPU/query (µs) | 56.548 | 51.900 | -8.22% |

The patched run completes 1,097,545 successful transactions across all 500 clients, with zero failed transactions. Backend ConnOK stays 10 and ConnERR stays 0 in all 62 snapshots. During the central measurement snapshots, ConnUsed ranges 10–10 and ConnFree ranges 0–0. No backend connection is created during warmup or measurement. Raw-log hashes and nearest-rank p50/p95/p99 thresholds were independently checked against all 1,097,545 records.

## Separate call-count verification

The throughput run has no perf, eBPF, strace or source timing instrumentation. A separate isolated run attaches a single worker uprobe to SSL_is_init_finished and gates counters only after all 500 benchmark clients and ten backends are established. A fresh TLS frontend connection exercises the probe before the gate; it closes before counting begins. This verifies probe attachment without introducing connection setup into the counting interval.

| Check | Result |
|---|---:|
| Recorded baseline calls/query | 11.0003 |
| Patched steady-state calls | 0 |
| Counting interval (seconds) | 20.0727 |
| Pool query-counter bracket | 389,142 |
| Outside-window calls proving the probe works | 35 |

The patched window has zero calls, so query-counter boundary slack cannot affect the zero-per-query conclusion. Both the throughput run and the call-count run retain ten backends with unchanged ConnOK/ConnERR and finish with zero failed transactions. The diagnostic query rate is not used as a throughput result.

## Implementation

PgSQL_Data_Stream owns a tls13_handshake_complete boolean and an inline ssl_handshake_is_complete() predicate. The flag starts false and becomes true only after SSL_do_handshake returns success and the existing peer-certificate/SPIFFE checks finish. It is set only for owned frontend TLS 1.3 streams. The six active call sites in frontend read/drain, write-poll and poll-rearm paths use the predicate.

The flag resets before a new frontend SSL object and on backend TLS borrowing/release. Older TLS versions and borrowed backend streams continue querying OpenSSL. Read/write, error handling and ciphertext draining remain on their existing paths, including TLS 1.3 post-handshake traffic. A TLS 1.2 frontend connection and SELECT 1 smoke check passed before backend prewarming and measurement; its output is retained.

The source was built from f3163c864 in a separate worktree at /home/rene/pg-network-bench/src/proxysql-tls-handshake-cache. Existing dependency artifacts were shared by hard link and only lib/ and src/ were built. Release options are -O2 -fno-omit-frame-pointer -ggdb with PROXYSQL31, FFTO, TSDB, ED25519 and CLICKHOUSE enabled. The embedded version string is held at 3.1.11-dev-ga0781dd to match the baseline; source commit and binary SHA identify the new build. The build succeeded. No test files were changed or suite run under the benchmark-first scope.

Candidate binary SHA256: 3fa61772707b3edee8342c84a1dfd1b6b4b2b18cd9c94b5e8a856fb3ad8a16f1.

## Artifacts

- source.patch and source/: exact committed change and source snapshots. source-provenance.json verifies their hashes.
- baseline/: reused throughput metadata and prior TLS caller-attribution evidence.
- tls-handshake-cache-benchmark-cached-20261024T125711Z/: unprofiled result, pool snapshots, native/TLS settings, full client-completion counts and percentile metadata.
- tls-handshake-cache-counts-cached-20261024T130056Z/: generated probe, raw maps, positive-control output, exact gate/query brackets and isolated-instance cleanup.
- latency-audit.json: independent log-hash and quantile-rank verification.
- comparison.json: machine-readable before/after comparison and checks.

Raw transaction logs remain on lon104 at /home/rene/pg-network-bench/results/tls-handshake-cache-benchmark-cached-20261024T125711Z/transactions.*.gz. They are excluded from Git; individual uncompressed hashes are in latency-percentiles.json.
