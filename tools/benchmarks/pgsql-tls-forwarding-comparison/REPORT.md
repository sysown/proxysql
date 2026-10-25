# TLS comparison after the forwarding patches

The latest patches apply to the TLS path, but neither workload shows a throughput improvement in this single-client comparison. Fresh previous-build, latest-build and PgBouncer measurements isolate the three forwarding patches from the earlier TLS handshake-cache optimization.

## Throughput

| Workload | Previous ProxySQL TPS | Latest ProxySQL TPS | PgBouncer TPS | Latest vs previous | Latest vs PgBouncer |
|---|---:|---:|---:|---:|---:|
| SELECT 1 | 7,738.20 | 7,733.42 | 7,824.21 | -0.06% | -1.16% |
| 4KB / 42 rows | 4,290.39 | 4,264.18 | 4,089.38 | -0.61% | +4.27% |

Each cell represents one fresh unprofiled sixty-second measurement. Small differences are preliminary observations, not repeated-run confidence estimates. Execution order is preserved in the series plan: previous/latest/PgBouncer for SELECT 1, then latest/previous/PgBouncer for 4KB. This reverses the ProxySQL order between workloads but does not eliminate time-dependent variation.

## Latency and proxy CPU

Latency is measured from every successful transaction using pgbench logs on tmpfs. CPU covers the proxy process in the central measurement interval; it excludes pgbench and PostgreSQL.

| Workload | Build | Mean µs | p95 µs | p99 µs | User CPU/query µs | Kernel CPU/query µs | Total CPU/query µs |
|---|---|---:|---:|---:|---:|---:|---:|
| SELECT 1 | Previous ProxySQL | 126.58 | 159 | 187 | 26.18 | 30.76 | 56.94 |
| SELECT 1 | Latest ProxySQL | 126.65 | 159 | 188 | 26.31 | 30.13 | 56.44 |
| SELECT 1 | PgBouncer | 125.09 | 157 | 193 | 23.01 | 29.65 | 52.66 |
| 4KB / 42 rows | Previous ProxySQL | 230.24 | 308 | 359 | 41.63 | 39.53 | 81.17 |
| 4KB / 42 rows | Latest ProxySQL | 231.54 | 309 | 361 | 40.91 | 39.78 | 80.70 |
| 4KB / 42 rows | PgBouncer | 241.17 | 334 | 362 | 41.09 | 41.48 | 82.57 |

## Conditions and source identity

lon104, localhost TCP on both hops, PostgreSQL backend, one persistent workload client, one pgbench job pinned to CPU two, one proxy worker/core pinned to CPU zero, controller pinned to CPU eighteen, performance governor. Ten backend connections are established before warmup and retained throughout the run. Each case has twenty seconds warmup and sixty seconds measured. Simple query protocol; exact query snapshots are preserved and match across all builds.

TLSv1.3 with TLS_AES_256_GCM_SHA384 is verified on both hops. Workload clients use PGSSLMODE=require. ProxySQL frontend SSL and backend server use_ssl are enabled. PgBouncer server_tls_sslmode=require; client_tls_sslmode=allow permits plaintext administrative monitoring, while every benchmark workload connection requires TLS. Administrative monitoring stays plaintext for both products.

ProxySQL uses the native backend protocol, commands_stats=false, query_digests=false, query_processor_parser=0, free_connections_pct=100, and no backend maximum age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10, reserve_pool_size=0, and long idle/lifetime settings. No profiling or source timing hooks are enabled.

Previous source: `de5cfbba7de79151cf8c9e847b9d293d65a29b57`. It already includes the frontend TLS handshake-completion cache. Latest source: `754dc4af4792b22c825d9663c4a86739bc0cbaff`. It adds the raw COPY negative filter, consumed completed-session work flag and bounded native DataRow span copying. Shared-pool behavior is unchanged. Both executables are the same immutable binaries used in the preceding work; no rebuild was needed for this comparison.

PgBouncer version: PgBouncer 1.26.1. Both ProxySQL executables intentionally retain the same embedded version string; use the recorded source commits and SHA256 values to identify them. Binary metadata, runtime settings and the TLS proof are captured per case.

## Pool, output and audit checks

All six cases have zero failed transactions and retain the same ten backend connections. ProxySQL ConnOK remains ten, ConnERR zero, and ConnUsed plus ConnFree remains ten in every snapshot. PgBouncer retains all backend identities and logs no server connection creation or closing during the steady period. Its sv_used/sv_tested states are retained pool states and should not be equated with executing queries; all server states sum to ten.

Before pool preparation, exact text output for each workload was compared against direct PostgreSQL output over TLS, confirming the scalar result or all forty-two rows. Digest maps remain empty and unchanged. Every isolated instance stops afterward, and the new harnesses use exclusive locks and explicit interrupt cleanup.

Independent verification checked all **2,155,902 transaction records**, uncompressed log hashes, exact nearest-rank percentile boundaries, raw-log means, binary hashes, runtime variables, TLS evidence, pool retention and cleanup. Main-worktree staged changes remain unchanged. No product code or repository tests were modified by this comparison.

## Artifacts

- [comparison.json](comparison.json): full measurements, latency metadata, pool ranges, source/binary provenance and relative differences.
- Per-case directories: query text, output hash, TLS proof, pgbench output, settings and one-second pool snapshots.
- The series directory: execution plan, command manifest, completion marker and independent audit.
- Standalone benchmark, query-output, report, verification and controller scripts are stored alongside this report.

Raw transactions.*.gz archives remain in their original /home/rene/pg-network-bench/results/ directories on lon104 and are excluded from Git. Their uncompressed hashes remain in latency metadata.
