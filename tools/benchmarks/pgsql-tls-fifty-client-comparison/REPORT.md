# Fifty-client TLS comparison after the forwarding patches

With 50 clients, 16 pgbench threads, 10 retained backends and TLS on both hops, latest ProxySQL measured 3.82% more TPS than the previous build for 4KB, and 1.29% less for SELECT 1. These are single-run observations. The three forwarding patches are compared independently of the earlier TLS handshake-cache change.

## Throughput

| Workload | Previous ProxySQL TPS | Latest ProxySQL TPS | PgBouncer TPS | Latest vs previous | Latest vs PgBouncer |
|---|---:|---:|---:|---:|---:|
| SELECT 1 | 30,852.11 | 30,454.39 | 26,764.49 | -1.29% | +13.79% |
| 4KB / 42 rows | 22,011.74 | 22,852.61 | 20,368.52 | +3.82% | +12.20% |

Each cell represents one fresh unprofiled sixty-second measurement. Small differences are preliminary observations, not repeated-run confidence estimates. Execution order is preserved in the series plan: previous/latest/PgBouncer for SELECT 1, then latest/previous/PgBouncer for 4KB. This reverses the ProxySQL order between workloads but does not eliminate time-dependent variation.

## Latency and proxy CPU

Latency is measured from every successful transaction using pgbench logs on tmpfs. CPU covers the proxy process in the central measurement interval; it excludes pgbench and PostgreSQL.

| Workload | Build | Mean ms | p95 ms | p99 ms | User CPU/query µs | Kernel CPU/query µs | Total CPU/query µs |
|---|---|---:|---:|---:|---:|---:|---:|
| SELECT 1 | Previous ProxySQL | 1.617 | 1.969 | 2.036 | 14.59 | 17.74 | 32.33 |
| SELECT 1 | Latest ProxySQL | 1.639 | 1.995 | 2.063 | 14.68 | 18.06 | 32.74 |
| SELECT 1 | PgBouncer | 1.865 | 1.944 | 2.013 | 15.20 | 21.98 | 37.18 |
| 4KB / 42 rows | Previous ProxySQL | 2.268 | 2.559 | 2.640 | 24.11 | 21.22 | 45.33 |
| 4KB / 42 rows | Latest ProxySQL | 2.185 | 2.450 | 2.538 | 22.44 | 21.20 | 43.64 |
| 4KB / 42 rows | PgBouncer | 2.452 | 2.771 | 2.825 | 22.41 | 26.46 | 48.87 |

## Conditions and source identity

lon104, localhost TCP on both hops, PostgreSQL backend, fifty persistent workload clients, sixteen pgbench threads on CPUs 2,4,6,8,10,12,14,16, one proxy worker/core pinned to CPU zero, controller pinned to CPU eighteen, performance governor. 10 backend connections are established before warmup and retained throughout the run. Each case has twenty seconds warmup and sixty seconds measured. Simple query protocol; exact query snapshots are preserved and match across all builds.

TLSv1.3 with TLS_AES_256_GCM_SHA384 is verified on both hops. Workload clients use PGSSLMODE=require. ProxySQL frontend SSL and backend server use_ssl are enabled. PgBouncer server_tls_sslmode=require; client_tls_sslmode=allow permits plaintext administrative monitoring, while every benchmark workload connection requires TLS. Administrative monitoring stays plaintext for both products.

ProxySQL uses the native backend protocol, commands_stats=false, query_digests=false, query_processor_parser=0, free_connections_pct=100, and no backend maximum age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10, reserve_pool_size=0, and long idle/lifetime settings. No profiling or source timing hooks are enabled.

Previous source: `de5cfbba7de79151cf8c9e847b9d293d65a29b57`. It already includes the frontend TLS handshake-completion cache. Latest source: `754dc4af4792b22c825d9663c4a86739bc0cbaff`. It adds the raw COPY negative filter, consumed completed-session work flag and bounded native DataRow span copying. Shared-pool behavior is unchanged. Both executables are the same immutable binaries used in the preceding work; no rebuild was needed for this comparison.

PgBouncer version: PgBouncer 1.26.1. Both ProxySQL executables intentionally retain the same embedded version string; use the recorded source commits and SHA256 values to identify them. Binary metadata, runtime settings and the TLS proof are captured per case.

## Pool, output and audit checks

All six cases have zero failed transactions and retain the same 10 backend connections. ProxySQL ConnOK remains 10, ConnERR zero, and ConnUsed plus ConnFree remains 10 in every snapshot. PgBouncer retains all backend identities and logs no server connection creation or closing during the steady period. Its sv_used/sv_tested states are retained pool states and should not be equated with executing queries; all server states sum to 10.

Before pool preparation, exact text output for each workload was compared against direct PostgreSQL output over TLS, confirming the scalar result or all forty-two rows. Digest maps remain empty and unchanged. Every isolated instance stops afterward, and the new harnesses use exclusive locks and explicit interrupt cleanup.

Independent verification checked all **9,150,798 transaction records**, uncompressed log hashes, exact nearest-rank percentile boundaries, raw-log means, binary hashes, runtime variables, TLS evidence, pool retention and cleanup. Main-worktree staged changes remain unchanged. No product code or repository tests were modified by this comparison.

## Artifacts

- [comparison.json](comparison.json): full measurements, latency metadata, pool ranges, source/binary provenance and relative differences.
- Per-case directories: query text, output hash, TLS proof, pgbench output, settings and one-second pool snapshots.
- The series directory: execution plan, command manifest, completion marker and independent audit.
- Standalone benchmark, query-output, report, verification and controller scripts are stored alongside this report.

Raw transactions.*.gz archives remain in their original /home/rene/pg-network-bench/results/ directories on lon104 and are excluded from Git. Their uncompressed hashes remain in latency metadata.

## ProxySQL backend usage

Central-window one-second samples. Averages describe the sampled pool state; the retained connection count is constant.

| Workload | Build | ConnUsed range | ConnFree range | Mean used | Mean free | Samples with free connections |
|---|---|---:|---:|---:|---:|---:|
| SELECT 1 | Previous | 10–10 | 0–0 | 10.00 | 0.00 | 0/51 |
| SELECT 1 | Latest | 10–10 | 0–0 | 10.00 | 0.00 | 0/51 |
| 4KB / 42 rows | Previous | 10–10 | 0–0 | 10.00 | 0.00 | 0/51 |
| 4KB / 42 rows | Latest | 10–10 | 0–0 | 10.00 | 0.00 | 0/51 |

The frontend client count increases from the preceding comparison; the backend cap is explicitly recorded above. The driver also uses the established multi-client thread count and CPU set. Pool capacity is prepared completely before warmup; no new backend connections are permitted during measurement.
