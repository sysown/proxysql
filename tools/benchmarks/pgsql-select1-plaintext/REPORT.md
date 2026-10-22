# SELECT 1 without TLS: ProxySQL and PgBouncer

One 60-second measured run per implementation, following a 20-second warmup. Localhost TCP on lon104; 50 clients; 16 pgbench threads; simple query protocol; SELECT 1; 64 pre-established backend connections. Proxy CPU 0; client CPUs 2,4,6,8,10,12,14,16; performance governor. ProxySQL uses one worker and native backend protocol; PgBouncer uses transaction pooling. TLS is disabled and checked on both hops. No perf or custom timers.

| Implementation | TPS | Latency (ms) | CPU µs/query | User µs/query | Kernel µs/query |
|---|---:|---:|---:|---:|---:|
| ProxySQL phased baseline (9f92e9d84) | 42457.30 | 1.177 | 23.513 | 6.785 | 16.727 |
| ProxySQL deferred I/O (b17a986f3) | 42949.15 | 1.164 | 23.239 | 6.626 | 16.613 |
| PgBouncer 1.26.1 | 58644.43 | 0.852 | 17.004 | 1.904 | 15.101 |

Deferred I/O versus baseline: +1.16% TPS. Deferred I/O versus PgBouncer: -26.76% TPS. Baseline versus PgBouncer: -27.60% TPS.

Backend creation occurs only in preparation, before warmup. ProxySQL ConnOK stays at 64 and ConnERR at 0; Used + Free stays at 64 for all 62 snapshots. PgBouncer retains exactly the same 64 server identities (backend PID, connection time, pointer); sv_login stays zero; connection logs contain no server creation or closure during warmup or measurement. All runs have zero failed transactions.

| Implementation | Used/active mean (range) | Free/idle mean (range) |
|---|---:|---:|
| ProxySQL phased baseline (9f92e9d84) | 38.10 (3–50) | 25.90 (14–61) |
| ProxySQL deferred I/O (b17a986f3) | 35.78 (4–50) | 28.22 (14–60) |
| PgBouncer 1.26.1 | 9.86 (3–29) | 39.39 (17–58) |

CPU/query uses process user/system tick deltas divided by proxy query-counter deltas over approximately seconds 5–55. Pool means use the same central snapshots. PgBouncer active/idle counters are reported alongside ProxySQL used/free; their internal state definitions differ. PgBouncer also has sv_used/sv_tested states, so active plus idle alone need not equal 64; the assertions include all server states. With 64 backends and 50 clients, idle backends are expected.

These are preliminary single-run comparisons, not confidence intervals. The temporary PgBouncer listener used a dynamically selected free TCP port (recorded in port.txt) and the existing PgBouncer binary; other PgBouncer listeners were untouched. ProxySQL used port 6233. Prior ProxySQL runtime was restored and the temporary PgBouncer stopped after measurement.

Two PgBouncer preparation attempts were rejected before warmup or measurement: an occupied listener port, then a mistaken zero server lifetime causing immediate backend retirement. The successful run uses a free listener port and 86400-second lifetime and idle timeout. Neither rejected attempt contributes performance numbers.

Artifacts include raw pgbench output, per-second snapshots, prepared pools, binary hashes, plaintext checks, settings, and harnesses. No source changes or compilation were performed.
