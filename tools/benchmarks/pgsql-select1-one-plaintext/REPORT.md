# One-client SELECT 1 without TLS: ProxySQL and PgBouncer

One 60-second measured run per implementation, following a 20-second warmup. Localhost TCP on lon104; one client; one pgbench thread; simple query protocol; SELECT 1; 64 pre-established backend connections. Proxy CPU 0; client CPUs 2,4,6,8,10,12,14,16; performance governor. ProxySQL uses one worker and native backend protocol; PgBouncer uses transaction pooling. TLS is disabled and checked on both hops. No perf or custom timers.

| Implementation | TPS | Latency (ms) | CPU µs/query | User µs/query | Kernel µs/query |
|---|---:|---:|---:|---:|---:|
| ProxySQL upstream v3.0 (a0781dd90) | 9831.41 | 0.102 | 45.519 | 16.340 | 29.180 |
| ProxySQL phased baseline (9f92e9d84) | 10464.56 | 0.095 | 44.606 | 16.302 | 28.304 |
| ProxySQL deferred I/O (b17a986f3) | 10479.04 | 0.095 | 45.402 | 16.611 | 28.792 |
| PgBouncer 1.26.1 | 13313.22 | 0.075 | 27.634 | 5.319 | 22.315 |

Deferred I/O versus upstream: +6.59% TPS. Deferred I/O versus baseline: +0.14% TPS. Deferred I/O versus PgBouncer: -21.29% TPS. Baseline versus PgBouncer: -21.40% TPS.

Backend creation occurs only in preparation, before warmup. ProxySQL ConnOK stays at 64 and ConnERR at 0; Used + Free stays at 64 for all 62 snapshots. PgBouncer retains exactly the same 64 server identities (backend PID, connection time, pointer); sv_login stays zero; connection logs contain no server creation or closure during warmup or measurement. All runs have zero failed transactions.

| Implementation | Used/active mean (range) | Free/idle mean (range) |
|---|---:|---:|
| ProxySQL upstream v3.0 (a0781dd90) | 0.98 (0–1) | 63.02 (63–64) |
| ProxySQL phased baseline (9f92e9d84) | 0.88 (0–1) | 63.12 (63–64) |
| ProxySQL deferred I/O (b17a986f3) | 0.86 (0–1) | 63.14 (63–64) |
| PgBouncer 1.26.1 | 0.67 (0–1) | 6.45 (0–64) |

CPU/query uses process user/system tick deltas divided by proxy query-counter deltas over approximately seconds 5–55. Pool means use the same central snapshots. PgBouncer active/idle counters are reported alongside ProxySQL used/free; their internal state definitions differ. PgBouncer also has sv_used/sv_tested states, so active plus idle alone need not equal 64; the assertions include all server states. With 64 backends and one client, idle backends are expected.

These are preliminary single-run comparisons, not confidence intervals. The temporary PgBouncer listener used a dynamically selected free TCP port (recorded in port.txt) and the existing PgBouncer binary; other PgBouncer listeners were untouched. ProxySQL used port 6233. Prior ProxySQL runtime was restored and the temporary PgBouncer stopped after measurement.

The deferred-I/O source is committed as 7ec3bfd59 plus b17a986f3; neither the index nor the working tree contains uncommitted source changes. Upstream v3.0 was checked at 8b23f48df6a62800ddd0ab57078bcbcc24ca246a. Its changes since a0781dd90 affect packaging/CI/documentation only; src, lib, include, deps and common_mk are identical, and Makefile changes only add packaging targets. The upstream row uses the preserved a0781dd90 binary with recorded SHA-256 rather than rebuilding identical runtime source. This is explicitly not a newly compiled 8b23f48df binary.

Artifacts include raw pgbench output, per-second snapshots, prepared pools, binary hashes, plaintext checks, settings, and harnesses. No source changes or compilation were performed.
