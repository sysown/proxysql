# Basic MySQL sysbench comparison

**Superseded:** See the [standard ProxySQL 4.0 build rerun](2026-11-13-tcp-sysbench-v4.html). This earlier run used a PROXYSQL40-enabled executable with an incorrect 3.0.13 version banner after bypassing the top-level build; its raw measurements are retained.

**48 runs completed successfully; zero ignored SQL errors and zero reconnects.** One five-second stock sysbench run per configuration, no repeat-run averages.

All backends are the same MySQL server. Native TCP uses MySQL HGM only.

## Method

sysbench 1.0.20, prepared statements, unchanged stock point-select and read-only Lua scripts. Eight prewarmed InnoDB tables of 100,000 rows; 2 GiB buffer pool; uniform random keys. MySQL 8.0.46, maximum connections 4096 and prepared statements 262144. TLS disabled at the server and compression restricted to uncompressed.

Native TCP and HAProxy have two forwarding workers and a two-core budget (CPUs 6–7). Database CPUs 0–5; sysbench CPUs 8–13. ProxySQL keeps its MySQL frontend workers and Admin enabled. HAProxy is 3.5-dev11 from the local checkout. The same ProxySQL process exposes native TCP and permanent fast-forward listeners; modes run sequentially and their order rotates between cells.

No checkpoint, reporting wrapper, per-session security scan or extra profiling was used. Dataset prewarm ran once before all tests.

## Point-select: queries per second

| Connections | Direct MySQL | Native TCP | HAProxy | Fast-forward |
|---:|---:|---:|---:|---:|
| 4 | 75,217 | 48,683 | 44,839 | 47,753 |
| 16 | 133,238 | 109,715 | 110,484 | 93,233 |
| 64 | 130,130 | 108,184 | 110,564 | 41,366 |
| 256 | 120,500 | 95,323 | 104,545 | 18,910 |
| 512 | 112,324 | 80,992 | 80,948 | 15,057 |
| 1024 | 100,609 | 81,931 | 74,408 | 12,437 |

## Read-only: transactions per second

| Connections | Direct MySQL | Native TCP | HAProxy | Fast-forward |
|---:|---:|---:|---:|---:|
| 4 | 3,021 | 1,969 | 2,158 | 2,088 |
| 16 | 6,118 | 5,710 | 5,697 | 5,083 |
| 64 | 5,888 | 5,808 | 5,988 | 2,750 |
| 256 | 5,300 | 5,157 | 5,877 | 1,117 |
| 512 | 4,882 | 5,018 | 4,945 | 907 |
| 1024 | 4,630 | 4,286 | 4,138 | 773 |

## Point-query p95 latency (ms)

| Connections | Direct MySQL | Native TCP | HAProxy | Fast-forward |
|---:|---:|---:|---:|---:|
| 4 | 0.06 | 0.11 | 0.13 | 0.10 |
| 16 | 0.15 | 0.15 | 0.16 | 0.24 |
| 64 | 0.57 | 0.62 | 0.61 | 2.71 |
| 256 | 2.86 | 2.76 | 2.66 | 16.41 |
| 512 | 5.67 | 7.84 | 8.13 | 36.24 |
| 1024 | 11.45 | 12.98 | 14.46 | 86.00 |

## Read-only transaction p95 latency (ms)

| Connections | Direct MySQL | Native TCP | HAProxy | Fast-forward |
|---:|---:|---:|---:|---:|
| 4 | 1.79 | 2.61 | 2.81 | 2.07 |
| 16 | 3.19 | 3.19 | 3.19 | 4.65 |
| 64 | 12.08 | 11.87 | 11.45 | 34.95 |
| 256 | 70.55 | 64.47 | 45.79 | 325.98 |
| 512 | 153.02 | 137.35 | 108.68 | 682.06 |
| 1024 | 350.33 | 244.38 | 248.83 | 1,304.21 |

## Interpretation

Native TCP and HAProxy were broadly comparable in this basic run; neither led at every connection count. At 16 connections, point-select throughput was 109,715 QPS native versus 110,484 HAProxy. At 1024, native reached 81,931 QPS versus 74,408 HAProxy. Read-only at 1024 reached 4,286 TPS native versus 4,138 HAProxy.

Fast-forward throughput fell markedly at higher concurrency: 12,437 point QPS and 773 read-only TPS at 1024 connections. This run measures that behavior but does not profile its cause.

A point-select event is one primary-key SELECT. A read-only transaction contains ten point reads, four range reads, and BEGIN/COMMIT (16 SQL statements). Its p95 covers the entire transaction. These are short single-pass observations; small differences and occasional proxy throughput above the direct baseline require repeats before treating them as advantages.

## Raw evidence

[CSV](2026-11-13-tcp-sysbench-basic.csv) · [JSON](2026-11-13-tcp-sysbench-basic.json)

Each raw log includes the stock sysbench counts, measured elapsed time, rates, p95 and error totals. Root checked all 48 unique cells, zero errors/reconnects, rates against counts/time, and one/16 SQL statements per event as appropriate. All owned benchmark processes were stopped after completion.

| Workload | Connections | Direct | Native | HAProxy | Fast-forward |
|---|---:|---|---|---|---|
| oltp_point_select | 4 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-4-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-4-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-4-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-4-ff.log) |
| oltp_point_select | 16 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-16-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-16-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-16-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-16-ff.log) |
| oltp_point_select | 64 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-64-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-64-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-64-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-64-ff.log) |
| oltp_point_select | 256 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-256-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-256-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-256-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-256-ff.log) |
| oltp_point_select | 512 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-512-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-512-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-512-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-512-ff.log) |
| oltp_point_select | 1024 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-1024-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-1024-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-1024-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_point_select-1024-ff.log) |
| oltp_read_only | 4 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-4-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-4-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-4-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-4-ff.log) |
| oltp_read_only | 16 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-16-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-16-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-16-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-16-ff.log) |
| oltp_read_only | 64 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-64-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-64-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-64-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-64-ff.log) |
| oltp_read_only | 256 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-256-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-256-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-256-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-256-ff.log) |
| oltp_read_only | 512 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-512-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-512-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-512-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-512-ff.log) |
| oltp_read_only | 1024 | [direct](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-1024-direct.log) | [native](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-1024-native.log) | [haproxy](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-1024-haproxy.log) | [ff](2026-11-13-tcp-sysbench-basic-logs/oltp_read_only-1024-ff.log) |

## Command

```sh
sysbench --config-file=PRIVATE.cnf --threads=N --time=5 --events=0 \
  --db-driver=mysql --db-ps-mode=auto --mysql-ssl=off --mysql-compression=off \
  --rand-type=uniform --rand-seed=20261113 --tables=8 --table_size=100000 \
  --range_size=100 --percentile=95 /usr/share/sysbench/oltp_point_select.lua run
```

Use `oltp_read_only.lua` for the read-only workload. Credentials were kept in private config files. The basic launcher and original logs remain under `/tmp/tcp-sysbench-benchmark/`.
