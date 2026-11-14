# MySQL sysbench comparison: standard ProxySQL 4.0 build

**48 cases completed; zero ignored SQL errors and zero reconnects.** Both native TCP and fast forward use the same freshly rebuilt **ProxySQL 4.0.13-144-ge30a016** executable. All paths use one MySQL backend; native TCP uses MySQL HGM.

This rerun supersedes the [earlier basic benchmark](2026-11-13-tcp-sysbench-basic.html), whose executable had an incorrect 3.0.13 version banner after bypassing the top-level build. Earlier raw measurements are preserved.

## Standard build

The build ran in the original repository using its top-level Makefile:

```sh
make PROXYSQL40=1 clean
make PROXYSQL40=1 -j8 NPROCS=8
./src/proxysql --version
# ProxySQL version 4.0.13-144-ge30a016, codename Truls
```

Dependencies, the core and plugins were built by the normal top-level targets. The benchmark started after compilation finished. The running process executable path and loaded TCP plugin were checked; the loaded plugin hash matches the rebuilt artifact.

| Artifact | SHA-256 |
|---|---|
| `src/proxysql` | `4692b1f0924a218df0c3721e0febf41176a118418cbdcf1046a5022a9999e037` |
| `plugins/tcp_proxy/proxysql_tcp_proxy.so` | `bd6886b009b0c18a2ee6d6f06774435429239b9b53d73795188e96d73efcff30` |

## Method


sysbench 1.0.20, prepared statements, unchanged stock point-select and read-only Lua scripts. Eight prewarmed InnoDB tables of 100,000 rows; 2 GiB buffer pool; uniform random keys. MySQL 8.0.46, maximum connections 4096 and prepared statements 262144. TLS disabled at the server and compression restricted to uncompressed.

Native TCP and HAProxy have two forwarding workers and a two-core budget (CPUs 6–7). Database CPUs 0–5; sysbench CPUs 8–13. ProxySQL keeps its MySQL frontend workers and Admin enabled. HAProxy is 3.5-dev11 from the local checkout. The same ProxySQL process exposes native TCP and permanent fast-forward listeners; modes run sequentially and their order rotates between cells.

No checkpoint, reporting wrapper, per-session security scan or extra profiling was used. Dataset prewarm ran once before all tests.

## Point-select: queries per second

| Connections | Direct MySQL | Native TCP | HAProxy | Fast forward |
|---:|---:|---:|---:|---:|
| 4 | 73,338 | 48,739 | 45,571 | 48,263 |
| 16 | 124,467 | 107,867 | 106,714 | 107,708 |
| 64 | 123,350 | 106,557 | 100,341 | 108,950 |
| 256 | 115,782 | 101,994 | 104,226 | 101,652 |
| 512 | 107,300 | 92,398 | 87,585 | 83,284 |
| 1024 | 97,836 | 76,733 | 73,862 | 68,710 |

## Read-only: transactions per second

| Connections | Direct MySQL | Native TCP | HAProxy | Fast forward |
|---:|---:|---:|---:|---:|
| 4 | 2,630 | 2,018 | 2,172 | 2,217 |
| 16 | 5,758 | 5,578 | 5,545 | 5,519 |
| 64 | 5,643 | 5,767 | 5,898 | 5,958 |
| 256 | 5,385 | 5,507 | 5,531 | 5,517 |
| 512 | 4,997 | 4,906 | 4,148 | 4,411 |
| 1024 | 4,594 | 4,247 | 4,121 | 2,509 |

## Point-query p95 latency (ms)

| Connections | Direct MySQL | Native TCP | HAProxy | Fast forward |
|---:|---:|---:|---:|---:|
| 4 | 0.07 | 0.09 | 0.10 | 0.10 |
| 16 | 0.18 | 0.16 | 0.17 | 0.20 |
| 64 | 0.73 | 0.64 | 0.68 | 0.90 |
| 256 | 2.91 | 2.71 | 2.66 | 2.71 |
| 512 | 7.70 | 5.77 | 6.67 | 7.17 |
| 1024 | 15.83 | 13.22 | 15.00 | 15.27 |

## Read-only transaction p95 latency (ms)

| Connections | Direct MySQL | Native TCP | HAProxy | Fast forward |
|---:|---:|---:|---:|---:|
| 4 | 2.03 | 2.76 | 2.66 | 2.81 |
| 16 | 3.89 | 3.30 | 3.36 | 3.55 |
| 64 | 15.27 | 12.30 | 12.98 | 15.00 |
| 256 | 64.47 | 57.87 | 65.65 | 59.99 |
| 512 | 121.08 | 106.75 | 158.63 | 153.02 |
| 1024 | 272.27 | 244.38 | 248.83 | 369.77 |

## Interpretation

At 1,024 connections, native TCP delivered **76,733 point QPS**, HAProxy **73,862**, and fast forward **68,710**. Read-only throughput was **4,247 TPS** native, **4,121 TPS** HAProxy and **2,509 TPS** fast forward.

These are single five-second runs per cell. They show the throughput and latency observed in this setup; small differences require repeated runs before claiming an advantage. The benchmark does not establish the cause of fast-forward scaling behavior.

A point-select event is one primary-key SELECT. A read-only transaction contains ten point reads, four range reads, and BEGIN/COMMIT (16 SQL statements). Its p95 covers the entire transaction.

## Raw evidence

[CSV](2026-11-13-tcp-sysbench-v4.csv) · [JSON with build identity and verification](2026-11-13-tcp-sysbench-v4.json) · [Build manifest](2026-11-13-tcp-sysbench-v4-logs/build-manifest.json) · [Launcher](2026-11-13-tcp-sysbench-v4-logs/launcher.py) · [Dataset prewarm log](2026-11-13-tcp-sysbench-v4-logs/prewarm.log)

All 48 unique cases were checked against their raw logs, including counts, elapsed time, throughput, errors and one/16 SQL statements per event. Benchmark daemons were stopped after completion. Build logs remain in `/tmp/tcp-proper-v4-rebuild/`; their hashes are recorded in the manifest.

| Workload | Connections | Direct | Native | HAProxy | Fast forward |
|---|---:|---|---|---|---|
| oltp_point_select | 4 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-4-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-4-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-4-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-4-ff.log) |
| oltp_point_select | 16 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-16-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-16-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-16-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-16-ff.log) |
| oltp_point_select | 64 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-64-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-64-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-64-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-64-ff.log) |
| oltp_point_select | 256 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-256-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-256-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-256-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-256-ff.log) |
| oltp_point_select | 512 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-512-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-512-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-512-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-512-ff.log) |
| oltp_point_select | 1024 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-1024-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-1024-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-1024-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_point_select-1024-ff.log) |
| oltp_read_only | 4 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-4-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-4-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-4-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-4-ff.log) |
| oltp_read_only | 16 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-16-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-16-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-16-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-16-ff.log) |
| oltp_read_only | 64 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-64-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-64-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-64-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-64-ff.log) |
| oltp_read_only | 256 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-256-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-256-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-256-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-256-ff.log) |
| oltp_read_only | 512 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-512-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-512-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-512-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-512-ff.log) |
| oltp_read_only | 1024 | [direct](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-1024-direct.log) | [native](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-1024-native.log) | [haproxy](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-1024-haproxy.log) | [ff](2026-11-13-tcp-sysbench-v4-logs/oltp_read_only-1024-ff.log) |

## Command

```sh
sysbench --config-file=PRIVATE.cnf --threads=N --time=5 --events=0 \
  --db-driver=mysql --db-ps-mode=auto --mysql-ssl=off --mysql-compression=off \
  --rand-type=uniform --rand-seed=20261113 --tables=8 --table_size=100000 \
  --range_size=100 --percentile=95 /usr/share/sysbench/oltp_point_select.lua run
```

Use `oltp_read_only.lua` for the read-only workload. Credentials were kept in private config files. The basic launcher and original logs remain under `/tmp/tcp-sysbench-benchmark/`.
