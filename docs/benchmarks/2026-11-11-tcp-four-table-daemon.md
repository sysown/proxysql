# Four-table TCP proxy full-daemon benchmark

Date: 2026-11-11. Status: local loopback measurement; not a deployment claim.

Environment: `dev128`, 6.8.0-85-generic, x86_64, 32 CPUs, `AMD Ryzen 9 5950X 16-Core Processor`. Load average at start: [0.9248046875, 0.97265625, 1.08056640625]. Python: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`.

## Provenance and scope

- ProxySQL host: `/tmp/tcp-four-table/core-final/proxysql` sha256 `81c4f518f15e05af5de94a14ac445570ffbd0845e9f7bd4a2e9a85b281800d02`.
- Plugin source: `/tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so` sha256 `f4111f8949276645977d9ee917eed9784c574017d3a00709050b614ca527b9c4`; immutable run snapshot `/tmp/tcp-four-table/validation-final/benchmark-raw/proxysql_tcp_proxy.benchmark.snapshot.so` sha256 `f4111f8949276645977d9ee917eed9784c574017d3a00709050b614ca527b9c4`.
- ProxySQL modes use the whole daemon process PID for CPU/RSS/fd/thread values: core, Admin, SQLite, metrics, plugin and mapped HGM accounting are included. These are not `engine_harness` or engine-only measurements.
- Monitors and SQL worker listeners were disabled for mysql and pgsql modes. TCP forwarding workers and the Admin interface remained active.
- Source files: 318 files verified from `/tmp/tcp-four-table/validation-final/final-source-provenance.json` sha256 `81c828a0f52a8055fd687db9dc74b55ad9affa94f3a52201a471b22a02d7a2c2`; core manifest `05c62af6935bf59cf0902d9ad8b8637a967e782a582a9d58d5e459dc9ff3110c`, plugin manifest `d8a14d467d97dcb0b7f66f5dfef5eefbbddabd764db257331d84d335e7fccbb0`. Full list in raw JSON.

## Workload

| Parameter | Value |
|---|---|
| Mode order | direct, mysql, pgsql, haproxy |
| Backend | task-owned selector echo process PID 3402640 127.0.0.1:37645 |
| Client concurrency | 4 |
| Daemon/HAProxy worker threads | 2 |
| RTT payload / warmup / samples per connection | 64 B / 20 / 300 |
| Connections/s payload | 64 B |
| Throughput payload / duration | 65536 B / 2.0 s |
| Idle connections | 8 |

Each connection/s transaction requires connect + send + exact echo receive + close. Throughput verifies every echoed chunk byte-for-byte; MiB/s is application payload.

## Results

| Mode | Status | RTT p50 / p95 / p99 ms | Connections/s | MiB/s c→s | MiB/s s→c | Daemon CPU % | Daemon RSS KiB | Daemon fds | Daemon threads |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct | completed | 0.037 / 0.064 / 0.090 | 16137.3 | 1388.23 | 1388.23 | null | null | null | null |
| mysql | completed | 0.066 / 0.102 / 0.122 | 14015.0 | 1264.28 | 1264.28 | 133.4 | 35648 | 21 | 10 |
| pgsql | completed | 0.055 / 0.074 / 0.086 | 14557.4 | 1264.76 | 1264.76 | 131.2 | 35008 | 21 | 10 |
| haproxy | completed | 0.069 / 0.086 / 0.124 | 15690.5 | 1145.01 | 1145.01 | 130.6 | 14388 | 10 | 2 |

## Mode details

### direct: completed

- Target: 127.0.0.1:37645; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 32289; throughput transactions: 44481.
- Idle connections: 8; quiescent interval 1.000083 s; proxy idle CPU None.
- Backend reconciliation: c→s 2918303816 (expected 2918303816), s→c 2918303816 (expected 2918303816), connections 32306/32306.

### mysql: completed

- Target: 127.0.0.1:51819; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 28034; throughput transactions: 40466.
- Idle connections: 8; quiescent interval 1.00007 s; proxy idle CPU 0.0.
- Whole daemon PID during measurement `3402727`; config `/tmp/tcp-four-table/validation-final/benchmark-raw/bench-mysql/proxysql.cfg`, log `/tmp/tcp-four-table/validation-final/benchmark-raw/bench-mysql/daemon.log`, post-run returncode `0`.
- Backend reconciliation: c→s 2654904456 (expected 2654904456), s→c 2654904456 (expected 2654904456), connections 28051/28051.
- Mapped HGM reconciliation: byte deltas 2654904456/2654904456 (expected 2654904456/2654904456); Used/Free after drain 0/0.
- TCP hostgroup 20 -> MYSQL hostgroup 10 (mandatory mapping; no local server inventory). SQL recorded in raw JSON.

### pgsql: completed

- Target: 127.0.0.1:40933; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 29120; throughput transactions: 40481.
- Idle connections: 8; quiescent interval 1.000065 s; proxy idle CPU 0.0.
- Whole daemon PID during measurement `3402901`; config `/tmp/tcp-four-table/validation-final/benchmark-raw/bench-pgsql/proxysql.cfg`, log `/tmp/tcp-four-table/validation-final/benchmark-raw/bench-pgsql/daemon.log`, post-run returncode `0`.
- Backend reconciliation: c→s 2655957000 (expected 2655957000), s→c 2655957000 (expected 2655957000), connections 29137/29137.
- Mapped HGM reconciliation: byte deltas 2655957000/2655957000 (expected 2655957000/2655957000); Used/Free after drain 0/0.
- TCP hostgroup 20 -> PGSQL hostgroup 10 (mandatory mapping; no local server inventory). SQL recorded in raw JSON.

### haproxy: completed

- Target: 127.0.0.1:38819; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 31385; throughput transactions: 36650.
- Idle connections: 8; quiescent interval 1.000087 s; proxy idle CPU 0.0.
- Backend reconciliation: c→s 2405033544 (expected 2405033544), s→c 2405033544 (expected 2405033544), connections 31402/31402.
- HAProxy version 3.5-dev11 2026/11/04 - https://haproxy.org/ nbthread=2.

## Caveats

- Local loopback short runs only; Python client/backend scheduling and GIL limits apply.
- Modes run sequentially and each ProxySQL mode starts a fresh task-owned daemon.
- `mysql` and `pgsql` CPU/RSS/fd/thread figures describe the whole daemon process, not the standalone Engine harness and not a deployment footprint.
- Missing optional HAProxy is an explicit skipped mode and is never fabricated.
- A failed exact-byte precheck or benchmark phase marks that mode `error`; the process exits nonzero if any requested mode errored.

Raw JSON: `/home/rene/.codex/worktrees/483d/proxysql/docs/benchmarks/2026-11-11-tcp-four-table-daemon.json`.
