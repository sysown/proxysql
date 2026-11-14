# Mapped TCP proxy full-daemon benchmark

Date: 2026-11-11. Status: local loopback measurement; not a deployment claim.

Environment: `dev128`, 6.8.0-85-generic, x86_64, 32 CPUs, `AMD Ryzen 9 5950X 16-Core Processor`. Load average at start: [1.12353515625, 1.5009765625, 1.5498046875]. Python: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`.

## Provenance and scope

- ProxySQL host: `/tmp/native-tcp-hgm/core-final-v2-daemon` sha256 `0954cf2534ccb1217dbe4a9ade47f06b2a2a3a3db6f9b638c9a04735b2564451`.
- Plugin source: `/tmp/native-tcp-hgm/engine-binaries-candidate-v3/proxysql_tcp_proxy.release.so` sha256 `55ca8e586481a459272287ed2335448455217236b846f86ee0dc56b890b80e75`; immutable run snapshot `/tmp/native-tcp-hgm/final-validation/benchmark-raw/proxysql_tcp_proxy.benchmark.snapshot.so` sha256 `55ca8e586481a459272287ed2335448455217236b846f86ee0dc56b890b80e75`.
- ProxySQL modes use the whole daemon process PID for CPU/RSS/fd/thread values: core, Admin, SQLite, metrics, plugin and mapped HGM accounting are included. These are not `engine_harness` or engine-only measurements.
- Monitors and SQL worker listeners were disabled for static, mysql and pgsql modes. TCP forwarding workers and the Admin interface remained active.
- Approved source provenance: 17 Core snapshot files, 12 Engine/plugin snapshot files, and 2 unchanged Engine units; every file digest is verified and included in the raw JSON. This includes `backend_provider.cpp` (`1299a4959c9b108a327ce3b3f8aeacad79240c551083d1b712b98a96ffc9ca8b`) and `ProxySQL_PluginRawBackend.cpp` (`2a2b72fa964a2f3f8901eb386e55b77e92595b76b451a52b687302b038d1a066`).

## Workload

| Parameter | Value |
|---|---|
| Mode order | direct, static, mysql, pgsql, haproxy |
| Backend | task-owned selector echo process PID 3164042 127.0.0.1:38069 |
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
| direct | completed | 0.092 / 0.184 / 0.244 | 17641.3 | 1513.26 | 1513.26 | null | null | null | null |
| static | completed | 0.082 / 0.109 / 0.129 | 14803.8 | 1371.72 | 1371.72 | 138.6 | 35740 | 23 | 10 |
| mysql | completed | 0.085 / 0.105 / 0.117 | 13629.6 | 1393.15 | 1393.15 | 138.3 | 35296 | 23 | 11 |
| pgsql | completed | 0.087 / 0.110 / 0.122 | 14569.8 | 1259.59 | 1259.59 | 133.6 | 34516 | 23 | 11 |
| haproxy | completed | 0.064 / 0.137 / 0.151 | 15517.6 | 1124.15 | 1124.15 | 130.0 | 14364 | 10 | 2 |

## Mode details

### direct: completed

- Target: 127.0.0.1:38069; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 35287; throughput transactions: 48436.
- Idle connections: 8; quiescent interval 1.000069 s; proxy idle CPU None.
- Backend reconciliation: c→s 3177690568 (expected 3177690568), s→c 3177690568 (expected 3177690568), connections 35304/35304.

### static: completed

- Target: 127.0.0.1:36417; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 29613; throughput transactions: 43904.
- Idle connections: 8; quiescent interval 1.000091 s; proxy idle CPU 0.0.
- Whole daemon PID during measurement `3164104`; config `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-static/proxysql.cfg`, log `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-static/daemon.log`, post-run returncode `0`.
- Backend reconciliation: c→s 2880318280 (expected 2880318280), s→c 2880318280 (expected 2880318280), connections 29630/29630.
- Static mode used tcp_hostgroups/tcp_servers/tcp_listeners (no mapping row); SQL recorded in raw JSON.

### mysql: completed

- Target: 127.0.0.1:37879; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 27264; throughput transactions: 44590.
- Idle connections: 8; quiescent interval 1.000078 s; proxy idle CPU 0.0.
- Whole daemon PID during measurement `3164239`; config `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-mysql/proxysql.cfg`, log `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-mysql/daemon.log`, post-run returncode `0`.
- Backend reconciliation: c→s 2925125640 (expected 2925125640), s→c 2925125640 (expected 2925125640), connections 27281/27281.
- Mapped HGM reconciliation: byte deltas 2925125640/2925125640 (expected 2925125640/2925125640); Used/Free after drain 0/0.
- Mapped TCP hostgroup 20 -> MYSQL hostgroup 10 (no tcp_servers rows). SQL recorded in raw JSON.

### pgsql: completed

- Target: 127.0.0.1:47935; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 29143; throughput transactions: 40317.
- Idle connections: 8; quiescent interval 1.000075 s; proxy idle CPU 0.0.
- Whole daemon PID during measurement `3164400`; config `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-pgsql/proxysql.cfg`, log `/tmp/native-tcp-hgm/final-validation/benchmark-raw/bench-pgsql/daemon.log`, post-run returncode `0`.
- Backend reconciliation: c→s 2645210568 (expected 2645210568), s→c 2645210568 (expected 2645210568), connections 29160/29160.
- Mapped HGM reconciliation: byte deltas 2645210568/2645210568 (expected 2645210568/2645210568); Used/Free after drain 0/0.
- Mapped TCP hostgroup 20 -> PGSQL hostgroup 10 (no tcp_servers rows). SQL recorded in raw JSON.

### haproxy: completed

- Target: 127.0.0.1:34635; precheck 1 MiB exact echo sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200; connections: 31040; throughput transactions: 35982.
- Idle connections: 8; quiescent interval 1.000079 s; proxy idle CPU 0.0.
- Backend reconciliation: c→s 2361233416 (expected 2361233416), s→c 2361233416 (expected 2361233416), connections 31057/31057.
- HAProxy HAProxy version 3.5-dev11 2026/11/04 - https://haproxy.org/ nbthread=2.

## Caveats

- Local loopback short runs only; Python client/backend scheduling and GIL limits apply.
- Modes run sequentially and each ProxySQL mode starts a fresh task-owned daemon.
- `static`, `mysql` and `pgsql` CPU/RSS/fd/thread figures describe the whole daemon process, not the standalone Engine harness and not a deployment footprint.
- Missing optional HAProxy is an explicit skipped mode and is never fabricated.
- A failed exact-byte precheck or benchmark phase marks that mode `error`; the process exits nonzero if any requested mode errored.

Raw JSON: [2026-11-11-tcp-hostgroup-mapping-daemon.json](2026-11-11-tcp-hostgroup-mapping-daemon.json).

## Final matched-artifact provenance

- Benchmark JSON SHA256: `918fe1c7ed2dd3a90f6e15d5e2b5e085f5cc36476276ff258819dab806427aa4`.
- Approval-ready manifest `/tmp/native-tcp-hgm/final-validation-ready.json` SHA256 `d7cb4e784f851668888fb5bb3a64715427fb84b630224a7937bb02fd3e53e2af`; approved status: FINAL CORE V2 / ENGINE V3 SOURCE APPROVED FOR VALIDATION; integration signoff separate.
- Core source manifest `/tmp/native-tcp-hgm/core-final-v2-manifest.json` SHA256 `e82dddfca5c8521cfad3d3cb575b8ed4bef66acfdfd415dc1307a29fe5727125`; authoritative snapshot `/tmp/native-tcp-hgm/core-source-final-v2`.
- Engine/plugin source manifest `/tmp/native-tcp-hgm/engine-source-candidate-v3/manifest.json` SHA256 `a67bee4ccd3dc329faa8ba545b3538f9a921bd653f5ca2b119dbe195cc896ac8`; worktree `/home/rene/.codex/worktrees/8616/proxysql`; service_version=2, outer_plugin_abi=18.
- Approved daemon `/tmp/native-tcp-hgm/core-final-v2-daemon` SHA256 `0954cf2534ccb1217dbe4a9ade47f06b2a2a3a3db6f9b638c9a04735b2564451`.
- Approved release plugin `/tmp/native-tcp-hgm/engine-binaries-candidate-v3/proxysql_tcp_proxy.release.so` SHA256 `55ca8e586481a459272287ed2335448455217236b846f86ee0dc56b890b80e75`; immutable run snapshot SHA256 `55ca8e586481a459272287ed2335448455217236b846f86ee0dc56b890b80e75`.
- Daemon all-12 result `/tmp/native-tcp-hgm/final-validation/daemon-all12.json` SHA256 `fe0dad8a2e3c648fd781e43d05e0be497f586dd15d216a65e1babd8fe6935542`: {'BLOCKED': 0, 'FAIL': 0, 'PASS': 12} exit 0.
- Static standalone 44 result `/tmp/native-tcp-hgm/final-validation/static44-final-header/summary.json` SHA256 `001dd20ecf1791bdc8d824f6455af0779543b0830ed30e2bb2f7b80e1b34ba41`: {'PASS': 44, 'FAIL': 0, 'BLOCKED': 0, 'INCONCLUSIVE': 0}, harness SHA256 `043ba866bd990cd2aec0d3a58c4623948ad5a8dab6b54c7f743afe4c9614083f`.
- Source digests above are verified against the immutable approved snapshots, including the raw-backend adapter. Full Core/Engine manifests, tool hashes, phase values and raw records are embedded in the JSON.

- Static harness reports the actual public-header SHA256 `bf08ead8131dc597dbfae8e9672a2c323fc24bccfe5971dd5113d13ebaa72c76`, embedded from that file at compile time and verified against the approved source digest.
- Metadata enrichment preserved every measured record: canonical measurement SHA256 `b7ca52623ce805ec72db25456ec32300878c1c2efaaa099b5044b89e2ab48822`.
