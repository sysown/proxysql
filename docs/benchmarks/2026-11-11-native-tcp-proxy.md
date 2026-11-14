# Native TCP proxy engine benchmark

Date: 2026-11-11. Status: local loopback measurement; not a deployment claim.

Environment: `dev128`, 6.8.0-85-generic, x86_64, 32 CPUs, `AMD Ryzen 9 5950X 16-Core Processor`. Load average at start: [0.81689453125, 0.998046875, 0.9951171875]. Compiler: `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`. Python: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`.

## Workload

| Parameter | Value |
|---|---|
| Mode order | direct, native, haproxy |
| Backend | task-owned selector echo process, PID 2758864, 127.0.0.1:40821 |
| Client concurrency | 4 |
| Engine/HAProxy worker threads | 2 |
| RTT payload / warmup / samples per connection | 64 B / 20 / 300 |
| Connections/s payload | 64 B |
| Throughput payload / duration | 65536 B / 2.0 s |
| Idle connections measured | 256 |

Each connection/s sample is a completed connect + send + exact echo receive + close transaction. Throughput verifies every echoed payload chunk byte-for-byte; rates are application payload bytes per second, separately for client→server and server→client.

Scope of native mode: the native target is the **standalone `engine_harness` process** linked from the reviewed Engine sources. Its proxy CPU, RSS, fd and thread figures describe only that harness process. They exclude ProxySQL core, Admin, SQLite, metrics and plugin/daemon integration work, so they are not a full-daemon or full-plugin footprint.

## Results

| Mode | Status | RTT p50 / p95 / p99 ms | Connections/s | MiB/s c→s | MiB/s s→c | Proxy CPU % (native = harness only) | Backend CPU % | Proxy idle CPU % (native = harness only) | Proxy RSS idle Δ KiB (native = harness only) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct | completed | 0.052 / 0.107 / 0.137 | 16600.0 | 1443.92 | 1443.92 | null | 59.4 | null | null |
| native | completed | 0.050 / 0.072 / 0.093 | 15798.7 | 1214.37 | 1214.37 | 127.1 | 66.3 | 0.0 | 7680 |
| haproxy | completed | 0.055 / 0.069 / 0.077 | 15699.2 | 1167.98 | 1167.98 | 135.7 | 66.7 | 0.0 | 512 |

Proxy/backend CPU percentages in the first CPU columns are process tick deltas over the mode's whole monotonic elapsed window (including bounded client-thread joins), not sums of short phase percentages. Direct mode has no proxy PID, so its proxy CPU/RSS fields are `null`; backend CPU is still measured. Native proxy CPU/RSS/fd/thread values cover only the standalone Engine harness, not a full ProxySQL daemon. The idle CPU column is a separate quiescent sample taken over the configured interval only after the idle flows were established and settled; establishment CPU is reported separately in the mode details. Idle RSS/fd/thread deltas compare the settled idle state with the pre-connection baseline.

## Mode details

### direct: completed

- Precheck: 1 MiB exact echo in 0.001698 s, sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200 raw samples.
- Connections/s: 33204 completed transactions in 2.000245 s.
- Throughput: 3029073920 c→s bytes and 3029073920 s→c bytes, 46220 verified echo transactions.
- Idle resources: 256 connections; settle 0.5 s.
  - Establishment (connect + echo + settle, 0.524285 s) process CPU: proxy=None, backend=1.907.
  - Quiescent 1.000092 s (tick precision 10.0 ms) process CPU: proxy=None, backend=0.0.
  - Baseline -> settled idle deltas: proxy None, backend {'rss_kb_delta': 0, 'fds_delta': 256, 'threads_delta': 0}.
  - Socket options: TCP_NODELAY on benchmark client sockets and accepted Python backend sockets.

### native: completed

- Precheck: 1 MiB exact echo in 0.003665 s, sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200 raw samples.
- Connections/s: 31603 completed transactions in 2.000351 s.
- Throughput: 2547187712 c→s bytes and 2547187712 s→c bytes, 38867 verified echo transactions.
- Idle resources: 256 connections; settle 0.5 s.
  - Establishment (connect + echo + settle, 0.616206 s) process CPU: proxy=4.869, backend=1.623.
  - Quiescent 1.000067 s (tick precision 10.0 ms) process CPU: proxy=0.0, backend=0.0.
  - Baseline -> settled idle deltas: proxy {'rss_kb_delta': 7680, 'fds_delta': 512, 'threads_delta': 0}, backend {'rss_kb_delta': 0, 'fds_delta': 256, 'threads_delta': 0}.
  - Socket options: TCP_NODELAY on benchmark client sockets and accepted Python backend sockets.
- Engine settings: worker_threads=2, buffer_size=16384.
- Native target scope: standalone Engine harness only; proxy CPU/RSS/fd/thread values exclude ProxySQL core, Admin, SQLite, metrics and plugin/daemon integration footprint.

### haproxy: completed

- Precheck: 1 MiB exact echo in 0.004326 s, sha256 `06f5f32a1282780cd4109090a8559854f1fad9ab26208560f31e102ce0ba6397`.
- RTT samples: 1200 raw samples.
- Connections/s: 31404 completed transactions in 2.000361 s.
- Throughput: 2450194432 c→s bytes and 2450194432 s→c bytes, 37387 verified echo transactions.
- Idle resources: 256 connections; settle 0.5 s.
  - Establishment (connect + echo + settle, 0.595661 s) process CPU: proxy=3.358, backend=3.358.
  - Quiescent 1.000086 s (tick precision 10.0 ms) process CPU: proxy=0.0, backend=0.0.
  - Baseline -> settled idle deltas: proxy {'rss_kb_delta': 512, 'fds_delta': 512, 'threads_delta': 0}, backend {'rss_kb_delta': 0, 'fds_delta': 256, 'threads_delta': 0}.
  - Socket options: TCP_NODELAY on benchmark client sockets and accepted Python backend sockets.
- HAProxy: `HAProxy version 3.5-dev11 2026/11/04 - https://haproxy.org/` sha256 `1684852bad690fda9d87492e137d0c3e989234f84e9fc45f36bf34c1f11937e9`, nbthread=2.

## Engine source provenance and test status

- Readiness marker: `/tmp/native-tcp-proxy/test-engine-sources-ready.json` (manifest sha256 `b9d2aa18cb4acdbc3291c1fc3ac7b16d42a69066647f6d778151a5029fda3263`).
- Marker status: FINAL WRAPPER-FIXED SOURCE APPROVED FOR FULL ADVERSARIAL/BENCHMARK VALIDATION; root integration review separate.
- Marker note: Supersedes queue-fixed source after public start/apply sustained-OOM containment/partial-start cleanup repair. Only engine.cpp differs among6productiondeps: a7351cd1a8eae8eec8b17c5d35c0185608f691455351d7368fa1d20a3e8db5df. Engine coordinator independently69cases/1138checks normal+ASan/UBSan/leaks green, externalOOMmodes0. Refresh44suite+identical3mode workload; do not reuse pre-wrapper performance evidence. Integration approval remainsfalse and separate.
- Frozen header sha256: `2b826b1ef861ff6f36b5b937715e6b92470345d3ef24615c70174a541dc7e24b`.
- Resolved source digests at run time:
  - `/home/rene/.codex/worktrees/483d/proxysql/plugins/tcp_proxy/src/config.cpp` `d463104fc63a38b579ea0b0db90d9a00e5878bf1f00875793a7dd39460fe8a81`
  - `/home/rene/.codex/worktrees/483d/proxysql/plugins/tcp_proxy/src/engine.cpp` `a7351cd1a8eae8eec8b17c5d35c0185608f691455351d7368fa1d20a3e8db5df`
  - `/home/rene/.codex/worktrees/483d/proxysql/plugins/tcp_proxy/src/selection.cpp` `11d1fd03e152d628e84a9ca7cbeaffe18b7126425a24e4f261e3a9ea7bebb10d`
  - `/home/rene/.codex/worktrees/483d/proxysql/plugins/tcp_proxy/src/health.cpp` `9e7fa31ef7b3c36915346ebc5d55bbe17cfd9a23e9dd32f809f70bac6a5e810e`
- Adversarial suite at `/tmp/native-tcp-proxy/test-wrapper-final-results/summary.json`: 44 PASS, 0 FAIL, 0 BLOCKED, 0 INCONCLUSIVE (44 scenarios).

## Caveats

- Loopback only; no external network, production endpoint or load generator.
- Python clients/backends are subject to interpreter scheduling and GIL limits. The client process and backend are separate, but Python-side cost can dominate at high rates and masks some engine detail.
- Mode order is sequential and each mode starts a fresh measurement session; the backend process is shared but counters are sampled around each mode.
- Percentiles are nearest-rank over raw per-connection RTT samples; they are not confidence intervals.
- Idle CPU comes from /proc utime+stime clock ticks, whose precision is stated per sample (typically 10 ms); a one-second quiescent sample therefore has tick-quantized resolution. RSS deltas are single-sample VmRSS observations, not allocator accounting.
- Native mode is skipped unless production Engine sources were approved and a harness was built; a failed exact-byte precheck blocks benchmark runs rather than producing fabricated numbers.
- Native mode measures the standalone `engine_harness` process only. Its CPU/RSS/fd/thread numbers exclude ProxySQL core, Admin, SQLite, metrics and plugin/daemon integration and cannot describe a full daemon/plugin footprint.
- Measurements describe this host and these short runs only.

Raw evidence: [benchmark JSON](2026-11-11-native-tcp-proxy.json).
