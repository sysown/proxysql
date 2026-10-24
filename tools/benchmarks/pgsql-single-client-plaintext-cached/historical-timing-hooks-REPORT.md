# PostgreSQL worker-loop timing hooks compiled out

Commit `f3163c864` puts the diagnostic function and all sixteen call sites behind `#if 0`. The linked executable and PgSQL_Thread object contain neither the timing symbol nor its environment-variable name. See verification.json and no-loop-timing.patch.

One candidate measurement uses the existing copy-free classifier, retained 16 KiB result buffers, deferred I/O, native backend protocol, one proxy worker pinned to CPU 0, one pgbench client/thread, simple SELECT 1, localhost TCP, and TLS disabled on both hops. All 64 backend connections were established before a 20-second warmup and 60-second measurement. No baseline rerun was performed.

| Measurement | Existing classifier results, hooks recording disabled (two runs, mean) | Timing hooks compiled out (one run) | Change |
|---|---:|---:|---:|
| TPS | 10513.35 | 10798.88 | +2.72% |
| Proxy userspace CPU per query | 16.361 µs | 15.851 µs | -3.12% |
| Proxy total CPU per query | 44.124 µs | 42.966 µs | -2.63% |

Observed improvement in this single run; its magnitude remains subject to run-to-run variation. The earlier two classifier TPS measurements were 10,572.08 and 10,454.62. CPU figures use the same process tick sampling method as those runs.

All 62 pool snapshots kept ConnOK=64, ConnERR=0 and ConnUsed+ConnFree=64. No new backend connections or failed transactions occurred during measurement. The harness restored the previous runtime after completing; restoration.json records the independent check.

The timing hooks are completely absent from this candidate binary. The restoration step returns the prior listener to its prior binary; the candidate is preserved on lon104 as `/home/rene/pg-network-bench/src/proxysql-head-command-view-no-loop-timing`.
