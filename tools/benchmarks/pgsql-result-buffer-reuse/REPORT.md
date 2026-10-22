# PostgreSQL small-result buffer reuse

The reuse change is implemented and the requested 8 KiB variant is preserved separately. **This six-run cohort does not demonstrate a throughput improvement:** reuse at 16 KiB averaged about 1% lower, while reuse at 8 KiB was essentially unchanged from the original. Run-to-run ranges overlap.

## Measured results

Same workload throughout: lon104, localhost TCP, one pgbench client and one pgbench thread, simple `SELECT 1`, no TLS on either hop, native backend protocol, one proxy worker pinned to CPU 0. The 64 backend connections were established before warmup and retained. Query digests stayed enabled.

Balanced run order: original → reuse 16 KiB → reuse 8 KiB → reuse 8 KiB → reuse 16 KiB → original. Each run had 20 seconds of warmup and 60 seconds of measurement. No perf, source timers or compilation ran during measurement.

| Build | TPS 1 | TPS 2 | Mean TPS | Mean process user µs/query |
|---|---:|---:|---:|---:|
| Original, 16 KiB | 10,671.45 | 10,519.08 | 10,595.26 | 16.015 |
| Reuse fix, 16 KiB | 10,316.26 | 10,663.67 | 10,489.96 | 16.619 |
| Reuse fix, 8 KiB | 10,447.26 | 10,748.59 | 10,597.93 | 15.976 |

The 16 KiB reuse build changes mean TPS by **-0.99%** and process userspace CPU/query by **+3.77%** versus the contemporary original. The 8 KiB reuse build changes mean TPS by **+0.03%** versus original and **+1.03%** versus 16 KiB reuse.

These are preliminary means from two runs per build. Timing variation and code layout can affect small differences; this is not evidence of a universal gain. Process CPU comes from /proc ticks and includes the other proxy threads, so it is not an exact function timer.

Every run kept ConnOK=64, ConnERR=0 and ConnUsed+ConnFree=64 at all 62 snapshots. No failed transactions. With one client, ConnUsed 0–1 and ConnFree 63–64 are expected. See [audit](audit.json), [raw comparison](comparison.json) and the per-run samples.

## Implementation

The original flush shrank small result buffers with `realloc`, queued them, and allocated a fresh full-capacity buffer. The fix allocates a packet sized to the small result, copies the occupied bytes into it, and retains the accumulation buffer. Larger buffers retain the existing ownership handoff, avoiding an added large-result copy. Empty flushes remain no-ops.

- `8d5c3230f`: buffer reuse with the original 16 KiB capacity, on `optimization/pgsql-forwarding-hotpath`.
- `17d43c15f`: separate 8 KiB experiment, on `experiment/pgsql-result-buffer-8k`.
- Baseline binary source: `4699f3175`, including the earlier bounded tokenizer-copy fix.

The 8 KiB experiment also changes the small-result copy threshold from 8 KiB to 4 KiB, flush boundaries, and queued-byte/backpressure estimates that use this constant. This SELECT 1 comparison does not establish its behavior for larger result sets. Across 64 retained accumulation buffers, nominal capacity is 1 MiB at 16 KiB versus 512 KiB at 8 KiB; this is not a measured total-RSS reduction.

Both optimized builds completed. An isolated ASan/UBSan harness extracted the actual original and patched reserve/flush functions and checked 18,385 cases at 16 KiB and 10,193 at 8 KiB, including every length through capacity, randomized reserve/flush sequences, byte identity, buffer retention and independently owned queued packets. Repository tests were not modified. See [validation output](buffer-validation.txt).

## Targeted CPU profile after the change

A follow-up DWARF profile of the 16 KiB reuse build collected 13,677 userspace-cycle samples with zero loss, using the same fixed-period event and 8 KiB stack snapshots as the earlier original-build capture (13,344 samples).

| Profiled work | Original | Reuse, 16 KiB |
|---|---:|---:|
| `buffer_to_PSarrayOut` and callees | 4.47% | 0.78% |
| All allocator self samples | 5.42% | 1.65% |

The large realloc-related sample cluster disappears from the buffer path. This supports removal of the targeted allocation cost; it does not override the unprofiled result or demonstrate lower whole-query CPU/latency. These are shares of sampled userspace cycles from separate captures, not absolute per-function elapsed times. Other path shares also vary between captures.

For scale only, 4.5% of roughly 16 microseconds of proxy userspace CPU is about 0.7 microseconds, whereas end-to-end query latency is roughly 94–97 microseconds here. Even eliminating that entire path would correspond to less than 1% of end-to-end latency under this simplified budget; the change retains some work. This explains why a large reduction within the small path need not produce an obvious TPS change amid the observed variation. It is not a causal explanation of each run's difference.

The follow-up profile also retained ConnOK=64, ConnERR=0 and a pool total of 64 throughout, with zero failed transactions. The prior runtime was restored. See [profile comparison](profile-comparison.json) and [detailed patched profile](profile-result-buffer-reuse16-20261022T231442Z/hotspots.json). The earlier baseline capture remains in the previous remaining-hotspots report; no new workload condition was introduced.

## Timing hooks and classification

Neither was modified during this comparison. See [code locations and proposed follow-up](HOOKS-AND-CLASSIFICATION.md). The disabled hook is `pgsql_loop_timing_point`, defined at `lib/PgSQL_Thread.cpp:84`, with 16 call sites in the worker/session loops. Its getenv runs once; disabled calls still incur function and gate-check overhead.

Command classification can be improved with non-owning pointer-and-length tokens, length-first keyword comparisons, and compile-time lengths for literal keyword helpers. The important remaining work is preserving delimiter, parentheses, multi-token command and cancellation/termination semantics. No classifier performance gain is claimed here.

## Artifacts and state

The capture harness, binary registry with SHA-256 hashes, per-run settings, plaintext checks and one-second pool snapshots accompany this report. Source changes have separate verbose commits. The 16 KiB source branch remains the main optimization branch; the 8 KiB experiment is preserved separately. Prior runtime restoration is checked after the series. Pre-existing staged deferred-I/O cost files are preserved.

Raw follow-up profiling data remains losslessly compressed on lon104; recovery paths and hashes are in [the capture manifest](profile-result-buffer-reuse16-20261022T231442Z/compressed-artifacts.json). To make build space, older raw profiles were also preserved with verified lossless compression, recorded in [this manifest](older-profile-compression.json).
