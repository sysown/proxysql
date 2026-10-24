# Plaintext optimization opportunities

The current optimized native-backend build has concrete work to remove from the plaintext path. The clearest small change is a conservative negative filter before the COPY regex when no digest exists. The scheduler also revisits a completed, backendless session once per query. The larger response-path opportunity is avoiding reconstruction and repeated copying of native backend messages.

No product code, binary, existing test, or persistent proxy configuration was changed for this investigation. These are profiling findings, not measured speedups from patches.

## Conditions and existing throughput reference

lon104, localhost TCP on both hops, PostgreSQL, one persistent pgbench client and one job, simple protocol, one ProxySQL worker. Ten backend connections were established before warmup and retained throughout measurement. Proxy CPU zero, pgbench CPU two, diagnostic controller CPU eighteen. CPU governor performance. TLS disabled on both hops and checked using frontend conninfo and backend pg_stat_ssl. Commands statistics and digests disabled; parser selector set to zero. Native backend protocol enabled. PgBouncer transaction pooling with the same ten-connection cap.

Existing unprofiled results from the preceding benchmark, preserved in [unprofiled-reference.json](unprofiled-reference.json):

| Workload | ProxySQL TPS | PgBouncer TPS | ProxySQL user CPU/query | PgBouncer user CPU/query | Extra total proxy CPU/query |
|---|---:|---:|---:|---:|---:|
| SELECT 1 | 10,984 | 12,779 | 12.00 µs | 5.63 µs | 9.07 µs |
| 42 rows / about 4KB | 5,396 | 6,608 | 20.99 µs | 9.62 µs | 18.09 µs |

These baselines were not rerun. The additional runs collected profiles under the same conditions; their throughput is diagnostic and must not replace the unprofiled comparison.

## Where userspace CPU goes

The following estimates use each run's measured worker user CPU/query, distributed according to weighted userspace cycle samples. They are approximate inclusive path costs. Nested rows overlap and must not be added. They are not the amount a patch is guaranteed to save.

| ProxySQL path | SELECT 1: user cycles | Estimated µs/query | 4KB: user cycles | Estimated µs/query |
|---|---:|---:|---:|---:|
| COPY regex / RE2 | 5.28% | 0.66 | 6.79% | 1.32 |
| Native result processing | 5.52% | 0.69 | 14.12% | 2.74 |
| ↳ per-message result append | 3.31% | 0.42 | 8.70% | 1.69 |
| ↳ result buffer handoff | 1.05% | 0.13 | 1.67% | 0.32 |
| Pool checkout | 6.17% | 0.78 | 5.61% | 1.09 |
| Pool return / local-cache flush | 3.09% | 0.39 | 2.72% | 0.53 |
| Session writeout, userspace portion | 4.44% | 0.56 | 3.86% | 0.75 |

User CPU/query during sampling: ProxySQL 12.56 / 19.41 µs; PgBouncer 6.06 / 9.98 µs for SELECT 1 / 4KB respectively. Sampling adds substantial kernel overhead, so the unprofiled figures above remain the primary CPU comparison.

### First: skip the COPY regex for queries that cannot contain COPY

At [PgSQL_Session.cpp:3664](source/PgSQL_Session.cpp#L3664), the handler checks for COPY before sending the query. The digest-present path already avoids RE2 when a cheap search fails. The raw-query fallback assigns QueryPointer and calls the regex without that precheck.

That fallback is active with parsing/digests disabled. The call trace measures approximately one RE2 PartialMatchN call per query even for SELECT 1. Sampled RE2 stacks lead directly back to this handler, rather than query rules.

A conservative case-insensitive negative check on raw query bytes can bypass RE2 when COPY is absent. It must preserve the current matching behavior around whitespace, comments, strings and multiple statements; a simplistic first-word-only dispatch is not sufficient. Keep the regex for possible matches. This also benefits TLS because it is above the transport layer.

### Second: avoid the backendless revisit after completion

The dedicated SELECT 1 trace records these full handler callers:

| Caller | Calls/query, approximately |
|---|---:|
| Early frontend dispatch, PgSQL_Thread.cpp:4661 | 1 |
| Backend-owning scan, PgSQL_Thread.cpp:4789 | 1 |
| Remaining backendless scan, PgSQL_Thread.cpp:4835 | 1 |

All measured handler entries use the full handler, not its I/O-only mode. There are also thirty-two background idle-connection handler calls in the window, negligible beside the query traffic. Exact addresses and source resolution are in [handler-callsites.json](plain-calls-select1-cached-20261024T202827Z/handler-callsites.json).

The backend completion path releases the connection and changes the session to WAITING_CLIENT_DATA. Its to_process flag still qualifies it for the backendless scan later in the same worker pass. Early-dispatch sessions have a dispatched exclusion; a session completed by the backend scan does not get that exclusion. The full handler already checks queued frontend packets before returning, at [PgSQL_Session.cpp:4182](source/PgSQL_Session.cpp#L4182).

For this synchronous client, the third call does not have another queued command to execute. The handler nevertheless repeats its preamble, packet checks and writeout epilogue. The trace measures about three writeout calls and six set_pollout calls per query. set_pollout updates userspace poll state; these are not six syscalls.

A narrowly scoped fix would mark a completed session as handled for this pass, or consume its work flag after handling all current work. It must still schedule buffered/pipelined commands, pending frontend I/O, disconnects, pauses and session teardown. This should be investigated before attempting another broad scheduler rewrite. Removing one handler entry does not imply removing a third of CPU time; the redundant entry is lighter than the useful entries, and its exclusive time has not been separately measured.

### Third: reduce native result reconstruction and copying

The backend has already supplied valid PostgreSQL wire messages. The native path feeds bytes into a framer, walks every message, and calls [add_native_backend_message](source/PgSQL_Protocol.cpp#L2918). That method reserves space, rebuilds the five-byte header, copies the payload and updates message flags/counters. It does not decode and re-encode individual column values.

SELECT 1 has four normal result messages; the call trace confirms about four appends/query. The 42-row result has forty-five normal result messages: RowDescription, forty-two DataRow messages, CommandComplete and ReadyForQuery. Per-message work therefore grows substantially even though the result fits into a small response buffer.

The small-result handoff then allocates an output packet and copies the accumulated bytes at [buffer_to_PSarrayOut](source/PgSQL_Protocol.cpp#L3119). The frontend output path copies packets into its send queue at [array2buffer](source/PgSQL_Data_Stream.cpp). The current reuse optimization avoids repeated large reallocations, but these copies and one output allocation remain.

As corroboration, resolved libc memcpy self cost is about 0.26 µs/query for SELECT 1 and 0.86 µs/query for 4KB in ProxySQL. These costs overlap the path estimates above. This excludes inlined copies and kernel copying.

The opportunity is to validate and account for messages while forwarding a larger contiguous span of original wire bytes, rather than reconstructing every header and copying every payload separately. Buffer ownership, partial messages, backpressure, query cache behavior, response interception and ReadyForQuery bookkeeping must remain correct. This is a larger change than the COPY guard or completed-session exclusion.

### Fourth: reduce shared-pool work for the single-worker case

A released connection enters the local cache, but [return_local_connections](source/PgSQL_Thread.cpp#L6812) publishes that cache to the global pool at the end of the iteration. A sequential client's next request arrives on a later wakeup, so checkout again traverses the shared pool, selects a server/connection and checks compatibility. The profile includes shared pool locking and variable matching on that route.

Retaining a bounded reusable connection locally across worker iterations could avoid part of the measured checkout/return work when there is one worker. This needs separate evaluation of pool accounting, runtime server changes, age/health handling and sharing when there are multiple workers. The current profile does not demonstrate lock contention; it demonstrates CPU spent performing the operations.

## What the syscall count rules out for this case

The dedicated worker trace counts approximately two recvfrom, two sendto and two poll entries per query. It records zero connect entries. These are entries, not successful-byte counts; return values/EAGAIN were not traced. The poll counts include background worker wakeups, too small here to change the rounded result.

There is no evidence in this single-client SELECT 1 run of a large extra-syscall multiplier caused by deferred I/O. The repeated handler/writeout work happens mostly in userspace. This does not establish syscall behavior for 4KB, TLS or many clients, and no new PgBouncer syscall trace was collected for this investigation.

## Measurement and validation

Four CPU profiles: existing immutable optimized binary and PgBouncer, SELECT 1 and 4KB, sequentially. Each case used twenty seconds warmup and sixty seconds measurement. perf sampled the busiest proxy worker at 399 Hz, cycles in user and kernel mode, DWARF call stacks, with a gated approximately forty-second steady window. Exports use --no-inline. Every profile reports zero lost samples. Raw data and stacks remain on lon104; raw-artifact.json records each perf archive's location, size and SHA256.

A fifth run counted calls on the same ProxySQL SELECT 1 setup using aggregate bpftrace maps, without source timers. It is separate from cycle profiling. It counted 368,497 pool queries across a bracket surrounding the gate; the exact enabled window was 39.93 seconds. Snapshot/control boundary slack is 0.32%, explaining the small difference between counts/query and whole integers. The exact maps are in [call-summary.json](plain-calls-select1-cached-20261024T202827Z/call-summary.json).

CPU profiles contain 11,687 / 11,016 samples for SELECT 1 ProxySQL / PgBouncer, and 10,463 / 9,911 for 4KB. Resolved userspace samples are much fewer, so small path percentages are approximate. Libc leaf symbols were resolved using debug information with a matching build ID. About nine to eleven percent of PgBouncer userspace leaf weight remains unresolved, principally in stripped libevent; the report does not assign that to particular PgBouncer functions. Inclusive stacks can be truncated, so path attribution can undercount. Do not sum inclusive paths or compare executable-only percentages between proxies.

All five runs had zero failed transactions, ten retained backends and unchanged pool membership. ProxySQL ConnOK remained ten, ConnERR zero, and total ConnUsed plus ConnFree remained ten in every snapshot; native protocol stayed enabled. PgBouncer checked backend identities every second plus server connection logs. Digest maps remained empty and unchanged. All isolated instances were stopped afterward.

ProxySQL binary SHA256: 3fa61772707b3edee8342c84a1dfd1b6b4b2b18cd9c94b5e8a856fb3ad8a16f1. Canonical code commit: de5cfbba7de79151cf8c9e847b9d293d65a29b57; the later evidence commits do not change this binary. PgBouncer version and binary hash are preserved per case in binary.json.

The diagnostic series is under /home/rene/pg-network-bench/results/plain-profile-select1-series-20261024T201957Z on lon104. Per-case directories and reusable profiling/export/analysis scripts are preserved alongside this report. Raw perf and compressed transaction archives remain remote and are excluded from Git.

Recommended order: COPY negative filter, completed-session revisit exclusion, then result-copy batching. Benchmark each change separately under the same fixed-pool condition. The pool-cache idea should follow those, since it changes ownership/accounting across iterations.
