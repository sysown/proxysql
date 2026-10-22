# One-client plaintext syscall counts and deferred-I/O CPU profile

SELECT 1 over localhost TCP on lon104; one client and one pgbench thread; 64 pre-established and retained backend connections. ProxySQL deferred-I/O commit b17a986f3 with native backend protocol and one worker on CPU 0. PgBouncer 1.26.1 uses transaction pooling on CPU 0. TLS is disabled and verified on both hops. Query digests remain enabled. All source timing flags are unset.

Three separate runs: ProxySQL syscall counters, PgBouncer syscall counters, then ProxySQL CPU sampling with syscall counters detached. Each uses 20 seconds of warmup and 60 seconds of workload; profiling is enabled during approximately seconds 10–50. No source edits or compilation.

**Syscalls per query** (all current threads in the proxy process):

| Syscall | Deferred I/O | PgBouncer |
|---|---:|---:|
| `recvfrom` | 1.99005 | 1.98125 |
| `sendto` | 1.98929 | 1.98123 |
| `poll` | 1.99070 | 0.00000 |
| `epoll_wait` | 0.00000 | 1.97686 |
| `read` | 0.00000 | 0.00000 |
| `write` | 0.00000 | 0.00194 |
| `readv` | 0.00000 | 0.00000 |
| `writev` | 0.00000 | 0.00000 |
| `connect` | 0.00000 | 0.00000 |
| **All syscall entries** | **5.99176** | **5.95678** |

Both are approximately **two receives + two sends + two waits = six syscalls/query**. On this Linux, libc recv/send enter the kernel as recvfrom/sendto. ProxySQL waits with poll; PgBouncer waits with epoll_wait. No tracked read/write/recv/send exit returned EAGAIN in either run. There were no connect syscalls during the enabled windows. Minor calls include administrative sampling, housekeeping and logging; they are not all query-path work.

| Counting evidence | Deferred I/O | PgBouncer |
|---|---:|---:|
| Total syscall entries | 671,598 | 740,190 |
| Queries in enclosing counter interval | 112,087 | 124,260 |
| Enabled seconds | 39.959 | 39.841 |
| Boundary slack (percent of enabled duration) | 0.514% | 0.843% |
| Raw total minus sum of named entry counters | -22 | 5 |

perf stat counted all 345 available named syscall entries, plus the raw total and eight filtered EAGAIN exit counters. Every event ran 100% of its enabled time: no multiplex scaling. FIFO enable/disable acknowledgements bracket the window. Query snapshots enclose the counter window and take time, so the reported ratios slightly undercount true calls per in-window query; interpret 1.98–1.99 as approximately two. Small raw/named discrepancies arise at counter-enable/disable boundaries. The 5.99 versus 5.96 difference is not evidence of a useful syscall reduction.

Counting this many events substantially perturbs execution. These runs are syscall diagnostics, not throughput benchmarks or CPU-cost measurements. Their full-run TPS was 4674 (ProxySQL) and 5126 (PgBouncer), versus the prior unprofiled 10479 and 13313. The subsequent CPU capture has none of these tracepoint counters attached.

**CPU profile: ProxySQL deferred I/O only.** perf record sampled hardware cycles at requested frequency 999 Hz, with frame-pointer call stacks, on the query worker selected from the post-warmup thread CPU counters. User and kernel execution are included; sleeping time and PostgreSQL/pgbench execution are excluded.

35,070 samples; zero lost samples. Percentages below are weighted by sampled cycle periods, not wall time.

| Where cycles were sampled | Share of total |
|---|---:|
| Linux kernel | 67.70% |
| ProxySQL executable, including statically linked code | 23.98% |
| libc | 7.57% |
| vDSO | 0.42% |
| libstdc++ | 0.33% |

The executable share is **not a pure ProxySQL-source percentage**: it also includes linked allocator/library routines.

Kernel syscall paths, including descendants in the sampled call chains:

| Kernel path | Inclusive share of all sampled cycles |
|---|---:|
| `__x64_sys_sendto` | 36.14% |
| `__x64_sys_poll` | 21.87% |
| `__x64_sys_recvfrom` | 5.20% |

These are inclusive call-chain estimates, not syscall wall-clock durations; the poll share is CPU spent entering, processing, scheduling and returning from the wait, not time asleep. Do not add inclusive parent/child percentages together or add them to the self percentages below. Frame-pointer unwinding can truncate userspace stacks, so userspace inclusive totals are not treated as exhaustive.

Largest userspace self costs (excluding their callees):

| Function | Share of all sampled cycles | Share of userspace cycles |
|---|---:|---:|
| `pgsql_query_digest_and_first_comment` | 1.40% | 4.33% |
| `PgSQL_Session::handler` | 1.24% | 3.84% |
| `PgSQL_Thread::process_all_sessions` | 1.13% | 3.49% |
| `PgSQL_Thread::run` | 0.93% | 2.87% |
| `PgSQL_Session::get_pkts_from_client` | 0.81% | 2.50% |
| `pgsql_loop_timing_point` | 0.56% | 1.75% |
| `pthread_mutex_lock` | 0.47% | 1.45% |
| `PgSQL_Connection::handler` | 0.45% | 1.39% |
| `recv` | 0.41% | 1.27% |
| `tolower` | 0.36% | 1.13% |
| `__strcasestr` | 0.36% | 1.11% |
| `Query_Processor<PgSQL_Query_Processor>::process_query` | 0.35% | 1.07% |
| `Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::writeout` | 0.34% | 1.07% |
| `SpookyHash::Short` | 0.32% | 1.00% |
| `__vdso_clock_gettime` | 0.32% | 0.99% |

Largest kernel self costs:

| Function | Share of all sampled cycles |
|---|---:|
| `_raw_spin_lock_irqsave` | 2.07% |
| `nf_conntrack_tcp_packet` | 1.46% |
| `do_sys_poll` | 1.38% |
| `tcp_ack` | 1.35% |
| `__fget_light` | 1.29% |
| `entry_SYSCALL_64` | 1.27% |
| `nft_do_chain` | 1.15% |
| `syscall_return_via_sysret` | 1.13% |
| `psi_group_change` | 1.04% |
| `fput` | 1.03% |
| `dequeue_entity` | 1.01% |
| `update_blocked_averages` | 0.92% |

The disabled `pgsql_loop_timing_point` hook still appears at 0.57% self cycles. Source inspection confirms it checks the cached PX_PGSQL_LOOP_TIMING setting and returns immediately when unset; this is the existing call/check overhead, not active timer collection. No patch was made in response.

The syscall quantity is essentially the same in both proxies. The deferred-I/O worker spends most sampled cycles in the kernel, notably the send and poll paths. Userspace cost is distributed across digesting, session scheduling/handling, packet processing and many smaller functions; digesting alone is 1.40% of total cycles. This capture does not establish why the same syscall count costs different amounts across proxies, and it is not a PgBouncer CPU profile.

The CPU-profile run reached 9469 TPS versus the prior unprofiled 10479; profiling and run variation affect these numbers, so sampled shares are the result of interest. No backend connections were created during warmup or measured workload in any run. All 64 stayed established; all runs had zero failed transactions. Prior ProxySQL runtime was restored and the temporary PgBouncer was stopped.

Raw self profile: [profile-one-cpu-proxysql-20261022T173747Z/perf-self.txt](profile-one-cpu-proxysql-20261022T173747Z/perf-self.txt). Inclusive call chains: [profile-one-cpu-proxysql-20261022T173747Z/perf-inclusive.txt](profile-one-cpu-proxysql-20261022T173747Z/perf-inclusive.txt). The full perf.data path, size and SHA-256 are recorded in `profile-one-cpu-proxysql-20261022T173747Z/raw-artifact.json`. Each syscall directory contains every raw event count, count/query ratio, query boundaries, pool snapshots and the exact command.
