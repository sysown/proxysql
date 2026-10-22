# Measured forwarding latency: deferred I/O versus PgBouncer

One client and one pgbench thread; SELECT 1; simple PostgreSQL protocol; localhost TCP on lon104; TLS disabled on both hops; 64 pre-established and retained backends. ProxySQL deferred-I/O b17a986f3 uses the native backend and one worker on CPU 0. PgBouncer 1.26.1 uses transaction pooling on CPU 0.

**TCP_NODELAY=1 and TCP_CORK=0 were verified on the live frontend socket and all 64 live backend sockets of each proxy.** Inspection used pidfd_getfd to duplicate descriptors temporarily, followed by getsockopt; it neither changes socket options nor establishes connections. The exact endpoints, FD roles and option values are saved in socket-options.json.

After 20 seconds of warmup, a continuous 60-second workload ran. A five-second perf trace captured enter/exit events for recvfrom, sendto, poll and epoll_wait on the query-processing thread, beginning approximately 10 seconds into that workload. No source timers, source edits or compilation.

Matched 47,233 complete ProxySQL transactions and 53,963 PgBouncer transactions. Each accepted transaction has exactly one 15-byte frontend receive, one 15-byte backend send, one 66-byte backend receive and one 66-byte frontend send; request/response backend FDs match. All transactions between the initial and final trace boundaries matched; the final boundary transaction is deliberately dropped. No failed I/O calls, no lost trace samples, and zero failed pgbench transactions.

All values below are **microseconds of traced wall time**. Entry/exit events are kernel syscall tracepoints, so intervals between syscalls include the syscall-return/entry boundary, any scheduling delay and tracing overhead; they are not pure userspace CPU measurements.

| Interval | ProxySQL median | ProxySQL p95 | PgBouncer median | PgBouncer p95 |
|---|---:|---:|---:|---:|
| Frontend recv returns → backend send enters | 7.184 | 7.400 | 1.783 | 1.860 |
| Backend recv returns → frontend send enters | 4.953 | 5.114 | 1.452 | 1.516 |
| Backend send syscall duration | 10.454 | 10.929 | 8.475 | 20.842 |
| Frontend send syscall duration | 9.190 | 10.341 | 7.451 | 7.739 |
| Frontend recv returns → backend send returns | 17.639 | 18.253 | 10.262 | 22.639 |
| Backend recv returns → frontend send returns | 14.151 | 15.527 | 8.906 | 9.224 |
| Frontend wait returns → recv returns | 3.781 | 3.913 | 3.311 | 3.413 |
| Backend wait returns → recv returns | 4.801 | 4.973 | 3.584 | 3.762 |
| Backend send returns → backend recv returns | 49.678 | 76.110 | 46.145 | 81.554 |
| Frontend recv returns → frontend send returns | 81.413 | 108.205 | 65.373 | 102.512 |

Including the send syscall means that the kernel accepted the bytes; it does not establish when the peer received them. The backend roundtrip interval includes PostgreSQL execution, TCP transport, proxy scheduling and receive processing. Wait-return-to-receive intervals start at poll/epoll_wait return, not when data first arrived in the kernel. Thus they do not measure the entire inbound socket-queue delay.

| Mean forwarding components | Deferred I/O | PgBouncer |
|---|---:|---:|
| Frontend recv returns → backend send enters | 7.214 | 1.830 |
| Backend recv returns → frontend send enters | 4.978 | 1.465 |
| Backend send syscall duration | 10.535 | 9.484 |
| Frontend send syscall duration | 9.621 | 7.492 |
| Frontend recv returns → backend send returns | 17.749 | 11.315 |
| Backend recv returns → frontend send returns | 14.599 | 8.957 |

Mean request-plus-response work between receive completion and send entry is **12.193 µs/query for ProxySQL versus 3.295 µs/query for PgBouncer**, a difference of **8.897 µs/query** in this trace. These means can be added; separate interval medians/p95s must not be added and interpreted as the percentile of the combined interval. TCP_NODELAY is already enabled on both proxies.

**Tracing overhead is measurable.** The query rates within the traces, compared with the median of untraced five-second progress intervals in the same continuous workload, were:

| | Traced queries/s | Untraced median queries/s | Change |
|---|---:|---:|---:|
| ProxySQL | 9440.4 | 10410.5 | -9.3% |
| PgBouncer | 10785.6 | 13378.4 | -19.4% |

Accordingly, these are measured instrumented latencies, not zero-overhead estimates. The same event set was used for both proxies; overhead is not assumed to cancel. Median, p95, p99, mean, extrema, exact matching counts and byte counts are preserved in forwarding-summary.json.

ProxySQL poll calls had nfds=3 or 4 in this capture. No backend connections were created during warmup or workload: ConnOK remained 64 and ConnERR remained zero, while PgBouncer retained the identical 64 backend identities and its connection log showed no backend creation or closure. Pool state was checked every second.

Raw forwarding.data files and full trace.txt exports remain in their lon104 result directories. Each raw-artifact.json records the file path, size and SHA-256. The initial ProxySQL trace export encountered a perf file-ownership guard after capture; re-exporting the same intact data with -f corrected it. The workload and trace were not rerun. Prior ProxySQL runtime was restored and the temporary PgBouncer was stopped.
