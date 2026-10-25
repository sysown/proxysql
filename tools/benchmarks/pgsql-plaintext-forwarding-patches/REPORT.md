# Plaintext forwarding patches and results

Implemented and committed all three approved changes on `optimization/pgsql-plaintext-forwarding`. Shared-pool behavior is unchanged. The final call trace confirms the intended work was removed; throughput differences in this single-client setup are modest and variable.

| Code commit | Change |
|---|---|
| `81c0b3a55` | Skip the COPY regex when raw SQL contains no case-insensitive COPY substring |
| `84c6a5662` | Consume completed session work before the backendless scan revisits it |
| `754dc4af4` | Batch adjacent native simple-query DataRows using their original wire bytes |

The complete product diff is in [product.patch](product.patch). Detailed commit descriptions are in [commit-messages.txt](commit-messages.txt).

## Final throughput

All runs: lon104, localhost TCP on both hops, no TLS, one persistent client, one pgbench job, one ProxySQL worker, ten pre-established retained backends. Native backend protocol enabled. Commands statistics, query digests and parsing disabled. Proxy CPU zero, client CPU two, controller CPU eighteen; performance governor. Twenty seconds warmup, sixty seconds measured, simple query protocol, per-transaction latency logging to tmpfs.

| Workload | Before these patches: TPS | Final TPS | Before: user CPU/query | Final: user CPU/query | Before p99 | Final p99 |
|---|---:|---:|---:|---:|---:|---:|
| SELECT 1 | 10,983.58 | 10,706.36 | 12.00 µs | 11.80 µs | 125 µs | 128 µs |
| 42 rows / about 4KB | 5,395.83 | 5,514.36 | 20.99 µs | 19.11 µs | 293 µs | 286 µs |

The original measurements are preserved in [unprofiled-reference.json](unprofiled-reference.json), not rerun. These old-versus-final differences are not paired causal estimates. SELECT 1 does not show a stable throughput improvement. The 4KB result is approximately two percent above the original reference, but a single final run does not establish a sustained gain.

For the result-batching change specifically, its immediately preceding 4KB reference was **5,459.88 TPS**, user CPU **19.49 µs/query**, p99 **290 µs**. Final batching measured **5,514.36 TPS**, **19.11 µs/query**, p99 **286 µs**: approximately **one percent more TPS** in that comparison.

## Intermediate measurements and the scalar recheck

| Scalar build | Run | TPS | User CPU/query | p99 |
|---|---|---:|---:|---:|
| COPY guard | Initial | 11,000.80 | 11.23 µs | 125 µs |
| COPY + completed-session guard | Initial | 10,458.58 | 11.83 µs | 132 µs |
| COPY guard | Focused repeat | 10,487.20 | 12.03 µs | 134 µs |
| COPY + completed-session guard | Focused repeat | 10,897.76 | 11.51 µs | 126 µs |
| All patches | Final | 10,706.36 | 11.80 µs | 128 µs |

The initially lower scheduler result triggered a pause before further patching and a focused COPY-versus-scheduler repeat. The repeat moved in the opposite direction. Both initial and repeated observations are retained; neither a consistent scheduler regression nor a reliable speedup is established by these samples. Do not treat removed handler calls as a proportional reduction in CPU or increase in TPS.

Historical PgBouncer references under this configuration were 12,779.02 TPS for SELECT 1 and 6,608.28 TPS for 4KB. PgBouncer was not rerun during this implementation task, so those figures provide earlier context rather than a new paired comparison.

## Final call-count verification

A separate 4KB diagnostic used aggregate bpftrace counters on the immutable final binary. Its throughput is excluded from all tables above because uprobes add overhead. The window bracket contained 196,761 pool queries; counting was enabled for 39.94 seconds. Snapshot/control boundary slack was 0.297%, explaining the small difference between normalized counts and whole integers.

| Operation | Calls/query, approximately |
|---|---:|
| Full session handler | 2 |
| Session writeout | 2 |
| set_pollout | 5 |
| COPY regex / RE2 PartialMatchN | 0 |
| Native per-message result append | 3 |
| Native row-span append | 1 |
| New backend connect | 0 |

Every counted row-span append contained **exactly 42 rows**: **8,250,438 rows / 196,439 batches**. There were **589,317** normal message appends, corresponding to RowDescription, CommandComplete and ReadyForQuery for those queries. DataRows now use the single span append instead of individual reconstruction and copies.

Handler callers resolve to early frontend dispatch and the backend-owning scan. The former completed-session call from the backendless scan is absent. Thirty-two background idle-connection handler entries are separately visible and negligible. The previous unpatched SELECT 1 trace had approximately three full handler calls/query; source-resolved caller absence is the direct evidence for this fix, rather than comparing totals across different workloads.

set_pollout is a userspace poll-interest update, not a syscall. Exact counters, normalization and source resolution are in [call-verification.json](call-verification.json), [handler-callsites.json](handler-callsites.json), and the final diagnostic directory listed in [diagnostics.json](diagnostics.json).

## What changed

**COPY fallback.** Keep the existing query-start gate and digest prefilter. When no digest exists, conservatively skip RE2 only when COPY is absent from raw text entirely. Possible matches still use the existing regex, preserving comments, whitespace, case and multiple-statement behavior.

**Completed-session revisit.** After a successful backend handler, clear the consumed work flag only when the session is waiting for client input, its current backend is detached, and its frontend has neither pending readiness nor queued packets. The handler already consumes readiness and drains queued commands. Pending output remains armed for later poll readiness. This avoids expanding the existing linearly searched dispatched-session vector. Inline waiter handoff and shared-pool publication remain unchanged.

**Native result batching.** Coalesce complete adjacent DataRow frames into a span bounded by the result accumulation-buffer capacity. Copy the original headers and payloads together; update tuple state, rows, packets and bytes in bulk. Stop before non-row, incomplete or malformed frames and leave those to existing handling. Copy the borrowed span before another framer feed can move storage. Enable batching only when the buffered-byte upper bound cannot trigger existing fetch/throttle suspension; otherwise keep the per-row path. Extended-query handling and all other result-message side effects stay on their existing paths.

This is a bounded row-copy optimization. The existing owned output buffers and small-result handoff allocation/copy remain; it is not a zero-copy lifetime redesign.

## Correctness and validation

- Actual frontend output matched direct PostgreSQL output for scalar queries, NULL/empty/multiline values, the 42-row result, empty results, a large individual row, many rows, multiple statements, transactions and COPY output. Expected division errors, including errors after an earlier result, were also checked.
- Final unprofiled runs additionally checked large results with a temporarily reduced resultset threshold, then restored the setting before pool preparation and warmup. This exercises the suspension fallback as well as the normal batching path.
- All seven accepted throughput runs had zero failed transactions. Every snapshot retained exactly ten backends: ConnOK remained ten, ConnERR zero, and ConnUsed plus ConnFree remained ten. Digest maps stayed empty and unchanged.
- An independent raw-log audit checked **3,870,804 transactions**, log hashes, percentile ranks, immutable binary hashes, runtime settings, plaintext transport, local backend addresses and instance cleanup. See [verification.json](verification.json).
- The separate final diagnostic also retained ten backends, counted zero connect calls, and passed its operation-count checks. Diagnostic tools and isolated processes stopped afterward.
- A fresh read-only reviewer found no correctness blocker in the product diff. See [REVIEW.md](REVIEW.md). Runtime evidence is separate from that review.
- Repository tests were unchanged and were not run, following the benchmark-first instruction. Verification here consists of builds, standalone execution checks, benchmarks and the independent audit.

## Experiment control and excluded data

Three affected directories are explicitly excluded in [excluded.json](excluded.json): an earlier 4KB run and two diagnostic attempts that overlapped after an interrupt inherited as ignored under nohup. Their numbers do not enter the tables or verification above. The new benchmark and diagnostic harnesses take an exclusive lock and install explicit interrupt handlers. Subsequent build and benchmark phases were serialized. The unfavorable initial scalar measurement remains included because it was unaffected by this overlap.

The isolated build dependencies had been removed after the earlier build. Existing prebuilt dependencies were restored locally without rebuilding shared dependencies. The restored SQLite object was checked byte-for-byte against the existing archive. All product builds used the established release flags, feature flags and fixed embedded version string; metadata records the actual source commit and SHA256 for each immutable executable. Diagnostic source timers remain compiled out.

The main worktree's pre-existing staged changes remained unchanged. The earlier branch is preserved; implementation is on `optimization/pgsql-plaintext-forwarding`. Binary provenance is in [plaintext-implementation-binaries.json](plaintext-implementation-binaries.json). Raw compressed transaction archives remain under their per-run directories on lon104 and are excluded from Git.

Reproducible benchmark, correctness, diagnostic, collection and verification scripts are stored alongside this report. [runs.json](runs.json) lists accepted throughput runs with their original absolute locations. No shared-pool optimization was implemented.
