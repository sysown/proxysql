from pathlib import Path
import json,collections,statistics,re,shutil,sys
root=Path(sys.argv[1]) if len(sys.argv)>1 else (Path(__file__).resolve().parent if (Path(__file__).resolve().parent/'REPORT.md').exists() else Path(__file__).resolve().parent.parent/'results/forwarding-hotpath')
# Keep the earlier, explicitly qualified sampling tables as supporting evidence.
old=root/'REPORT.md'
if not (root/'sampling-details.md').exists():shutil.copy2(old,root/'sampling-details.md')
def load(p,n):return json.loads((p/n).read_text())
allruns=sorted(p for p in root.iterdir() if p.is_dir() and (p/'samples.json').exists())
audit=[]
for p in allruns:
 rows=load(p,'samples.json');prep=load(p,'prepared.json');v={r['variable_name']:r['variable_value'] for r in load(p,'settings.json')}
 assert v['pgsql-query_digests']=='true' and v['pgsql-threads']=='1' and v['pgsql-have_ssl']=='false' and v['pgsql-use_native_backend_protocol']=='true'
 assert prep['ConnOK']=='64' and prep['ConnFree']=='64' and prep['ConnUsed']=='0'
 assert len(rows)==62
 assert all(r['ConnOK']=='64' and r['ConnERR']=='0' and int(r['ConnUsed'])+int(r['ConnFree'])==64 for r in rows)
 assert 'number of failed transactions: 0' in (p/'pgbench.txt').read_text()
 if (p/'integrity.txt').exists():assert '# Total Lost Samples: 0' in (p/'integrity.txt').read_text()
 if (p/'socket-options.json').exists():
  sockets=load(p,'socket-options.json')['sockets'];assert len(sockets)==65
  assert all(s['tcp_nodelay']==1 and s['tcp_cork']==0 for s in sockets)
 audit.append(p.name+': PASS; 64 retained backends, ConnOK=64, ConnERR=0, 62 snapshots, zero failed queries; native, plaintext, one worker, query digests enabled.')
(root/'audit.txt').write_text('\n'.join(audit)+'\n')
counts={mode:load(next(root.glob('count-forwarding-'+mode+'-*')),'counter-summary.json') for mode in ['candidate','optimized']}
un=load(root,'unprofiled-summary.json');before=counts['candidate'];after=counts['optimized']
metrics=[]
for k,label in [('instructions:u','Retired userspace instructions/query'),('cycles:u','Userspace cycles/query'),('branch-misses:u','Userspace branch misses/query'),('L1-icache-load-misses','Userspace L1 instruction-cache misses/query')]:
 a=before['per_query'][k];b=after['per_query'][k];metrics.append(dict(metric=label,before=a,after=b,percent_change=(b/a-1)*100))
(root/'counter-comparison.json').write_text(json.dumps(metrics,indent=2))
lines=['# ProxySQL forwarding CPU investigation','',
'The short-query tokenizer copy is a confirmed removable operation. Replacing its formatted copy with `memcpy` removes about 589 retired instructions per query and reduces counted worker userspace cycles by 5.7% in a matched counting-only pair. **It is not a demonstrated throughput improvement:** four unprofiled runs averaged 1.76% lower TPS with the change. The experimental patch is committed and preserved; no overall performance fix is claimed.','',
'## Controlled workload','',
'lon104, bare metal processes, PostgreSQL on localhost TCP; `SELECT 1`, simple query protocol, one pgbench client and one pgbench thread. One ProxySQL worker pinned to CPU 0; pgbench affinity CPUs 2,4,6,8,10,12,14,16; performance governor. Native backend protocol, TLS disabled on both hops, query digests enabled. All 64 backend connections are created before the 20-second warmup; each measurement lasts 60 seconds and asserts unchanged ConnOK/ConnERR plus a pool total of 64 every second. No repository test was changed.','',
'Baseline: deferred I/O `b17a986f3`, binary SHA-256 `961419b9503186758a2d7d772429f0bc36d6f2127422be3784bac3002acc0f82`. Patch: `73f822839`, binary SHA-256 `2b8476839d5ce8c1943d72aee23651f3143573872ec3eb7a70080c00bc16884c`. Source differs only in `lib/c_tokenizer.cpp`. Branch: `optimization/pgsql-forwarding-hotpath`.','',
'## Where the work occurs','',
'These are measured function locations plus verified source behavior. Self samples do not include callees. Very short phase percentages varied between captures, so they are not presented as exact steady-state time allocations. Full sample counts and per-function tables are preserved in the capture directories and [sampling details](sampling-details.md).','',
'| Path | Functions / source | Work done |','|---|---|---|',
'| Request normalization | `pgsql_query_digest_and_first_comment`, `lib/pgsql_tokenizer.cpp:2830` | Multiple normalization/compression passes, character classification and case folding. Largest named request hotspot in all four captures. |',
'| Request classification | `legacy_command_type` → `tokenizer`, `lib/c_tokenizer.cpp:24` | Copy digest/prefix into mutable storage, split tokens and classify the SQL command. The short-input copy unnecessarily invokes printf formatting. |',
'| Query rules and backend acquisition | `Query_Processor::process_query`, `get_MyConn_from_pool`, `MyHGC_find`, `get_random_MySrvC` | Rule/default processing, hostgroup lookup, pool selection and session-state compatibility checks. |',
'| Response buffering | `PgSQL_Query_Result::add_native_backend_message` and `buffer_to_PSarrayOut`, `lib/PgSQL_Protocol.cpp:3119` | Build client-wire messages. For a small result, shrink the 16 KiB accumulation buffer with realloc, hand it to the output queue, then allocate another 16 KiB buffer. Allocator functions are prominent response samples. |',
'| Response state/accounting | `PgSQL_TxnCmdParser::parse`, `ProcessQueryAndSetStatusFlags`, `sync_txn_tracker_with_backend`, `query_parser_update_counters`, `QP_query_digest_stats::add_time` | Transaction/multiplexing state, digest accounting, hash lookup and synchronization. |',
'| Worker work outside forwarding intervals | `process_all_sessions`, `run`, `ProcessAllMyDS_BeforePoll`, local-pool publication | Scheduling/scanning, poll setup, connection publication and housekeeping. The disabled `pgsql_loop_timing_point` hook still incurs calls and environment-gate checks; it is visible in samples. |','',
'```mermaid','flowchart TD',
'    A["Frontend recv returns"] --> B["Digest normalization"]',
'    B --> C["Command classification: tokenizer copy and token scans"]',
'    C --> D["Query rules, hostgroup/pool lookup, session compatibility"]',
'    D --> E["Encode query / backend send"]',
'    E --> F["Backend work and poll waiting"]',
'    F --> G["Backend recv returns"]',
'    G --> H["Frame response / result-buffer allocation and copies"]',
'    H --> I["Transaction state, digest counters, release connection"]',
'    I --> J["Frontend send"]',
'    J --> K["Worker scheduling, pool publication, poll preparation"]',
'    K --> A','```','',
'## The code change','',
'`tokenizer()` already knows the input length. For inputs at most 127 bytes, it used `snprintf(buffer, 128, "%.*s", length, input)`. The patch copies `length + 1` bytes, including the terminating NUL, into that same 128-byte buffer. Longer inputs retain the existing `strdup` path. This is shared tokenizer code, not a SELECT 1 special case. Digest generation, routing, transaction tracking and the scheduler are unchanged.','',
'The original call-stack capture identifies snprintf below `legacy_command_type → tokenizer`; disassembly verifies the call changes to memcpy. Formatted-copy symbols disappear from both patched phase captures. An isolated differential check of the actual original and patched tokenizer implementations matched 31,694 cases, including NULL input, embedded terminators, both empty-token modes, varied delimiters and the 127/128-byte allocation boundary. The optimized build completed.','',
'## Counting-only CPU comparison','',
'`perf stat` counted only the worker, for the central 40 seconds. Four events were enabled/disabled through an acknowledged control FIFO; all ran without multiplexing. No syscall tracing, sampled interrupts, source timers or call stacks were enabled in these runs. Query counts bracket the acknowledged counter window; the exact boundary slack is retained in `counter-summary.json`. This reduces profiling intrusion but does not imply zero overhead: per-thread hardware counters can affect context-switch work. The counting runs delivered 9,811 versus 9,746 TPS, below the unprofiled runs; they are used for CPU attribution, not production throughput estimates.','',
'| Metric | Original | Copy patch | Change |','|---|---:|---:|---:|']
for m in metrics:lines.append(f'| {m["metric"]} | {m["before"]:,.2f} | {m["after"]:,.2f} | {m["percent_change"]:+.2f}% |')
lines += ['',f'IPC: {before["user_ipc"]:.3f} → {after["user_ipc"]:.3f}. Counted worker userspace time: {before["worker_user_us_per_query"]:.3f} → {after["worker_user_us_per_query"]:.3f} µs/query. These counters do **not** support blaming the patched regression on more instruction-cache misses; misses fell in this pair. The cause of the unprofiled regression is not established.','',
'## Unprofiled throughput','',
'Run order: original → copy → copy → original. No perf process or source timing was active.','',
'| Build | TPS run 1 | TPS run 2 | Mean TPS | Mean process user µs/query |','|---|---:|---:|---:|---:|']
for mode,label in [('candidate','Original deferred I/O'),('optimized','Tokenizer copy')]:
 rs=sorted(un[mode]['runs'],key=lambda x:x['path']);m=un[mode]['means'];lines.append(f'| {label} | {rs[0]["tps"]:,.2f} | {rs[1]["tps"]:,.2f} | {m["tps"]:,.2f} | {m["user_us_per_query"]:.3f} |')
lines += ['', '**Decision:** preserve the patch as a measured CPU experiment, not an accepted end-to-end performance fix. Lower instructions and cycles in an instrumented pair do not override the negative unprofiled result. No further scheduling or protocol change was made to chase TPS.','',
'## Forwarding intervals and sampling limits','',
'Precise-sampling captures measured frontend recv return → backend send entry at **8.230 → 6.931 µs**, and backend recv return → frontend send entry at **4.910 → 4.973 µs**. The ordinary-sampling pair similarly measured **8.196 → 7.017 µs** on the request path. These are traced wall-time syscall-boundary intervals; they include return/entry work and scheduling delay, not just userspace execution. Tracing perturbs the workload, so these are not uninstrumented latency claims.','',
'All phase captures lost zero samples. Nevertheless the original binary’s sampled request/response/outside split moved from 57.8/12.0/30.2% with ordinary sampling to 42.8/20.1/37.1% with precise sampling. The earlier 58/12/30 split is therefore **not a stable cost allocation**. Precise IP sampling alone does not establish stable attribution at these short boundaries. Function locations identify concrete work; the counting-only instruction/cycle totals and separate unprofiled runs provide independent checks.','',
'libc samples were resolved with debuginfo build ID `93ac61ec5a8eb1396f9fbd350e3169a558528a40`, matching the installed library. Apparent nearest-export labels such as `__nss_database_lookup` were not interpreted as actual work. No new backend connections occurred in any measured window; TCP_NODELAY=1 and TCP_CORK=0 were read from the live frontend and all 64 backend sockets in each phase capture.','',
'## Artifacts and state','',
'- [Audit of settings, per-second pool samples and failures](audit.txt).',
'- [Counter comparison](counter-comparison.json) and [unprofiled repetitions](unprofiled-summary.json).',
'- [Tokenizer differential validation](tokenizer-validation.txt).',
'- [Experimental source patch](73f822839.patch).',
'- Raw large perf captures remain under `/home/rene/pg-network-bench/results/` on lon104, losslessly compressed as `phase.data.gz` and `trace.txt.gz`; exported metadata records original SHA-256 hashes. No raw perf binary is committed to git.',
'- The previous runtime was restored after every run. The final restoration check confirms no pgbench process remains and the earlier inline-handoff binary is active again. The experimental binary is preserved separately.',
'- The pre-existing staged `tools/benchmarks/pgsql-deferred-io-cost` files were left untouched.','']
text='\n'.join(lines)
final_dirs=sorted(root.glob('tokenizer-final-one-plain-*'))
if final_dirs:
 assert len(final_dirs)==4
 final={}
 for mode in ['candidate','bounded']:
  runs=[dict(path=p.name,**load(p,'summary.json')) for p in final_dirs if load(p,'summary.json')['mode']==mode]
  assert len(runs)==2
  final[mode]=dict(runs=runs,means={k:statistics.mean(r[k] for r in runs) for k in ['tps','user_us_per_query','system_us_per_query','cpu_us_per_query']})
 a=final['candidate']['means'];b=final['bounded']['means'];gain=(b['tps']/a['tps']-1)*100;cpu=(b['user_us_per_query']/a['user_us_per_query']-1)*100
 (root/'final-unprofiled-summary.json').write_text(json.dumps(final,indent=2))
 opening=f"The final bounded tokenizer copy (`4699f3175`) averaged **{b['tps']:,.2f} TPS versus {a['tps']:,.2f} TPS ({gain:+.2f}%)**, with process userspace CPU/query **{cpu:+.2f}%** in the final matched, unprofiled batch. This is a preliminary result from two runs per build, not a general performance guarantee. The earlier unprofiled baseline ranged from 10,536 to 10,627 TPS, illustrating why these modest gains must be qualified. The concrete change removes printf formatting from a per-query text copy."
 first=text.split('\n\n')[1];text=text.replace(first,opening,1)
 section=['## Final bounded-copy validation','', 'Final commit: `4699f3175` (on top of `73f822839`); binary SHA-256 `9a3e63ec57d69f5033891ecd7147a0e1f8301f7ebe280f3c51a3c0049a977479`. Run order: bounded copy → original → original → bounded copy. No perf collection or source timing was active.', '', '| Build | TPS run 1 | TPS run 2 | Mean TPS | Mean process user µs/query |','|---|---:|---:|---:|---:|']
 for mode,label in [('candidate','Original deferred I/O'),('bounded','Final bounded copy')]:
  rs=final[mode]['runs'];m=final[mode]['means'];section.append(f"| {label} | {rs[0]['tps']:,.2f} | {rs[1]['tps']:,.2f} | {m['tps']:,.2f} | {m['user_us_per_query']:.3f} |")
 section += ['', 'The final copy clamps the number of bytes to the destination capacity and writes the NUL terminator explicitly, preserving the original snprintf behavior even when the size_t input length narrows to the legacy int field. It passed the 31,694 ordinary differential cases and 16 additional forced-length cases. It received its own build and measurements: the CPU counters and traced forwarding intervals below belong to the earlier `73f822839` prototype, not this final binary.', '', 'This change addresses one measured per-query cost. It does not resolve the whole ProxySQL/PgBouncer gap, establish a stable percentage for every forwarding phase, or explain the intermediate prototype’s unprofiled regression.', '']
 text=text.replace('## Where the work occurs','\n'.join(section)+'\n## Where the work occurs',1)
 text=text.replace('Patch: `73f822839`','First prototype: `73f822839`',1)
 text=text.replace('## Counting-only CPU comparison','## Intermediate prototype: counting-only CPU comparison',1)
 text=text.replace('## Unprofiled throughput','## Intermediate prototype: unprofiled throughput',1)
 text=text.replace('**Decision:** preserve the patch as a measured CPU experiment, not an accepted end-to-end performance fix.', '**Intermediate result:** the first copy implementation was a measured CPU experiment without an end-to-end performance win. It was superseded by the separately measured bounded copy above.')
 text=text.replace('The patch copies `length + 1` bytes, including the terminating NUL, into that same 128-byte buffer.', 'The first prototype copied `length + 1` bytes into that buffer. The final version instead copies a bounded prefix and writes its NUL explicitly, retaining the original snprintf truncation semantics.')
 text=text.replace('- [Experimental source patch](73f822839.patch).','- [Final cumulative source patch](tokenizer-bounded.patch), [initial implementation commit](73f822839.patch), and [bounded-copy refinement commit](4699f3175.patch).')
(root/'REPORT.md').write_text(text)
print('PASS:',len(allruns),'runs audited; report generated.')
