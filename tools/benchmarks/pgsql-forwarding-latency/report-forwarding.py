from pathlib import Path
import json,re,statistics
r=Path(__file__).resolve().parent.parent/'results/forwarding-latency'
dirs=[next(r.glob('forwarding-proxysql-*')),next(r.glob('forwarding-pgbouncer-*'))]
rows=[]
for d in dirs:
 s=json.loads((d/'forwarding-summary.json').read_text());samples=json.loads((d/'samples.json').read_text());log=(d/'pgbench.txt').read_text()
 assert len(samples)==62 and 'number of failed transactions: 0' in log
 assert 'number of clients: 1\n' in log and 'number of threads: 1\n' in log
 assert 'backend ssl=false: f||' in (d/'plaintext.txt').read_text()
 opt=json.loads((d/'socket-options.json').read_text());assert len(opt['sockets'])==65 and not opt['errors']
 assert all(x['tcp_nodelay']==1 and x['tcp_cork']==0 for x in opt['sockets'])
 assert '# Total Lost Samples: 0' in (d/'trace-integrity.txt').read_text()
 if 'proxysql' in d.name:assert all(x['ConnOK']=='64' and x['ConnERR']=='0' and int(x['ConnUsed'])+int(x['ConnFree'])==64 for x in samples)
 else:
  assert all(x['identities']==samples[0]['identities'] and len(x['identities'])==64 and x['sv_login']=='0' for x in samples)
  assert not re.search(r'LOG S-.*(?:new connection|closing because)',(d/'steady-log.txt').read_text())
 assert s['skipped']=={'last_trace_boundary_query':1} and not s['nonpositive_returns']
 prog=[(float(t),float(tps)) for t,tps in re.findall(r'progress: ([\d.]+) s, ([\d.]+) tps',log)]
 untraced=[tps for t,tps in prog if t<=10 or t>=25]
 s['untraced_progress_median_tps']=statistics.median(untraced)
 s['traced_tps_delta_pct']=(s['matched_trace_tps']/s['untraced_progress_median_tps']-1)*100
 s['full_run_tps']=float(re.search(r'tps = ([\d.]+)',log)[1]);rows.append(s)
 # Exported perf text may contain trailing padding.
 for f in d.glob('trace-*.txt'):
  f.write_text('\n'.join(x.rstrip() for x in f.read_text().splitlines())+'\n')
a,b=rows
labels=[('request_processing','Frontend recv returns → backend send enters'),('response_processing','Backend recv returns → frontend send enters'),('request_send_syscall','Backend send syscall duration'),('response_send_syscall','Frontend send syscall duration'),('request_forward_complete','Frontend recv returns → backend send returns'),('response_forward_complete','Backend recv returns → frontend send returns'),('frontend_wait_return_to_recv_complete','Frontend wait returns → recv returns'),('backend_wait_return_to_recv_complete','Backend wait returns → recv returns'),('backend_roundtrip_including_proxy_wait','Backend send returns → backend recv returns'),('proxy_received_query_to_response_sent','Frontend recv returns → frontend send returns')]
lines=['# Measured forwarding latency: deferred I/O versus PgBouncer','',
'One client and one pgbench thread; SELECT 1; simple PostgreSQL protocol; localhost TCP on lon104; TLS disabled on both hops; 64 pre-established and retained backends. ProxySQL deferred-I/O b17a986f3 uses the native backend and one worker on CPU 0. PgBouncer 1.26.1 uses transaction pooling on CPU 0.','',
'**TCP_NODELAY=1 and TCP_CORK=0 were verified on the live frontend socket and all 64 live backend sockets of each proxy.** Inspection used pidfd_getfd to duplicate descriptors temporarily, followed by getsockopt; it neither changes socket options nor establishes connections. The exact endpoints, FD roles and option values are saved in socket-options.json.','',
'After 20 seconds of warmup, a continuous 60-second workload ran. A five-second perf trace captured enter/exit events for recvfrom, sendto, poll and epoll_wait on the query-processing thread, beginning approximately 10 seconds into that workload. No source timers, source edits or compilation.','',
f"Matched {a['accepted_queries']:,} complete ProxySQL transactions and {b['accepted_queries']:,} PgBouncer transactions. Each accepted transaction has exactly one 15-byte frontend receive, one 15-byte backend send, one 66-byte backend receive and one 66-byte frontend send; request/response backend FDs match. All transactions between the initial and final trace boundaries matched; the final boundary transaction is deliberately dropped. No failed I/O calls, no lost trace samples, and zero failed pgbench transactions.",'',
'All values below are **microseconds of traced wall time**. Entry/exit events are kernel syscall tracepoints, so intervals between syscalls include the syscall-return/entry boundary, any scheduling delay and tracing overhead; they are not pure userspace CPU measurements.','',
'| Interval | ProxySQL median | ProxySQL p95 | PgBouncer median | PgBouncer p95 |','|---|---:|---:|---:|---:|']
for key,label in labels:
 x,y=a['metrics'][key],b['metrics'][key];lines.append(f"| {label} | {x['p50_us']:.3f} | {x['p95_us']:.3f} | {y['p50_us']:.3f} | {y['p95_us']:.3f} |")
lines+=['',
'Including the send syscall means that the kernel accepted the bytes; it does not establish when the peer received them. The backend roundtrip interval includes PostgreSQL execution, TCP transport, proxy scheduling and receive processing. Wait-return-to-receive intervals start at poll/epoll_wait return, not when data first arrived in the kernel. Thus they do not measure the entire inbound socket-queue delay.','',
'| Mean forwarding components | Deferred I/O | PgBouncer |','|---|---:|---:|']
for key,label in labels[:6]:lines.append(f"| {label} | {a['metrics'][key]['mean_us']:.3f} | {b['metrics'][key]['mean_us']:.3f} |")
pa=sum(a['metrics'][k]['mean_us'] for k in ['request_processing','response_processing']);pb=sum(b['metrics'][k]['mean_us'] for k in ['request_processing','response_processing'])
lines+=['',f'Mean request-plus-response work between receive completion and send entry is **{pa:.3f} µs/query for ProxySQL versus {pb:.3f} µs/query for PgBouncer**, a difference of **{pa-pb:.3f} µs/query** in this trace. These means can be added; separate interval medians/p95s must not be added and interpreted as the percentile of the combined interval. TCP_NODELAY is already enabled on both proxies.','',
'**Tracing overhead is measurable.** The query rates within the traces, compared with the median of untraced five-second progress intervals in the same continuous workload, were:','',
'| | Traced queries/s | Untraced median queries/s | Change |','|---|---:|---:|---:|']
for label,s in zip(['ProxySQL','PgBouncer'],rows):lines.append(f"| {label} | {s['matched_trace_tps']:.1f} | {s['untraced_progress_median_tps']:.1f} | {s['traced_tps_delta_pct']:+.1f}% |")
lines+=['',
'Accordingly, these are measured instrumented latencies, not zero-overhead estimates. The same event set was used for both proxies; overhead is not assumed to cancel. Median, p95, p99, mean, extrema, exact matching counts and byte counts are preserved in forwarding-summary.json.','',
'ProxySQL poll calls had nfds=3 or 4 in this capture. No backend connections were created during warmup or workload: ConnOK remained 64 and ConnERR remained zero, while PgBouncer retained the identical 64 backend identities and its connection log showed no backend creation or closure. Pool state was checked every second.','',
'Raw forwarding.data files and full trace.txt exports remain in their lon104 result directories. Each raw-artifact.json records the file path, size and SHA-256. The initial ProxySQL trace export encountered a perf file-ownership guard after capture; re-exporting the same intact data with -f corrected it. The workload and trace were not rerun. Prior ProxySQL runtime was restored and the temporary PgBouncer was stopped.']
(r/'REPORT.md').write_text('\n'.join(lines)+'\n');(r/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(dict(checks_pass=True,proxysql_queries=a['accepted_queries'],pgbouncer_queries=b['accepted_queries'],mean_extra_processing_us=pa-pb,tracing_tps_changes=[s['traced_tps_delta_pct'] for s in rows]),indent=2))
