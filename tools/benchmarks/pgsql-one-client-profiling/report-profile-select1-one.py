from pathlib import Path
from collections import defaultdict
import json,re,html
r=Path(__file__).resolve().parent.parent/'results/profile-select1-one'
px=next(r.glob('profile-one-syscalls-proxysql-*'));pg=next(r.glob('profile-one-syscalls-pgbouncer-*'));cpu=next(r.glob('profile-one-cpu-proxysql-*'))
a=json.loads((px/'syscall-summary.json').read_text());b=json.loads((pg/'syscall-summary.json').read_text())
for d in [px,pg,cpu]:
 log=(d/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in log and 'number of clients: 1\n' in log and 'number of threads: 1\n' in log
 assert 'backend ssl=false: f||' in (d/'plaintext.txt').read_text()
 ss=json.loads((d/'samples.json').read_text());assert len(ss)==62
 if d!=pg:assert all(s['ConnOK']=='64' and s['ConnERR']=='0' and int(s['ConnUsed'])+int(s['ConnFree'])==64 for s in ss)
 else:
  assert all(s['identities']==ss[0]['identities'] and len(s['identities'])==64 and s['sv_login']=='0' for s in ss)
  assert not re.search(r'LOG S-.*(?:new connection|closing because)',(d/'steady-log.txt').read_text())
for x in [a,b]:
 assert x['running_pct_min']==100
 assert all(v==0 for k,v in x['counts'].items() if k.startswith('syscalls:sys_exit_'))
text=(cpu/'perf-self.txt').read_text();assert '# Total Lost Samples: 0' in text
rows=[]
for line in text.splitlines():
 c=[x.strip() for x in line.split('|')]
 if len(c)>4 and c[0].endswith('%'):rows.append(dict(samples=int(c[1]),period=int(c[2]),dso=c[3],symbol=c[4]))
total=sum(x['period'] for x in rows);assert total==int(re.search(r'Event count \(approx.\): (\d+)',text)[1])
bydso=defaultdict(int)
for x in rows:x['pct']=100*x['period']/total;bydso[x['dso']]+=x['period']
groups={k:100*v/total for k,v in bydso.items()}
inclusive=[]
for line in (cpu/'perf-inclusive.txt').read_text().splitlines():
 c=[x.strip() for x in line.split('|')]
 if len(c)>3 and c[0].endswith('%'):inclusive.append(dict(inclusive_pct=float(c[0].rstrip('%')),self_pct=float(c[1].rstrip('%')),dso=c[2],symbol=c[3]))
result=dict(samples=sum(x['samples'] for x in rows),total_period=total,groups=groups,self=rows,inclusive=inclusive)
(cpu/'cpu-summary.json').write_text(json.dumps(result,indent=2)+'\n')
lines=['# One-client plaintext syscall counts and deferred-I/O CPU profile','',
'SELECT 1 over localhost TCP on lon104; one client and one pgbench thread; 64 pre-established and retained backend connections. ProxySQL deferred-I/O commit b17a986f3 with native backend protocol and one worker on CPU 0. PgBouncer 1.26.1 uses transaction pooling on CPU 0. TLS is disabled and verified on both hops. Query digests remain enabled. All source timing flags are unset.','',
'Three separate runs: ProxySQL syscall counters, PgBouncer syscall counters, then ProxySQL CPU sampling with syscall counters detached. Each uses 20 seconds of warmup and 60 seconds of workload; profiling is enabled during approximately seconds 10–50. No source edits or compilation.','',
'**Syscalls per query** (all current threads in the proxy process):','',
'| Syscall | Deferred I/O | PgBouncer |','|---|---:|---:|']
keys=['recvfrom','sendto','poll','epoll_wait','read','write','readv','writev','connect']
for k in keys:lines.append(f"| `{k}` | {a['calls_per_query']['syscalls:sys_enter_'+k]:.5f} | {b['calls_per_query']['syscalls:sys_enter_'+k]:.5f} |")
lines += [f"| **All syscall entries** | **{a['calls_per_query']['raw_syscalls:sys_enter']:.5f}** | **{b['calls_per_query']['raw_syscalls:sys_enter']:.5f}** |",'',
'Both are approximately **two receives + two sends + two waits = six syscalls/query**. On this Linux, libc recv/send enter the kernel as recvfrom/sendto. ProxySQL waits with poll; PgBouncer waits with epoll_wait. No tracked read/write/recv/send exit returned EAGAIN in either run. There were no connect syscalls during the enabled windows. Minor calls include administrative sampling, housekeeping and logging; they are not all query-path work.','',
'| Counting evidence | Deferred I/O | PgBouncer |','|---|---:|---:|',
f"| Total syscall entries | {a['raw_total']:,} | {b['raw_total']:,} |",
f"| Queries in enclosing counter interval | {a['queries']:,} | {b['queries']:,} |",
f"| Enabled seconds | {a['enabled_seconds']:.3f} | {b['enabled_seconds']:.3f} |",
f"| Boundary slack (percent of enabled duration) | {a['boundary_slack_pct']:.3f}% | {b['boundary_slack_pct']:.3f}% |",
f"| Raw total minus sum of named entry counters | {a['raw_minus_named']} | {b['raw_minus_named']} |",'',
'perf stat counted all 345 available named syscall entries, plus the raw total and eight filtered EAGAIN exit counters. Every event ran 100% of its enabled time: no multiplex scaling. FIFO enable/disable acknowledgements bracket the window. Query snapshots enclose the counter window and take time, so the reported ratios slightly undercount true calls per in-window query; interpret 1.98–1.99 as approximately two. Small raw/named discrepancies arise at counter-enable/disable boundaries. The 5.99 versus 5.96 difference is not evidence of a useful syscall reduction.','',
'Counting this many events substantially perturbs execution. These runs are syscall diagnostics, not throughput benchmarks or CPU-cost measurements. Their full-run TPS was 4674 (ProxySQL) and 5126 (PgBouncer), versus the prior unprofiled 10479 and 13313. The subsequent CPU capture has none of these tracepoint counters attached.','',
'**CPU profile: ProxySQL deferred I/O only.** perf record sampled hardware cycles at requested frequency 999 Hz, with frame-pointer call stacks, on the query worker selected from the post-warmup thread CPU counters. User and kernel execution are included; sleeping time and PostgreSQL/pgbench execution are excluded.','',
f"{result['samples']:,} samples; zero lost samples. Percentages below are weighted by sampled cycle periods, not wall time.",'',
'| Where cycles were sampled | Share of total |','|---|---:|']
labels={'[kernel.kallsyms]':'Linux kernel','proxysql-head-deferred-session-io':'ProxySQL executable, including statically linked code','libc.so.6':'libc','[vdso]':'vDSO','libstdc++.so.6.0.30':'libstdc++'}
for k,v in groups.items():lines.append(f'| {labels.get(k,k)} | {v:.2f}% |')
lines+=['','The executable share is **not a pure ProxySQL-source percentage**: it also includes linked allocator/library routines.','',
'Kernel syscall paths, including descendants in the sampled call chains:','',
'| Kernel path | Inclusive share of all sampled cycles |','|---|---:|']
for name in ['__x64_sys_sendto','__x64_sys_poll','__x64_sys_recvfrom']:
 x=next(x for x in inclusive if x['symbol']=='[k] '+name);lines.append(f"| `{name}` | {x['inclusive_pct']:.2f}% |")
lines+=['',
'These are inclusive call-chain estimates, not syscall wall-clock durations; the poll share is CPU spent entering, processing, scheduling and returning from the wait, not time asleep. Do not add inclusive parent/child percentages together or add them to the self percentages below. Frame-pointer unwinding can truncate userspace stacks, so userspace inclusive totals are not treated as exhaustive.','',
'Largest userspace self costs (excluding their callees):','',
'| Function | Share of all sampled cycles | Share of userspace cycles |','|---|---:|---:|']
user_pct=100-groups['[kernel.kallsyms]']
for x in [x for x in rows if x['symbol'].startswith('[.]')][:15]:lines.append(f"| `{x['symbol'][4:]}` | {x['pct']:.2f}% | {x['pct']/user_pct*100:.2f}% |")
lines+=['',
'Largest kernel self costs:','',
'| Function | Share of all sampled cycles |','|---|---:|']
for x in [x for x in rows if x['symbol'].startswith('[k]')][:12]:lines.append(f"| `{x['symbol'][4:]}` | {x['pct']:.2f}% |")
lines+=['',
'The disabled `pgsql_loop_timing_point` hook still appears at 0.57% self cycles. Source inspection confirms it checks the cached PX_PGSQL_LOOP_TIMING setting and returns immediately when unset; this is the existing call/check overhead, not active timer collection. No patch was made in response.','',
'The syscall quantity is essentially the same in both proxies. The deferred-I/O worker spends most sampled cycles in the kernel, notably the send and poll paths. Userspace cost is distributed across digesting, session scheduling/handling, packet processing and many smaller functions; digesting alone is 1.40% of total cycles. This capture does not establish why the same syscall count costs different amounts across proxies, and it is not a PgBouncer CPU profile.','',
'The CPU-profile run reached 9469 TPS versus the prior unprofiled 10479; profiling and run variation affect these numbers, so sampled shares are the result of interest. No backend connections were created during warmup or measured workload in any run. All 64 stayed established; all runs had zero failed transactions. Prior ProxySQL runtime was restored and the temporary PgBouncer was stopped.','',
f'Raw self profile: [{cpu.name}/perf-self.txt]({cpu.name}/perf-self.txt). Inclusive call chains: [{cpu.name}/perf-inclusive.txt]({cpu.name}/perf-inclusive.txt). The full perf.data path, size and SHA-256 are recorded in `{cpu.name}/raw-artifact.json`. Each syscall directory contains every raw event count, count/query ratio, query boundaries, pool snapshots and the exact command.']
(r/'REPORT.md').write_text('\n'.join(lines)+'\n')
print(json.dumps(dict(cpu_groups=groups,samples=result['samples'],px_syscalls_per_query=a['raw_total']/a['queries'],pg_syscalls_per_query=b['raw_total']/b['queries'],checks_pass=True),indent=2))
