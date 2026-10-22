from pathlib import Path
import json,re,statistics
r=Path(__file__).resolve().parent.parent/'results/select1-one-plaintext'
rows=[]
for mode in ['head','baseline','candidate','pgbouncer']:
 ds=list(r.glob('select1-one-plain-'+mode+'-*'));assert len(ds)==1,ds
 d=ds[0];s=json.loads((d/'summary.json').read_text());samples=json.loads((d/'samples.json').read_text())
 assert len(samples)==62
 log=(d/'pgbench.txt').read_text()
 assert 'number of failed transactions: 0' in log
 assert 'number of clients: 1\n' in log and 'number of threads: 1\n' in log
 assert 'query mode: simple' in log and 'transaction type: select1.sql' in log
 assert 'backend ssl=false: f||' in (d/'plaintext.txt').read_text()
 if mode!='pgbouncer':
  assert all(int(x['ConnUsed'])+int(x['ConnFree'])==64 and x['ConnOK']=='64' and x['ConnERR']=='0' for x in samples)
  used=[int(x['ConnUsed']) for x in samples[5:56]];free=[int(x['ConnFree']) for x in samples[5:56]]
 else:
  assert all(x['identities']==samples[0]['identities'] and len(x['identities'])==64 and x['sv_login']=='0' for x in samples)
  assert not re.search(r'LOG S-.*(?:new connection|closing because)',(d/'steady-log.txt').read_text())
  used=[int(x['sv_active']) for x in samples[5:56]];free=[int(x['sv_idle']) for x in samples[5:56]]
 s.update(used_mean=statistics.mean(used),used_min=min(used),used_max=max(used),free_mean=statistics.mean(free),free_min=min(free),free_max=max(free),artifact=d.name)
 rows.append(s)
(r/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
labels=['ProxySQL upstream v3.0 (a0781dd90)','ProxySQL phased baseline (9f92e9d84)','ProxySQL deferred I/O (b17a986f3)',json.loads((list(r.glob('select1-one-plain-pgbouncer-*'))[0]/'binary.json').read_text())['version'].splitlines()[0]]
lines=['# One-client SELECT 1 without TLS: ProxySQL and PgBouncer','',
'One 60-second measured run per implementation, following a 20-second warmup. Localhost TCP on lon104; one client; one pgbench thread; simple query protocol; SELECT 1; 64 pre-established backend connections. Proxy CPU 0; client CPUs 2,4,6,8,10,12,14,16; performance governor. ProxySQL uses one worker and native backend protocol; PgBouncer uses transaction pooling. TLS is disabled and checked on both hops. No perf or custom timers.','',
'| Implementation | TPS | Latency (ms) | CPU µs/query | User µs/query | Kernel µs/query |',
'|---|---:|---:|---:|---:|---:|']
for label,s in zip(labels,rows):lines.append(f"| {label} | {s['tps']:.2f} | {s['latency_ms']:.3f} | {s['cpu_us_per_query']:.3f} | {s['user_us_per_query']:.3f} | {s['system_us_per_query']:.3f} |")
h,b,c,p=rows
lines+=['',f"Deferred I/O versus upstream: {(c['tps']/h['tps']-1)*100:+.2f}% TPS. Deferred I/O versus baseline: {(c['tps']/b['tps']-1)*100:+.2f}% TPS. Deferred I/O versus PgBouncer: {(c['tps']/p['tps']-1)*100:+.2f}% TPS. Baseline versus PgBouncer: {(b['tps']/p['tps']-1)*100:+.2f}% TPS.",'',
'Backend creation occurs only in preparation, before warmup. ProxySQL ConnOK stays at 64 and ConnERR at 0; Used + Free stays at 64 for all 62 snapshots. PgBouncer retains exactly the same 64 server identities (backend PID, connection time, pointer); sv_login stays zero; connection logs contain no server creation or closure during warmup or measurement. All runs have zero failed transactions.','',
'| Implementation | Used/active mean (range) | Free/idle mean (range) |','|---|---:|---:|']
for label,s in zip(labels,rows):lines.append(f"| {label} | {s['used_mean']:.2f} ({s['used_min']}–{s['used_max']}) | {s['free_mean']:.2f} ({s['free_min']}–{s['free_max']}) |")
lines+=['',
'CPU/query uses process user/system tick deltas divided by proxy query-counter deltas over approximately seconds 5–55. Pool means use the same central snapshots. PgBouncer active/idle counters are reported alongside ProxySQL used/free; their internal state definitions differ. PgBouncer also has sv_used/sv_tested states, so active plus idle alone need not equal 64; the assertions include all server states. With 64 backends and one client, idle backends are expected.','',
'These are preliminary single-run comparisons, not confidence intervals. The temporary PgBouncer listener used a dynamically selected free TCP port (recorded in port.txt) and the existing PgBouncer binary; other PgBouncer listeners were untouched. ProxySQL used port 6233. Prior ProxySQL runtime was restored and the temporary PgBouncer stopped after measurement.','',
'The deferred-I/O source is committed as 7ec3bfd59 plus b17a986f3; neither the index nor the working tree contains uncommitted source changes. Upstream v3.0 was checked at 8b23f48df6a62800ddd0ab57078bcbcc24ca246a. Its changes since a0781dd90 affect packaging/CI/documentation only; src, lib, include, deps and common_mk are identical, and Makefile changes only add packaging targets. The upstream row uses the preserved a0781dd90 binary with recorded SHA-256 rather than rebuilding identical runtime source. This is explicitly not a newly compiled 8b23f48df binary.', '',
'Artifacts include raw pgbench output, per-second snapshots, prepared pools, binary hashes, plaintext checks, settings, and harnesses. No source changes or compilation were performed.']
(r/'REPORT.md').write_text('\n'.join(lines)+'\n')
print(json.dumps(rows,indent=2))
