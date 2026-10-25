from pathlib import Path
import json,sys
root=Path(sys.argv[1]);series=next(root.glob('tls-forwarding-series-*'))
manifest=json.loads((series/'runs.json').read_text());verification=json.loads((series/'verification.json').read_text());metadata=json.loads((root/'tls-forwarding-binaries.json').read_text())
assert len(manifest)==6 and verification['records_verified']==sum(x['summary']['logged_transactions'] for x in manifest)
results={}
for run in manifest:
 d=root/Path(run['directory']).name;s=json.loads((d/'summary.json').read_text());lat=json.loads((d/'latency-percentiles.json').read_text());b=json.loads((d/'binary.json').read_text());samples=json.loads((d/'samples.json').read_text())
 assert s==run['summary'] and s['tls'] and s['backend_cap']==10 and s['clients']==s['jobs']==1 and len(samples)==62
 assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped'] and 'number of failed transactions: 0' in (d/'pgbench.txt').read_text()
 assert 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in (d/'tls.txt').read_text() and 't|TLSv1.3|TLS_AES_256_GCM_SHA384' in (d/'tls.txt').read_text()
 assert json.loads((d/'query-output-check.json').read_text())['output_matches_backend']
 central=samples[5:56]
 if run['proxy']=='pgbouncer':
  assert all(x['identities']==samples[0]['identities'] and len(x['identities'])==10 and int(x['sv_login'])==0 for x in samples)
  pool=dict(active_min=min(int(x['sv_active']) for x in central),active_max=max(int(x['sv_active']) for x in central),idle_min=min(int(x['sv_idle']) for x in central),idle_max=max(int(x['sv_idle']) for x in central),other_min=min(sum(int(x.get(k,0)) for k in ['sv_used','sv_tested','sv_login']) for x in central),other_max=max(sum(int(x.get(k,0)) for k in ['sv_used','sv_tested','sv_login']) for x in central))
 else:
  assert b['sha256']==metadata[run['proxy']]['sha256'] and b['backend']=='native' and not b['profiling']
  assert all(x['ConnOK']=='10' and x['ConnERR']=='0' and int(x['ConnUsed'])+int(x['ConnFree'])==10 for x in samples)
  pool=dict(used_min=min(int(x['ConnUsed']) for x in central),used_max=max(int(x['ConnUsed']) for x in central),free_min=min(int(x['ConnFree']) for x in central),free_max=max(int(x['ConnFree']) for x in central))
 results[run['workload']+':'+run['proxy']]=dict(directory=d.name,summary=s,latency=lat,binary=b,pool=pool)
relative={}
for workload in ['select1','4kb']:
 s={p:results[workload+':'+p]['summary'] for p in ['previous','latest','pgbouncer']}
 relative[workload]=dict(latest_vs_previous_pct=100*(s['latest']['tps']/s['previous']['tps']-1),latest_vs_pgbouncer_pct=100*(s['latest']['tps']/s['pgbouncer']['tps']-1),previous_vs_pgbouncer_pct=100*(s['previous']['tps']/s['pgbouncer']['tps']-1),latest_user_cpu_change_pct=100*(s['latest']['user_us_per_query']/s['previous']['user_us_per_query']-1))
(root/'comparison.json').write_text(json.dumps(dict(results=results,relative=relative,verification=verification,binaries=metadata),indent=2)+'\n')
lines=['# TLS comparison after the forwarding patches','',
'Fresh previous-build, latest-build and PgBouncer comparisons under the same single-client condition. These runs isolate the latest three forwarding patches from the earlier TLS handshake-cache optimization.','',
'## Throughput','',
'| Workload | Previous ProxySQL TPS | Latest ProxySQL TPS | PgBouncer TPS | Latest vs previous | Latest vs PgBouncer |','|---|---:|---:|---:|---:|---:|']
for w,label in [('select1','SELECT 1'),('4kb','4KB / 42 rows')]:
 s={p:results[w+':'+p]['summary'] for p in ['previous','latest','pgbouncer']};v=relative[w]
 lines.append(f'| {label} | {s["previous"]["tps"]:,.2f} | {s["latest"]["tps"]:,.2f} | {s["pgbouncer"]["tps"]:,.2f} | {v["latest_vs_previous_pct"]:+.2f}% | {v["latest_vs_pgbouncer_pct"]:+.2f}% |')
lines+=['','Each cell represents one fresh unprofiled sixty-second measurement. Small differences are preliminary observations, not repeated-run confidence estimates. Execution order is preserved in the series plan: previous/latest/PgBouncer for SELECT 1, then latest/previous/PgBouncer for 4KB. This reverses the ProxySQL order between workloads but does not eliminate time-dependent variation.','',
'## Latency and proxy CPU','',
'Latency is measured from every successful transaction using pgbench logs on tmpfs. CPU covers the proxy process in the central measurement interval; it excludes pgbench and PostgreSQL.','',
'| Workload | Build | Mean µs | p95 µs | p99 µs | User CPU/query µs | Kernel CPU/query µs | Total CPU/query µs |','|---|---|---:|---:|---:|---:|---:|---:|']
for w,label in [('select1','SELECT 1'),('4kb','4KB / 42 rows')]:
 for p,name in [('previous','Previous ProxySQL'),('latest','Latest ProxySQL'),('pgbouncer','PgBouncer')]:
  x=results[w+':'+p];s=x['summary'];lat=x['latency']
  lines.append(f'| {label} | {name} | {lat["mean_ms"]*1000:.2f} | {s["p95_ms"]*1000:.0f} | {s["p99_ms"]*1000:.0f} | {s["user_us_per_query"]:.2f} | {s["system_us_per_query"]:.2f} | {s["cpu_us_per_query"]:.2f} |')
lines+=['','## Conditions and source identity','',
'lon104, localhost TCP on both hops, PostgreSQL backend, one persistent workload client, one pgbench job pinned to CPU two, one proxy worker/core pinned to CPU zero, controller pinned to CPU eighteen, performance governor. Ten backend connections are established before warmup and retained throughout the run. Each case has twenty seconds warmup and sixty seconds measured. Simple query protocol; exact query snapshots are preserved and match across all builds.','',
'TLSv1.3 with TLS_AES_256_GCM_SHA384 is verified on both hops. Workload clients use PGSSLMODE=require. ProxySQL frontend SSL and backend server use_ssl are enabled. PgBouncer server_tls_sslmode=require; client_tls_sslmode=allow permits plaintext administrative monitoring, while every benchmark workload connection requires TLS. Administrative monitoring stays plaintext for both products.','',
'ProxySQL uses the native backend protocol, commands_stats=false, query_digests=false, query_processor_parser=0, free_connections_pct=100, and no backend maximum age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10, reserve_pool_size=0, and long idle/lifetime settings. No profiling or source timing hooks are enabled.','',
f'Previous source: `{metadata["previous"]["commit"]}`. It already includes the frontend TLS handshake-completion cache. Latest source: `{metadata["latest"]["commit"]}`. It adds the raw COPY negative filter, consumed completed-session work flag and bounded native DataRow span copying. Shared-pool behavior is unchanged. Both executables are the same immutable binaries used in the preceding work; no rebuild was needed for this comparison.','',
'Both ProxySQL executables intentionally retain the same embedded version string; use the recorded source commits and SHA256 values to identify them. Binary metadata, runtime settings and the TLS proof are captured per case.','',
'## Pool, output and audit checks','',
'All six cases have zero failed transactions and retain the same ten backend connections. ProxySQL ConnOK remains ten, ConnERR zero, and ConnUsed plus ConnFree remains ten in every snapshot. PgBouncer retains all backend identities and logs no server connection creation or closing during the steady period. Its sv_used/sv_tested states are retained pool states and should not be equated with executing queries; all server states sum to ten.','',
'Before pool preparation, exact text output for each workload was compared against direct PostgreSQL output over TLS, confirming the scalar result or all forty-two rows. Digest maps remain empty and unchanged. Every isolated instance stops afterward, and the new harnesses use exclusive locks and explicit interrupt cleanup.','',
f'Independent verification checked all **{verification["records_verified"]:,} transaction records**, uncompressed log hashes, exact nearest-rank percentile boundaries, raw-log means, binary hashes, runtime variables, TLS evidence, pool retention and cleanup. Main-worktree staged changes remain unchanged. No product code or repository tests were modified by this comparison.','',
'## Artifacts','',
'- [comparison.json](comparison.json): full measurements, latency metadata, pool ranges, source/binary provenance and relative differences.','- Per-case directories: query text, output hash, TLS proof, pgbench output, settings and one-second pool snapshots.','- The series directory: execution plan, command manifest, completion marker and independent audit.','- Standalone benchmark, query-output, report, verification and controller scripts are stored alongside this report.','',
'Raw transactions.*.gz archives remain in their original /home/rene/pg-network-bench/results/ directories on lon104 and are excluded from Git. Their uncompressed hashes remain in latency metadata.','']
(root/'REPORT.md').write_text('\n'.join(lines));print(json.dumps(relative,indent=2))
