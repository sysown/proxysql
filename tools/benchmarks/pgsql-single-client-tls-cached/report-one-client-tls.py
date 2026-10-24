from pathlib import Path
import json, re, sys

root=Path(sys.argv[1]);series=root/'one-client-tls-series-20261024T133402Z'
manifest=json.loads((series/'runs.json').read_text());verification=json.loads((series/'verification.json').read_text())
rewrite=json.loads((root/'commit-description-rewrite.json').read_text())
assert len(manifest)==4
assert {(r['proxy'],r['workload']) for r in manifest}=={(p,w) for p in ['cached','pgbouncer'] for w in ['select1','4kb']}
assert verification['records_verified']==sum(r['summary']['logged_transactions'] for r in manifest)
results={}
for run in manifest:
    d=root/Path(run['directory']).name
    summary=json.loads((d/'summary.json').read_text());lat=json.loads((d/'latency-percentiles.json').read_text())
    binary=json.loads((d/'binary.json').read_text());samples=json.loads((d/'samples.json').read_text())
    assert summary==run['summary'] and summary['clients']==summary['jobs']==summary['clients_with_completions']==1
    assert summary['backend_cap']==10 and summary['tls']
    assert len(samples)==62 and lat['samples']==summary['logged_transactions']
    text=(d/'pgbench.txt').read_text()
    assert 'number of failed transactions: 0' in text
    assert re.search(r'number of clients:\s*1\b',text) and re.search(r'number of threads:\s*1\b',text)
    assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped']
    assert 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in (d/'tls.txt').read_text()
    assert 't|TLSv1.3|TLS_AES_256_GCM_SHA384' in (d/'tls.txt').read_text()
    central=samples[5:56]
    if run['proxy']=='cached':
        assert binary['sha256']=='3fa61772707b3edee8342c84a1dfd1b6b4b2b18cd9c94b5e8a856fb3ad8a16f1'
        assert binary['metadata']['commit']==rewrite['code']['new']
        values={x['variable_name']:x['variable_value'] for x in json.loads((d/'settings.json').read_text())}
        assert values['pgsql-threads']=='1' and values['pgsql-use_native_backend_protocol']=='true'
        assert values['pgsql-query_digests']==values['pgsql-commands_stats']=='false'
        assert all(s['ConnOK']=='10' and s['ConnERR']=='0' and int(s['ConnUsed'])+int(s['ConnFree'])==10 for s in samples)
        pool=dict(used_min=min(int(s['ConnUsed']) for s in central),used_max=max(int(s['ConnUsed']) for s in central),free_min=min(int(s['ConnFree']) for s in central),free_max=max(int(s['ConnFree']) for s in central))
    else:
        settings=json.loads((d/'settings.json').read_text())
        assert settings['pool_mode']=='transaction' and settings['default_pool_size']==settings['min_pool_size']=='10' and settings['reserve_pool_size']=='0'
        assert all(sum(int(s.get(k,0)) for k in ['sv_active','sv_idle','sv_used','sv_tested','sv_login'])==10 for s in samples)
        assert all(s['identities']==samples[0]['identities'] and len(s['identities'])==10 and int(s['sv_login'])==0 for s in samples)
        assert not re.search(r'LOG S-.*(?:new connection|closing because)',(d/'steady-log.txt').read_text())
        pool=dict(active_min=min(int(s['sv_active']) for s in central),active_max=max(int(s['sv_active']) for s in central),idle_min=min(int(s['sv_idle']) for s in central),idle_max=max(int(s['sv_idle']) for s in central))
    if run['proxy']=='pgbouncer':
        other=[sum(int(s.get(k,0)) for k in ['sv_used','sv_tested','sv_login']) for s in central]
        pool.update(other_min=min(other),other_max=max(other))
    else:pool.update(other_min=0,other_max=0)
    results[run['workload']+':'+run['proxy']]=dict(directory=d.name,summary=summary,latency=lat,binary=binary,pool=pool)

deltas={}
for workload in ['select1','4kb']:
    a=results[workload+':cached'];b=results[workload+':pgbouncer']
    name='select1.sql' if workload=='select1' else 'select42_4kb.sql'
    assert (root/a['directory']/name).read_bytes()==(root/b['directory']/name).read_bytes()
    deltas[workload]=100*(a['summary']['tps']/b['summary']['tps']-1)
comparison=dict(results=results,proxysql_tps_relative_pct=deltas,verification=verification,commit_description_rewrite=rewrite)
(root/'comparison.json').write_text(json.dumps(comparison,indent=2)+'\n')
pgversion=results['select1:pgbouncer']['binary']['version'].splitlines()[0]
lines=['# Single-client TLS comparison','',
f'Cached ProxySQL source commit {rewrite["code"]["new"]} versus {pgversion}. The ProxySQL executable is unchanged from the handshake-cache experiment. Its original build commit is preserved; the active source/evidence commit messages were rewritten into detailed prose without numerical figures. commit-description-rewrite.json records old/new identities and identical tree verification.','',
'## Conditions','',
'Fresh unprofiled runs on lon104 over localhost TCP: one persistent frontend client, one pgbench thread pinned to CPU 2, one proxy worker/core pinned to CPU 0, performance governor, ten backend connections established before warmup and retained throughout, TLSv1.3 AES-256-GCM on both hops, simple query protocol, twenty seconds warmup followed by sixty seconds measured. The preparation step uses concurrent sleepers solely to establish the backend pool; it is outside warmup and measurement.','',
'ProxySQL uses its native backend implementation with commands_stats=false, query_digests=false, full free-connection retention and no maximum connection age. PgBouncer uses transaction pooling, default_pool_size=10, min_pool_size=10 and reserve_pool_size=0. Administrative monitoring is plaintext for both products; every workload client requires TLS. PgBouncer allows plaintext only to keep administrative monitoring from performing repeated TLS handshakes.','',
'The scalar workload is SELECT 1. The resultset workload is the existing generated 42-row query with approximately 4 KB of PostgreSQL response data. Exact query snapshots match between proxies. Each case is a single fresh run; the table is an initial comparison rather than a repeated-run confidence estimate.','',
'## Throughput','',
'| Workload | Cached ProxySQL TPS | PgBouncer TPS | ProxySQL relative |','|---|---:|---:|---:|']
for workload,label in [('select1','SELECT 1'),('4kb','4KB / 42 rows')]:
    a=results[workload+':cached']['summary'];b=results[workload+':pgbouncer']['summary']
    lines.append(f'| {label} | {a["tps"]:,.2f} | {b["tps"]:,.2f} | {deltas[workload]:+.2f}% |')
lines+=['','## Latency and proxy CPU','',
'Latency percentiles use every successful transaction, recorded on tmpfs during measurement. Means below use the complete raw-log average rather than the rounded pgbench summary. CPU figures cover only each proxy process, using the central measurement interval.','',
'| Workload | Proxy | Mean (µs) | p50 (µs) | p95 (µs) | p99 (µs) | User CPU/query (µs) | Kernel CPU/query (µs) | Total CPU/query (µs) |','|---|---|---:|---:|---:|---:|---:|---:|---:|']
for workload,label in [('select1','SELECT 1'),('4kb','4KB / 42 rows')]:
    for proxy,pname in [('cached','ProxySQL'),('pgbouncer','PgBouncer')]:
        x=results[workload+':'+proxy];s=x['summary'];lat=x['latency']
        lines.append(f'| {label} | {pname} | {lat["mean_ms"]*1000:.2f} | {s["p50_ms"]*1000:.0f} | {s["p95_ms"]*1000:.0f} | {s["p99_ms"]*1000:.0f} | {s["user_us_per_query"]:.2f} | {s["system_us_per_query"]:.2f} | {s["cpu_us_per_query"]:.2f} |')
lines+=['','## Pool and correctness checks','',
'Every case reports zero failed transactions and keeps the same ten backend connections. ProxySQL ConnOK stays ten and ConnERR stays zero in every snapshot. PgBouncer retains the same backend process identities and reports no server connection creation or close in the steady connection log. No profiling or source timing hooks are enabled. All isolated instances stop after their runs.','',
'| Workload | Proxy | Used/active range | Free/idle range | Other retained states | Successful transactions |','|---|---|---:|---:|---:|---:|']
for workload,label in [('select1','SELECT 1'),('4kb','4KB / 42 rows')]:
    for proxy,pname in [('cached','ProxySQL'),('pgbouncer','PgBouncer')]:
        x=results[workload+':'+proxy];p=x['pool'];u='used' if proxy=='cached' else 'active';f='free' if proxy=='cached' else 'idle'
        lines.append(f'| {label} | {pname} | {p[u+"_min"]}–{p[u+"_max"]} | {p[f+"_min"]}–{p[f+"_max"]} | {p["other_min"]}–{p["other_max"]} | {x["summary"]["logged_transactions"]:,} |')
lines+=['',
'Spare backend connections are expected here: a single client has at most one workload query outstanding. Pool counters may also include maintenance activity. PgBouncer other retained states comprise sv_used, sv_tested and sv_login; its active/idle columns alone do not cover the retained pool. Every snapshot totals the configured backend count across all states.','',
f'Independent verification streamed all {verification["records_verified"]:,} transaction records, checked their client identity and uncompressed log hashes, and checked the exact nearest-rank p50/p95/p99 boundaries. The ProxySQL and PgBouncer executable hashes match their captured provenance. The original staged work remains unchanged.','',
'## Artifacts','',
'- comparison.json: complete results, latency metadata, pool ranges and commit-description mapping.','- one-client-tls-series-20261024T133402Z/: execution order, summaries and independent verification.','- Per-case directories: query, TLS proof, settings, binary identity, pool snapshots, pgbench output and latency/log-hash metadata.','- benchmark-one-tls-proxysql.py and benchmark-one-tls-pgbouncer.py: reproduction scripts.','',
'Large transactions.*.gz files remain in their original per-case /home/rene/pg-network-bench/results/ directories on lon104; they are excluded from Git. Their uncompressed hashes are retained in latency-percentiles.json.','']
(root/'REPORT.md').write_text('\n'.join(lines))
print('VERIFIED '+str(root/'REPORT.md'))
print(json.dumps(deltas,indent=2))
