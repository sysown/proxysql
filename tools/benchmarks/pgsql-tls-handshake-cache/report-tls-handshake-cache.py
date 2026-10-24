from pathlib import Path
import hashlib, json, statistics, sys

root=Path(sys.argv[1]); base=root/'baseline'
bench=root/'tls-handshake-cache-benchmark-cached-20261024T125711Z'
trace=root/'tls-handshake-cache-counts-cached-20261024T130056Z'
before=json.loads((base/'summary.json').read_text()); after=json.loads((bench/'summary.json').read_text())
maps=json.loads((trace/'counter-maps.json').read_text()); window=json.loads((trace/'call-summary.json').read_text())
manifest=json.loads((root/'binaries.json').read_text())['cached']
provenance=json.loads((root/'source-provenance.json').read_text())
audit=json.loads((root/'latency-audit.json').read_text())
assert provenance['commit']==manifest['commit']=='bd2353e922cb5cb13e5f6941f1079fd1685511ff'
for name,digest in provenance['sha256'].items():assert hashlib.sha256((root/'source'/name).read_bytes()).hexdigest()==digest
assert (base/'select42_4kb.sql').read_bytes()==(bench/'select42_4kb.sql').read_bytes()
assert after['clients_with_completions']==500 and after['logged_transactions']==audit['raw_records_verified']==1097545
assert audit['all_uncompressed_log_hashes_match'] and audit['quantile_rank_checks_passed']
assert maps['@gate_count']==2 and maps['@observed_tls_checks']>0
assert not sum(maps.get('@calls',{}).values()),maps
assert ':SSL_is_init_finished ' in (trace/'counter.bt').read_text()
pool={}
for d in [bench,trace]:
    samples=json.loads((d/'samples.json').read_text())
    assert all(s['ConnOK']=='10' and s['ConnERR']=='0' and int(s['ConnUsed'])+int(s['ConnFree'])==10 for s in samples)
    assert json.loads((d/'binary.json').read_text())['sha256']==manifest['sha256']
    assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped']
    text=(d/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text
    values={x['variable_name']:x['variable_value'] for x in json.loads((d/'settings.json').read_text())}
    assert all(values[k]==v for k,v in {'pgsql-threads':'1','pgsql-use_native_backend_protocol':'true','pgsql-query_digests':'false','pgsql-commands_stats':'false','pgsql-have_ssl':'true','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0'}.items())
    pool[d.name]=dict(snapshots=len(samples),conn_ok='10',conn_err='0')
assert 'TLSv1.2' in (bench/'tls12-smoke.txt').read_text()
central=json.loads((bench/'samples.json').read_text())[5:56]
usage=dict(used_min=min(int(s['ConnUsed']) for s in central),used_max=max(int(s['ConnUsed']) for s in central),free_min=min(int(s['ConnFree']) for s in central),free_max=max(int(s['ConnFree']) for s in central))
reference=json.loads((base/'tls-call-attribution.json').read_text())
baseline_ssl_checks=sum(s['per_query'] for s in reference['sites'] if s['metric']=='SSL_is_init_finished')
deltas={k:100*(after[k]/before[k]-1) for k in ['tps','latency_ms','p50_ms','p95_ms','p99_ms','user_us_per_query','system_us_per_query','cpu_us_per_query']}
comparison=dict(baseline=before,cached=after,percent_change=deltas,baseline_kind='previously recorded unprofiled run; not a fresh paired control',steady_pool=usage,pool_checks=pool,call_check=dict(steady_ssl_is_init_finished=0,baseline_calls_per_query=baseline_ssl_checks,enabled_seconds=window['enabled_seconds'],pool_query_bracket=window['queries'],outside_gate_positive_control_calls=maps['@observed_tls_checks']),source_commit=manifest['commit'],source_base_commit=manifest['base_commit'],binary_sha256=manifest['sha256'])
(root/'comparison.json').write_text(json.dumps(comparison,indent=2)+'\n')
lines=['# Cached frontend TLS handshake: first benchmark','',
'An isolated cache experiment on optimized f3163c864. Code commit: bd2353e922cb5cb13e5f6941f1079fd1685511ff, branch optimization/pgsql-tls-handshake-cache. No scheduler or BIO-counter optimization is combined with this change.','',
'## Result','',
'500 clients, 10 pre-established retained backends, localhost TCP on lon104, 42-row / 4063-byte response, TLSv1.3 AES-256-GCM on both hops, one proxy worker pinned to CPU 0, 16 pgbench jobs pinned to CPUs 2,4,6,8,10,12,14,16, performance governor, native backend protocol, commands_stats=false and query_digests=false. Twenty seconds warmup, sixty seconds pgbench measurement, one-second pool snapshots and complete transaction logs on tmpfs. Administrative monitoring uses plaintext.','',
'The before column reuses the recorded 2026-10-23T11:45:39Z unprofiled f3163c864 run. The patched run was recorded at 2026-10-24T12:57:11Z. This is a preliminary comparison across runs at different times, rather than a contemporaneous paired A/B or a confidence interval. It does not establish that the entire observed difference was caused by the cache. No baseline was rerun.','',
'| Metric | Recorded f3163c864 | Cached TLS handshake | Change |','|---|---:|---:|---:|']
for label,key,fmt in [('TPS','tps',',.2f'),('Mean latency (ms)','latency_ms','.3f'),('p50 latency (ms)','p50_ms','.3f'),('p95 latency (ms)','p95_ms','.3f'),('p99 latency (ms)','p99_ms','.3f'),('User CPU/query (µs)','user_us_per_query','.3f'),('Kernel CPU/query (µs)','system_us_per_query','.3f'),('Total proxy CPU/query (µs)','cpu_us_per_query','.3f')]:
    lines.append(f'| {label} | {format(before[key],fmt)} | {format(after[key],fmt)} | {deltas[key]:+.2f}% |')
lines+=['',f'The patched run completes {after["logged_transactions"]:,} successful transactions across all 500 clients, with zero failed transactions. Backend ConnOK stays 10 and ConnERR stays 0 in all 62 snapshots. During the central measurement snapshots, ConnUsed ranges {usage["used_min"]}–{usage["used_max"]} and ConnFree ranges {usage["free_min"]}–{usage["free_max"]}. No backend connection is created during warmup or measurement. Raw-log hashes and nearest-rank p50/p95/p99 thresholds were independently checked against all 1,097,545 records.','',
'## Separate call-count verification','',
'The throughput run has no perf, eBPF, strace or source timing instrumentation. A separate isolated run attaches a single worker uprobe to SSL_is_init_finished and gates counters only after all 500 benchmark clients and ten backends are established. A fresh TLS frontend connection exercises the probe before the gate; it closes before counting begins. This verifies probe attachment without introducing connection setup into the counting interval.','',
'| Check | Result |','|---|---:|',
f'| Recorded baseline calls/query | {baseline_ssl_checks:.4f} |',
'| Patched steady-state calls | 0 |',
f'| Counting interval (seconds) | {window["enabled_seconds"]:.4f} |',
f'| Pool query-counter bracket | {window["queries"]:,} |',
f'| Outside-window calls proving the probe works | {maps["@observed_tls_checks"]} |','',
'The patched window has zero calls, so query-counter boundary slack cannot affect the zero-per-query conclusion. Both the throughput run and the call-count run retain ten backends with unchanged ConnOK/ConnERR and finish with zero failed transactions. The diagnostic query rate is not used as a throughput result.','',
'## Implementation','',
'PgSQL_Data_Stream owns a tls13_handshake_complete boolean and an inline ssl_handshake_is_complete() predicate. The flag starts false and becomes true only after SSL_do_handshake returns success and the existing peer-certificate/SPIFFE checks finish. It is set only for owned frontend TLS 1.3 streams. The six active call sites in frontend read/drain, write-poll and poll-rearm paths use the predicate.','',
'The flag resets before a new frontend SSL object and on backend TLS borrowing/release. Older TLS versions and borrowed backend streams continue querying OpenSSL. Read/write, error handling and ciphertext draining remain on their existing paths, including TLS 1.3 post-handshake traffic. A TLS 1.2 frontend connection and SELECT 1 smoke check passed before backend prewarming and measurement; its output is retained.','',
'The source was built from f3163c864 in a separate worktree at /home/rene/pg-network-bench/src/proxysql-tls-handshake-cache. Existing dependency artifacts were shared by hard link and only lib/ and src/ were built. Release options are -O2 -fno-omit-frame-pointer -ggdb with PROXYSQL31, FFTO, TSDB, ED25519 and CLICKHOUSE enabled. The embedded version string is held at 3.1.11-dev-ga0781dd to match the baseline; source commit and binary SHA identify the new build. The build succeeded. No test files were changed or suite run under the benchmark-first scope.','',
f'Candidate binary SHA256: {manifest["sha256"]}.','',
'## Artifacts','',
'- source.patch and source/: exact committed change and source snapshots. source-provenance.json verifies their hashes.','- baseline/: reused throughput metadata and prior TLS caller-attribution evidence.','- tls-handshake-cache-benchmark-cached-20261024T125711Z/: unprofiled result, pool snapshots, native/TLS settings, full client-completion counts and percentile metadata.','- tls-handshake-cache-counts-cached-20261024T130056Z/: generated probe, raw maps, positive-control output, exact gate/query brackets and isolated-instance cleanup.','- latency-audit.json: independent log-hash and quantile-rank verification.','- comparison.json: machine-readable before/after comparison and checks.','',
'Raw transaction logs remain on lon104 at /home/rene/pg-network-bench/results/tls-handshake-cache-benchmark-cached-20261024T125711Z/transactions.*.gz. They are excluded from Git; individual uncompressed hashes are in latency-percentiles.json.','']
(root/'REPORT.md').write_text('\n'.join(lines))
print('VERIFIED '+str(root/'REPORT.md'))
print(json.dumps(dict(tps_change_pct=deltas['tps'],steady_ssl_checks=0,outside_gate_control_calls=maps['@observed_tls_checks'],pool=usage),indent=2))
