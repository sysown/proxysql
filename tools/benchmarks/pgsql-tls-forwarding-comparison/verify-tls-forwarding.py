from pathlib import Path
import collections,gzip,hashlib,json,math,subprocess,sys,re
root=Path.home()/'pg-network-bench';series=Path(sys.argv[1]);runs=json.loads((series/'runs.json').read_text())
assert len(runs)==6 and json.loads((series/'finished.json').read_text())['complete']
assert {(r['proxy'],r['workload']) for r in runs}=={(p,w) for p in ['previous','latest','pgbouncer'] for w in ['select1','4kb']}
metadata=json.loads((root/'tls-forwarding-binaries.json').read_text());records=[];queries={}
for run in runs:
 d=Path(run['directory']);s=json.loads((d/'summary.json').read_text());lat=json.loads((d/'latency-percentiles.json').read_text());b=json.loads((d/'binary.json').read_text());samples=json.loads((d/'samples.json').read_text())
 assert s==run['summary'] and s['clients']==s['jobs']==s['clients_with_completions']==1 and s['backend_cap']==10 and s['tls']
 text=(d/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text
 assert re.search(r'number of clients:\s*1\b',text) and re.search(r'number of threads:\s*1\b',text)
 tls=(d/'tls.txt').read_text();assert 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in tls and 't|TLSv1.3|TLS_AES_256_GCM_SHA384' in tls
 assert len(samples)==62
 check=json.loads((d/'query-output-check.json').read_text());assert check['output_matches_backend'] and check['rows']==(1 if run['workload']=='select1' else 42)
 name='select1.sql' if run['workload']=='select1' else 'select42_4kb.sql';query=(d/name).read_bytes()
 if run['workload'] in queries:assert queries[run['workload']]==query
 else:queries[run['workload']]=query
 cuts={k:round(lat[k]*1000) for k in ['p50_ms','p95_ms','p99_ms']};below=collections.Counter();leq=collections.Counter();n=total=0
 for item in lat['logs']:
  digest=hashlib.sha256()
  with gzip.open(d/item['file'],'rb') as source:
   for line in source:
    digest.update(line);f=line.split();assert len(f)==6 and int(f[0])==0;v=int(f[2]);assert v>=0;n+=1;total+=v
    for key,cutoff in cuts.items():below[key]+=v<cutoff;leq[key]+=v<=cutoff
  assert digest.hexdigest()==item['uncompressed_sha256']
 assert n==lat['samples']==s['logged_transactions'] and abs(total/n/1000-lat['mean_ms'])<1e-9
 for key,fraction in [('p50_ms',.5),('p95_ms',.95),('p99_ms',.99)]:assert below[key]<math.ceil(n*fraction)<=leq[key]
 assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped']
 stat=Path('/proc/'+str(b['pid'])+'/stat');assert not stat.exists() or stat.read_text().split()[2]=='Z'
 if run['proxy']!='pgbouncer':
  binary=root/metadata[run['proxy']]['file'];assert b['metadata']==metadata[run['proxy']] and not b['profiling'] and b['backend']=='native'
  settings={x['variable_name']:x['variable_value'] for x in json.loads((d/'settings.json').read_text())}
  expected={'pgsql-threads':'1','pgsql-use_native_backend_protocol':'true','pgsql-query_processor_parser':'0','pgsql-query_digests':'false','pgsql-commands_stats':'false','pgsql-have_ssl':'true','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0'}
  for k,v in expected.items():assert settings[k]==v,(k,settings)
  assert all(x['ConnOK']=='10' and x['ConnERR']=='0' and int(x['ConnUsed'])+int(x['ConnFree'])==10 for x in samples)
  servers=json.loads((d/'servers.json').read_text());assert all(x['hostname'] in ['127.0.0.1','localhost'] and int(x['port'])==5432 and int(x['max_connections'])==10 and x['use_ssl']=='1' for x in servers)
  assert json.loads((d/'digest-map-before.json').read_text())==json.loads((d/'digest-map-after.json').read_text())
 else:
  binary=root/'pgbouncer/bin/pgbouncer';settings=json.loads((d/'settings.json').read_text())
  assert settings['pool_mode']=='transaction' and settings['default_pool_size']==settings['min_pool_size']=='10' and settings['reserve_pool_size']=='0'
  assert settings['client_tls_sslmode']=='allow' and settings['server_tls_sslmode']=='require'
  assert all(x['identities']==samples[0]['identities'] and len(x['identities'])==10 and int(x['sv_login'])==0 for x in samples)
  assert all(sum(int(x.get(k,0)) for k in ['sv_active','sv_idle','sv_used','sv_tested','sv_login'])==10 for x in samples)
  assert not re.search(r'LOG S-.*(?:new connection|closing because)',(d/'steady-log.txt').read_text())
  servers=json.loads((d/'servers-after-prewarm.json').read_text());assert all(x['addr'] in ['127.0.0.1','::1'] and int(x['port'])==5432 for x in servers if x['database']=='networkbench')
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==b['sha256']
 records.append(dict(proxy=run['proxy'],workload=run['workload'],records_verified=n,log_hashes_match=True,percentile_ranks_verified=True,binary_hash_matches=True,ten_backends_retained=True,tls_both_hops=True,native_backend=True if run['proxy']!='pgbouncer' else None,output_matches_backend=True,isolated_instance_stopped=True))
for tool in ['bpftrace','perf','strace']:assert subprocess.run(['pgrep','-x',tool],stdout=subprocess.DEVNULL).returncode==1
assert subprocess.check_output(['git','-C',str(root/'src/proxysql-head'),'diff','--cached','--raw'])==(root/'tls-forwarding-main-staged-before.txt').read_bytes()
result=dict(runs=records,records_verified=sum(x['records_verified'] for x in records),profiling_tools_absent=True,main_staged_files_unchanged=True)
(series/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(records_verified=result['records_verified'],runs=len(records),verification='passed')))
