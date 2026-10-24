from pathlib import Path
import collections, gzip, hashlib, json, math, subprocess, sys

root=Path.home()/'pg-network-bench';series=Path(sys.argv[1])
runs=json.loads((series/'runs.json').read_text());assert len(runs)==4
records=[]
for run in runs:
    d=Path(run['directory']);s=json.loads((d/'summary.json').read_text());lat=json.loads((d/'latency-percentiles.json').read_text());b=json.loads((d/'binary.json').read_text())
    assert s['clients']==s['jobs']==s['clients_with_completions']==1 and s['backend_cap']==10 and not s['tls']
    assert 'number of failed transactions: 0' in (d/'pgbench.txt').read_text()
    assert 'SSL connection' not in (d/'transport.txt').read_text()
    assert 'backend pg_stat_ssl: f||' in (d/'transport.txt').read_text()
    cuts={k:round(lat[k]*1000) for k in ['p50_ms','p95_ms','p99_ms']};below=collections.Counter();leq=collections.Counter();n=0
    for item in lat['logs']:
        digest=hashlib.sha256()
        with gzip.open(d/item['file'],'rb') as source:
            for line in source:
                digest.update(line);fields=line.split();assert int(fields[0])==0;value=int(fields[2]);n+=1
                for key,cutoff in cuts.items():below[key]+=value<cutoff;leq[key]+=value<=cutoff
        assert digest.hexdigest()==item['uncompressed_sha256']
    assert n==lat['samples']==s['logged_transactions']
    for key,fraction in [('p50_ms',.5),('p95_ms',.95),('p99_ms',.99)]:assert below[key]<math.ceil(n*fraction)<=leq[key]
    assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped']
    if run['proxy']=='cached':
        assert not Path('/proc/'+str(b['pid'])).exists();binary=root/'src/proxysql-head-tls-handshake-cache'
        servers=json.loads((d/'servers.json').read_text())
        assert all(x['hostname'] in ['127.0.0.1','localhost'] and int(x['port'])==5432 for x in servers)
    else:
        stat=Path('/proc/'+str(b['pid'])+'/stat');assert not stat.exists() or stat.read_text().split()[2]=='Z';binary=root/'pgbouncer/bin/pgbouncer'
        servers=json.loads((d/'servers-after-prewarm.json').read_text())
        assert all(x['addr'] in ['127.0.0.1','::1'] and int(x['port'])==5432 for x in servers if x['database']=='networkbench')
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==b['sha256']
    records.append(dict(proxy=run['proxy'],workload=run['workload'],records_verified=n,log_hashes_match=True,percentile_ranks_verified=True,binary_hash_matches=True,isolated_instance_stopped=True,plaintext_both_hops=True,backend_is_local=True))
for tool in ['bpftrace','perf','strace']:assert subprocess.run(['pgrep','-x',tool],stdout=subprocess.DEVNULL).returncode==1
assert subprocess.check_output(['git','-C',str(root/'src/proxysql-head'),'diff','--cached','--raw'])==(root/'one-client-plain-main-staged-before.txt').read_bytes()
result=dict(runs=records,records_verified=sum(x['records_verified'] for x in records),profiling_tools_absent=['bpftrace','perf','strace'],main_staged_files_unchanged=True)
(series/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(records_verified=result['records_verified'],runs=len(records),verification='passed')))
