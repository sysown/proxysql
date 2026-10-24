from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,hashlib,socket,tempfile,shutil,sys,math,gzip,collections
r=Path.home()/'pg-network-bench'
mode=sys.argv[1];assert mode=='cached'
workload=sys.argv[2];assert workload in ['select1','4kb']
query_file={'select1':'select1.sql','4kb':'select42_4kb.sql'}[workload]
metadata=json.loads((r/'tls-handshake-cache-binaries.json').read_text())[mode]
out=r/'results'/('one-client-tls-'+workload+'-'+mode+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
binary=r/metadata['file'];assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata['sha256']
version=subprocess.run([str(binary),'--version'],text=True,capture_output=True,check=True)
assert metadata['version_prefix'] in version.stdout,version.stdout
source_config=(r/'proxysql-309.cnf').read_text()
u,pw=re.search(r'admin_credentials\s*=\s*"([^"]+)"',source_config)[1].split(':',1)
ce=os.environ.copy();ce.update(PGSSLMODE='require',PGPASSWORD=next(x.split(':',4)[4] for x in (r/'.pgpass').read_text().splitlines() if x.startswith('*:5432:')))
ae=os.environ.copy();ae.update(PGSSLMODE='disable',PGUSER=u,PGPASSWORD=pw)
temp=tempfile.TemporaryDirectory(prefix='isolated-pgsql-'+mode+'-4kb-',dir=r)
tmp=Path(temp.name);tmp.chmod(0o700);data=tmp/'data';data.mkdir(mode=0o700)
olddata=Path(re.search(r'datadir\s*=\s*"([^"]+)"',source_config)[1])
for name in ['proxysql-cert.pem','proxysql-key.pem','proxysql-ca.pem']:shutil.copy2(olddata/name,data/name)
sockets=[]
for _ in range(4):
 sock=socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
ports=[str(sock.getsockname()[1]) for sock in sockets]
adminport,port,mysqlport,adminmysqlport=ports
config=source_config.replace(str(olddata),str(data)).replace(str(r/'proxysql-309.log'),str(tmp/'proxysql.log'))
for previous,new in [('6332',adminport),('6333',port),('6334',mysqlport),('6335',adminmysqlport)]:config=config.replace(':'+previous,':'+new)
cfg=tmp/'private.cnf';cfg.write_text(config);cfg.chmod(0o600)
(out/'ports.json').write_text(json.dumps(dict(admin=adminport,frontend=port),indent=2))
for sock in sockets:sock.close()
p=None;parent=None;pid=None;logtemp=None
args=['taskset','-c','2','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c','1','-j','1','-M','simple','-f',query_file]
(out/query_file).write_text((r/query_file).read_text())
def q(sql):
 return list(csv.DictReader(io.StringIO(subprocess.check_output(['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',adminport,'-d','admin','-c',sql],env=ae,text=True,stderr=subprocess.DEVNULL))))
try:
 assert {x.read_text().strip() for x in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}=={'performance'}
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(100):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('3.0.9 startup failed')
 parent=int((data/'proxysql.pid').read_text());pid=int(subprocess.check_output(['pgrep','-P',str(parent)],text=True).strip())
 assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 for key,value in {'pgsql-commands_stats':'false','pgsql-query_digests':'false','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0','pgsql-have_ssl':'true'}.items():q("UPDATE global_variables SET variable_value='"+value+"' WHERE variable_name='"+key+"'")
 available={row['variable_name'] for row in q("SELECT variable_name FROM global_variables WHERE variable_name IN ('pgsql-use_native_backend_protocol','pgsql-query_processor_parser')")}
 for key in available:q("UPDATE global_variables SET variable_value='"+('true' if key=='pgsql-use_native_backend_protocol' else '0')+"' WHERE variable_name='"+key+"'")
 q('LOAD PGSQL VARIABLES TO RUNTIME')
 tables={x['name'] for x in q("SELECT name FROM sqlite_master WHERE name IN ('pgsql_hostgroup_attributes','runtime_pgsql_hostgroup_attributes')")}
 if 'pgsql_hostgroup_attributes' in tables:q('UPDATE pgsql_hostgroup_attributes SET free_connections_pct=100')
 q('UPDATE pgsql_servers SET max_connections=10,use_ssl=1');q('LOAD PGSQL SERVERS TO RUNTIME')
 q("UPDATE pgsql_users SET use_ssl=1 WHERE username='networkbench'");q('LOAD PGSQL USERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-commands_stats','pgsql-query_digests','pgsql-use_native_backend_protocol','pgsql-have_ssl','pgsql-free_connections_pct','pgsql-connection_max_age_ms')")
 values={x['variable_name']:x['variable_value'] for x in settings}
 for key,value in {'pgsql-threads':'1','pgsql-commands_stats':'false','pgsql-query_digests':'false','pgsql-have_ssl':'true','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0'}.items():assert values[key]==value,(key,values)
 if mode in ['optimized','head','cached']:assert values.get('pgsql-use_native_backend_protocol')=='true',values
 if mode=='309':assert 'pgsql-use_native_backend_protocol' not in values,values
 (out/'settings.json').write_text(json.dumps(settings,indent=2))
 rules=q('SELECT rule_id,match_digest,match_pattern FROM runtime_pgsql_query_rules WHERE active=1');assert not rules,rules;(out/'active-query-rules.json').write_text(json.dumps(rules,indent=2))
 servers=q('SELECT hostgroup_id,hostname,port,max_connections,use_ssl FROM runtime_pgsql_servers');assert all(int(x['max_connections'])==10 and int(x['use_ssl'])==1 for x in servers);(out/'servers.json').write_text(json.dumps(servers,indent=2))
 if 'runtime_pgsql_hostgroup_attributes' in tables:
  attrs=q('SELECT hostgroup_id,free_connections_pct FROM runtime_pgsql_hostgroup_attributes');assert all(int(x['free_connections_pct'])==100 for x in attrs),attrs
  (out/'hostgroup-attributes.json').write_text(json.dumps(attrs,indent=2))
 (out/'binary.json').write_text(json.dumps(dict(version=version.stdout.strip(),version_stderr=version.stderr.strip(),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),backend='native' if values.get('pgsql-use_native_backend_protocol')=='true' else 'libpq',native_backend_setting_present='pgsql-use_native_backend_protocol' in values,metadata=metadata,profiling=False,transaction_logging=True,pid=pid),indent=2))
 print(mode+': isolated instance ready; one worker, TLS both hops, commands_stats=false, query_digests=false, 10-backend cap.',flush=True)
 pa=['psql','-X','-w','-h','127.0.0.1','-p',port,'-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert 'SSL connection' in front and 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in front and back=='t|TLSv1.3|TLS_AES_256_GCM_SHA384';(out/'tls.txt').write_text(front+'Frontend PGSSLMODE=require; backend TLS: '+back+'\n')
 # Establish the whole cap before warmup, holding each backend long enough
 # for all 10 clients to acquire one. This is preparation, not measurement.
 prewarm=out/'prewarm.sql';prewarm.write_text('SELECT pg_sleep(2);\n')
 prep=list(args);prep[prep.index('-c',prep.index('pgbench'))+1]='10';prep[prep.index('-f')+1]=str(prewarm);prep[prep.index('-j')+1]='10'
 with (out/'prewarm.txt').open('w') as f:subprocess.run(prep+['-t','1'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
 def pool_snapshot():
  rows=q('SELECT ConnUsed,ConnFree,ConnOK,ConnERR,Queries FROM stats_pgsql_connection_pool');assert len(rows)==1,rows
  st=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  return dict(wall_ns=time.monotonic_ns(),cpu_user_ticks=int(st[11]),cpu_system_ticks=int(st[12]),**rows[0])
 for _ in range(100):
  prepared=pool_snapshot()
  if int(prepared['ConnUsed'])==0 and int(prepared['ConnFree'])==10:break
  time.sleep(.1)
 else:raise RuntimeError('Prewarm did not establish all 10 backends: '+str(prepared))
 (out/'prepared.json').write_text(json.dumps(prepared,indent=2))
 digest_before=q('SELECT COUNT(*) AS digest_rows, COALESCE(SUM(count_star),0) AS total_count FROM stats_pgsql_query_digest');(out/'digest-map-before.json').write_text(json.dumps(digest_before,indent=2))
 assert int(digest_before[0]['digest_rows'])==0 and int(digest_before[0]['total_count'])==0,digest_before
 with (out/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
 print(mode+': warmup completed; measuring 60 seconds with 10 established backends.',flush=True)
 baseline=pool_snapshot();assert int(baseline['ConnUsed'])+int(baseline['ConnFree'])==10,baseline
 assert baseline['ConnOK']==prepared['ConnOK'] and baseline['ConnERR']==prepared['ConnERR'],(prepared,baseline)
 samples=[baseline];(out/'samples.json').write_text(json.dumps(samples,indent=2))
 def check_pool():
  sample=pool_snapshot();samples.append(sample);(out/'samples.json').write_text(json.dumps(samples,indent=2))
  assert sample['ConnOK']==baseline['ConnOK'],('REJECT: new backend connection during measurement',baseline,sample)
  assert sample['ConnERR']==baseline['ConnERR'],('REJECT: backend connect error during measurement',baseline,sample)
  assert int(sample['ConnUsed'])+int(sample['ConnFree'])==10,('REJECT: backend pool size changed',sample)
 logtemp=tempfile.TemporaryDirectory(prefix='pgbench-latency-'+mode+'-',dir='/dev/shm');logroot=Path(logtemp.name)
 with (out/'pgbench.txt').open('w') as f:
  t0=time.monotonic_ns();p=subprocess.Popen(args+['-T','60','-P','5','-l','--log-prefix',str(logroot/'transactions')],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT)
  for i in range(1,61):
   time.sleep(max(0,(t0+i*1000000000-time.monotonic_ns())/1e9));check_pool()
  assert p.wait()==0
  check_pool()
 t1=time.monotonic_ns()
 digest_after=q('SELECT COUNT(*) AS digest_rows, COALESCE(SUM(count_star),0) AS total_count FROM stats_pgsql_query_digest');(out/'digest-map-after.json').write_text(json.dumps(digest_after,indent=2))
 assert digest_after==digest_before,('REJECT: digest-map statistics changed',digest_before,digest_after)
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-2000:]
 (out/'window.json').write_text(json.dumps(dict(measure_start_ns=t0,measure_end_ns=t1,steady_start_ns=t0+10_000_000_000,steady_end_ns=t0+50_000_000_000),indent=2))
 first,last=samples[5],samples[55];queries=int(last['Queries'])-int(first['Queries']);hz=os.sysconf('SC_CLK_TCK')
 summary=dict(mode=mode,workload=workload,clients=1,jobs=1,backend_cap=10,tls=True,commands_stats=False,query_digests=False,digest_map_unchanged=True,tps=float(re.search(r'tps = ([\d.]+)',text)[1]),latency_ms=float(re.search(r'latency average = ([\d.]+)',text)[1]),conn_ok_start=baseline['ConnOK'],conn_ok_end=samples[-1]['ConnOK'],conn_err_end=samples[-1]['ConnERR'],snapshots=len(samples),cpu_us_per_query=sum(last[k]-first[k] for k in ['cpu_user_ticks','cpu_system_ticks'])*1e6/hz/queries,user_us_per_query=(last['cpu_user_ticks']-first['cpu_user_ticks'])*1e6/hz/queries,system_us_per_query=(last['cpu_system_ticks']-first['cpu_system_ticks'])*1e6/hz/queries)
 histogram=collections.Counter();clients=collections.Counter();file_metadata=[];total_us=0;observations=0
 for logfile in sorted(logroot.glob('transactions.*')):
  loghash=hashlib.sha256()
  with logfile.open('rb') as source, gzip.open(out/(logfile.name+'.gz'),'wb',compresslevel=1) as archive:
   for line in source:
    loghash.update(line);archive.write(line);fields=line.split();assert len(fields)==6,line
    client=int(fields[0]);latency=int(fields[2]);assert 0<=client<1 and latency>=0,line
    clients[client]+=1;histogram[latency]+=1;total_us+=latency;observations+=1
  file_metadata.append(dict(file=logfile.name+'.gz',uncompressed_sha256=loghash.hexdigest()))
 expected_count=int(re.search(r'number of transactions actually processed: (\d+)',text)[1]);assert observations==expected_count,(observations,expected_count)
 assert observations>0 and len(file_metadata)==1,(observations,len(file_metadata))
 targets={key:math.ceil(observations*fraction) for key,fraction in [('p50_ms',.50),('p95_ms',.95),('p99_ms',.99)]};percentiles={};running=0
 for latency,count in sorted(histogram.items()):
  running+=count
  for key,rank in targets.items():
   if key not in percentiles and running>=rank:percentiles[key]=latency/1000
 log_mean_ms=total_us/observations/1000;assert abs(log_mean_ms-summary['latency_ms'])<.01,(log_mean_ms,summary)
 latency_result=dict(method='nearest rank over all successful measured transactions; pgbench raw log third column in microseconds',samples=observations,mean_ms=log_mean_ms,max_ms=max(histogram)/1000,**percentiles,clients_with_completions=len(clients),completed_per_client_min=min(clients.get(i,0) for i in range(1)),completed_per_client_max=max(clients.values()),logs=file_metadata,log_storage_during_measurement='tmpfs /dev/shm',sampling_rate=1.0)
 (out/'latency-percentiles.json').write_text(json.dumps(latency_result,indent=2));(out/'completed-per-client.json').write_text(json.dumps(dict(sorted(clients.items())),indent=2))
 summary.update(percentiles,logged_transactions=observations,clients_with_completions=len(clients))
 (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
 print('PASS: 10 established backends retained; ConnOK/ConnERR unchanged during warmup and every measurement snapshot; zero failed transactions.',flush=True)

finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=15)
 if parent is None and (data/'proxysql.pid').exists():parent=int((data/'proxysql.pid').read_text())
 pids=[]
 if parent is not None:
  pids=[parent]+[int(x) for x in subprocess.run(['pgrep','-P',str(parent)],capture_output=True,text=True).stdout.split()]
  for process in pids:
   try:os.kill(process,signal.SIGTERM)
   except ProcessLookupError:pass
  for _ in range(100):
   if all(not Path(f'/proc/{process}/stat').exists() or Path(f'/proc/{process}/stat').read_text().split()[2]=='Z' for process in pids):break
   time.sleep(.1)
  else:raise RuntimeError('Isolated 3.0.9 instance did not stop')
 (out/'cleanup.json').write_text(json.dumps(dict(isolated_instance_stopped=True,existing_listeners_untouched=True),indent=2))
 if logtemp is not None:logtemp.cleanup()
 temp.cleanup()
print('DONE '+str(out),flush=True)
