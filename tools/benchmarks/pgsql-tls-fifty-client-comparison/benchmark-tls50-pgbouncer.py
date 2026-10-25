from pathlib import Path
import os,subprocess,time,json,csv,io,re,signal,hashlib,socket,tempfile,gzip,math,collections
r=Path.home()/'pg-network-bench'
import fcntl
run_lock=(r/'plaintext-implementation.lock').open('a')
fcntl.flock(run_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
def interrupted(signum,frame):raise KeyboardInterrupt
signal.signal(signal.SIGTERM,interrupted)
signal.signal(signal.SIGINT,interrupted)
import sys
workload=sys.argv[1];assert workload in ['select1','4kb']
backend_cap=int(sys.argv[2]);assert backend_cap in [10,50]
clients_n=50;jobs_n=16
client_cpus='2,4,6,8,10,12,14,16'
query_file={'select1':'select1.sql','4kb':'select42_4kb.sql'}[workload]
out=r/'results'/('tls50-b'+str(backend_cap)+'-'+workload+'-pgbouncer-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
env=os.environ.copy();env.update(PGSSLMODE='require',PGPASSWORD=next(x.split(':',4)[4] for x in (r/'.pgpass').read_text().splitlines() if x.startswith('*:5432:')))
sock=socket.socket();sock.bind(('127.0.0.1',0));port=str(sock.getsockname()[1]);sock.close();(out/'port.txt').write_text(port+'\n')
cfg=out/'private.ini';pf=out/'pgbouncer.pid';log=out/'pgbouncer.log'
s=(r/'pgbouncer-plain.ini').read_text()
for key,val in dict(listen_port=port,pidfile=str(pf),logfile=str(log),default_pool_size=str(backend_cap),min_pool_size=str(backend_cap),reserve_pool_size='0',client_tls_sslmode='allow',server_tls_sslmode='require',server_lifetime='86400',server_idle_timeout='86400',log_connections='1',log_disconnections='1').items():
 if re.search(r'^'+key+r'\s*=',s,re.M):s=re.sub(r'^'+key+r'\s*=.*$',key+' = '+val,s,flags=re.M)
 else:s+='\n'+key+' = '+val+'\n'
cfg.write_text(s);cfg.chmod(0o600)
pa=['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',port,'-U','networkbench','-d']
admin_env=env.copy();admin_env['PGSSLMODE']='disable'
def q(sql):return list(csv.DictReader(io.StringIO(subprocess.check_output(pa+['pgbouncer','-c',sql],env=admin_env,text=True,stderr=subprocess.DEVNULL))))
def save(name,value):(out/(name+'.json')).write_text(json.dumps(value,indent=2))
p=None;pid=None;logtemp=None
(out/query_file).write_text((r/query_file).read_text())
try:
 assert {x.read_text().strip() for x in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}=={'performance'}
 binary=r/'pgbouncer/bin/pgbouncer'
 subprocess.run(['taskset','-c','0',str(binary),'-d',str(cfg)],cwd=r,check=True)
 for _ in range(50):
  try:config={x['key']:x['value'] for x in q('SHOW CONFIG')};break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('PgBouncer startup failed')
 pid=int(pf.read_text());assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 assert config['pool_mode']=='transaction' and config['default_pool_size']==str(backend_cap) and config['reserve_pool_size']=='0'
 assert config['client_tls_sslmode']=='allow' and config['server_tls_sslmode']=='require'
 db=next(x for x in q('SHOW DATABASES') if x['name']=='networkbench');assert db['pool_size']==str(backend_cap) and db['reserve_pool_size']=='0',db
 save('settings',{k:config[k] for k in ['pool_mode','default_pool_size','min_pool_size','reserve_pool_size','server_idle_timeout','server_lifetime','client_tls_sslmode','server_tls_sslmode']})
 save('binary',dict(version=subprocess.check_output([str(binary),'--version'],text=True).strip(),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),pid=pid))
 front=subprocess.check_output(pa+['networkbench','-c',r'\conninfo'],env=env,text=True)
 back=subprocess.check_output(pa+['networkbench','-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=env,text=True).strip()
 assert 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in front and back=='t|TLSv1.3|TLS_AES_256_GCM_SHA384';(out/'tls.txt').write_text(front+'Frontend PGSSLMODE=require; backend TLS: '+back+'\n')
 from verify_tls_query_output import verify
 verify(out,pa+['networkbench'],env,query_file,r)
 args=['taskset','-c',client_cpus,'pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c',str(clients_n),'-j',str(jobs_n),'-M','simple','-f',query_file]
 pre=out/'prewarm.sql';pre.write_text('SELECT pg_sleep(2);\n');prep=list(args);prep[prep.index('-c',prep.index('pgbench'))+1]=str(backend_cap);prep[prep.index('-f')+1]=str(pre);prep[prep.index('-j')+1]=str(min(16,backend_cap))
 with (out/'prewarm.txt').open('w') as f:subprocess.run(prep+['-t','1'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 def snap():
  pools=[x for x in q('SHOW POOLS') if x['database']=='networkbench'];assert len(pools)==1,pools
  servers=[x for x in q('SHOW SERVERS') if x['database']=='networkbench'];assert len(servers)==backend_cap,len(servers)
  identities=sorted((x['remote_pid'],x['connect_time'],x['ptr']) for x in servers)
  st=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  stats=next(x for x in q('SHOW STATS') if x['database']=='networkbench')
  return dict(wall_ns=time.monotonic_ns(),cpu_user_ticks=int(st[11]),cpu_system_ticks=int(st[12]),Queries=stats['total_query_count'],identities=identities,**pools[0])
 prepared=snap();save('prepared',prepared)
 save('servers-after-prewarm',q('SHOW SERVERS'))
 log_offset=log.stat().st_size
 with (out/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 baseline=snap();assert baseline['identities']==prepared['identities'];samples=[baseline]
 print('pgbouncer: warmup complete; measuring 60 seconds with '+str(backend_cap)+' established backends.',flush=True)
 logtemp=tempfile.TemporaryDirectory(prefix='pgbench-latency-pgbouncer-',dir='/dev/shm');logroot=Path(logtemp.name)
 with (out/'pgbench.txt').open('w') as f:
  t0=time.monotonic_ns();p=subprocess.Popen(args+['-T','60','-P','5','-l','--log-prefix',str(logroot/'transactions')],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT)
  for i in range(1,61):
   time.sleep(max(0,(t0+i*1_000_000_000-time.monotonic_ns())/1e9));sample=snap();samples.append(sample);save('samples',samples)
   assert sample['identities']==prepared['identities'],'Backend identity changed'
   assert sum(int(sample.get(k,0)) for k in ['sv_active','sv_idle','sv_used','sv_tested','sv_login'])==backend_cap,sample
   assert int(sample['sv_login'])==0,sample
  assert p.wait()==0
 samples.append(snap());assert samples[-1]['identities']==prepared['identities'];save('samples',samples)
 # Connection logging proves absence of a transient replacement between snapshots.
 tail=log.read_bytes()[log_offset:].decode();(out/'steady-log.txt').write_text(tail)
 assert not re.search(r'LOG S-.*(?:new connection|closing because)',tail), 'Server connection churn in log'
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text
 first,last=samples[5],samples[55];queries=int(last['Queries'])-int(first['Queries']);hz=os.sysconf('SC_CLK_TCK')
 summary=dict(mode='pgbouncer',workload=workload,clients=clients_n,jobs=jobs_n,backend_cap=backend_cap,client_cpus=client_cpus,tls=True,tps=float(re.search(r'tps = ([\d.]+)',text)[1]),latency_ms=float(re.search(r'latency average = ([\d.]+)',text)[1]),snapshots=len(samples),conn_created_steady=0,backend_identities_unchanged=True,cpu_us_per_query=sum(last[k]-first[k] for k in ['cpu_user_ticks','cpu_system_ticks'])*1e6/hz/queries,user_us_per_query=(last['cpu_user_ticks']-first['cpu_user_ticks'])*1e6/hz/queries,system_us_per_query=(last['cpu_system_ticks']-first['cpu_system_ticks'])*1e6/hz/queries)
 histogram=collections.Counter();clients=collections.Counter();file_metadata=[];total_us=0;observations=0
 for logfile in sorted(logroot.glob('transactions.*')):
  loghash=hashlib.sha256()
  with logfile.open('rb') as source, gzip.open(out/(logfile.name+'.gz'),'wb',compresslevel=1) as archive:
   for line in source:
    loghash.update(line);archive.write(line);fields=line.split();assert len(fields)==6,line
    client=int(fields[0]);latency=int(fields[2]);assert 0<=client<clients_n and latency>=0,line
    clients[client]+=1;histogram[latency]+=1;total_us+=latency;observations+=1
  file_metadata.append(dict(file=logfile.name+'.gz',uncompressed_sha256=loghash.hexdigest()))
 expected_count=int(re.search(r'number of transactions actually processed: (\d+)',text)[1]);assert observations==expected_count,(observations,expected_count)
 assert observations>0 and len(file_metadata)==jobs_n,(observations,len(file_metadata))
 targets={key:math.ceil(observations*fraction) for key,fraction in [('p50_ms',.50),('p95_ms',.95),('p99_ms',.99)]};percentiles={};running=0
 for latency,count in sorted(histogram.items()):
  running+=count
  for key,rank in targets.items():
   if key not in percentiles and running>=rank:percentiles[key]=latency/1000
 log_mean_ms=total_us/observations/1000;assert abs(log_mean_ms-summary['latency_ms'])<.01,(log_mean_ms,summary)
 latency_result=dict(method='nearest rank over all successful measured transactions; pgbench raw log third column in microseconds',samples=observations,mean_ms=log_mean_ms,max_ms=max(histogram)/1000,**percentiles,clients_with_completions=len(clients),completed_per_client_min=min(clients.get(i,0) for i in range(clients_n)),completed_per_client_max=max(clients.values()),logs=file_metadata,log_storage_during_measurement='tmpfs /dev/shm',sampling_rate=1.0)
 (out/'latency-percentiles.json').write_text(json.dumps(latency_result,indent=2));(out/'completed-per-client.json').write_text(json.dumps(dict(sorted(clients.items())),indent=2))
 summary.update(percentiles,logged_transactions=observations,clients_with_completions=len(clients))
 (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)

finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=15)
 if pid is None and pf.exists():pid=int(pf.read_text())
 if pid is not None:
  try:os.kill(pid,signal.SIGTERM)
  except ProcessLookupError:pass
  for _ in range(100):
   stat=Path(f'/proc/{pid}/stat')
   if not stat.exists() or stat.read_text().split()[2]=='Z':break
   time.sleep(.1)
  else:raise RuntimeError('Temporary PgBouncer did not stop')
 cfg.unlink(missing_ok=True)
 if logtemp is not None:logtemp.cleanup()
 save('cleanup',dict(isolated_instance_stopped=True,private_config_removed=not cfg.exists()))
print('DONE '+str(out),flush=True)
