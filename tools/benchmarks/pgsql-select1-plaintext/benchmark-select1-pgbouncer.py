from pathlib import Path
import os,subprocess,time,json,csv,io,re,signal,hashlib,socket
r=Path.home()/'pg-network-bench'
out=r/'results'/('select1-plain-pgbouncer-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
env=os.environ.copy();env.update(PGSSLMODE='disable',PGPASSWORD=next(x.split(':',4)[4] for x in (r/'.pgpass').read_text().splitlines() if x.startswith('*:5432:')))
sock=socket.socket();sock.bind(('127.0.0.1',0));port=str(sock.getsockname()[1]);sock.close();(out/'port.txt').write_text(port+'\n')
cfg=out/'private.ini';pf=out/'pgbouncer.pid';log=out/'pgbouncer.log'
s=(r/'pgbouncer-plain.ini').read_text()
for key,val in dict(listen_port=port,pidfile=str(pf),logfile=str(log),default_pool_size='64',min_pool_size='64',reserve_pool_size='0',server_lifetime='86400',server_idle_timeout='86400',log_connections='1',log_disconnections='1').items():
 if re.search(r'^'+key+r'\s*=',s,re.M):s=re.sub(r'^'+key+r'\s*=.*$',key+' = '+val,s,flags=re.M)
 else:s+='\n'+key+' = '+val+'\n'
cfg.write_text(s);cfg.chmod(0o600)
pa=['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',port,'-U','networkbench','-d']
def q(sql):return list(csv.DictReader(io.StringIO(subprocess.check_output(pa+['pgbouncer','-c',sql],env=env,text=True,stderr=subprocess.DEVNULL))))
def save(name,value):(out/(name+'.json')).write_text(json.dumps(value,indent=2))
p=None;pid=None
try:
 assert {x.read_text().strip() for x in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}=={'performance'}
 binary=r/'pgbouncer/bin/pgbouncer'
 subprocess.run(['taskset','-c','0',str(binary),'-d',str(cfg)],cwd=r,check=True)
 for _ in range(50):
  try:config={x['key']:x['value'] for x in q('SHOW CONFIG')};break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('PgBouncer startup failed')
 pid=int(pf.read_text());assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 assert config['pool_mode']=='transaction' and config['default_pool_size']=='64' and config['reserve_pool_size']=='0'
 assert config['client_tls_sslmode']==config['server_tls_sslmode']=='disable'
 db=next(x for x in q('SHOW DATABASES') if x['name']=='networkbench');assert db['pool_size']=='64' and db['reserve_pool_size']=='0',db
 save('settings',{k:config[k] for k in ['pool_mode','default_pool_size','min_pool_size','reserve_pool_size','server_idle_timeout','server_lifetime','client_tls_sslmode','server_tls_sslmode']})
 save('binary',dict(version=subprocess.check_output([str(binary),'--version'],text=True).strip(),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),pid=pid))
 front=subprocess.check_output(pa+['networkbench','-c',r'\conninfo'],env=env,text=True)
 back=subprocess.check_output(pa+['networkbench','-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=env,text=True).strip()
 assert 'SSL connection' not in front and back=='f||';(out/'plaintext.txt').write_text(front+'Frontend PGSSLMODE=disable; backend ssl=false: '+back+'\n')
 args=['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c','50','-j','16','-M','simple','-f','select1.sql']
 pre=out/'prewarm.sql';pre.write_text('SELECT pg_sleep(2);\n');prep=list(args);prep[prep.index('-c',prep.index('pgbench'))+1]='64';prep[prep.index('-f')+1]=str(pre)
 with (out/'prewarm.txt').open('w') as f:subprocess.run(prep+['-t','1'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 def snap():
  pools=[x for x in q('SHOW POOLS') if x['database']=='networkbench'];assert len(pools)==1,pools
  servers=[x for x in q('SHOW SERVERS') if x['database']=='networkbench'];assert len(servers)==64,len(servers)
  identities=sorted((x['remote_pid'],x['connect_time'],x['ptr']) for x in servers)
  st=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  stats=next(x for x in q('SHOW STATS') if x['database']=='networkbench')
  return dict(wall_ns=time.monotonic_ns(),cpu_user_ticks=int(st[11]),cpu_system_ticks=int(st[12]),Queries=stats['total_query_count'],identities=identities,**pools[0])
 prepared=snap();save('prepared',prepared)
 log_offset=log.stat().st_size
 with (out/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 baseline=snap();assert baseline['identities']==prepared['identities'];samples=[baseline]
 print('pgbouncer: warmup complete; measuring 60 seconds with 64 established backends.',flush=True)
 with (out/'pgbench.txt').open('w') as f:
  t0=time.monotonic_ns();p=subprocess.Popen(args+['-T','60','-P','5'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT)
  for i in range(1,61):
   time.sleep(max(0,(t0+i*1_000_000_000-time.monotonic_ns())/1e9));sample=snap();samples.append(sample);save('samples',samples)
   assert sample['identities']==prepared['identities'],'Backend identity changed'
   assert sum(int(sample.get(k,0)) for k in ['sv_active','sv_idle','sv_used','sv_tested','sv_login'])==64,sample
   assert int(sample['sv_login'])==0,sample
  assert p.wait()==0
 samples.append(snap());assert samples[-1]['identities']==prepared['identities'];save('samples',samples)
 # Connection logging proves absence of a transient replacement between snapshots.
 tail=log.read_bytes()[log_offset:].decode();(out/'steady-log.txt').write_text(tail)
 assert not re.search(r'LOG S-.*(?:new connection|closing because)',tail), 'Server connection churn in log'
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text
 first,last=samples[5],samples[55];queries=int(last['Queries'])-int(first['Queries']);hz=os.sysconf('SC_CLK_TCK')
 summary=dict(mode='pgbouncer',tps=float(re.search(r'tps = ([\d.]+)',text)[1]),latency_ms=float(re.search(r'latency average = ([\d.]+)',text)[1]),snapshots=len(samples),conn_created_steady=0,backend_identities_unchanged=True,cpu_us_per_query=sum(last[k]-first[k] for k in ['cpu_user_ticks','cpu_system_ticks'])*1e6/hz/queries,user_us_per_query=(last['cpu_user_ticks']-first['cpu_user_ticks'])*1e6/hz/queries,system_us_per_query=(last['cpu_system_ticks']-first['cpu_system_ticks'])*1e6/hz/queries)
 save('summary',summary);print(json.dumps(summary),flush=True)
finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=15)
 if pid is not None:
  os.kill(pid,signal.SIGTERM)
 cfg.unlink(missing_ok=True)
print('DONE '+str(out),flush=True)
