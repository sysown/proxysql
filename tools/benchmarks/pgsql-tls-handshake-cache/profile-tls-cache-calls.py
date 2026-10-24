from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,hashlib,socket,tempfile,shutil,sys,math,gzip,collections
r=Path.home()/'pg-network-bench'
mode=sys.argv[1];assert mode=='cached';metadata=json.loads((r/'tls-handshake-cache-binaries.json').read_text())[mode]
out=r/'results'/('tls-handshake-cache-counts-'+mode+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
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
p=None;parent=None;pid=None;logtemp=None;counter=None
from tls_cache_counter import TLSCounter
args=['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c','500','-j','16','-M','simple','-f','select42_4kb.sql']
(out/'select42_4kb.sql').write_text((r/'select42_4kb.sql').read_text())
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
 (out/'binary.json').write_text(json.dumps(dict(version=version.stdout.strip(),version_stderr=version.stderr.strip(),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),backend='native' if values.get('pgsql-use_native_backend_protocol')=='true' else 'libpq',native_backend_setting_present='pgsql-use_native_backend_protocol' in values,metadata=metadata,profiling=True,transaction_logging=False,pid=pid),indent=2))
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
 print(mode+': warmup completed; preparing gated TLS call counters with 10 established backends.',flush=True)
 baseline=pool_snapshot();assert int(baseline['ConnUsed'])+int(baseline['ConnFree'])==10,baseline
 assert baseline['ConnOK']==prepared['ConnOK'] and baseline['ConnERR']==prepared['ConnERR'],(prepared,baseline)
 samples=[baseline];(out/'samples.json').write_text(json.dumps(samples,indent=2))
 def check_pool():
  sample=pool_snapshot();samples.append(sample);(out/'samples.json').write_text(json.dumps(samples,indent=2))
  assert sample['ConnOK']==baseline['ConnOK'],('REJECT: new backend connection during measurement',baseline,sample)
  assert sample['ConnERR']==baseline['ConnERR'],('REJECT: backend connect error during measurement',baseline,sample)
  assert int(sample['ConnUsed'])+int(sample['ConnFree'])==10,('REJECT: backend pool size changed',sample)
 # Keep this one client process alive while compiling/attaching probes, so
 # connection setup and teardown are outside the explicitly gated window.
 with (out/'pgbench.txt').open('w') as f:
  p=subprocess.Popen(args+['-T','60','-P','5'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT)
  time.sleep(10);check_pool()
  counter=TLSCounter.__new__(TLSCounter)
  counter.__init__(out,pid,binary,port)
  # Exercise the probe with one fresh frontend TLS handshake before counting.
  control=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True)
  assert 'TLSv1.3' in control,control
  (out/'pre-window-positive-control.txt').write_text(control)
  assert p.poll() is None, 'pgbench exited before counting'
  check_pool()
  def bracketed_snapshot():
   a=time.monotonic_ns();s=pool_snapshot();b=time.monotonic_ns()
   s.update(before_ns=a,after_ns=b);return s
  counter.begin(bracketed_snapshot)
  print(mode+': TLS and syscall call counts enabled for 20 seconds; all 500 frontend sockets and 10 backend sockets established.',flush=True)
  t0=time.monotonic()
  for i in range(1,21):
   time.sleep(max(0,t0+i-time.monotonic()));check_pool()
   assert p.poll() is None, 'pgbench exited inside count window'
  counter.end(bracketed_snapshot)
  result=counter.finish()
  # Let pgbench finish naturally after counting is disabled and probes detach.
  status=p.wait(timeout=45)
  assert status==0,(status,(out/'pgbench.txt').read_text()[-1500:])
  check_pool()
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-2000:]
 digest_after=q('SELECT COUNT(*) AS digest_rows, COALESCE(SUM(count_star),0) AS total_count FROM stats_pgsql_query_digest');(out/'digest-map-after.json').write_text(json.dumps(digest_after,indent=2))
 assert digest_after==digest_before,('REJECT: digest-map statistics changed',digest_before,digest_after)
 (out/'summary.json').write_text(json.dumps(dict(mode=mode,queries=result['queries'],enabled_seconds=result['enabled_seconds'],conn_ok_start=baseline['ConnOK'],conn_ok_end=samples[-1]['ConnOK'],conn_err_end=samples[-1]['ConnERR'],snapshots=len(samples),tls=True,query_digests=False,commands_stats=False,zero_failed_transactions=True,profiling_only=True),indent=2))
 print('PASS: TLS call counts collected; ConnOK/ConnERR unchanged and all 10 established backends retained.',flush=True)

finally:
 if counter is not None:counter.cleanup()
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
