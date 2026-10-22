import importlib.util
_spec=importlib.util.spec_from_file_location('forwarding_tracer',str(__import__('pathlib').Path(__file__).with_name('phase-cpu-precise-tracer.py')))
_mod=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_mod)
Tracer=_mod.Tracer
tracer=None
from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,statistics,hashlib,sys
mode=sys.argv[1]
selected={'optimized':'proxysql-head-tokenizer-copy','head':'proxysql-head-before-single-worker-fix','baseline':'proxysql-head-deferred-io-baseline','candidate':'proxysql-head-deferred-session-io','control':'proxysql-head-eager-frontend-control','nohandler':'proxysql-head-eager-no-handler-control','eagerall':'proxysql-head-eager-all-control'}[mode]
expected={'optimized':'2b8476839d5ce8c1943d72aee23651f3143573872ec3eb7a70080c00bc16884c','head':'8451ea4f29158aa0b3728089b8de67b12a84ad7ad32b26d801b0e19cb1704467','baseline':'e8056e3c607e4ea534066417a92b59cb76056cf9e8d6cd9367f622eb716552f7','candidate':'961419b9503186758a2d7d772429f0bc36d6f2127422be3784bac3002acc0f82','control':'313fc06127a7c9158ede8a083e832db37732bd775c4cfb6de54fb9f42adca276','nohandler':'5e03229ed8c12510dd0ea2a59bda72a8a7b4bd9565a994b6da92653c86e8cc96','eagerall':'fadf72759c169427af487313a02a5eab40195e0978cc49bb02588ea8d1797d51'}[mode]
r=Path.home()/'pg-network-bench';assert hashlib.sha256((r/'src'/selected).read_bytes()).hexdigest()==expected
out=r/'results'/('phase-precise-'+mode+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
pw=next(x.split(':',4)[4] for x in (r/'.pgpass').read_text().splitlines() if x.startswith('*:5432:'))
ce=os.environ.copy();ce['PGPASSWORD']=pw
assert {p.read_text().strip() for p in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}=={'performance'}
def setup(case):
 global cfg,pf,ae,adminport,port,cap,clients,tls
 tls=case=='tls50';cfg=r/('proxysql-head.cnf' if tls else 'proxysql-plain.cnf');pf=r/('proxysql-head-data/proxysql.pid' if tls else 'proxysql-plain-data/proxysql.pid');adminport='6232' if tls else '7132';port='6233' if tls else '7133';cap=64 if tls else 10;clients=50 if tls else 500
 u,p=re.search(r'admin_credentials="([^"]+)"',cfg.read_text())[1].split(':',1);ae=os.environ.copy();ae.update(PGPASSWORD=p,PGSSLMODE='disable');ae['PGUSER']=u;ce['PGSSLMODE']='require' if tls else 'disable'
def q(sql):
 return list(csv.DictReader(io.StringIO(subprocess.check_output(['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',adminport,'-d','admin','-c',sql],env=ae,text=True,stderr=subprocess.DEVNULL))))
def start(mode):
 if pf.exists():
  parent=int(pf.read_text());kids=subprocess.run(['pgrep','-P',str(parent)],capture_output=True,text=True).stdout.split();pids=[parent]+list(map(int,kids))
  for pid in pids:
   try:os.kill(pid,signal.SIGTERM)
   except ProcessLookupError:pass
  for _ in range(100):
   if all(not Path(f'/proc/{pid}/stat').exists() or Path(f'/proc/{pid}/stat').read_text().split()[2]=='Z' for pid in pids):break
   time.sleep(.1)
  else:raise RuntimeError('stop failed')
  pf.unlink(missing_ok=True)
 binary=r/'src'/(selected if mode=='timing' else 'proxysql-head-inline-handoff')
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(50):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('start failed')
 q("UPDATE global_variables SET variable_value='100' WHERE variable_name='pgsql-free_connections_pct'")
 ssl_on=mode!='timing'
 q("UPDATE global_variables SET variable_value='"+str(ssl_on).lower()+"' WHERE variable_name='pgsql-have_ssl'");q('LOAD PGSQL VARIABLES TO RUNTIME')
 q(f'UPDATE pgsql_servers SET max_connections={cap},use_ssl={int(ssl_on)}');q('LOAD PGSQL SERVERS TO RUNTIME')
 q(f"UPDATE pgsql_users SET use_ssl={int(ssl_on)} WHERE username='networkbench'");q('LOAD PGSQL USERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-use_native_backend_protocol','pgsql-free_connections_pct','pgsql-have_ssl','pgsql-query_digests')");v={x['variable_name']:x['variable_value'] for x in settings};assert v['pgsql-threads']=='1' and v['pgsql-use_native_backend_protocol']=='true' and v['pgsql-free_connections_pct']=='100' and v['pgsql-have_ssl']==str(ssl_on).lower(),v
 attrs=q('SELECT hostgroup_id,free_connections_pct FROM runtime_pgsql_hostgroup_attributes');assert all(int(x['free_connections_pct'])==100 for x in attrs),attrs
 age=q("SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-connection_max_age_ms'");assert age[0]['variable_value']=='0',age
 return settings

p=None
setup('tls50');ce['PGSSLMODE']='disable';os.environ.pop('PX_PGSQL_UNIFIED_LOOP',None);os.environ.pop('PX_PGSQL_UNIFIED_REFRESH',None)
args=['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p','6233','-U','networkbench','networkbench','-c','1','-j','1','-M','simple','-f','select1.sql']
try:
 os.environ.pop('PX_PGSQL_PHASE_DETAIL',None);os.environ.pop('PX_PGSQL_LOOP_TIMING',None)
 settings=start('timing');(out/'settings.json').write_text(json.dumps(settings,indent=2))
 pid=int(subprocess.check_output(['pgrep','-P',pf.read_text().strip()],text=True).strip());environ=(Path('/proc')/str(pid)/'environ').read_bytes();assert b'PX_PGSQL_PHASE_DETAIL=' not in environ and b'PX_PGSQL_LOOP_TIMING=' not in environ and b'PX_PGSQL_UNIFIED_LOOP=' not in environ
 assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 (out/'binary.json').write_text(json.dumps(dict(sha256=expected,commit={'optimized':'73f822839','head':'a0781dd90','baseline':'9f92e9d84','candidate':'b17a986f3','control':'639cf5aba','nohandler':'a3f93cad1','eagerall':'51d6ad785'}[mode],scheduler='upstream' if mode=='head' else 'phased',timers=False,profiling=True,mode=mode,pid=pid),indent=2))
 pa=['psql','-X','-w','-h','127.0.0.1','-p','6233','-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert 'SSL connection' not in front and back=='f||';(out/'plaintext.txt').write_text(front+'Frontend PGSSLMODE=disable; backend ssl=false: '+back+'\n')
 # Establish the whole cap before warmup, holding each backend long enough
 # for all 64 clients to acquire one. This is preparation, not measurement.
 prewarm=out/'prewarm.sql';prewarm.write_text('SELECT pg_sleep(2);\n')
 prep=list(args);prep[prep.index('-c',prep.index('pgbench'))+1]='64';prep[prep.index('-f')+1]=str(prewarm);prep[prep.index('-j')+1]='16'
 with (out/'prewarm.txt').open('w') as f:subprocess.run(prep+['-t','1'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
 def pool_snapshot():
  rows=q('SELECT ConnUsed,ConnFree,ConnOK,ConnERR,Queries FROM stats_pgsql_connection_pool');assert len(rows)==1,rows
  st=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  return dict(wall_ns=time.monotonic_ns(),cpu_user_ticks=int(st[11]),cpu_system_ticks=int(st[12]),**rows[0])
 for _ in range(100):
  prepared=pool_snapshot()
  if int(prepared['ConnUsed'])==0 and int(prepared['ConnFree'])==64:break
  time.sleep(.1)
 else:raise RuntimeError('Prewarm did not establish all 64 backends: '+str(prepared))
 (out/'prepared.json').write_text(json.dumps(prepared,indent=2))
 with (out/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
 print(mode+': warmup completed; measuring 60 seconds with 64 established backends.',flush=True)
 baseline=pool_snapshot();assert int(baseline['ConnUsed'])+int(baseline['ConnFree'])==64,baseline
 assert baseline['ConnOK']==prepared['ConnOK'] and baseline['ConnERR']==prepared['ConnERR'],(prepared,baseline)
 samples=[baseline];(out/'samples.json').write_text(json.dumps(samples,indent=2))
 def check_pool():
  sample=pool_snapshot();samples.append(sample);(out/'samples.json').write_text(json.dumps(samples,indent=2))
  assert sample['ConnOK']==baseline['ConnOK'],('REJECT: new backend connection during measurement',baseline,sample)
  assert sample['ConnERR']==baseline['ConnERR'],('REJECT: backend connect error during measurement',baseline,sample)
  assert int(sample['ConnUsed'])+int(sample['ConnFree'])==64,('REJECT: backend pool size changed',sample)
 with (out/'pgbench.txt').open('w') as f:
  t0=time.monotonic_ns();p=subprocess.Popen(args+['-T','60','-P','5'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT)
  for i in range(1,61):
   time.sleep(max(0,(t0+i*1000000000-time.monotonic_ns())/1e9));check_pool()
   if i==10:tracer=Tracer(out,pid,port)
  assert p.wait()==0
  check_pool()
 tracer.finish()
 t1=time.monotonic_ns()
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-2000:]
 (out/'window.json').write_text(json.dumps(dict(measure_start_ns=t0,measure_end_ns=t1,steady_start_ns=t0+10_000_000_000,steady_end_ns=t0+50_000_000_000),indent=2))
 first,last=samples[5],samples[55];queries=int(last['Queries'])-int(first['Queries']);hz=os.sysconf('SC_CLK_TCK')
 summary=dict(mode=mode,tps=float(re.search(r'tps = ([\d.]+)',text)[1]),latency_ms=float(re.search(r'latency average = ([\d.]+)',text)[1]),conn_ok_start=baseline['ConnOK'],conn_ok_end=samples[-1]['ConnOK'],conn_err_end=samples[-1]['ConnERR'],snapshots=len(samples),cpu_us_per_query=sum(last[k]-first[k] for k in ['cpu_user_ticks','cpu_system_ticks'])*1e6/hz/queries,user_us_per_query=(last['cpu_user_ticks']-first['cpu_user_ticks'])*1e6/hz/queries,system_us_per_query=(last['cpu_system_ticks']-first['cpu_system_ticks'])*1e6/hz/queries)
 (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
 print('PASS: 64 established backends retained; ConnOK/ConnERR unchanged during warmup and every measurement snapshot; zero failed transactions.',flush=True)

finally:
 if tracer is not None:tracer.cleanup()
 os.environ.pop('PX_PGSQL_PHASE_DETAIL',None)
 if p is not None and p.poll() is None:
  p.terminate();p.wait(timeout=15)
 os.environ.pop('PX_PGSQL_LOOP_TIMING',None);start('restore');print('Restored prior clean inline-handoff TLS binary with corrected 100% retention.',flush=True)
print('DONE '+str(out),flush=True)
