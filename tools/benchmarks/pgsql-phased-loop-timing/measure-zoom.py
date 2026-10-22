from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,statistics,hashlib
r=Path.home()/'pg-network-bench';out=r/'results'/('phased-loop-zoom-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
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
 binary=r/'src'/('proxysql-head-loop-timing-zoom' if mode=='timing' else 'proxysql-head-inline-handoff')
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(50):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('start failed')
 q(f'UPDATE pgsql_servers SET max_connections={cap},use_ssl={int(tls)}');q('LOAD PGSQL SERVERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-use_native_backend_protocol','pgsql-free_connections_pct','pgsql-have_ssl','pgsql-query_digests')");v={x['variable_name']:x['variable_value'] for x in settings};assert v['pgsql-threads']=='1' and v['pgsql-use_native_backend_protocol']=='true' and v['pgsql-free_connections_pct']==('10' if tls else '100'),v
 return settings

setup('tls50');os.environ.pop('PX_PGSQL_UNIFIED_LOOP',None);os.environ.pop('PX_PGSQL_UNIFIED_REFRESH',None)
args=['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p','6233','-U','networkbench','networkbench','-c','50','-j','16','-M','simple','-f','select42_4kb.sql']
try:
 os.environ['PX_PGSQL_LOOP_TIMING']=str(out/'timing.jsonl');settings=start('timing');os.environ.pop('PX_PGSQL_LOOP_TIMING');(out/'settings.json').write_text(json.dumps(settings,indent=2))
 pid=int(subprocess.check_output(['pgrep','-P',pf.read_text().strip()],text=True).strip());environ=(Path('/proc')/str(pid)/'environ').read_bytes();assert b'PX_PGSQL_LOOP_TIMING=' in environ and b'PX_PGSQL_UNIFIED_LOOP=' not in environ
 assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 (out/'binary.json').write_text(json.dumps(dict(sha256=hashlib.sha256((r/'src/proxysql-head-loop-timing-zoom').read_bytes()).hexdigest(),commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=r/'src/proxysql-head',text=True).strip(),scheduler='phased',pid=pid),indent=2))
 pa=['psql','-X','-w','-h','127.0.0.1','-p','6233','-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert 'TLSv1.3' in front and back=='t|TLSv1.3|TLS_AES_256_GCM_SHA384';(out/'tls.txt').write_text(front+'Backend: '+back+'\n')
 with (out/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
 with (out/'pgbench.txt').open('w') as f:
  t0=time.monotonic_ns();p=subprocess.Popen(args+['-T','60','-P','5'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT);samples=[]
  for i in range(5,56):
   time.sleep(max(0,(t0+i*1000000000-time.monotonic_ns())/1e9));assert p.poll() is None;pool=q('SELECT ConnUsed,ConnFree,ConnOK,ConnERR,Queries FROM stats_pgsql_connection_pool')[0];assert int(pool['ConnUsed'])+int(pool['ConnFree'])<=64; samples.append(dict(wall_ns=time.monotonic_ns(),**pool))
  assert p.wait()==0
 text=(out/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-2000:];(out/'samples.json').write_text(json.dumps(samples,indent=2));(out/'window.json').write_text(json.dumps(dict(measure_start_ns=t0,steady_start_ns=t0+10_000_000_000,steady_end_ns=t0+50_000_000_000),indent=2));print('Measurement completed with zero failed transactions.',flush=True)
finally:
 os.environ.pop('PX_PGSQL_LOOP_TIMING',None);start('restore');print('Restored prior clean inline-handoff TLS runtime.',flush=True)
print('DONE '+str(out),flush=True)
