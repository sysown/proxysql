from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,statistics,hashlib,sys
r=Path.home()/'pg-network-bench';kind=sys.argv[1] if len(sys.argv)>1 else 'smoke';out=r/'results'/('unified-'+kind+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
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
 binary=r/'src'/('proxysql-head-inline-handoff' if mode=='restore' else 'proxysql-head-unified-ready-loop')
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(50):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('start failed')
 q(f'UPDATE pgsql_servers SET max_connections={cap},use_ssl={int(tls)}');q('LOAD PGSQL SERVERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-use_native_backend_protocol','pgsql-free_connections_pct','pgsql-have_ssl','pgsql-query_digests')");v={x['variable_name']:x['variable_value'] for x in settings};assert v['pgsql-threads']=='1' and v['pgsql-use_native_backend_protocol']=='true' and v['pgsql-free_connections_pct']==('10' if tls else '100'),v
 return settings

def start_mode(mode):
 for key in ['PX_PGSQL_UNIFIED_LOOP','PX_PGSQL_UNIFIED_REFRESH']:os.environ.pop(key,None)
 if mode in ['queue','refresh']:os.environ['PX_PGSQL_UNIFIED_LOOP']='1'
 if mode=='refresh':os.environ['PX_PGSQL_UNIFIED_REFRESH']='1'
 try:return start(mode)
 finally:
  for key in ['PX_PGSQL_UNIFIED_LOOP','PX_PGSQL_UNIFIED_REFRESH']:os.environ.pop(key,None)
def worker():return int(subprocess.check_output(['pgrep','-P',pf.read_text().strip()],text=True).strip())
def cpu(pid):
 v=Path(f'/proc/{pid}/stat').read_text().split();return [int(v[13]),int(v[14])]
def args(clients,threads,protocol='simple',sql='select42_4kb.sql',seconds=45):return ['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c',str(clients),'-j',str(threads),'-M',protocol,'-f',sql,'-T',str(seconds),'-P','5']
def completed_run(path,a):
 with path.open('w') as f:run=subprocess.run(a,cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT)
 text=path.read_text();assert run.returncode==0 and 'number of failed transactions: 0' in text,(str(path),text[-1500:]);return text
def audit(path):
 pa=['psql','-X','-w','-h','127.0.0.1','-p',port,'-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert ('TLSv1.3' in front)==tls and back==('t|TLSv1.3|TLS_AES_256_GCM_SHA384' if tls else 'f||'),(front,back);path.write_text(front+'Backend: '+back+'\n')
(out/'binary.json').write_text(json.dumps(dict(sha256=hashlib.sha256((r/'src/proxysql-head-unified-ready-loop').read_bytes()).hexdigest(),commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=r/'src/proxysql-head',text=True).strip()),indent=2))
rows=[]
try:
 if kind=='smoke':
  (out/'transaction.sql').write_text('BEGIN;\nSELECT 1;\nCOMMIT;\n')
  for mode in ['queue','refresh']:
   setup('tls50');start_mode(mode);audit(out/f'{mode}-tls.txt')
   for label,n,j,proto,sql in [('single',1,1,'simple','select1.sql'),('4kb',50,16,'simple','select42_4kb.sql'),('extended',50,16,'extended','select42_4kb.sql'),('transactions',10,4,'simple',str(out/'transaction.sql'))]:
    text=completed_run(out/f'{mode}-{label}.txt',args(n,j,proto,sql,5));print(mode,label,re.search(r'tps = ([\d.]+)',text)[1],'PASS',flush=True)
   setup('plain500');start_mode(mode);completed_run(out/f'{mode}-plain500.txt',args(500,16,seconds=8));print(mode,'plain500 PASS',flush=True)
   with (out/f'{mode}-disconnect.txt').open('w') as f:
    p=subprocess.Popen(args(500,16,sql='select1.sql',seconds=60),cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT);time.sleep(5);p.terminate();p.wait(timeout=10)
   time.sleep(3);active=q("SELECT COUNT(*) AS n FROM stats_pgsql_processlist WHERE user='networkbench'");(out/f'{mode}-disconnect-after.json').write_text(json.dumps(active));assert active[0]['n']=='0',active;print(mode,'disconnect PASS',flush=True)
 else:
  for case in (['tls50'] if kind=='tls' else ['plain500']):
   setup(case)
   for i,mode in enumerate(['legacy','queue','refresh','refresh','queue','legacy','queue','legacy','refresh']):
    d=out/f'{i:02d}-{mode}';d.mkdir();settings=start_mode(mode);pid=worker();(d/'settings.json').write_text(json.dumps(settings,indent=2));audit(d/'tls.txt')
    envnames=[x.split(b'=')[0].decode() for x in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0') if x];assert ('PX_PGSQL_UNIFIED_LOOP' in envnames)==(mode!='legacy');assert ('PX_PGSQL_UNIFIED_REFRESH' in envnames)==(mode=='refresh');(d/'mode.json').write_text(json.dumps(dict(mode=mode,pid=pid,unified=mode!='legacy',refresh=mode=='refresh')))
    if tls:completed_run(d/'warmup.txt',args(50,16,seconds=20))
    seconds=60 if tls else 45
    with (d/'pgbench.txt').open('w') as f:
     p=subprocess.Popen(args(clients,16,seconds=seconds),cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT);t0=time.monotonic();samples=[]
     for j in range(5 if tls else 10,seconds-4):
      time.sleep(max(0,t0+j-time.monotonic()));assert p.poll() is None,'client exited early';pool=q('SELECT ConnUsed,ConnFree,ConnOK,ConnERR,Queries FROM stats_pgsql_connection_pool')[0];assert int(pool['ConnUsed'])+int(pool['ConnFree'])<=cap,pool;samples.append(dict(elapsed=time.monotonic()-t0,cpu=cpu(pid),**pool))
     assert p.wait()==0
    (d/'samples.json').write_text(json.dumps(samples,indent=2));text=(d/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-1500:];first,last=samples[0],samples[-1];queries=int(last['Queries'])-int(first['Queries']);ticks=os.sysconf('SC_CLK_TCK')
    row=dict(case=case,mode=mode,run=i,tps=float(re.search(r'tps = ([\d.]+)',text)[1]),latency_ms=float(re.search(r'latency average = ([\d.]+)',text)[1]),steady_tps=queries/(last['elapsed']-first['elapsed']),cpu_us_per_query=sum(last['cpu'][k]-first['cpu'][k] for k in [0,1])*1e6/ticks/queries,used_mean=statistics.mean(int(s['ConnUsed']) for s in samples),used_min=min(int(s['ConnUsed']) for s in samples),used_max=max(int(s['ConnUsed']) for s in samples),free_mean=statistics.mean(int(s['ConnFree']) for s in samples),free_min=min(int(s['ConnFree']) for s in samples),free_max=max(int(s['ConnFree']) for s in samples),conn_created=int(last['ConnOK'])-int(first['ConnOK']),conn_errors=int(last['ConnERR'])-int(first['ConnERR']));rows.append(row);(out/'summary.json').write_text(json.dumps(rows,indent=2));print(json.dumps(row),flush=True)
finally:
 for case in ['tls50','plain500']:setup(case);start_mode('restore')
 print('Restored clean inline-handoff on both listeners.',flush=True)
print('DONE '+str(out),flush=True)
