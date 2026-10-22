from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,statistics,hashlib,select
r=Path.home()/'pg-network-bench';out=r/'results'/('proxy-syscalls-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
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
 binary=r/'src'/('proxysql-head-dispatch-first' if mode=='early' else 'proxysql-head-inline-handoff')
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(50):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('start failed')
 q(f'UPDATE pgsql_servers SET max_connections={cap},use_ssl={int(tls)}');q('LOAD PGSQL SERVERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-use_native_backend_protocol','pgsql-free_connections_pct','pgsql-have_ssl','pgsql-query_digests')");v={x['variable_name']:x['variable_value'] for x in settings};assert v['pgsql-threads']=='1' and v['pgsql-use_native_backend_protocol']=='true' and v['pgsql-free_connections_pct']==('10' if tls else '100'),v
 return settings

setup('tls50')
for key in ['PX_PGSQL_UNIFIED_LOOP','PX_PGSQL_UNIFIED_REFRESH','PX_PGSQL_LOOP_TIMING']:os.environ.pop(key,None)
bcfg=r/'pgbouncer.ini';original=bcfg.read_bytes();backup=r/'pgbouncer.ini.before-syscall-measurement';assert not backup.exists(),'previous backup needs review'
bpid=int((r/'pgbouncer.pid').read_text())
def bq(sql):return list(csv.DictReader(io.StringIO(subprocess.check_output(['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','6432','-U','networkbench','-d','pgbouncer','-c',sql],env=ce,text=True))))
def count(candidate):
 if candidate=='proxysql':return int(q('SELECT Queries FROM stats_pgsql_connection_pool')[0]['Queries'])
 return int(next(x for x in bq('SHOW STATS') if x['database']=='networkbench')['total_query_count'])
def snap(candidate):
 before=time.monotonic_ns();n=count(candidate);after=time.monotonic_ns();return dict(count=n,before_ns=before,after_ns=after,mid_ns=(before+after)//2)
def ack_command(ctl,ack,command):
 before=time.monotonic_ns();os.write(ctl,(command+'\n').encode());buf=b'';deadline=time.monotonic()+5
 while b'\n' not in buf:
  remaining=deadline-time.monotonic();assert remaining>0,('perf control timeout',command)
  if select.select([ack],[],[],remaining)[0]:buf+=os.read(ack,4096)
 after=time.monotonic_ns();assert b'ack' in buf,buf;return dict(before_ns=before,after_ns=after,mid_ns=(before+after)//2)
available=set(subprocess.check_output(['sudo','-n','perf','list','--raw-dump'],text=True).split())
entries=['read','write','readv','writev','recvfrom','sendto','recvmsg','sendmsg','recvmmsg','sendmmsg','poll','ppoll','epoll_wait','epoll_pwait','epoll_pwait2','epoll_ctl','connect','accept','accept4','close','shutdown','setsockopt','getsockopt','fcntl','ioctl','futex','clock_gettime']
events=['raw_syscalls:sys_enter']+[f'syscalls:sys_enter_{x}' for x in entries]
events=[x for x in events if x in available];assert 'raw_syscalls:sys_enter' in events, 'raw syscall event unavailable'
exits=[f'syscalls:sys_exit_{x}' for x in ['read','write','readv','writev','recvfrom','sendto','recvmsg','sendmsg'] if f'syscalls:sys_exit_{x}' in available]
(out/'events.json').write_text(json.dumps(dict(entries=events,eagain_exits=exits),indent=2))
rows=[]
try:
 backup.write_bytes(original);backup.chmod(0o600)
 text=original.decode();text,n=re.subn(r'(?m)^(default_pool_size\s*=\s*)\d+',r'\g<1>64',text);assert n==1;bcfg.write_text(text);os.kill(bpid,signal.SIGHUP);time.sleep(.5)
 config={x['key']:x['value'] for x in bq('SHOW CONFIG')};assert config['default_pool_size']=='64' and config['pool_mode']=='transaction' and config['reserve_pool_size']=='0';assert config['server_tls_sslmode']=='require' and config['client_tls_sslmode']=='require';db=next(x for x in bq('SHOW DATABASES') if x['name']=='networkbench');assert db['pool_size']=='64' and db['reserve_pool_size']=='0';(out/'pgbouncer-settings.json').write_text(json.dumps({k:config[k] for k in ['default_pool_size','reserve_pool_size','pool_mode','server_tls_sslmode','client_tls_sslmode']},indent=2))
 for candidate in ['proxysql','pgbouncer']:
  d=out/candidate;d.mkdir()
  if candidate=='proxysql':
   settings=start('early');pid=int(subprocess.check_output(['pgrep','-P',pf.read_text().strip()],text=True).strip());port='6233';(d/'settings.json').write_text(json.dumps(settings,indent=2))
  else:pid=bpid;port='6432'
  assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
  procenv=(Path('/proc')/str(pid)/'environ').read_bytes();assert b'PX_PGSQL_LOOP_TIMING=' not in procenv and b'PX_PGSQL_UNIFIED_LOOP=' not in procenv
  exe=Path('/proc')/str(pid)/'exe';(d/'binary.json').write_text(json.dumps(dict(pid=pid,path=str(exe.resolve()),sha256=hashlib.sha256(exe.read_bytes()).hexdigest()),indent=2))
  pa=['psql','-X','-w','-h','127.0.0.1','-p',port,'-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert 'TLSv1.3' in front and back=='t|TLSv1.3|TLS_AES_256_GCM_SHA384';(d/'tls.txt').write_text(front+'Backend: '+back+'\n')
  args=['taskset','-c','2,4,6,8,10,12,14,16','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c','50','-j','16','-M','simple','-f','select42_4kb.sql']
  with (d/'warmup.txt').open('w') as f:subprocess.run(args+['-T','20'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT,check=True)
  ctlpath=d/'perf-control';ackpath=d/'perf-ack';os.mkfifo(ctlpath,0o600);os.mkfifo(ackpath,0o600);ctl=os.open(ctlpath,os.O_RDWR|os.O_NONBLOCK);ack=os.open(ackpath,os.O_RDWR|os.O_NONBLOCK)
  with (d/'pgbench.txt').open('w') as f, (d/'perf-control.log').open('w') as log:
   client=subprocess.Popen(args+['-T','50','-P','5'],cwd=r,env=ce,stdout=f,stderr=subprocess.STDOUT);time.sleep(5)
   pargs=['sudo','-n','perf','stat','-D','-1',f'--control=fifo:{ctlpath},{ackpath}','-x',';','-o',str(d/'perf-stat.csv'),'-p',str(pid)]
   for event in events:pargs+=['-e',event]
   for event in exits:pargs+=['-e',event,'--filter','ret == -11']
   perf=subprocess.Popen(pargs+['--','sleep','40'],stdout=log,stderr=subprocess.STDOUT)
   try:
    time.sleep(.3);assert perf.poll() is None,(d/'perf-control.log').read_text();first=snap(candidate);enabled=ack_command(ctl,ack,'enable');time.sleep(30);disabled=ack_command(ctl,ack,'disable');last=snap(candidate);assert perf.wait(timeout=20)==0,(d/'perf-control.log').read_text();assert client.wait(timeout=20)==0
   finally:
    os.close(ctl);os.close(ack);ctlpath.unlink(missing_ok=True);ackpath.unlink(missing_ok=True)
    for process in [perf,client]:
     if process.poll() is None:process.terminate();process.wait(timeout=10)
  text=(d/'pgbench.txt').read_text();assert 'number of failed transactions: 0' in text,text[-1500:]
  queries=last['count']-first['count'];counter_dt=(last['mid_ns']-first['mid_ns'])/1e9;perf_dt=(disabled['mid_ns']-enabled['mid_ns'])/1e9;stats={}
  for line in (d/'perf-stat.csv').read_text().splitlines():
   if line.startswith('#'):continue
   cols=line.split(';')
   if len(cols)>=3 and cols[2].strip() in events+exits:
    value=cols[0].strip();assert value.isdigit(),line;stats[cols[2].strip()]=int(value)
  assert len(stats)==len(events)+len(exits),(len(stats),len(events),len(exits));assert stats['raw_syscalls:sys_enter']>0
  boundary_slack_ns=max(0,enabled['after_ns']-first['before_ns'])+max(0,last['after_ns']-disabled['before_ns'])
  result=dict(candidate=candidate,queries=queries,query_counter_seconds=counter_dt,perf_enabled_seconds=perf_dt,boundary_slack_ms=boundary_slack_ns/1e6,boundary_slack_pct=boundary_slack_ns/1e9/perf_dt*100,query_counter_first=first,query_counter_last=last,enable=enabled,disable=disabled,counts=stats,calls_per_query={k:v/queries for k,v in stats.items()})
  (d/'summary.json').write_text(json.dumps(result,indent=2));rows.append(result);(out/'summary.json').write_text(json.dumps(rows,indent=2));print(json.dumps({k:result[k] for k in ['candidate','queries','perf_enabled_seconds','boundary_slack_ms','boundary_slack_pct','calls_per_query']}),flush=True)
finally:
 bcfg.write_bytes(original);os.kill(bpid,signal.SIGHUP);time.sleep(.3);assert bcfg.read_bytes()==original;backup.unlink(missing_ok=True);start('restore');print('Restored original PgBouncer config and clean inline-handoff TLS runtime.',flush=True)
print('DONE '+str(out),flush=True)
