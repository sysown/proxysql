from pathlib import Path
import subprocess,time,json,signal,fcntl
r=Path.home()/'pg-network-bench';guard=(r/'tls-forwarding-series.lock').open('a');fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
series=r/'results'/('tls-forwarding-series-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));series.mkdir();print('SERIES '+str(series),flush=True)
plan=[('previous','select1'),('latest','select1'),('pgbouncer','select1'),('latest','4kb'),('previous','4kb'),('pgbouncer','4kb')]
(series/'plan.json').write_text(json.dumps(dict(order=plan,clients=1,jobs=1,backend_cap=10,tls_both_hops=True,warmup_seconds=20,measure_seconds=60,profiling=False),indent=2)+'\n')
runs=[];p=None
(series/'runs.json').write_text('[]\n')
def interrupt(signum,frame):
 if p is not None and p.poll() is None:p.terminate()
 raise KeyboardInterrupt
signal.signal(signal.SIGTERM,interrupt);signal.signal(signal.SIGINT,interrupt)
try:
 for proxy,workload in plan:
  script='benchmark-tls-forwarding-pgbouncer.py' if proxy=='pgbouncer' else 'benchmark-tls-forwarding-proxysql.py'
  args=[workload] if proxy=='pgbouncer' else [proxy,workload]
  command=['python3','-u',script]+args;print('RUN '+proxy+' '+workload,flush=True)
  p=subprocess.Popen(command,cwd=r,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  directory=None
  for line in p.stdout:
   print(line,end='',flush=True)
   if line.startswith('DONE '):directory=line[5:].strip()
  rc=p.wait();assert rc==0 and directory,(proxy,workload,rc,directory)
  d=Path(directory);summary=json.loads((d/'summary.json').read_text());assert json.loads((d/'cleanup.json').read_text())['isolated_instance_stopped']
  runs.append(dict(proxy=proxy,workload=workload,directory=directory,summary=summary,command=command))
  (series/'runs.json').write_text(json.dumps(runs,indent=2)+'\n');p=None
 assert len(runs)==6
 (series/'finished.json').write_text(json.dumps(dict(cases_completed=6,complete=True),indent=2)+'\n');print('DONE SERIES '+str(series),flush=True)
finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=30)
