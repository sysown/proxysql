from pathlib import Path
import os,subprocess,time,json,select,signal
class Profiler:
 def __init__(self,out,pid,kind):
  self.out=out;self.pid=pid;self.kind=kind;self.proc=None;self.fds=[];self.log=None
  self.ctlpath=out/'perf-control';self.ackpath=out/'perf-ack'
  for path in [self.ctlpath,self.ackpath]:os.mkfifo(path,0o600)
  self.ctl=os.open(self.ctlpath,os.O_RDWR|os.O_NONBLOCK);self.ack=os.open(self.ackpath,os.O_RDWR|os.O_NONBLOCK);self.fds=[self.ctl,self.ack]
  control=f'--control=fifo:{self.ctlpath},{self.ackpath}'
  threads=[]
  for p in Path(f'/proc/{pid}/task').iterdir():
   st=(p/'stat').read_text().rsplit(')',1)[1].split();threads.append(dict(tid=int(p.name),ticks=int(st[11])+int(st[12]),comm=(p/'comm').read_text().strip()))
  self.worker=max(threads,key=lambda x:x['ticks'])['tid']
  (out/'threads.json').write_text(json.dumps(dict(worker=self.worker,threads=threads),indent=2))
  base=['sudo','-n','taskset','-c','18','prlimit','--nofile=65536:65536','perf']
  self.events=['cycles:u','instructions:u','branch-misses:u','L1-icache-load-misses:u']
  command=base+['stat','-D','-1',control,'-x',';','--no-big-num','-o',str(out/'perf-stat.csv'),'-t',str(self.worker)]
  for event in self.events:command+=['-e',event]
  command+=['--','sleep','58']
  (out/'profile-command.json').write_text(json.dumps(command,indent=2))
  self.log=(out/'perf-control.log').open('w');self.proc=subprocess.Popen(command,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  time.sleep(.5);assert self.proc.poll() is None,(out/'perf-control.log').read_text()
 def command(self,name):
  before=time.monotonic_ns();os.write(self.ctl,(name+'\n').encode());buf=b'';deadline=time.monotonic()+5
  while b'\n' not in buf:
   remaining=deadline-time.monotonic();assert remaining>0,('control timeout',name)
   if select.select([self.ack],[],[],remaining)[0]:buf+=os.read(self.ack,4096)
  assert b'ack' in buf;after=time.monotonic_ns();return dict(before_ns=before,after_ns=after,mid_ns=(before+after)//2)
 def snapshot(self,snap):
  a=time.monotonic_ns();s=snap();b=time.monotonic_ns();s.update(before_ns=a,after_ns=b,mid_ns=(a+b)//2)
  st=Path(f'/proc/{self.pid}/task/{self.worker}/stat').read_text().rsplit(')',1)[1].split();s.update(worker_user_ticks=int(st[11]),worker_system_ticks=int(st[12]));return s
 def begin(self,snap):
  self.first=self.snapshot(snap);self.enabled=self.command('enable');print(self.kind+': profiling enabled for 40 seconds.',flush=True)
 def end(self,snap):
  self.disabled=self.command('disable');self.last=self.snapshot(snap)
  queries=int(self.last['Queries'])-int(self.first['Queries'])
  dt=(self.disabled['mid_ns']-self.enabled['mid_ns'])/1e9
  slack=self.enabled['after_ns']-self.first['before_ns']+self.last['after_ns']-self.disabled['before_ns']
  self.window=dict(start=self.first,end=self.last,enable=self.enabled,disable=self.disabled,queries=queries,enabled_seconds=dt,boundary_slack_ms=slack/1e6,boundary_slack_pct=slack/1e9/dt*100)
  (self.out/'profile-window.json').write_text(json.dumps(self.window,indent=2))
 def finish(self):
  assert self.proc.wait(timeout=10)==0,(self.out/'perf-control.log').read_text();self.log.close();self.log=None
  subprocess.run(['sudo','-n','chown',f'{os.getuid()}:{os.getgid()}',str(self.out/'perf-stat.csv')],check=True)
  counts={};running={}
  for line in (self.out/'perf-stat.csv').read_text().splitlines():
   cols=line.split(';')
   if len(cols)<5:continue
   event=cols[2].strip()
   if not event:continue
   assert cols[0].strip().isdigit(),line
   counts[event]=int(cols[0]);running[event]=float(cols[4]);assert running[event]>=99.99,line
  assert len(counts)==4,counts
  q=self.window['queries'];result=dict(**self.window,counts=counts,per_query={k:v/q for k,v in counts.items()},running_pct_min=min(running.values()),user_ipc=counts['instructions:u']/counts['cycles:u'])
  hz=os.sysconf('SC_CLK_TCK');result['worker_user_us_per_query']=(self.last['worker_user_ticks']-self.first['worker_user_ticks'])*1e6/hz/q
  result['observed_user_cycles_per_us']=result['per_query']['cycles:u']/result['worker_user_us_per_query']
  (self.out/'counter-summary.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:result[k] for k in ['per_query','user_ipc','worker_user_us_per_query','observed_user_cycles_per_us']}),flush=True)
  self.cleanup()
 def cleanup(self):
  if self.proc is not None and self.proc.poll() is None:
   subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=False);self.proc.wait(timeout=15)
  if self.log is not None:self.log.close();self.log=None
  for fd in self.fds:os.close(fd)
  self.fds=[];self.ctlpath.unlink(missing_ok=True);self.ackpath.unlink(missing_ok=True)
