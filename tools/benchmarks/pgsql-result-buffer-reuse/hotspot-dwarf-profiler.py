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
  if kind=='syscalls':
   available=set(subprocess.check_output(['sudo','-n','perf','list','--raw-dump'],text=True).split())
   self.events=['raw_syscalls:sys_enter']+sorted(x for x in available if x.startswith('syscalls:sys_enter_'))
   self.exits=[f'syscalls:sys_exit_{x}' for x in ['read','write','readv','writev','recvfrom','sendto','recvmsg','sendmsg'] if f'syscalls:sys_exit_{x}' in available]
   command=base+['stat','-D','-1',control,'-x',';','--no-big-num','-o',str(out/'perf-stat.csv'),'-p',str(pid)]
   for event in self.events:command+=['-e',event]
   for event in self.exits:command+=['-e',event,'--filter','ret == -11']
   command+=['--','sleep','58']
   (out/'events.json').write_text(json.dumps(dict(entries=self.events,eagain_exits=self.exits,scope='all current proxy-process threads'),indent=2))
  else:
   command=base+['record','-D','-1',control,'-e','cycles/period=1000003/u','--call-graph','dwarf,8192','-t',str(self.worker),'-o',str(out/'perf.data'),'--','sleep','58']
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
  fn='perf-stat.csv' if self.kind=='syscalls' else 'perf.data'
  subprocess.run(['sudo','-n','chown',f'{os.getuid()}:{os.getgid()}',str(self.out/fn)],check=True)
  if self.kind=='syscalls':
   counts={};running={}
   for line in (self.out/fn).read_text().splitlines():
    cols=line.split(';')
    if len(cols)<5 or cols[2].strip() not in self.events+self.exits:continue
    event=cols[2].strip();assert cols[0].strip().isdigit(),line
    counts[event]=int(cols[0]);running[event]=float(cols[4]);assert running[event]>=99.99,line
   assert len(counts)==len(self.events)+len(self.exits),(len(counts),len(self.events),len(self.exits))
   queries=self.window['queries'];total=counts['raw_syscalls:sys_enter'];named=sum(counts[x] for x in self.events if x!='raw_syscalls:sys_enter')
   result=dict(**self.window,counts=counts,calls_per_query={k:v/queries for k,v in counts.items()},raw_total=total,named_total=named,raw_minus_named=total-named,running_pct_min=min(running.values()))
   (self.out/'syscall-summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(dict(profile='syscalls',queries=queries,total_syscalls=total,syscalls_per_query=total/queries,boundary_slack_pct=self.window['boundary_slack_pct'],raw_minus_named=total-named)),flush=True)
  self.cleanup()
 def cleanup(self):
  if self.proc is not None and self.proc.poll() is None:
   subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=False);self.proc.wait(timeout=15)
  if self.log is not None:self.log.close();self.log=None
  for fd in self.fds:os.close(fd)
  self.fds=[];self.ctlpath.unlink(missing_ok=True);self.ackpath.unlink(missing_ok=True)
