from pathlib import Path
import os,subprocess,time,json,signal
class Tracer:
 def __init__(self,out,pid,port):
  self.out=out;self.proc=None;self.log=None
  command=['sudo','-n','python3',str(Path(__file__).with_name('read-socket-options.py')),str(pid),str(port)]
  check=subprocess.run(command,text=True,capture_output=True)
  (out/'socket-options.json').write_text(check.stdout)
  assert check.returncode==0,check.stderr
  threads=[]
  for p in Path(f'/proc/{pid}/task').iterdir():
   st=(p/'stat').read_text().rsplit(')',1)[1].split();threads.append(dict(tid=int(p.name),ticks=int(st[11])+int(st[12]),comm=(p/'comm').read_text().strip()))
  worker=max(threads,key=lambda x:x['ticks']);(out/'threads.json').write_text(json.dumps(dict(selected=worker,threads=threads),indent=2))
  events=[f'syscalls:sys_{side}_{name}' for name in ['recvfrom','sendto','poll','epoll_wait'] for side in ['enter','exit']]
  command=['sudo','-n','taskset','-c','18','perf','record','-m','512','-t',str(worker['tid']),'-o',str(out/'forwarding.data')]
  for e in events:command+=['-e',e]
  command+=['--','sleep','5']
  (out/'trace-command.json').write_text(json.dumps(command,indent=2));self.log=(out/'trace.log').open('w');self.proc=subprocess.Popen(command,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  print('TCP_NODELAY=1 and TCP_CORK=0 verified on frontend and all 64 backends; capturing five-second forwarding trace.',flush=True)
 def finish(self):
  assert self.proc.wait(timeout=10)==0;self.log.close();self.log=None
  subprocess.run(['sudo','-n','chown',f'{os.getuid()}:{os.getgid()}',str(self.out/'forwarding.data')],check=True)
  with (self.out/'trace.txt').open('w') as f, (self.out/'trace-errors.txt').open('w') as err:
   subprocess.run(['sudo','-n','perf','script','-f','--ns','-i',str(self.out/'forwarding.data'),'-F','trace:time,event,trace'],stdout=f,stderr=err,check=True)
  with (self.out/'trace-header.txt').open('w') as f:subprocess.run(['sudo','-n','perf','report','-f','-i',str(self.out/'forwarding.data'),'--stdio','--header-only'],stdout=f,check=True)
 def cleanup(self):
  if self.proc is not None and self.proc.poll() is None:
   subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=False);self.proc.wait(timeout=15)
  if self.log is not None:self.log.close();self.log=None
