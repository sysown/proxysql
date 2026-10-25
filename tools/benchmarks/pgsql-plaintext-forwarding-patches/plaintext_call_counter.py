from pathlib import Path
import os,subprocess,time,json,signal
class Profiler:
 def __init__(self,out,pid,kind):
  self.out,self.pid,self.proc=out,pid,None
  threads=[]
  for p in Path(f'/proc/{pid}/task').iterdir():
   s=(p/'stat').read_text().rsplit(')',1)[1].split();threads.append((int(s[11])+int(s[12]),int(p.name)))
  self.worker=max(threads)[1]
  binary=Path(os.readlink(f'/proc/{pid}/exe'));(out/'maps.txt').write_text(Path(f'/proc/{pid}/maps').read_text())
  symbols=[line.split()[-1] for line in subprocess.check_output(['nm','--defined-only',str(binary)],text=True).splitlines() if len(line.split())==3 and line.split()[1] in ['T','t','W','w']]
  def sym(fragment):
   found=[s for s in symbols if fragment in s and ('PgSQL' in s or fragment=='PartialMatchNE') and '.cold' not in s and '.localalias' not in s];assert len(found)==1,(fragment,found);return found[0]
  names={1:sym('PgSQL_Session7handlerE'),2:sym('8writeoutEv'),3:sym('set_polloutEv'),4:sym('add_native_backend_message'),5:sym('PartialMatchNE')}
  if any('add_native_data_rows' in s for s in symbols):names[6]=sym('add_native_data_rows')
  pred=f'tid == {self.worker} && @enabled'
  controller=os.getpid()
  code=[f'BEGIN {{ printf("READY\\n"); }}',f'tracepoint:syscalls:sys_enter_kill /pid == {controller} && args->pid == {pid} && args->sig == 0/ {{ @enabled = !@enabled; @gates = count(); if (@enabled) {{ @start = nsecs; }} else {{ @end = nsecs; }} }}']
  for key,s in names.items():
   extra=' $caller = *(uint64*)uptr(reg("sp")); @handler[$caller, arg1 & 255] = count();' if key==1 else ''
   if key==6:extra+=' @row_count = sum(arg3); @row_bytes = sum(arg2);'
   code.append(f'uprobe:{binary}:{s} /{pred}/ {{ @calls[{key}] = count();{extra} }}')
  for n in ['poll','recvfrom','sendto','connect']:
   code.append(f'tracepoint:syscalls:sys_enter_{n} /{pred}/ {{ @syscalls[probe] = count(); }}')
  code.append('END { clear(@enabled); }')
  (out/'counter.bt').write_text('\n'.join(code)+'\n');(out/'symbols.json').write_text(json.dumps(names,indent=2))
  self.stdout=(out/'bpftrace.jsonl').open('w');self.stderr=(out/'bpftrace.stderr').open('w')
  cmd=['sudo','-n','taskset','-c','18','bpftrace','-f','json',str(out/'counter.bt')]
  (out/'profile-command.json').write_text(json.dumps(cmd,indent=2));self.proc=subprocess.Popen(cmd,stdout=self.stdout,stderr=self.stderr,start_new_session=True)
  deadline=time.monotonic()+60
  while 'READY' not in (out/'bpftrace.jsonl').read_text():
   assert self.proc.poll() is None,(out/'bpftrace.stderr').read_text();assert time.monotonic()<deadline;time.sleep(.25)
 def snapshot(self,snap):
  a=time.monotonic_ns();s=snap();s.update(before_ns=a,after_ns=time.monotonic_ns());return s
 def begin(self,snap):
  self.first=self.snapshot(snap);a=time.monotonic_ns();os.kill(self.pid,0);self.enable=dict(before_ns=a,after_ns=time.monotonic_ns());print('Counter gate enabled.',flush=True)
 def end(self,snap):
  a=time.monotonic_ns();os.kill(self.pid,0);self.disable=dict(before_ns=a,after_ns=time.monotonic_ns());self.last=self.snapshot(snap)
 def finish(self):
  subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=True);assert self.proc.wait(timeout=30)==0,(self.out/'bpftrace.stderr').read_text()
  self.stdout.close();self.stderr.close();maps={}
  for line in (self.out/'bpftrace.jsonl').read_text().splitlines():
   if line.strip():
    e=json.loads(line)
    if e['type']=='map':maps.update(e['data'])
  assert maps['@gates']==2,maps
  q=int(self.last['Queries'])-int(self.first['Queries']);sec=(maps['@end']-maps['@start'])/1e9
  slack=(self.enable['after_ns']-self.first['before_ns']+self.last['after_ns']-self.disable['before_ns'])/1e9
  result=dict(queries=q,seconds=sec,boundary_slack_pct=slack/sec*100,start=self.first,end=self.last,enable=self.enable,disable=self.disable,maps=maps)
  for key in ['@calls','@handler','@syscalls']:result[key[1:]+'_per_query']={k:v/q for k,v in maps.get(key,{}).items()}
  (self.out/'call-summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['calls_per_query']),flush=True)
 def cleanup(self):
  if self.proc is not None and self.proc.poll() is None:
   subprocess.run(['sudo','-n','kill','-INT','--','-'+str(self.proc.pid)],check=False);self.proc.wait(timeout=30)
