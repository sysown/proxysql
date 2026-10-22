from pathlib import Path
from collections import Counter,defaultdict
import sys,json,re,statistics,gzip,hashlib
p=Path(sys.argv[1]);options=json.loads((p/'socket-options.json').read_text());roles={x['fd']:x['role'] for x in options['sockets']}
assert not options['errors'];assert all(x['tcp_nodelay']==1 and x['tcp_cork']==0 for x in options['sockets'])
assert not (p/'trace-errors.txt').read_text().strip(),(p/'trace-errors.txt').read_text()
rx=re.compile(r'^\s*(\d+)\.(\d+):\s+syscalls:sys_(enter|exit)_(\w+):\s*(.*)$')
pending={};io=[];wait_exit=None;last_wait=None;events=0;orphan=0;nfds=Counter();returns=Counter();sizes=Counter();first_ts=None;last_ts=None
with (p/'trace.txt').open() as f:
 for line in f:
  if not line.strip():continue
  m=rx.match(line);assert m,line[:200]
  t=int(m[1])*10**9+int(m[2].ljust(9,'0'));side,name,body=m.group(3,4,5);events+=1
  if first_ts is None:first_ts=t
  last_ts=t
  if side=='enter':
   fields={k:int(v,0) for k,v in re.findall(r'(\w+):\s*(0x[0-9a-f]+|-?\d+)',body)}
   pending[name]=dict(start=t,fields=fields,wait_exit=wait_exit)
   if 'nfds' in fields:nfds[fields['nfds']]+=1
  else:
   ret=int(body.strip(),0)
   if ret>=2**63:ret-=2**64
   ent=pending.pop(name,None)
   if name in ['poll','epoll_wait']:
    if ret>0:wait_exit=t
    continue
   if not ent:orphan+=1;continue
   fd=ent['fields']['fd'];role=roles.get(fd)
   if role is None:continue
   returns[(name,ret)]+=1
   if ret<=0:continue
   tag=('f' if role=='frontend' else 'b')+('r' if name=='recvfrom' else 's')
   sizes[(tag,ret)]+=1
   io.append(dict(tag=tag,fd=fd,start=ent['start'],end=t,bytes=ret,wait_exit=ent['wait_exit']))
metrics=defaultdict(list);skipped=Counter();accepted=0;current=[];query_spans=[]
def consume(c):
 global accepted
 if [x['tag'] for x in c]!=['fr','bs','br','fs']:
  skipped['sequence:'+','.join(x['tag'] for x in c)]+=1;return
 fr,bs,br,fs=c
 if bs['fd']!=br['fd']:skipped['backend_fd_mismatch']+=1;return
 if fr['bytes']!=15 or bs['bytes']!=15 or br['bytes']!=66 or fs['bytes']!=66:
  skipped['unexpected_query_or_response_size']+=1;return
 accepted+=1
 def add(k,end,start):
  assert end>=start,(k,end,start)
  metrics[k].append((end-start)/1000)
 add('request_processing',bs['start'],fr['end'])
 add('request_send_syscall',bs['end'],bs['start'])
 add('request_forward_complete',bs['end'],fr['end'])
 add('response_processing',fs['start'],br['end'])
 add('response_send_syscall',fs['end'],fs['start'])
 add('response_forward_complete',fs['end'],br['end'])
 add('backend_roundtrip_including_proxy_wait',br['end'],bs['end'])
 add('proxy_received_query_to_response_sent',fs['end'],fr['end'])
 for label,item in [('frontend',fr),('backend',br)]:
  if item['wait_exit'] is not None:
   add(label+'_wait_return_to_recv_complete',item['end'],item['wait_exit'])
 query_spans.append((fr['start'],fs['end']))
for item in io:
 if item['tag']=='fr':
  if current:consume(current)
  current=[item]
 elif current:current.append(item)
# Drop the last query, because the trace may end during a split response.
if current:skipped['last_trace_boundary_query']+=1
assert accepted>1000,(accepted,skipped)
def summary(xs):
 s=sorted(xs)
 def pct(p):
  at=(len(s)-1)*p;lo=int(at);hi=min(lo+1,len(s)-1);return s[lo]+(s[hi]-s[lo])*(at-lo)
 return dict(n=len(s),mean_us=statistics.mean(s),p50_us=pct(.5),p95_us=pct(.95),p99_us=pct(.99),min_us=s[0],max_us=s[-1])
result=dict(accepted_queries=accepted,trace_seconds=(last_ts-first_ts)/1e9,trace_events=events,orphan_exit_at_boundary=orphan,skipped=dict(skipped),metrics={k:summary(v) for k,v in metrics.items()},io_sizes={f'{k[0]}:{k[1]}':v for k,v in sizes.items()},nonpositive_returns={f'{k[0]}:{k[1]}':v for k,v in returns.items() if k[1]<=0},poll_nfds=dict(nfds),matched_trace_tps=(accepted-1)/((query_spans[-1][0]-query_spans[0][0])/1e9))
(p/'forwarding-summary.json').write_text(json.dumps(result,indent=2)+'\n')
(p/'raw-artifact.json').write_text(json.dumps(dict(path=str(p/'forwarding.data'),bytes=(p/'forwarding.data').stat().st_size,sha256=hashlib.sha256((p/'forwarding.data').read_bytes()).hexdigest()),indent=2)+'\n')
print(json.dumps(result,indent=2))
