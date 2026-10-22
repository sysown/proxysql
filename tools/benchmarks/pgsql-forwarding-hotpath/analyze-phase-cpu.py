from pathlib import Path
import re,sys,json,collections
p=Path(sys.argv[1]);sockets=json.loads((p/'socket-options.json').read_text())['sockets'];roles={x['fd']:x['role'] for x in sockets}
pat=re.compile(r'^\s*(\d+)\.(\d+):\s+([^:]+):\s*(.*)$')
syscall=re.compile(r'^\s*(\d+)\.(\d+):\s+syscalls:(\w+):\s*(.*)$')
hw=re.compile(r'^\s*(\d+)\.(\d+):\s+cycles/period=200003/u(?:pp)?:\s+([0-9a-f]+)\s+(.*?)\s+\((.*)\)$')
counts=collections.defaultdict(collections.Counter);ips=collections.defaultdict(collections.Counter);dur=collections.defaultdict(list);phase='other';fd=None;start=None;pending=[];q=0;unparsed=[]
def ns(m):return int(m[1])*1000000000+int(m[2].ljust(9,'0'))
for line in (p/'trace.txt').open():
 m=syscall.match(line)
 if m:
  t=ns(m);ev=m[3];body=m[4]
  if ev=='sys_enter_recvfrom':
   fd=int(re.search(r'fd: (0x[0-9a-f]+)',body)[1],16)
  elif ev=='sys_exit_recvfrom':
   ret=int(body,16)
   if 0<ret<2**63:
    assert phase=='other',(phase,line)
    assert fd in roles,fd
    phase='request' if roles[fd]=='frontend' else 'response';start=t;pending=[]
  elif ev=='sys_enter_sendto':
   sendfd=int(re.search(r'fd: (0x[0-9a-f]+)',body)[1],16)
   if phase!='other':
    assert roles[sendfd]==('backend' if phase=='request' else 'frontend'),(phase,line)
    dur[phase].append((t-start)/1000)
    for ip,sym,dso in pending:counts[phase][(sym,dso)]+=1;ips[phase][ip]+=1
    if phase=='response':q+=1
   phase='other';start=None;pending=[]
  continue
 m=hw.match(line)
 if m:
  ip=m[3];sym=m[4];dso=m[5]
  if phase=='other':counts[phase][(sym,dso)]+=1;ips[phase][ip]+=1
  else:pending.append((ip,sym,dso))
  continue
 if line.strip():unparsed.append(line)
assert not unparsed,unparsed[:10]
summary={'complete_responses':q,'samples':sum(map(lambda x:sum(x.values()),counts.values())),'phases':{}}
for phase in ['request','response','other']:
 c=counts[phase];total=sum(c.values());ds=sorted(dur[phase]);rows=[dict(symbol=k[0],dso=k[1],samples=v,percent=100*v/total) for k,v in c.most_common()]
 summary['phases'][phase]=dict(samples=total,percent_all_samples=100*total/summary['samples'],rows=rows,mean_us=sum(ds)/len(ds) if ds else None,median_us=ds[len(ds)//2] if ds else None)
 print('\n',phase,total,'samples',summary['phases'][phase]['mean_us'],'us')
 for row in rows[:30]:print(f"{row['percent']:6.2f}% {row['samples']:6} {row['symbol']}")
(p/'phase-summary.json').write_text(json.dumps(summary,indent=2));(p/'phase-ips.json').write_text(json.dumps({k:dict(v) for k,v in ips.items()},indent=2))
