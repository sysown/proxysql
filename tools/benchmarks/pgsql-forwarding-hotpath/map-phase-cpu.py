import json,re,sys,subprocess,collections
from pathlib import Path
p=Path(sys.argv[1]);maps=[]
for l in (p/'mappings.txt').read_text().splitlines():
 m=re.search(r'\[(0x[0-9a-f]+)\((0x[0-9a-f]+)\) @ (0x[0-9a-f]+|0).*?\]: [rwxps-]+ (.*)$',l)
 if m:maps.append((int(m[1],16),int(m[2],16),int(m[3],16),m[4]))
phases=json.loads((p/'phase-ips.json').read_text());bydso=collections.defaultdict(set);ipinfo={}
for phase,ips in phases.items():
 for ip in ips:
  a=int(ip,16);mp=next((m for m in maps if m[0]<=a<m[0]+m[1]),None)
  if mp and Path(mp[3]).exists():
   a=a-mp[0]+mp[2];bydso[mp[3]].add(a);ipinfo[ip]=(mp[3],a)
lookup={}
for dso,addrs in bydso.items():
 addrs=sorted(addrs);a=subprocess.check_output(['addr2line','-e',('/tmp/pgsql-libc.debug' if dso.endswith('/libc.so.6') else dso),'-C','-f'],input='\n'.join(hex(x) for x in addrs)+'\n',text=True).splitlines()
 for i,addr in enumerate(addrs):lookup[(dso,addr)]={'function':a[i*2],'line':a[i*2+1]}
output={}
for phase,ips in phases.items():
 cnt=collections.Counter();unknown=collections.Counter()
 for ip,n in ips.items():
  if ip not in ipinfo:continue
  dso,a=ipinfo[ip];l=lookup[(dso,a)];cnt[(dso,l['function'],l['line'])]+=n
  if l['function']=='??':unknown[(dso,hex(a))]+=n
 output[phase]={'lines':[dict(dso=k[0],function=k[1],line=k[2],samples=v) for k,v in cnt.most_common()], 'unknown_ips':[dict(dso=k[0],ip=k[1],samples=v) for k,v in unknown.most_common()]}
 print('\n',phase)
 for k,n in cnt.most_common(35):print(n,k)
(p/'phase-lines.json').write_text(json.dumps(output,indent=2))
