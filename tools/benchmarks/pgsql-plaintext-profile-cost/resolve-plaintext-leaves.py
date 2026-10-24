from pathlib import Path
import subprocess,re,json,sys,collections
p=Path(sys.argv[1]);data=[];binary=None
for block in (p/'stacks.txt').read_text().strip().split('\n\n'):
 lines=block.splitlines()
 if len(lines)<2:continue
 m=re.match(r'[\d.]+:\s+(\d+)',lines[0]);f=re.match(r'\s*([a-f0-9]+) (.*?) \((.*)\)$',lines[1])
 if not m or not f:continue
 if not f[3].endswith('proxysql-head-tls-handshake-cache'):continue
 binary=f[3];data.append((f[1],f[2],int(m[1])))
assert binary
addrs=sorted({x[0] for x in data})
lines=subprocess.check_output(['addr2line','-C','-f','-e',binary],input='\n'.join(addrs)+'\n',text=True).splitlines();assert len(lines)==2*len(addrs)
lookup={a:(lines[2*i],lines[2*i+1]) for i,a in enumerate(addrs)};cnt=collections.Counter();samples=collections.Counter()
for a,fn,weight in data:
 key=(fn,*lookup[a]);cnt[key]+=weight;samples[key]+=1
result=[dict(symbol=k[0],source_function=k[1],source_line=k[2],period=v,samples=samples[k]) for k,v in cnt.most_common()]
(p/'leaf-source-lines.json').write_text(json.dumps(result,indent=2)+'\n')
for x in result[:25]:print(x)
