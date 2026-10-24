from pathlib import Path
import json,re,subprocess,sys
p=Path(sys.argv[1]);library='/usr/lib/x86_64-linux-gnu/libc.so.6';debug='/tmp/pgsql-libc.debug'
def buildid(path):return re.search(r'Build ID: (\w+)',subprocess.check_output(['readelf','-n',path],text=True,stderr=subprocess.DEVNULL))[1]
assert buildid(library)==buildid(debug)
addrs=set()
for block in (p/'stacks.txt').read_text().strip().split('\n\n'):
 ls=block.splitlines()
 if len(ls)<2:continue
 m=re.match(r'\s*([a-f0-9]+) (.*?) \((.*)\)$',ls[1])
 if m and m[3]==library:addrs.add(m[1])
addrs=sorted(addrs);lines=subprocess.check_output(['addr2line','-C','-f','-e',debug],input='\n'.join(addrs)+'\n',text=True).splitlines();assert len(lines)==len(addrs)*2
result=dict(build_id=buildid(library),library=library,debug_file=debug,symbols={a:dict(function=lines[2*i],line=lines[2*i+1]) for i,a in enumerate(addrs)})
(p/'libc-leaf-symbols.json').write_text(json.dumps(result,indent=2)+'\n')
