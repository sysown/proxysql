from pathlib import Path
import sys,re,json,collections,subprocess
p=Path(sys.argv[1]);maps=[]
for line in (p/'mappings.txt').read_text().splitlines():
 m=re.search(r'\[(0x[0-9a-f]+)\((0x[0-9a-f]+)\) @ (0x[0-9a-f]+|0).*?\]: [rwxps-]+ (.*)$',line)
 if m: maps.append((int(m[1],16),int(m[2],16),int(m[3],16),m[4]))
leaves=[];addresses=collections.defaultdict(set)
for line in (p/'leaves.txt').read_text().splitlines():
 m=re.match(r'(\d+\.\d+): .*?:\s+([0-9a-f]+) (.*?) \((.*)\)$',line)
 if not m:continue
 t,ip,fn,dso=m.groups();ip=int(ip,16)
 mp=next((v for v in maps if v[0]<=ip<v[0]+v[1]),None)
 addr=ip-mp[0]+mp[2] if mp else ip
 leaves.append(dict(time=t,address=addr,function=fn,dso=dso));addresses[dso].add(addr)
stacks={}
for block in (p/'stacks.txt').read_text().strip().split('\n\n'):
 lines=block.splitlines();m=re.match(r'(\d+\.\d+):',lines[0])
 if not m: continue
 frames=[]
 for line in lines[1:]:
  x=re.match(r'\s+([0-9a-f]+) (.*?) \((.*)\)$',line)
  if x:
   ip,fn,dso=x.groups();addr=int(ip,16);frames.append(dict(address=addr,function=fn,dso=dso));addresses[dso].add(addr)
 stacks[m[1]]=frames
lookup={}
for dso,addrs in addresses.items():
 if not Path(dso).exists():continue
 addrs=sorted(addrs);binary='/tmp/pgsql-libc.debug' if dso.endswith('/libc.so.6') else dso
 lines=subprocess.check_output(['addr2line','-e',binary,'-C','-f'],input='\n'.join(hex(a) for a in addrs)+'\n',text=True).splitlines()
 assert len(lines)==2*len(addrs)
 for i,a in enumerate(addrs):lookup[dso,a]=(lines[2*i],lines[2*i+1])
def resolved(f):
 fn,line=lookup.get((f['dso'],f['address']),('??','??:0'))
 # perf's containing symbol is useful for aggregate inline-heavy C++ functions.
 # Resolve all libc leaves because stripped nearest-export names are misleading.
 name=fn if f['dso'].endswith('/libc.so.6') and fn!='??' else f['function']
 return dict(**f,resolved_name=name,inline_function=fn,line=line)
leaves=[resolved(f) for f in leaves];n=len(leaves);assert n
cnt=collections.Counter((f['dso'],f['resolved_name']) for f in leaves)
linecnt=collections.Counter((f['dso'],f['resolved_name'],f['inline_function'],f['line']) for f in leaves)
roots=['pgsql_query_digest_and_first_comment','PgSQL_Query_Result::buffer_to_PSarrayOut','PgSQL_Query_Result::add_native_backend_message','PgSQL_Connection::ProcessQueryAndSetStatusFlags','PgSQL_ExplicitTxnStateMgr::handle_transaction','PgSQL_TxnCmdParser::parse','query_parser_update_counters','PgSQL_HostGroups_Manager::get_MyConn_from_pool','PgSQL_Thread::get_MyConn_local','pgsql_loop_timing_point','PgSQL_Logger::flush','legacy_command_type']
paths={}
for root in roots:
 selected=[]
 for f in leaves:
  frames=stacks.get(f['time'],[])
  if root in f['function'] or any(root in x['function'] for x in frames):selected.append(f)
 paths[root]=dict(samples=len(selected),percent=100*len(selected)/n,leaves=[dict(function=k,samples=v) for k,v in collections.Counter(x['resolved_name'] for x in selected).most_common(20)])
def allocation(f):
 name=f['resolved_name'].split('@')[0]
 return name.startswith('je_') or name in ['malloc','free','realloc','calloc','posix_memalign','aligned_alloc','malloc_usable_size']
alloc=[f for f in leaves if allocation(f)]
result=dict(samples=n,allocation_self_samples=len(alloc),allocation_self_percent=100*len(alloc)/n,functions=[dict(dso=k[0],function=k[1],samples=v,percent=100*v/n) for k,v in cnt.most_common()],paths=paths,lines=[dict(dso=k[0],function=k[1],inline_function=k[2],line=k[3],samples=v,percent=100*v/n) for k,v in linecnt.most_common()])
(p/'hotspots.json').write_text(json.dumps(result,indent=2))
print('samples',n,'allocator self',result['allocation_self_percent'])
for x in result['functions'][:35]:print(round(x['percent'],3),x['function'])
for k,v in paths.items():print('PATH',k,round(v['percent'],3),v['leaves'][:5])
