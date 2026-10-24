from pathlib import Path
import re,json,sys,collections
p=Path(sys.argv[1]); blocks=[]
for block in (p/'stacks.txt').read_text().strip().split('\n\n'):
 if not block.strip():continue
 lines=block.splitlines();m=re.match(r'([\d.]+):\s+(\d+)',lines[0])
 if not m:continue
 frames=[]
 for line in lines[1:]:
  f=re.match(r'\s*([a-f0-9]+) (.*?) \((.*)\)$',line)
  if f:frames.append(dict(ip=f[1],name=f[2],dso=f[3]))
 if frames:blocks.append(dict(time=float(m[1]),period=int(m[2]),frames=frames))
assert blocks
libc=json.loads((p/'libc-leaf-symbols.json').read_text()) if (p/'libc-leaf-symbols.json').exists() else None
if libc:
 for x in blocks:
  f=x['frames'][0]
  if f['dso']==libc['library'] and f['ip'] in libc['symbols']:
   resolved=libc['symbols'][f['ip']]['function']
   if resolved!='??':f['name']=resolved
period=sum(x['period'] for x in blocks)
users=[x for x in blocks if not x['frames'][0]['dso'].startswith('[') or x['frames'][0]['dso']=='[vdso]']
up=sum(x['period'] for x in users)
w=json.loads((p/'profile-window.json').read_text());q=w['queries'];u=(w['end']['worker_user_ticks']-w['start']['worker_user_ticks'])*10000/q;k=(w['end']['worker_system_ticks']-w['start']['worker_system_ticks'])*10000/q
roots={
'scheduler':['PgSQL_Thread::run','PgSQL_Thread::process_all_sessions'],
'handler':['PgSQL_Session::handler'],
'COPY_regex':['re2::','PgSQL_Connection::'],
'native_results':['PgSQL_Connection::native_fetch_result_cont'],
'native_message_copy':['PgSQL_Query_Result::add_native_backend_message'],
'pool_checkout':['PgSQL_Thread::get_MyConn_local','PgSQL_HostGroups_Manager::get_MyConn_from_pool'],
'pool_return':['PgSQL_Thread::push_MyConn_local','PgSQL_HostGroups_Manager::push_MyConn_to_pool','PgSQL_HostGroups_Manager::push_MyConn_to_pool_array','PgSQL_Thread::return_local_connections'],
'backend_variable_match':['PgSQL_Connection::number_of_matching_session_variables','PgSQL_Session::handler_again___verify_backend_user_db','PgSQL_Variables::'],
'query_processing':['Query_Processor<PgSQL_Query_Processor>::process_query'],
'writeout':['Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::writeout'],
'logger_checks':['PgSQL_Logger::is_events_logfile_open','PgSQL_Logger::flush'],
'buffer_handoff':['PgSQL_Query_Result::buffer_to_PSarrayOut'],
}
# Each category is inclusive within userspace samples. Categories overlap.
paths={}
for label,fragments in roots.items():
 if label=='COPY_regex':fragments=['re2::']
 selected=[x for x in users if any(any(frag in f['name'] for frag in fragments) for f in x['frames'])]
 weight=sum(x['period'] for x in selected)
 leaves=collections.Counter()
 for x in selected:leaves[x['frames'][0]['name']]+=x['period']
 paths[label]=dict(samples=len(selected),user_cycles_pct=100*weight/up,estimated_user_us_per_query=u*weight/up,leaves=leaves.most_common(12))
callers={}
for label,fragments in {'mutex':['pthread_mutex_lock','pthread_mutex_unlock'],'allocator':['malloc','free','realloc','calloc'],'clock':['clock_gettime'],'regex':['re2::']}.items():
 c=collections.Counter()
 for x in users:
  fs=x['frames'];name=fs[0]['name']
  hit=any(f in name for f in fragments) if label not in ['allocator'] else name in fragments
  if hit:c[' -> '.join(f['name'] for f in fs[:5])]+=x['period']
 callers[label]=[dict(stack=key,user_cycles_pct=100*v/up,estimated_user_us_per_query=u*v/up) for key,v in c.most_common(20)]
leaf=collections.Counter()
for x in users:leaf[x['frames'][0]['name']]+=x['period']
result=dict(samples=len(blocks),user_samples=len(users),period=period,user_period=up,user_cycle_pct=100*up/period,profile_queries=q,profile_seconds=w['enabled_seconds'],worker_user_us_per_query=u,worker_kernel_us_per_query=k,boundary_slack_pct=w['boundary_slack_pct'],paths=paths,callers=callers,user_leaves=[dict(function=f,user_cycles_pct=100*v/up,estimated_user_us_per_query=u*v/up) for f,v in leaf.most_common(70)],first_perf_time=blocks[0]['time'],last_perf_time=blocks[-1]['time'])
(p/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ['samples','user_samples','worker_user_us_per_query','worker_kernel_us_per_query','user_cycle_pct']},indent=2))
for k,v in paths.items():print(k,round(v['user_cycles_pct'],2),round(v['estimated_user_us_per_query'],3))
for k in ['mutex','regex']:print(k,json.dumps(callers[k][:5],indent=2))
