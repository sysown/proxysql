#!/usr/bin/env python3
import sys,os,json,re,csv,subprocess,configparser,importlib.util,resource,time
from pathlib import Path
sys.dont_write_bytecode=True
base=Path('/tmp/tcp-sysbench-benchmark')
spec=importlib.util.spec_from_file_location('setup_helpers',base/'sysbench_benchmark.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.HOST_BINARY=Path('/mnt/data/rene/proxysql7/proxysql/src/proxysql')
m.PLUGIN_BINARY=Path('/mnt/data/rene/proxysql7/proxysql/plugins/tcp_proxy/proxysql_tcp_proxy.so')
built_version=subprocess.check_output([str(m.HOST_BINARY),'--version'],text=True).strip()
assert 'version 4.' in built_version,built_version
print('REBUILT BINARY',built_version,flush=True)
out=base/('basic-v4-'+time.strftime('%Y%m%d-%H%M%S'));out.mkdir()
old=base/'runs/preflight2-20261113-131941-695885/mysql'
credentials=configparser.ConfigParser();credentials.read(old/'client.cnf')
db=m.BenchMysql(old,m.MYSQL_BINARY,m.MYSQLD_BINARY)
db.password=credentials['client']['password'];db.port=m.ffb.free_port()
db.socket_path=out/'mysql.sock';db.pid_path=out/'mysql.pid';db.log_path=out/'mysql.log';db.root_cnf=out/'root.cnf'
m.write_private(db.root_cnf,f'[client]\nuser=root\nprotocol=SOCKET\nsocket={db.socket_path}\n')
os.sched_setaffinity(0,{14,15})
proxy=hap=None;rows=[]
fields=['workload','connections','mode','ok','tps','qps','p95_ms','events','queries','elapsed_s','errors','reconnects','log']
csvfile=(out/'results.csv').open('w',newline='');writer=csv.DictWriter(csvfile,fieldnames=fields);writer.writeheader();csvfile.flush()
print('OUTPUT',out,flush=True)
try:
 args=[str(m.MYSQLD_BINARY),'--no-defaults',f'--datadir={db.datadir}',f'--socket={db.socket_path}',f'--pid-file={db.pid_path}',f'--log-error={db.log_path}',f'--port={db.port}','--bind-address=127.0.0.1','--max-connections=4096','--max-prepared-stmt-count=262144','--open-files-limit=65536','--thread-cache-size=1024','--innodb-buffer-pool-size=2G','--skip-log-bin','--skip-name-resolve','--skip-ssl','--protocol-compression-algorithms=uncompressed','--mysqlx=0']
 with db.log_path.open('ab') as log:db.proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,preexec_fn=m.child_setup(m.CPU_GROUPS['db']))
 db._wait_ready()
 print('MYSQL READY',db.port,db.root_value('SELECT @@version,@@have_ssl,@@max_connections,@@max_prepared_stmt_count'),flush=True)
 proxy=m.BenchProxy(m.HOST_BINARY,m.PLUGIN_BINARY,'mysql',m.MYSQL_BINARY,out,'proxy',mode='ff');proxy.start(db);proxy.fixture_port=db.port;cap=proxy.apply_capacity(True)
 assert cap['ok'],cap['errors']
 hap=m.HAProxy(out/'haproxy',db.port);hap.start()
 ports={'direct':db.port,'native':proxy.tcp_port,'ff':proxy.sql_port,'haproxy':hap.port}
 configs={mode:m.sysbench_config(db,out/f'{mode}.cnf',port) for mode,port in ports.items()}
 env=dict(os.environ,LC_ALL='C')
 prewarm=[str(m.SYSBENCH_BINARY),f"--config-file={configs['direct']}",'--threads=8','--tables=8','--table_size=100000',str(m.COMMON_LUA),'prewarm']
 warm=subprocess.run(prewarm,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=env,timeout=120,preexec_fn=m.child_setup(m.CPU_GROUPS['client']))
 (out/'prewarm.log').write_text(warm.stdout);assert warm.returncode==0,warm.stdout[-2000:]
 print('DATA PREWARMED; RUNNING STOCK SYSBENCH',flush=True)
 for wi,workload in enumerate(['oltp_point_select','oltp_read_only']):
  for ni,n in enumerate([4,16,64,256,512,1024]):
   order=['direct','native','ff','haproxy'];shift=(wi+ni)%4;order=order[shift:]+order[:shift]
   for mode in order:
    logpath=out/f'{workload}-{n}-{mode}.log'
    cmd=[str(m.SYSBENCH_BINARY),f'--config-file={configs[mode]}',f'--threads={n}','--time=5','--events=0','--db-driver=mysql','--db-ps-mode=auto','--mysql-ssl=off','--mysql-compression=off','--rand-type=uniform','--rand-seed=20261113','--tables=8','--table_size=100000','--range_size=100','--percentile=95',str(m.LUA_DIR/(workload+'.lua')),'run']
    try:
     p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=env,timeout=90,preexec_fn=m.child_setup(m.CPU_GROUPS['client']))
     text=p.stdout;rc=p.returncode
    except subprocess.TimeoutExpired as e:
     text=(e.stdout or b'').decode(errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or '');text+='\nTIMEOUT';rc=124
    logpath.write_text(text)
    def rate(label):
     match=re.search(r'^\s*'+label+r':\s+(\d+)\s+\(([\d.]+) per sec\.',text,re.M)
     return (int(match[1]),float(match[2])) if match else (None,None)
    events,tps=rate('transactions');queries,qps=rate('queries');errors,_=rate('ignored errors');reconnects,_=rate('reconnects')
    def val(pattern):
     match=re.search(pattern,text);return float(match[1]) if match else None
    row=dict(workload=workload,connections=n,mode=mode,ok=rc==0 and errors==0 and reconnects==0 and qps is not None,tps=tps,qps=qps,p95_ms=val(r'95th percentile:\s+([\d.]+)'),events=events,queries=queries,elapsed_s=val(r'total time:\s+([\d.]+)s'),errors=errors,reconnects=reconnects,log=str(logpath))
    rows.append(row);writer.writerow(row);csvfile.flush();(out/'results.json').write_text(json.dumps({'proxysql_version':built_version,'build_command':'make PROXYSQL40=1 -j8 NPROCS=8','host_binary':str(m.HOST_BINARY),'plugin_binary':str(m.PLUGIN_BINARY),'method':'One five-second stock sysbench run per cell, no checkpoint/wrapper, prepared statements, prewarmed eight tables x100000 rows, plaintext, CPUs DB0-5/proxy6-7/client8-13','ports':ports,'trials':rows},indent=2)+'\n')
    print(json.dumps(row),flush=True)
 print('COMPLETE',len(rows),'runs',out,flush=True)
finally:
 csvfile.close()
 for label,obj in [('haproxy',hap),('proxy',proxy),('mysql',db)]:
  if obj is not None:
   try:print('CLEANUP',label,obj.close() if label!='mysql' else obj.stop(),flush=True)
   except Exception as e:print('CLEANUP ERROR',label,type(e).__name__,flush=True)
