from pathlib import Path
import os,subprocess,time,json,re,csv,io,signal,hashlib,socket,tempfile,shutil,sys,math,gzip,collections
r=Path.home()/'pg-network-bench'
import fcntl
run_lock=(r/'plaintext-implementation.lock').open('a')
fcntl.flock(run_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
def interrupted(signum,frame):raise KeyboardInterrupt
signal.signal(signal.SIGTERM,interrupted)
signal.signal(signal.SIGINT,interrupted)
mode=sys.argv[1];assert mode in ['previous','latest']
workload=sys.argv[2];assert workload in ['select1','4kb']
query_file={'select1':'select1.sql','4kb':'select42_4kb.sql'}[workload]
metadata=json.loads((r/'tls-forwarding-binaries.json').read_text())[mode]
out=r/'results'/('tls-assurance-'+workload+'-'+mode+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()));out.mkdir();print(out,flush=True)
binary=r/metadata['file'];assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata['sha256']
version=subprocess.run([str(binary),'--version'],text=True,capture_output=True,check=True)
assert metadata['version_prefix'] in version.stdout,version.stdout
source_config=(r/'proxysql-309.cnf').read_text()
u,pw=re.search(r'admin_credentials\s*=\s*"([^"]+)"',source_config)[1].split(':',1)
ce=os.environ.copy();ce.update(PGSSLMODE='require',PGPASSWORD=next(x.split(':',4)[4] for x in (r/'.pgpass').read_text().splitlines() if x.startswith('*:5432:')))
ae=os.environ.copy();ae.update(PGSSLMODE='disable',PGUSER=u,PGPASSWORD=pw)
temp=tempfile.TemporaryDirectory(prefix='isolated-pgsql-'+mode+'-4kb-',dir=r)
tmp=Path(temp.name);tmp.chmod(0o700);data=tmp/'data';data.mkdir(mode=0o700)
olddata=Path(re.search(r'datadir\s*=\s*"([^"]+)"',source_config)[1])
for name in ['proxysql-cert.pem','proxysql-key.pem','proxysql-ca.pem']:shutil.copy2(olddata/name,data/name)
sockets=[]
for _ in range(4):
 sock=socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
ports=[str(sock.getsockname()[1]) for sock in sockets]
adminport,port,mysqlport,adminmysqlport=ports
config=source_config.replace(str(olddata),str(data)).replace(str(r/'proxysql-309.log'),str(tmp/'proxysql.log'))
for previous,new in [('6332',adminport),('6333',port),('6334',mysqlport),('6335',adminmysqlport)]:config=config.replace(':'+previous,':'+new)
cfg=tmp/'private.cnf';cfg.write_text(config);cfg.chmod(0o600)
(out/'ports.json').write_text(json.dumps(dict(admin=adminport,frontend=port),indent=2))
for sock in sockets:sock.close()
p=None;parent=None;pid=None;logtemp=None
args=['taskset','-c','2','pgbench','-n','-h','127.0.0.1','-p',port,'-U','networkbench','networkbench','-c','1','-j','1','-M','simple','-f',query_file]
(out/query_file).write_text((r/query_file).read_text())
def q(sql):
 return list(csv.DictReader(io.StringIO(subprocess.check_output(['psql','-X','-w','--csv','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',adminport,'-d','admin','-c',sql],env=ae,text=True,stderr=subprocess.DEVNULL))))
try:
 assert {x.read_text().strip() for x in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')}=={'performance'}
 subprocess.run(['taskset','-c','0',str(binary),'-c',str(cfg)],cwd=r,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(100):
  try:q('SELECT 1');break
  except subprocess.CalledProcessError:time.sleep(.2)
 else:raise RuntimeError('3.0.9 startup failed')
 parent=int((data/'proxysql.pid').read_text());pid=int(subprocess.check_output(['pgrep','-P',str(parent)],text=True).strip())
 assert subprocess.check_output(['taskset','-pc',str(pid)],text=True).strip().endswith(': 0')
 for key,value in {'pgsql-commands_stats':'false','pgsql-query_digests':'false','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0','pgsql-have_ssl':'true'}.items():q("UPDATE global_variables SET variable_value='"+value+"' WHERE variable_name='"+key+"'")
 available={row['variable_name'] for row in q("SELECT variable_name FROM global_variables WHERE variable_name IN ('pgsql-use_native_backend_protocol','pgsql-query_processor_parser')")}
 for key in available:q("UPDATE global_variables SET variable_value='"+('true' if key=='pgsql-use_native_backend_protocol' else '0')+"' WHERE variable_name='"+key+"'")
 q('LOAD PGSQL VARIABLES TO RUNTIME')
 tables={x['name'] for x in q("SELECT name FROM sqlite_master WHERE name IN ('pgsql_hostgroup_attributes','runtime_pgsql_hostgroup_attributes')")}
 if 'pgsql_hostgroup_attributes' in tables:q('UPDATE pgsql_hostgroup_attributes SET free_connections_pct=100')
 q('UPDATE pgsql_servers SET max_connections=10,use_ssl=1');q('LOAD PGSQL SERVERS TO RUNTIME')
 q("UPDATE pgsql_users SET use_ssl=1 WHERE username='networkbench'");q('LOAD PGSQL USERS TO RUNTIME')
 settings=q("SELECT variable_name,variable_value FROM runtime_global_variables WHERE variable_name IN ('pgsql-threads','pgsql-commands_stats','pgsql-query_digests','pgsql-use_native_backend_protocol','pgsql-query_processor_parser','pgsql-have_ssl','pgsql-free_connections_pct','pgsql-connection_max_age_ms')")
 values={x['variable_name']:x['variable_value'] for x in settings}
 for key,value in {'pgsql-threads':'1','pgsql-commands_stats':'false','pgsql-query_digests':'false','pgsql-have_ssl':'true','pgsql-free_connections_pct':'100','pgsql-connection_max_age_ms':'0'}.items():assert values[key]==value,(key,values)
 if mode in ['previous','latest']:assert values.get('pgsql-use_native_backend_protocol')=='true',values
 if mode=='309':assert 'pgsql-use_native_backend_protocol' not in values,values
 (out/'settings.json').write_text(json.dumps(settings,indent=2))
 rules=q('SELECT rule_id,match_digest,match_pattern FROM runtime_pgsql_query_rules WHERE active=1');assert not rules,rules;(out/'active-query-rules.json').write_text(json.dumps(rules,indent=2))
 servers=q('SELECT hostgroup_id,hostname,port,max_connections,use_ssl FROM runtime_pgsql_servers');assert all(int(x['max_connections'])==10 and int(x['use_ssl'])==1 for x in servers);(out/'servers.json').write_text(json.dumps(servers,indent=2))
 if 'runtime_pgsql_hostgroup_attributes' in tables:
  attrs=q('SELECT hostgroup_id,free_connections_pct FROM runtime_pgsql_hostgroup_attributes');assert all(int(x['free_connections_pct'])==100 for x in attrs),attrs
  (out/'hostgroup-attributes.json').write_text(json.dumps(attrs,indent=2))
 (out/'binary.json').write_text(json.dumps(dict(version=version.stdout.strip(),version_stderr=version.stderr.strip(),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),backend='native' if values.get('pgsql-use_native_backend_protocol')=='true' else 'libpq',native_backend_setting_present='pgsql-use_native_backend_protocol' in values,metadata=metadata,profiling=False,transaction_logging=True,pid=pid),indent=2))
 print(mode+': isolated instance ready; one worker, TLS both hops, commands_stats=false, query_digests=false, 10-backend cap.',flush=True)
 pa=['psql','-X','-w','-h','127.0.0.1','-p',port,'-U','networkbench','-d','networkbench'];front=subprocess.check_output(pa+['-c',r'\conninfo'],env=ce,text=True);back=subprocess.check_output(pa+['-Atc','SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()'],env=ce,text=True).strip();assert 'SSL connection' in front and 'TLSv1.3, cipher: TLS_AES_256_GCM_SHA384' in front and back=='t|TLSv1.3|TLS_AES_256_GCM_SHA384';(out/'tls.txt').write_text(front+'Frontend PGSSLMODE=require; backend TLS: '+back+'\n')
 from verify_tls_query_output import verify
 verify(out,pa,ce,query_file,r)

 import ssl,struct,threading,uuid
 evidence=[]
 def command(query,overrides=None):
  e=ce.copy();e.update(overrides or {})
  return subprocess.run(pa+['-q','-A','-t','-c',query],env=e,capture_output=True,timeout=10)
 good=command('SELECT 1;');assert good.returncode==0 and good.stdout.strip()==b'1'
 for name,envchange in [('plaintext-rejected',{'PGSSLMODE':'disable'}),('wrong-password-rejected',{'PGPASSWORD':'invalid-'+str(uuid.uuid4())})]:
  res=command('SELECT 1;',envchange);assert res.returncode!=0,(name,res.stdout,res.stderr)
  evidence.append(dict(check=name,rejected=True,error=res.stderr.decode(errors='replace')[:1000]))
 # A complete TLS handshake followed by a deliberately damaged application record.
 wire=socket.create_connection(('127.0.0.1',int(port)),timeout=3);wire.settimeout(3)
 wire.sendall(struct.pack('!II',8,80877103));assert wire.recv(1)==b'S'
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
 ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.maximum_version=ssl.TLSVersion.TLSv1_3
 incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO();tls=ctx.wrap_bio(incoming,outgoing,server_side=False,server_hostname='localhost')
 def drain():
  while outgoing.pending:wire.sendall(outgoing.read())
 for attempt in range(20):
  try:tls.do_handshake();drain();break
  except ssl.SSLWantReadError:
   drain();block=wire.recv(16384);assert block;incoming.write(block)
 else:raise RuntimeError('TLS handshake did not finish')
 assert tls.version()=='TLSv1.3';time.sleep(.05)
 startup=struct.pack('!I',196608)+b'user\0networkbench\0database\0networkbench\0\0'
 startup=struct.pack('!I',len(startup)+4)+startup
 assert tls.write(startup)==len(startup)
 encoded=bytearray(outgoing.read());assert len(encoded)>21;encoded[-1]^=1;wire.sendall(encoded)
 rejected=False;decrypted=b''
 for attempt in range(10):
  try:
   block=wire.recv(16384)
   if not block:rejected=True;break
   incoming.write(block)
   try:decrypted+=tls.read(16384)
   except ssl.SSLWantReadError:continue
   except ssl.SSLError:rejected=True;break
  except (ConnectionResetError,BrokenPipeError):rejected=True;break
 wire.close();assert rejected and not decrypted,('corrupt record accepted or not rejected',decrypted)
 evidence.append(dict(check='corrupt-tls13-record-rejected',handshake_finished=True,rejected=True,postgres_data_received=False))
 # Isolate a new hostgroup whose backend explicitly declines PostgreSQL SSLRequest.
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.2)
 fakeport=listener.getsockname()[1];stop=threading.Event();observations=[]
 def backend():
  while not stop.is_set():
   try:c,_=listener.accept()
   except socket.timeout:continue
   except OSError:break
   with c:
    c.settimeout(2);request=b''
    try:
     while len(request)<8:
      chunk=c.recv(8-len(request))
      if not chunk:break
      request+=chunk
     if request==struct.pack('!II',8,80877103):
      c.sendall(b'N')
      try:after=c.recv(1024)
      except socket.timeout:after=b'TIMEOUT'
     else:after=b'NOT_SSL_REQUEST'
     observations.append(dict(request_hex=request.hex(),bytes_after_refusal_hex=after.hex()))
    except (ConnectionResetError,BrokenPipeError):observations.append(dict(request_hex=request.hex(),bytes_after_refusal_hex=''))
 thread=threading.Thread(target=backend,daemon=True);thread.start()
 try:
  for variable in ['pgsql-connect_retries_on_failure','pgsql-connect_retries_delay']:
   if q("SELECT variable_name FROM global_variables WHERE variable_name='"+variable+"'"):
    q("UPDATE global_variables SET variable_value='0' WHERE variable_name='"+variable+"'")
  q('LOAD PGSQL VARIABLES TO RUNTIME')
  hid=int(q('SELECT COALESCE(MAX(hostgroup_id),0)+100 AS hid FROM pgsql_servers')[0]['hid'])
  q("INSERT INTO pgsql_servers(hostgroup_id,hostname,port,max_connections,use_ssl) VALUES("+str(hid)+",'127.0.0.1',"+str(fakeport)+",1,1)");q('LOAD PGSQL SERVERS TO RUNTIME')
  q("UPDATE pgsql_users SET default_hostgroup="+str(hid)+" WHERE username='networkbench'");q('LOAD PGSQL USERS TO RUNTIME')
  res=command('SELECT 1;');assert res.returncode!=0,(res.stdout,res.stderr)
 finally:stop.set();listener.close();thread.join(timeout=3)
 assert observations and all(x['request_hex']==struct.pack('!II',8,80877103).hex() and x['bytes_after_refusal_hex']=='' for x in observations),observations
 evidence.append(dict(check='backend-tls-refusal-rejected',query_failed=True,no_plaintext_startup_sent=True,connections=observations,error=res.stderr.decode(errors='replace')[:1000]))
 assert Path(f'/proc/{pid}').exists()
 (out/'assurance.json').write_text(json.dumps(dict(checks=evidence,proxy_stayed_running=True),indent=2)+'\n')
 print(json.dumps(evidence,indent=2),flush=True)

finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=15)
 if parent is None and (data/'proxysql.pid').exists():parent=int((data/'proxysql.pid').read_text())
 pids=[]
 if parent is not None:
  pids=[parent]+[int(x) for x in subprocess.run(['pgrep','-P',str(parent)],capture_output=True,text=True).stdout.split()]
  for process in pids:
   try:os.kill(process,signal.SIGTERM)
   except ProcessLookupError:pass
  for _ in range(100):
   if all(not Path(f'/proc/{process}/stat').exists() or Path(f'/proc/{process}/stat').read_text().split()[2]=='Z' for process in pids):break
   time.sleep(.1)
  else:raise RuntimeError('Isolated 3.0.9 instance did not stop')
 (out/'cleanup.json').write_text(json.dumps(dict(isolated_instance_stopped=True,existing_listeners_untouched=True),indent=2))
 if logtemp is not None:logtemp.cleanup()
 temp.cleanup()
print('DONE '+str(out),flush=True)
