#!/usr/bin/env python3
"""Isolated PostgreSQL LSN endpoint smoke test (explicit invocation).

Requires Docker, the postgres:17 image, psycopg2, pymysql and a PROXYSQL31 build.
Starts one writer, two physical replicas and a proxy using native backends.
Uses unique container/network names and dynamic local listeners; only resources
created by this invocation are removed. PostgreSQL and proxy logs remain in
--artifacts, including on failure. Run from any directory, for example:

  python3 test/tap/tests/pgsql_lsn_endpoint_smoke.py --artifacts /path/to/logs

This smoke test complements the LSN unit tests; it is not the complete failover,
TLS, cancellation, extended-protocol or performance acceptance matrix.
"""
import argparse, io, json, socket, statistics, struct, subprocess, time, uuid
from threading import Thread, Timer
from pathlib import Path
import psycopg2, pymysql
ROOT=Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--proxy',type=Path,default=ROOT/'src/proxysql')
parser.add_argument('--artifacts',type=Path,default=ROOT/'.superpowers/pgsql-lsn-smoke')
args=parser.parse_args()
OUT=args.artifacts.resolve()
OUT.mkdir(parents=True,exist_ok=True)
prefix='proxysql-lsn-'+uuid.uuid4().hex[:8]
containers=[]
proxy=None
checks=0

def run(*args, **kw):
    return subprocess.run(args,check=True,text=True,capture_output=True,timeout=60,**kw).stdout.strip()
def check(value, description):
    global checks
    checks+=1
    print(('ok' if value else 'not ok'), checks, '-', description, flush=True)
    if not value: raise AssertionError(description)
def wait(fn, seconds=20):
    end=time.monotonic()+seconds
    last=None
    while time.monotonic()<end:
        try:
            value=fn()
            if value: return value
        except Exception as e: last=e
        time.sleep(.025)
    raise TimeoutError(str(last) if last else 'condition not reached')
def connect(host,port=5432,user='postgres',password=None):
    c=psycopg2.connect(host=host,port=port,user=user,password=password,dbname='postgres',sslmode='disable',connect_timeout=2)
    c.autocommit=True
    return c
def query(c, sql):
    # Bound even a proxy state-machine stall; server-side statement_timeout
    # cannot interrupt a request that has not reached PostgreSQL.
    def expire():
        try:
            with socket.fromfd(c.fileno(), socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.shutdown(socket.SHUT_RDWR)
        except (OSError, psycopg2.Error):
            pass
    deadline=Timer(10,expire)
    deadline.start()
    try:
        with c.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall() if cur.description else []
    finally:
        deadline.cancel()
class ExtendedClient:
    """Authenticate with libpq, then exercise real Parse/Bind/Execute/Sync bytes."""
    def __init__(self, port):
        self.connection=connect('127.0.0.1',port,'lsn_app','lsn_test')
        self.socket=socket.fromfd(self.connection.fileno(),socket.AF_INET,socket.SOCK_STREAM)
        self.socket.settimeout(10)
    def read(self, size):
        data=b''
        while len(data)<size:
            part=self.socket.recv(size-len(data))
            if not part: raise ConnectionError('extended connection closed')
            data+=part
        return data
    def execute(self, sql):
        def message(kind,payload): return kind+struct.pack('!I',len(payload)+4)+payload
        self.socket.sendall(
            message(b'P',b'\0'+sql.encode()+b'\0\0\0')+
            message(b'B',b'\0\0'+struct.pack('!HHH',0,0,0))+
            message(b'D',b'P\0')+message(b'E',b'\0'+struct.pack('!I',0))+message(b'S',b''))
        rows=[]; error=None
        while True:
            kind=self.read(1); size=struct.unpack('!I',self.read(4))[0]
            payload=self.read(size-4)
            if kind==b'E': error=payload
            if kind==b'D':
                count=struct.unpack('!H',payload[:2])[0]; pos=2; row=[]
                for _ in range(count):
                    length=struct.unpack('!i',payload[pos:pos+4])[0]; pos+=4
                    row.append(None if length<0 else payload[pos:pos+length].decode())
                    if length>=0: pos+=length
                rows.append(tuple(row))
            if kind==b'Z':
                if error: raise AssertionError('extended error: '+repr(error))
                return rows
    def close(self):
        self.socket.close(); self.connection.close()

def measure_ordinary(connection):
    samples=[]
    with connection.cursor() as cursor:
        for index in range(550):
            started=time.perf_counter_ns()
            cursor.execute('/* ordinary_benchmark */ SELECT 1')
            assert cursor.fetchone()==(1,)
            if index>=50: samples.append((time.perf_counter_ns()-started)/1000)
    ordered=sorted(samples)
    return {'queries':len(samples),'p50_us':statistics.median(samples),
            'p95_us':ordered[int(len(samples)*.95)],
            'queries_per_second':1e6/statistics.mean(samples)}

def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def stop_proxy():
    global proxy
    if proxy:
        proxy.terminate()
        try: proxy.wait(10)
        except subprocess.TimeoutExpired: proxy.kill(); proxy.wait()
        proxy=None
try:
    run('docker','network','create',prefix)
    primary=prefix+'-writer'; containers.append(primary)
    run('docker','run','-d','--name',primary,'--network',prefix,'-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17',
        '-c','wal_level=replica','-c','max_wal_senders=20','-c','max_connections=100',
        '-c','log_statement=all','-c','log_line_prefix=%m [%p] %u@%d ')
    hosts=[]
    def address(name): return run('docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',name)
    hosts.append(address(primary))
    writer=wait(lambda:connect(hosts[0]))
    run('docker','exec',primary,'bash','-c',"printf 'host replication all all trust\\n' >> /var/lib/postgresql/data/pg_hba.conf")
    query(writer,'SELECT pg_reload_conf()')
    query(writer,"CREATE USER lsn_app PASSWORD 'lsn_test'")
    query(writer,"CREATE USER lsn_fresh PASSWORD 'lsn_test'")
    query(writer,'CREATE TABLE lsn_test(id int PRIMARY KEY, value text)')
    query(writer,'GRANT ALL ON lsn_test TO lsn_app')
    replicas=[]
    for n in range(2):
        name=prefix+'-replica'+str(n); containers.append(name)
        run('docker','run','-d','--name',name,'--network',prefix,'--user','postgres','--entrypoint','bash','postgres:17','-c',
            'pg_basebackup -h '+primary+' -U postgres -D /var/lib/postgresql/data -R -X stream && chmod 0700 /var/lib/postgresql/data && exec postgres -c hot_standby=on -c max_connections=100 -c max_wal_senders=20 -c log_statement=all -c \"log_line_prefix=%m [%p] %u@%d \"')
        hosts.append(address(name))
        replicas.append(wait(lambda:connect(hosts[-1])))
    def pause():
        for c in replicas: query(c,'SELECT pg_wal_replay_pause()')
        for c in replicas: wait(lambda:query(c,'SELECT pg_is_wal_replay_paused()')[0][0])
    def resume():
        for c in replicas: query(c,'SELECT pg_wal_replay_resume()')
    for native in (True,):
        mode='native' if native else 'libpq'
        datadir=OUT/(mode+'-'+prefix); datadir.mkdir()
        admin_port,pgsql_port,mysql_port=freeport(),freeport(),freeport()
        config=datadir/'proxysql.cnf'
        config.write_text('''admin_variables={admin_credentials="admin:admin";mysql_ifaces="127.0.0.1:%d";}
mysql_variables={threads=2;interfaces="127.0.0.1:%d";monitor_enabled=false;}
pgsql_variables={threads=2;interfaces="127.0.0.1:%d";monitor_username="postgres";monitor_password="";monitor_dbname="postgres";monitor_read_only_interval=60000;monitor_writer_is_also_reader=false;monitor_replication_lag_timeout=1000;use_native_backend_protocol=%s;monitor_lsn_poll_interval=10;monitor_lsn_poll_timeout=1000;monitor_lsn_history=1000;connect_timeout_server_max=600;connect_retries_delay=10;default_query_timeout=5000;}
'''%(admin_port,mysql_port,pgsql_port,str(native).lower()))
        log=open(datadir/'proxy.log','w')
        proxy=subprocess.Popen([str(args.proxy.resolve()),'-f','-e','--no-version-check','-c',str(config),'-D',str(datadir)],stdout=log,stderr=subprocess.STDOUT)
        admin=wait(lambda:pymysql.connect(host='127.0.0.1',port=admin_port,user='admin',password='admin',autocommit=True,connect_timeout=2))
        def aq(sql):
            with admin.cursor() as cur: cur.execute(sql); return cur.fetchall()
        aq("INSERT INTO pgsql_users(username,password,default_hostgroup,transaction_persistent) VALUES('lsn_app','lsn_test',10,0)")
        aq("INSERT INTO pgsql_users(username,password,default_hostgroup,transaction_persistent) VALUES('lsn_fresh','lsn_test',10,0)")
        aq('LOAD PGSQL USERS TO RUNTIME')
        for wh,rh in [(10,20),(30,40),(50,60)]:
            aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(%d,'%s',5432)"%(wh,hosts[0]))
            for host in hosts[1:]: aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(%d,'%s',5432)"%(rh,host))
        aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(60,'%s',5432)"%hosts[0])
        aq('LOAD PGSQL SERVERS TO RUNTIME')
        warm=connect('127.0.0.1',pgsql_port,'lsn_app','lsn_test')
        warm_pid=query(warm,'SELECT pg_backend_pid()')[0][0]
        latency={'polling_inactive':measure_ordinary(warm)}
        aq("INSERT INTO pgsql_query_rules(rule_id,active,match_pattern,destination_hostgroup,lsn_from_hostgroup,cache_ttl,apply) VALUES(1,1,'alias_write',30,NULL,NULL,1),(2,1,'alias_read',40,30,NULL,1),(3,1,'writer_alias',60,10,NULL,1),(4,1,'ordinary_read',20,NULL,NULL,1),(5,1,'cached_read',20,10,10000,1),(6,1,'^SELECT',20,10,NULL,1)")
        aq('LOAD PGSQL QUERY RULES TO RUNTIME')
        rows=wait(lambda: (r if len(r:=aq('SELECT hostname,port,lsn FROM stats_pgsql_lsn'))==3 and all(x[2] is not None for x in r) else None))
        check(len(rows)==3,mode+': three physical rows across duplicate hostgroup memberships')
        senders=[query(backend,"SELECT count(*) FROM pg_stat_activity WHERE backend_type='walsender' AND datname='postgres'")[0][0] for backend in [writer]+replicas]
        check(senders==[1,1,1],mode+': each endpoint has one monitor connection regardless of memberships')
        check(query(warm,'SELECT pg_is_in_recovery()')==[(True,)],mode+': enabling a rule uses the execution record captured before LOAD')
        latency['polling_active']=measure_ordinary(warm)
        (datadir/'ordinary-latency.json').write_text(json.dumps(latency,indent=2))
        fresh=connect('127.0.0.1',pgsql_port,'lsn_fresh','lsn_test')
        row=query(fresh,"/* first_application_query */ SELECT 1")
        check(row==[(1,)],mode+': fresh native connection executes normally')
        fresh.close()
        c=warm
        row=query(c,"/* pooled_settings */ SELECT pg_backend_pid()")
        check(row==[(warm_pid,)],mode+': existing session reuses its backend after rules load')
        query(c,"SET TIME ZONE 'Pacific/Honolulu'")
        row=query(c,"SELECT current_setting('TimeZone')")
        check(row==[('Pacific/Honolulu',)],mode+': idle WAL boundary permits causal selection and ordinary session settings')
        cached=query(c,'SELECT /* cached_read */ count(*) FROM lsn_test')
        pause()
        start=time.monotonic()
        query(c,"INSERT INTO lsn_test VALUES(101,'written')")
        check(time.monotonic()-start<.5,mode+': write acknowledgement does not wait for replica progress')
        row=query(c,'SELECT /* ordinary_read */ count(*) FROM lsn_test WHERE id=101')
        check(row==[(0,)],mode+': unconfigured read remains free to use a lagging replica')
        start=time.monotonic()
        row=query(c,'SELECT /* cached_read */ count(*) FROM lsn_test')
        check(row==cached and time.monotonic()-start<.5,mode+': cache hit keeps ordinary behavior despite unresolved backend dependency')
        start=time.monotonic()
        try:
            query(c,'SELECT value FROM lsn_test WHERE id=101')
            raise AssertionError('causal read unexpectedly selected a lagging replica or another hostgroup')
        except psycopg2.Error as error:
            check(error.pgcode=='08001' and .4<time.monotonic()-start<3,
                  mode+': lagged destinations reach ordinary acquisition timeout without writer fallback')
        query(replicas[0],'SELECT pg_wal_replay_resume()')
        wait(lambda:query(replicas[0],'SELECT count(*) FROM lsn_test WHERE id=101')[0][0]==1)
        row=query(c,'SELECT value,pg_is_in_recovery(),host(inet_server_addr()) FROM lsn_test WHERE id=101')
        check(row==[('written',True,hosts[1])],mode+': only caught-up destination qualifies')
        query(c,"/* alias_write */ INSERT INTO lsn_test VALUES(102,'shared')")
        row=query(c,'SELECT /* alias_read */ value,pg_is_in_recovery() FROM lsn_test WHERE id=102')
        check(row==[('shared',True)],mode+': source hostgroup comes from rule and keeps its own execution record')
        row=query(c,'SELECT /* writer_alias */ value FROM lsn_test WHERE id=101')
        check(row==[('written',)],mode+': any qualifying member of the destination can be selected')
        with c.cursor() as cur: cur.copy_expert('COPY lsn_test FROM STDIN',io.StringIO('103\tcopy\n'))
        row=query(c,'SELECT value FROM lsn_test WHERE id=103')
        check(row==[('copy',)],mode+': COPY completion is recorded')
        query(c,"BEGIN; INSERT INTO lsn_test VALUES(104,'transaction'); COMMIT")
        row=query(c,'SELECT value FROM lsn_test WHERE id=104')
        check(row==[('transaction',)],mode+': explicit commit is covered')
        extended=ExtendedClient(pgsql_port)
        try:
            extended.execute("INSERT INTO lsn_test VALUES(106,'extended')")
            row=extended.execute('SELECT value FROM lsn_test WHERE id=106')
            check(row==[('extended',)],mode+': extended Bind/Execute/Sync records source completion and constrains selection')
        finally:
            extended.close()
        pinned=connect('127.0.0.1',pgsql_port,'lsn_app','lsn_test')
        try:
            query(pinned,'BEGIN')
            query(pinned,"INSERT INTO lsn_test VALUES(107,'rollback')")
            try:
                query(pinned,'SELECT value FROM lsn_test WHERE id=107')
                raise AssertionError('pinned transaction moved across hostgroups')
            except psycopg2.Error as error:
                check(error.pgcode=='55000',mode+': causal read refuses an incompatible transaction pin')
            query(pinned,'ROLLBACK')
            check(query(writer,'SELECT count(*) FROM lsn_test WHERE id=107')==[(0,)],mode+': refused transaction is rolled back before frontend recovery')
        finally:
            pinned.close()
        # One replica remains paused beyond the history window; healthy peers
        # keep serving old and new dependencies while its position stays behind.
        time.sleep(1.2)
        row=query(c,'SELECT value,host(inet_server_addr()) FROM lsn_test WHERE id=104')
        check(row==[('transaction',hosts[1])],mode+': expired source history still resolves with one stuck destination')
        pause()
        query(c,"INSERT INTO lsn_test VALUES(105,'waited')")
        release=Timer(.15,lambda:query(replicas[0],'SELECT pg_wal_replay_resume()'))
        release.start()
        try:
            row=query(c,'SELECT value FROM lsn_test WHERE id=105')
            check(row==[('waited',)],mode+': acquisition retries become eligible when replay resumes')
        finally:
            release.join()
        pause()
        query(c,"INSERT INTO lsn_test VALUES(108,'cancelled')")
        cancel=Timer(.1,c.cancel); cancel.start()
        try:
            try:
                query(c,'SELECT value FROM lsn_test WHERE id=108')
                raise AssertionError('cancelled acquisition unexpectedly completed')
            except psycopg2.Error as error:
                check(error.pgcode=='57014',mode+': cancellation interrupts causal backend acquisition')
        finally:
            cancel.join()
        query(replicas[0],'SELECT pg_wal_replay_resume()')
        aq('DELETE FROM pgsql_servers WHERE hostgroup_id IN (30,40)')
        aq('LOAD PGSQL SERVERS TO RUNTIME')
        wait(lambda: len(r:=aq('SELECT * FROM stats_pgsql_lsn'))==3 and all(x[2] is not None for x in r))
        row=query(c,'SELECT value FROM lsn_test WHERE id=105')
        check(row==[('waited',)],mode+': duplicate membership removal keeps the physical history')
        aq("SET pgsql-monitor_enabled='false'")
        aq('LOAD PGSQL VARIABLES TO RUNTIME')
        wait(lambda: all(row[2] is None for row in aq('SELECT * FROM stats_pgsql_lsn')))
        query(c,"INSERT INTO lsn_test VALUES(109,'unsampled')")
        try:
            query(c,'SELECT value FROM lsn_test WHERE id=109')
            raise AssertionError('request without a post-completion sample unexpectedly ran')
        except psycopg2.Error as error:
            check(error.pgcode=='08001',mode+': unknown post-completion source progress uses ordinary acquisition timeout')
        aq("SET pgsql-monitor_enabled='true'")
        aq('LOAD PGSQL VARIABLES TO RUNTIME')
        wait(lambda: all(row[2] is not None for row in aq('SELECT * FROM stats_pgsql_lsn')))
        check(query(c,'SELECT value FROM lsn_test WHERE id=109')==[('unsampled',)],mode+': monitor restart resolves the retained frontend source timestamp')
        aq('UPDATE pgsql_servers SET max_connections=1 WHERE hostgroup_id=20')
        aq('LOAD PGSQL SERVERS TO RUNTIME')
        wait(lambda: all(row[2] is not None for row in aq('SELECT * FROM stats_pgsql_lsn')))
        holder=connect('127.0.0.1',pgsql_port,'lsn_app','lsn_test')
        query(holder,'/* holder_source */ SELECT 1')
        holder_errors=[]
        def occupy():
            try: query(holder,'SELECT pg_sleep(2)')
            except Exception as error: holder_errors.append(error)
        occupied=Thread(target=occupy); occupied.start()
        try:
            wait(lambda: int(aq("SELECT ConnUsed FROM stats_pgsql_connection_pool WHERE hostgroup=20 AND srv_host='%s'"%hosts[1])[0][0])==1)
            query(c,"INSERT INTO lsn_test VALUES(110,'pool')")
            try:
                query(c,'SELECT value FROM lsn_test WHERE id=110')
                raise AssertionError('exhausted eligible pool unexpectedly supplied a connection')
            except psycopg2.Error as error:
                check(error.pgcode=='08001',mode+': exhausted eligible pool retains ordinary acquisition timeout')
        finally:
            occupied.join(10); holder.close()
        check(not holder_errors and query(c,'SELECT value FROM lsn_test WHERE id=110')==[('pool',)],mode+': returned eligible backend serves the next causal request')
        def unexpected_application_sql():
            for name in containers:
                logs=subprocess.run(
                    ['docker','logs',name],capture_output=True,text=True,timeout=10)
                for line in (logs.stdout+logs.stderr).splitlines():
                    if 'lsn_app@postgres' not in line and 'lsn_fresh@postgres' not in line:
                        continue
                    if 'pg_postmaster_start_time' in line or 'IDENTIFY_SYSTEM' in line or 'pg_current_wal' in line or 'pg_control_init' in line:
                        return line
            return None
        check(unexpected_application_sql() is None,mode+': application connections send no LSN or server-identity queries')
        resume()
        c.close(); admin.close(); stop_proxy(); log.close()
    print('1..'+str(checks),flush=True)
except Exception:
    if 'admin' in globals():
        for sql in ['SELECT * FROM stats_pgsql_lsn','SELECT * FROM stats_pgsql_processlist','SELECT * FROM stats_pgsql_connection_pool']:
            try: print('# diagnostics',sql,aq(sql),flush=True)
            except Exception as diagnostic: print('# diagnostics unavailable:',diagnostic,flush=True)
    if 'writer' in globals():
        for backend in [writer]+replicas:
            try: print('# backend LSN',query(backend,'SELECT pg_current_wal_insert_lsn()' if backend is writer else 'SELECT pg_last_wal_replay_lsn()'),flush=True)
            except Exception as diagnostic: print('# backend diagnostics unavailable:',diagnostic,flush=True)
    raise
finally:
    stop_proxy()
    for name in reversed(containers):
        result=subprocess.run(['docker','logs',name],capture_output=True,text=True,timeout=10)
        (OUT/(name+'.log')).write_text(result.stdout+result.stderr)
        subprocess.run(['docker','rm','-fv',name],capture_output=True,timeout=20)
    subprocess.run(['docker','network','rm',prefix],capture_output=True,timeout=20)
