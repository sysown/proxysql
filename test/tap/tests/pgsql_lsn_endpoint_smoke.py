#!/usr/bin/env python3
"""Isolated PostgreSQL LSN endpoint smoke test (explicit invocation).

Requires Docker, the postgres:17 image, psycopg2, pymysql and a PROXYSQL31 build.
Starts one writer, two physical replicas and a fresh proxy per backend mode.
Uses unique container/network names and dynamic local listeners; only resources
created by this invocation are removed. PostgreSQL and proxy logs remain in
--artifacts, including on failure. Run from any directory, for example:

  python3 test/tap/tests/pgsql_lsn_endpoint_smoke.py --artifacts /path/to/logs

This smoke test complements the LSN unit tests; it is not the complete failover,
TLS, cancellation, extended-protocol or performance acceptance matrix.
"""
import argparse, io, socket, subprocess, time, uuid
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
    with c.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall() if cur.description else []
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
        '-c','wal_level=replica','-c','max_wal_senders=20','-c','max_connections=100')
    hosts=[]
    def address(name): return run('docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',name)
    hosts.append(address(primary))
    writer=wait(lambda:connect(hosts[0]))
    run('docker','exec',primary,'bash','-c',"printf 'host replication all all trust\\n' >> /var/lib/postgresql/data/pg_hba.conf")
    query(writer,'SELECT pg_reload_conf()')
    query(writer,"CREATE USER lsn_app PASSWORD 'lsn_test'")
    query(writer,'CREATE TABLE lsn_test(id int PRIMARY KEY, value text)')
    query(writer,'GRANT ALL ON lsn_test TO lsn_app')
    replicas=[]
    for n in range(2):
        name=prefix+'-replica'+str(n); containers.append(name)
        run('docker','run','-d','--name',name,'--network',prefix,'--user','postgres','--entrypoint','bash','postgres:17','-c',
            'pg_basebackup -h '+primary+' -U postgres -D /var/lib/postgresql/data -R -X stream && chmod 0700 /var/lib/postgresql/data && exec postgres -c hot_standby=on -c max_connections=100 -c max_wal_senders=20')
        hosts.append(address(name))
        replicas.append(wait(lambda:connect(hosts[-1])))
    def pause():
        for c in replicas: query(c,'SELECT pg_wal_replay_pause()')
        for c in replicas: wait(lambda:query(c,'SELECT pg_is_wal_replay_paused()')[0][0])
    def resume():
        for c in replicas: query(c,'SELECT pg_wal_replay_resume()')
    for native in (False,True):
        mode='native' if native else 'libpq'
        datadir=OUT/(mode+'-'+prefix); datadir.mkdir()
        admin_port,pgsql_port,mysql_port=freeport(),freeport(),freeport()
        config=datadir/'proxysql.cnf'
        config.write_text('''admin_variables={admin_credentials="admin:admin";mysql_ifaces="127.0.0.1:%d";}
mysql_variables={threads=2;interfaces="127.0.0.1:%d";monitor_enabled=false;}
pgsql_variables={threads=2;interfaces="127.0.0.1:%d";monitor_username="postgres";monitor_password="";monitor_dbname="postgres";monitor_read_only_interval=60000;monitor_writer_is_also_reader=false;monitor_replication_lag_timeout=1000;use_native_backend_protocol=%s;lsn_poll_interval=10;lsn_wait_timeout=200;default_query_timeout=5000;}
'''%(admin_port,mysql_port,pgsql_port,str(native).lower()))
        log=open(datadir/'proxy.log','w')
        proxy=subprocess.Popen([str(args.proxy.resolve()),'-f','-e','--no-version-check','-c',str(config),'-D',str(datadir)],stdout=log,stderr=subprocess.STDOUT)
        admin=wait(lambda:pymysql.connect(host='127.0.0.1',port=admin_port,user='admin',password='admin',autocommit=True,connect_timeout=2))
        def aq(sql):
            with admin.cursor() as cur: cur.execute(sql); return cur.fetchall()
        aq("INSERT INTO pgsql_users(username,password,default_hostgroup,transaction_persistent) VALUES('lsn_app','lsn_test',10,0)")
        aq('LOAD PGSQL USERS TO RUNTIME')
        for wh,rh in [(10,20),(30,40),(50,60)]:
            aq('INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup,lsn_causal_reads) VALUES(%d,%d,1)'%(wh,rh))
            aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(%d,'%s',5432)"%(wh,hosts[0]))
            for host in hosts[1:]: aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(%d,'%s',5432)"%(rh,host))
        aq("INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(60,'%s',5432)"%hosts[0])
        aq('LOAD PGSQL SERVERS TO RUNTIME')
        aq("INSERT INTO pgsql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) VALUES(1,1,'alias_write',30,1),(2,1,'alias_read',40,1),(3,1,'writer_alias',60,1),(4,1,'^SELECT',20,1)")
        aq('LOAD PGSQL QUERY RULES TO RUNTIME')
        rows=wait(lambda: (r if len(r:=aq('SELECT hostname,port,lsn FROM stats_pgsql_lsn'))==3 and all(x[2] is not None for x in r) else None))
        check(len(rows)==3,mode+': three physical rows across three hostgroup policies')
        senders=[query(backend,"SELECT count(*) FROM pg_stat_activity WHERE backend_type='walsender' AND datname='postgres'")[0][0] for backend in [writer]+replicas]
        check(senders==[1,1,1],mode+': each endpoint has one monitor connection regardless of memberships')
        c=connect('127.0.0.1',pgsql_port,'lsn_app','lsn_test')
        base=100 if native else 0
        pause()
        query(c,"INSERT INTO lsn_test VALUES(%d,'written')"%(base+1))
        start=time.monotonic()
        row=query(c,'SELECT value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+1))
        check(row==[('written',False)] and time.monotonic()-start<3,mode+': paused replicas fall back to origin with acknowledged write visible')
        query(replicas[0],'SELECT pg_wal_replay_resume()')
        wait(lambda:query(replicas[0],'SELECT count(*) FROM lsn_test WHERE id=%d'%(base+1))[0][0]==1)
        row=query(c,'SELECT value,pg_is_in_recovery(),host(inet_server_addr()) FROM lsn_test WHERE id=%d'%(base+1))
        check(row==[('written',True,hosts[1])],mode+': only the caught-up replica is admitted')
        pause()
        query(c,"/* alias_write */ INSERT INTO lsn_test VALUES(%d,'shared')"%(base+2))
        row=query(c,'SELECT /* alias_read */ value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+2))
        check(row==[('shared',False)],mode+': writes and reads through another policy preserve physical dependency')
        row=query(c,'SELECT /* writer_alias */ value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+2))
        check(row==[('shared',False)],mode+': writer membership in reader hostgroup shares its certificate')
        with c.cursor() as cur: cur.copy_expert('COPY lsn_test FROM STDIN',io.StringIO('%d\tcopy\n'%(base+3)))
        row=query(c,'SELECT value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+3))
        check(row==[('copy',False)],mode+': COPY idle completion preserves dependency')
        query(c,"BEGIN; INSERT INTO lsn_test VALUES(%d,'transaction'); COMMIT"%(base+4))
        row=query(c,'SELECT value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+4))
        check(row==[('transaction',False)],mode+': explicit commit is covered')
        aq('DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=30')
        aq('DELETE FROM pgsql_servers WHERE hostgroup_id IN (30,40)')
        aq('LOAD PGSQL SERVERS TO RUNTIME')
        wait(lambda: len(r:=aq('SELECT * FROM stats_pgsql_lsn'))==3 and all(x[2] is not None for x in r))
        row=query(c,'SELECT value,pg_is_in_recovery() FROM lsn_test WHERE id=%d'%(base+4))
        check(row==[('transaction',False)],mode+': removing a shared policy preserves the frontend dependency')
        resume()
        c.close(); admin.close(); stop_proxy(); log.close()
    print('1..'+str(checks),flush=True)
finally:
    stop_proxy()
    for name in reversed(containers):
        result=subprocess.run(['docker','logs',name],capture_output=True,text=True,timeout=10)
        (OUT/(name+'.log')).write_text(result.stdout+result.stderr)
        subprocess.run(['docker','rm','-fv',name],capture_output=True,timeout=20)
    subprocess.run(['docker','network','rm',prefix],capture_output=True,timeout=20)
