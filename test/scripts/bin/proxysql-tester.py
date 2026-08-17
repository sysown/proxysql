#!/usr/bin/env -S python3 -u
# run python stdout/stderr in unbuffered mode

import json
import os
import pymysql
import sys
import select
import subprocess
import random
import time
import glob
import datetime
import getopt
import traceback
import re

from packaging import version

import logging
import structlog
import sys

from structlog import get_logger, configure

# import custom libs
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.append(lib_path)
from group_reconciliation import reconcile_group_results
import utils

script = os.path.basename(__file__)

tests_logs_path = os.environ['TESTS_LOGS_PATH']
log_url_prefix = os.environ.get('JOB_URL', os.environ['TESTS_LOGS_PATH']).rstrip('/')
if os.environ.get('JOB_URL'):
    log_url_prefix += '/ws/ci_tests_logs'
if not os.path.isdir(tests_logs_path):
    os.makedirs(tests_logs_path)

strmh = logging.StreamHandler(stream=sys.stdout)
strmh.setLevel(logging.INFO)
fileh = logging.FileHandler(tests_logs_path + '/proxysql-tester.log', 'a')
fileh.setLevel(logging.DEBUG)
#fileh.setLevel(logging.INFO)
logging.basicConfig(
#                    stream=sys.stdout,
                    handlers=[strmh, fileh],
#                    format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    format='[%(asctime)s] %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG
                    )
log = logging.getLogger()
configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.render_to_log_kwargs,
#        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Global constants
WORKSPACE = os.environ['WORKSPACE'].rstrip('/') + '/'
COVERAGE_REPORTS_DIR = os.path.join(WORKSPACE, "src/coverage_reports/")
# Ensure coverage directory exists
if not os.path.isdir(COVERAGE_REPORTS_DIR):
    os.makedirs(COVERAGE_REPORTS_DIR, exist_ok=True)

padmin_conn_args = { 'host':os.environ.get('TAP_ADMINHOST'), 'port':int(os.environ.get('TAP_ADMINPORT')), 'user':os.environ.get('TAP_ADMINUSERNAME'), 'passwd':os.environ.get('TAP_ADMINPASSWORD') }
proot_conn_args = { 'host':os.environ.get('TAP_HOST'), 'port':int(os.environ.get('TAP_PORT')), 'user':os.environ.get('TAP_ROOTUSERNAME'), 'passwd':os.environ.get('TAP_ROOTPASSWORD') }
puser_conn_args = { 'host':os.environ.get('TAP_HOST'), 'port':int(os.environ.get('TAP_PORT')), 'user':os.environ.get('TAP_USERNAME'), 'passwd':os.environ.get('TAP_PASSWORD') }
mroot_conn_args = { 'host':os.environ.get('TAP_ROOTHOST'), 'port':int(os.environ.get('TAP_ROOTPORT')), 'user':os.environ.get('TAP_ROOTUSERNAME'), 'passwd':os.environ.get('TAP_ROOTPASSWORD') }
muser_conn_args = { 'host':os.environ.get('TAP_ROOTHOST'), 'port':int(os.environ.get('TAP_ROOTPORT')), 'user':os.environ.get('TAP_USERNAME'), 'passwd':os.environ.get('TAP_PASSWORD') }


# List of internal tests that require a at least the specified ProxySQL version:
internal_tap_tests_versions = [
    ('deprecate_eof_cache-t', "2.1.0"),
    ('eof_cache_mixed_flags-t', "2.1.0"),
    ('eof_conn_options_check-t', "2.1.0"),
    ('eof_mixed_flags_queries-t', "2.1.0"),
    ('eof_packet_mixed_queries-t', "2.1.0"),
    ('eof_test_ps_async-t', "2.1.0"),
    ('ok_packet_mixed_queries-t', "2.1.0"),
    ('ok_test_ps_async-t', "2.1.0"),
    ('eof_mixed_flags_queries-t', "2.4.0"),
]

##
# @brief Tap tests that require to be executed with an specific OpenSSL configuration.
# @details For the tests on this list, the env supplied to POpen call for launching the test
#  includes the variable 'OPENSSL_CONF', pointing to an OpenSSL config file with security level
#  set to '0'.
zero_sec_level_tap_tests = ["test_mysql-tls_version-t"]

def timer(func):
    def wrapper(*args, **kwargs):
        t = time.process_time()
        res = func(*args, **kwargs)
        log.debug(f"Timed '{func.__name__}' : {time.process_time() - t}s")
        return res
    return wrapper

def timer_warn1s(func):
    def wrapper(*args, **kwargs):
        t = time.process_time()
        res = func(*args, **kwargs)
        t = time.process_time() - t
        log.debug(f"Timed '{func.__name__}' : {t}s")
        if t > 1.0:
            log.critical(f"WARNING: Timed '{func.__name__}' : {t}s")
        return res
    return wrapper

class ProxySQLTester:

    def __init__(self, config_file, coverage):
        self.configuration = utils.init_config(config_file)
        self.padmin_conn = utils.open_mysql_conn(**padmin_conn_args)
#        self.proot_conn = utils.open_mysql_conn(**proot_conn_args)
#        self.puser_conn = utils.open_mysql_conn(**puser_conn_args)
        self.padmin_vers = '2.0.0'
        self.coverage = coverage

    def jsonify(self, json_data):
        return json.dumps(json_data, indent=4)

    def get_config(self):
        return (self.configuration)

    def padmin_command(self, command, display=False):
        with self.padmin_conn.cursor() as cursor:
            cursor.execute(command)
            result = cursor.fetchall()
        if display:
            log.debug(result)
        return result

    def proot_command(self, command, display=False):
        with self.proot_conn.cursor() as cursor:
            cursor.execute(command)
            result = cursor.fetchall()
        if display:
            log.debug(result)
        return result

    def puser_command(self, command, display=False):
        with self.puser_conn.cursor() as cursor:
            cursor.execute(command)
            result = cursor.fetchall()
        if display:
            log.debug(result)
        return result

    def log_test_run(self, run):
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        #log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")

        # run one of the tests 'run_XXXXX'
        rc, result, summary = getattr(psqlt, f'run_{run}')

        display_test_logs(run, rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)

        # generate coverage report for non-tap tests
        if self.coverage and 'tap_' not in run:
            generate_stage_coverage_report(padmin_conn_args, psqlt, f'3_1_{run}')

        log.info(f"Running '{run}' DONE")
        #log.info(f"Fulllog '{run}' http://localhost:28080/job/{os.environ['WORKSPACE']}/ws/ci_tests_logs/{script}/{run}.log")
        log.info(f"Fulllog '{run}' http://localhost:28080/job/{os.environ['WORKSPACE']}/ws/ci_tests_logs/{script}/tests/")
        #log.removeHandler(log.handlers[-1])

        return rc

    def run_benchmark(self):
        logs = []
        summary = []

        try:
            rc = 0
            self.padmin_command('select * from stats_mysql_connection_pool_reset')
            benchmark_script_path = os.path.expandvars(self.configuration['GLOBAL']['BENCHMARK_SCRIPT'])
            benchmark_result = utils.check_output(benchmark_script_path).decode('utf-8')
            conn_pool_info = self.padmin_command('select * from stats_mysql_connection_pool WHERE hostgroup IN (0,1)')
            for server in conn_pool_info:
                if int(server['ConnERR']) > 0 or int(server['ConnOK']) < 1:
                    log.critical('{srv_host}:{srv_port} ConnOK:{ConnOK} / ConnERR:{ConnERR}'.format(**server))
                    rc = 1
                else:
                    log.debug('OK for {srv_host}:{srv_port} ConnOK:{ConnOK} / ConnERR:{ConnERR}'.format(**server))

            for line in benchmark_result.split('\n'):
                if 'queries:' in line or 'transactions:' in line:
                    log.debug('Sysbench {}'.format(line))
                if '95th percentile:' in line:
                    log.debug('Sysbench latency {}'.format(line))

            return rc, logs, summary
        except Exception as e:
            log.critical('Benchmark failed due to {}'.format(e))
            log.exception(e)
            return 1, logs, summary

    def run_change_user_test(self):
        logs = []
        summary = []

        try:
            cbcub = self.padmin_command('select Variable_Value from stats_mysql_global '
                                        'where variable_name = "Com_backend_change_user";')[0]

            log.debug('Com_backend_change_user before test - {}'.format(cbcub))

            # While user `root` connection is open, open another for `testuser` and interact with DB:
#            pmysql_user_conn = utils.open_mysql_conn(**puser_conn_args)
#            user_conn_args = { 'host':'127.0.0.1', 'port':6033, 'user':'testuser', 'passwd':'testuser' }
#            pmysql_user_conn = utils.open_mysql_conn(**user_conn_args)

            puser_conn = utils.open_mysql_conn(**puser_conn_args)
            with puser_conn.cursor() as cursor:
#                cursor.execute('SELECT * FROM sysbench.sbtest1 LIMIT 1')
                cursor.execute('SELECT 1')
                puser_result = cursor.fetchall()
            puser_conn.close()

#            root_result = self.proot_command('SELECT * FROM sysbench.sbtest1 LIMIT 1')
            proot_conn = utils.open_mysql_conn(**proot_conn_args)
            with proot_conn.cursor() as cursor:
                cursor.execute('SELECT 1')
                proot_result = cursor.fetchall()
            proot_conn.close()

            log.debug('`root` data - {}'.format(proot_result))
            log.debug('`user` data - {}'.format(puser_result))

            cbcua = self.padmin_command('select Variable_Value from stats_mysql_global '
                                        'where variable_name = "Com_backend_change_user";')[0]

            log.debug('Com_backend_change_user after test - {}'.format(cbcua))

            if cbcub['Variable_Value'] == cbcua['Variable_Value']:
                log.critical('Com_backend_change_user did not increment {}'.format(cbcub))
                return 1, logs, summary
            else:
                log.debug('Com_backend_change_user incremented by {}'.format(int(cbcua['Variable_Value']) - int(cbcub['Variable_Value'])))
                return 0, logs, summary
        except Exception as e:
            log.critical('Change user test failed due to {}'.format(e))
            return 1, logs, summary

    def run_stats_table_check(self):
        rc = 0
        logs = []
        summary = []
        ignored_tables = [
            'stats_mysql_client_host_cache',
            'stats_proxysql_servers_status',
            'stats_mysql_client_host_cache_reset',
            'stats_mysql_gtid_executed',
            'stats_proxysql_message_metrics',
            'stats_proxysql_message_metrics_reset',
            'stats_mysql_processlist',  # 0 if no connections open
            'stats_mysql_query_events',  # 0 if no connections open
            
            # enable releavant pgsql stats once ready
            'stats_pgsql_client_host_cache',
            'stats_pgsql_client_host_cache_reset',
            'stats_pgsql_errors',
            'stats_pgsql_errors_reset',
            'stats_pgsql_free_connections',
            'stats_pgsql_processlist',
            'stats_pgsql_query_digest',
            'stats_pgsql_query_digest_reset',
            'stats_pgsql_query_rules',
            'stats_pgsql_prepared_statements_info',

            # MCP work in progres
            'stats_mcp_.*'
        ]

        if int(os.environ.get('PROXYSQL_CLUSTER', 0)) == 0:
            ignored_tables += [
                'stats_proxysql_servers_checksums',
                'stats_proxysql_servers_clients_status',
                'stats_proxysql_servers_metrics',
            ]

        puser_conn = utils.open_mysql_conn(**puser_conn_args)
        with puser_conn.cursor() as cursor:
            cursor.execute('SELECT version()')
            puser_result = cursor.fetchall()
        puser_conn.close()

        stl = self.padmin_command('show tables from stats')
        for st in stl:
            log.debug(f"Checking stats.{st['tables']} table with count(*)")
            ct = self.padmin_command('select count(*) cnt from stats.{}'.format(st['tables']))
            for ctrow in ct:
                if int(ctrow['cnt']) < 1:
                    #if st['tables'] in ignored_tables:
                    if any(re.match(f"^{it}$", st['tables']) for it in ignored_tables):
                        log.debug(f"Ignoring 'stats.{st['tables']}' expected to be 0")
                        summary.append((f"stats.{st['tables']}", None))
                    else:
                        log.critical(f"Table 'stats.{st['tables']}' has '{ctrow['cnt']}' rows")
                        summary.append((f"stats.{st['tables']}", 1))
                        rc = 1
                else:
                    log.debug(f"Table 'stats.{st['tables']}' has '{ctrow['cnt']}' rows")
                    summary.append((f"stats.{st['tables']}", 0))

        log.debug('All stats tables are populated')

        return rc, logs, summary

    def filtered_by_version(self, test_path, proxysql_v, groups=None):
        filtered = (False, '')

        # Check hardcoded version requirements (legacy)
        for tap_test in internal_tap_tests_versions:
            tap_test_n = tap_test[0]
            tap_test_v = tap_test[1]
            smaller_version = version.parse(proxysql_v) < version.parse(tap_test_v)

            if tap_test_n in test_path and smaller_version:
                filtered = (True, tap_test_v)
                break

        # Check @proxysql_min_version tag from groups.json
        if not filtered[0] and groups:
            test_basename = os.path.basename(test_path)
            test_groups = groups.get(test_basename, [])
            for entry in test_groups:
                if isinstance(entry, str) and entry.startswith("@proxysql_min_version:"):
                    min_ver = entry.split(":", 1)[1]
                    if version.parse(proxysql_v) < version.parse(min_ver):
                        filtered = (True, min_ver)
                    break

        return filtered

    def filtered_by_regex(self, test_path, pattern_var):
        filtered = (False, '')

        allmatch = [ '^.*$' ] if 'INCL' in pattern_var else []
        patterns = [ '^' + p + '$' for p in os.environ[pattern_var].strip('() ').split() ] or allmatch
        for pattern in patterns:
            tap_re = re.compile(pattern)
            match = tap_re.match(os.path.basename(test_path))
            if match:
                filtered = (True, tap_re.pattern)

        return filtered

    def execute_tap_tests(self, tests_path, internal):
        @timer_warn1s
        def reconfigure_proxysql():
            # we refresh at the beginning, before starting the test
            self.padmin_command('LOAD MYSQL VARIABLES FROM DISK')
            self.padmin_command('LOAD MYSQL VARIABLES TO RUNTIME')
            self.padmin_command('LOAD ADMIN VARIABLES FROM DISK')
            self.padmin_command('LOAD ADMIN VARIABLES TO RUNTIME')
            self.padmin_command('LOAD MYSQL USERS FROM DISK')
            self.padmin_command('LOAD MYSQL USERS TO RUNTIME')
            self.padmin_command('LOAD MYSQL SERVERS FROM DISK')
            self.padmin_command('LOAD MYSQL SERVERS TO RUNTIME')
            self.padmin_command('LOAD PROXYSQL SERVERS FROM DISK')
            self.padmin_command('LOAD PROXYSQL SERVERS TO RUNTIME')
            self.padmin_command('LOAD MYSQL QUERY RULES FROM DISK')
            self.padmin_command('LOAD MYSQL QUERY RULES TO RUNTIME')
            self.padmin_command('LOAD DEBUG FROM DISK')
            self.padmin_command('LOAD DEBUG TO RUNTIME')
            # refreshing pgsql tables
            if version.parse(self.padmin_vers) >= version.parse("3.0.0"):
                self.padmin_command('LOAD PGSQL VARIABLES FROM DISK')
                self.padmin_command('LOAD PGSQL VARIABLES TO RUNTIME')
                self.padmin_command('LOAD PGSQL USERS FROM DISK')
                self.padmin_command('LOAD PGSQL USERS TO RUNTIME')
                self.padmin_command('LOAD PGSQL SERVERS FROM DISK')
                self.padmin_command('LOAD PGSQL SERVERS TO RUNTIME')
                self.padmin_command('LOAD PGSQL QUERY RULES FROM DISK')
                self.padmin_command('LOAD PGSQL QUERY RULES TO RUNTIME')

            # This operations are performed to increase coverage.
            # They should have **no-impact** in test execution.
            self.padmin_command('SAVE MYSQL VARIABLES FROM RUNTIME')
            self.padmin_command('SAVE ADMIN VARIABLES FROM RUNTIME')
            self.padmin_command('SAVE MYSQL USERS FROM RUNTIME')
            self.padmin_command('SAVE MYSQL SERVERS FROM RUNTIME')
            self.padmin_command('SAVE PROXYSQL SERVERS FROM RUNTIME')
            self.padmin_command('SAVE MYSQL QUERY RULES FROM RUNTIME')
            self.padmin_command('SAVE MYSQL FIREWALL FROM RUNTIME')
            self.padmin_command('SAVE RESTAPI FROM RUNTIME')
            # NOTE: Only valid if 'GloMyAuth' is initialized
            # self.padmin_command('SAVE LDAP VARIABLES FROM RUNTIME')
            self.padmin_command('SAVE SCHEDULER FROM RUNTIME')
            self.padmin_command('SAVE SQLITESERVER VARIABLES FROM RUNTIME')
            # NOTE: Only valids for 'CLICKHOUSE' builds.
            # self.padmin_command('SAVE CLICKHOUSE USERS FROM RUNTIME')
            # self.padmin_command('SAVE CLICKHOUSE VARIABLES FROM RUNTIME')
            # saving pgsql tables
            if version.parse(self.padmin_vers) >= version.parse("3.0.0"):
                self.padmin_command('SAVE PGSQL VARIABLES FROM RUNTIME')
                self.padmin_command('SAVE PGSQL USERS FROM RUNTIME')
                self.padmin_command('SAVE PGSQL SERVERS FROM RUNTIME')
                self.padmin_command('SAVE PGSQL QUERY RULES FROM RUNTIME')
                self.padmin_command('SAVE PGSQL FIREWALL FROM RUNTIME')

            # waiting 5 seconds before running the test.
            # This is a random amount of time that allows monitoring to reconfigure proxysql.
            # This solves cases in which the TAP test itself immediately reconfigures proxysql
            # ending in some race condition.
            # For example , test_ps_large_result-t run "delete from mysql_query_rules"
            time.sleep(5)
            log.debug("SELECT * FROM stats_mysql_processlist;")
            self.padmin_command("SELECT * FROM stats_mysql_processlist;", True)

        @timer_warn1s
        def dump_runtime(msg, dumpid=0):
            if int(os.environ.get('TEST_PY_TAP_DUMP_RUNTIME', 1)):
                if dumpid == 0:
                    tables = [ t['tables'] for t in self.padmin_command("SHOW tables FROM stats_history;", False) if t['tables'].startswith('runtime_mysql_users_') ]
                    if tables:
                        dumpid = int(sorted(tables)[-1].rsplit('_', 1)[-1]) + 1
                    dumpid = f"{dumpid:04d}"
                log.debug(f"{msg} dumpid = '{dumpid}'")

                #log.debug("RUNTIME_TABLES")
                tables = (
                            ('runtime_proxysql_servers', "2.0.0"),
                            ('runtime_mysql_users', "2.0.0"),
                            ('runtime_mysql_query_rules', "2.0.0"),
                            ('runtime_mysql_servers', "2.0.0"),
                            ('runtime_mysql_replication_hostgroups', "2.0.0"),
                            ('runtime_mysql_galera_hostgroups', "2.0.0"),
                            ('runtime_mysql_group_replication_hostgroups', "2.0.0"),
                            ('runtime_pgsql_users', "3.0.0"),
                            ('runtime_pgsql_query_rules', "3.0.0"),
                            ('runtime_pgsql_servers', "3.0.0"),
                            ('runtime_pgsql_replication_hostgroups', "3.0.0")
                        )
                for table, vers in tables:
                    if version.parse(self.padmin_vers) >= version.parse(vers):
                        #log.debug(f"{table.upper()}")
                        self.padmin_command(f"DROP TABLE IF EXISTS stats_history.{table}_{dumpid}", False)
                        self.padmin_command(f"CREATE TABLE stats_history.{table}_{dumpid} AS SELECT * FROM main.{table}", False)

        @timer_warn1s
        def dump_stats(msg, dumpid=0):
            if int(os.environ.get('TEST_PY_TAP_DUMP_STATS', 1)):
                if dumpid == 0:
                    tables = [ t['tables'] for t in self.padmin_command("SHOW tables FROM stats_history;", False) if t['tables'].startswith('stats_mysql_users_') ]
                    if tables:
                        dumpid = int(sorted(tables)[-1].rsplit('_', 1)[-1]) + 1
                    dumpid = f"{dumpid:04d}"
                log.debug(f"{msg} dumpid = '{dumpid}'")

                #log.debug("STATS_TABLES")
                tables = [ t['tables'] for t in self.padmin_command("SHOW tables FROM stats;", False) if not t['tables'].endswith('_reset') ]

                for table in tables:
                    # skip these tables
                    if table in ('stats_mysql_commands_counters'):
                        continue
                    #log.debug(f"{table.upper()}")
                    self.padmin_command(f"DROP TABLE IF EXISTS stats_history.{table}_{dumpid}", False)
                    self.padmin_command(f"CREATE TABLE stats_history.{table}_{dumpid} AS SELECT * FROM stats.{table}", False)

        @timer_warn1s
        def prep_monitor(msg):
            log.debug(msg)
            try:
                self.padmin_command("DROP TABLE IF EXISTS stats_history.mysql_server_connect_log")
                self.padmin_command("""
CREATE TABLE stats_history.mysql_server_connect_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    connect_success_time_us INT DEFAULT 0,
    connect_error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us));
                """)
            except:
                pass
            try:
                self.padmin_command("DROP TABLE IF EXISTS stats_history.mysql_server_ping_log")
                self.padmin_command("""
CREATE TABLE stats_history.mysql_server_ping_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    ping_success_time_us INT DEFAULT 0,
    ping_error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us));
                """)
            except:
                pass
            try:
                self.padmin_command("DROP TABLE IF EXISTS stats_history.mysql_server_replication_lag_log")
                self.padmin_command("""
CREATE TABLE stats_history.mysql_server_replication_lag_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    repl_lag INT DEFAULT 0,
    error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us));
                """)
            except:
                pass
            try:
                self.padmin_command("DROP TABLE IF EXISTS stats_history.mysql_server_read_only_log")
                self.padmin_command("""
CREATE TABLE stats_history.mysql_server_read_only_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    read_only INT DEFAULT 1,
    error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us));
                """)
            except:
                pass

        @timer_warn1s
        def dump_monitor(msg):
            log.debug(msg)
            self.padmin_command("INSERT OR IGNORE INTO stats_history.mysql_server_connect_log SELECT * FROM monitor.mysql_server_connect_log")
            self.padmin_command("INSERT OR IGNORE INTO stats_history.mysql_server_ping_log SELECT * FROM monitor.mysql_server_ping_log")
            self.padmin_command("INSERT OR IGNORE INTO stats_history.mysql_server_replication_lag_log SELECT * FROM monitor.mysql_server_replication_lag_log")
            self.padmin_command("INSERT OR IGNORE INTO stats_history.mysql_server_read_only_log SELECT * FROM monitor.mysql_server_read_only_log")

        @timer_warn1s
        def shuffle_certs(cert_bundle):
            # prepare system CA cert bundle
            if not os.path.isfile(os.environ["REGULAR_INFRA_DATADIR"] + '/caservers-cert-bundle.pem'):
#                print(">>> GENERATING 'caservers-cert-bundle.pem' <<<")
                with open(os.environ["REGULAR_INFRA_DATADIR"] + '/caservers-cert-bundle.pem', 'wb') as wf:
                    for caf in [ f for f in os.listdir('/etc/ssl/certs/') if f.endswith('.pem') ]:
                        with open('/etc/ssl/certs/' + caf, 'rb') as rf:
                            wf.write(rf.read())

            # prepare combined system and db CA cert bundle
            if not os.path.isfile(os.environ["REGULAR_INFRA_DATADIR"] + '/' + cert_bundle):
#                print(f">>> GENERATING '{cert_bundle}' <<<")
                with open(os.environ["REGULAR_INFRA_DATADIR"] + '/' + cert_bundle, 'wb') as wf:
                    try:
                        with open(os.environ["REGULAR_INFRA_DATADIR"] + '/dbservers-cert-bundle.pem', 'rb') as rf:
                            wf.write(rf.read())
                    except:
                        log.info('Failed to get infra CERTs - no infra running?')
                    with open(os.environ["REGULAR_INFRA_DATADIR"] + '/caservers-cert-bundle.pem', 'rb') as rf:
                        wf.write(rf.read())

            # shuffle combined CA cert bundle
            with open(os.environ["REGULAR_INFRA_DATADIR"] + '/' + cert_bundle, 'rb') as rf:
                certs = rf.read().decode('utf-8').strip()
                certs = re.compile('(?<=-)\n+(?=-)').split(certs)
            random.shuffle(certs)
            with open(os.environ["REGULAR_INFRA_DATADIR"] + '/' + cert_bundle, 'wb') as wf:
                wf.write(('\n'.join(certs) + '\n').encode('utf-8'))

        @timer_warn1s
        def connection_test():
            def test_command(command):
                conn = utils.open_mysql_conn(**puser_conn_args)
                with conn.cursor() as cursor:
                   cursor.execute(command)
                   result = cursor.fetchall()
                conn.close()

            test_command("DO 1;")
            test_command("SELECT 1;")
            test_command("SELECT @@version;")
            test_command("SELECT version();")

        def disk_usage():
            dus = os.environ.get("TEST_PY_TAP_DISK_USAGE", "").strip()
            if dus:
                #result = subprocess.run("df -h | grep -P 'Filesystem|/dev/root'", shell=True)
                result = subprocess.run("df -h | grep -v 'docker'", shell=True)
                #print(result.stdout.decode())
                for du in dus.split():
                    result = subprocess.run(f"du -sh {du}", shell=True)
                    #print(result.stdout.decode())

        rc = 0
        logs = []
        summary = []
        fo_num = -2
        fo_cmd = ''
        tap_tests = []

        # Initialize variables before try block to avoid UnboundLocalError in validation
        TAP_GROUP = os.environ.get('TAP_GROUP', '')
        group_has_tests = False
        groups = {}

        if (internal):
            TAP = "INTERNAL TAP"
        else:
            TAP = "TAP"

        try:
            # Detect ProxySQL version to isolate unit test execution
            ver = self.padmin_command('select variable_value from global_variables where variable_name = "admin-version";')[0]
            fmt_ver = ver['variable_value'].split('-')[0]
            log.info(f"Detected admin-version='{fmt_ver}'")
            self.padmin_vers = fmt_ver

            tests_folder = os.path.basename(os.path.dirname(tests_path))
            dump_runtime(f"ProxySQL RUNTIME dump before:", f"{tests_folder}_init_0000")
            dump_stats(f"ProxySQL STATS dump before:", f"{tests_folder}_init_0000")
            prep_monitor(f"ProxySQL MONITOR prep to disk before test run.")
            dump_monitor(f"ProxySQL MONITOR dump to disk before test run.")

            # load groups json
            TAP_GROUP = os.environ.get('TAP_GROUP', '')
            group_has_tests = False

            if TAP_GROUP:
                log.info(f"Loading TAP_GROUP memberships for '{TAP_GROUP}' ... ")
                if os.path.isfile(f"{WORKSPACE}/test/tap/groups/groups.json"):
                    with open(f"{WORKSPACE}/test/tap/groups/groups.json") as jf:
                        groups = json.load(jf)
                    # Check if any tests belong to this group
                    for test_name, test_groups in groups.items():
                        if TAP_GROUP in test_groups:
                            group_has_tests = True
                            break

                    if group_has_tests:
                        log.info(f"Group '{TAP_GROUP}' has associated tests in groups.json")
                    else:
                        log.critical(
                            f"Group '{TAP_GROUP}' has no associated tests in groups.json. "
                            f"Refusing to fall back to running all TAP tests — aborting. "
                            f"Register tests for this group in test/tap/groups/groups.json, "
                            f"or unset TAP_GROUP to run the full suite intentionally."
                        )
                        sys.exit(1)
                else:
                    log.critical(
                        f"No groups.json found but TAP_GROUP='{TAP_GROUP}' is set. "
                        f"Refusing to fall back to running all TAP tests — aborting."
                    )
                    sys.exit(1)
            else:
                # No TAP_GROUP specified - load all groups for regular group membership checking
                log.info("No TAP_GROUP specified - loading all groups for membership checking")
                if os.path.isfile(f"{WORKSPACE}/test/tap/groups/groups.json"):
                    with open(f"{WORKSPACE}/test/tap/groups/groups.json") as jf:
                        groups = json.load(jf)
                    for t in sorted(groups):
                        if t == []:
                            log.warning(f"WARN: TAP test '{t}' is not member of any groups!")
                        if t == ['default']:
                            log.warning(f"WARN: TAP test '{t}' is only in the 'default' group!")
                else:
                    log.warning(f"WARN: no group membership file!")
                    groups = {}

            # Load group-specific environment variables if TAP_GROUP is set
            if TAP_GROUP:
                group_env_file = f"{WORKSPACE}/test/tap/groups/{TAP_GROUP}/env.sh"
                # Fallback to base group if subgroup env.sh doesn't exist (e.g., legacy-g1 -> legacy)
                base_group = re.sub(r'[-_]g[0-9]+.*$', '', TAP_GROUP)
                if not os.path.isfile(group_env_file) and base_group != TAP_GROUP:
                    group_env_file = f"{WORKSPACE}/test/tap/groups/{base_group}/env.sh"
                if os.path.isfile(group_env_file):
                    log.info(f"Loading group-specific environment from {group_env_file}")
                    try:
                        # Source the group env file to override environment variables (using . for portability)
                        result = subprocess.run(f". {group_env_file} && env",
                                              shell=True, capture_output=True, text=True)
                        if result.returncode == 0:
                            # Parse and update environment variables
                            for line in result.stdout.split('\n'):
                                if '=' in line and not line.startswith('_'):
                                    key, value = line.split('=', 1)
                                    os.environ[key] = value
                                    log.debug(f"Group env override: {key}={value}")
                        else:
                            log.error(f"Failed to source group env file: {result.stderr}")
                    except Exception as e:
                        log.error(f"Error loading group environment: {e}")
                else:
                    log.debug(f"No group-specific env.sh found for '{TAP_GROUP}'")

                # Log updated shuffle limit after group env loading
                shuffle_limit = int(os.environ.get('TEST_PY_TAP_SHUFFLE_LIMIT', 0))
                if shuffle_limit > 0:
                    group_mode = "specific tests" if group_has_tests else "all TAP tests"
                    log.info(f"Group '{TAP_GROUP}' will run {shuffle_limit} shuffled {group_mode}")

            # Impose alphabetical order for tests execution
            tap_tests = sorted(glob.glob(tests_path))
            log.debug(f"FILES : {tap_tests}")

            # Shuffle and limit tests if TEST_PY_TAP_SHUFFLE_LIMIT is defined and > 0
            shuffle_limit = int(os.environ.get('TEST_PY_TAP_SHUFFLE_LIMIT', 0))
            if shuffle_limit > 0:
                log.info(f"Shuffling TAP tests and limiting to top {shuffle_limit}")
                random.shuffle(tap_tests)
                if shuffle_limit < len(tap_tests):
                    tap_tests = tap_tests[:shuffle_limit]
                    log.info(f"Limited to {shuffle_limit} shuffled tests from {len(tap_tests)} total tests")
                else:
                    log.info(f"Using all {len(tap_tests)} shuffled tests (shuffle_limit={shuffle_limit} is larger than available tests)")
                log.info(f"Test list ({len(tap_tests)} tests): {[os.path.basename(t) for t in tap_tests]}")

            log_path = f'{tests_logs_path}/{script}/{tests_folder}/'
            os.makedirs(log_path, exist_ok=True)
            for fo_num, fo_cmd in enumerate(tap_tests):

                # omitted from groups.json (only check if groups.json has content and TAP_GROUP is not set or group has tests)
                if groups and (not TAP_GROUP or group_has_tests) and os.path.basename(fo_cmd) not in groups:
                    log.debug(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' omitted.")
                    log.debug(f"omitted: not present in groups.json: '{os.path.realpath(fo_cmd)}'")
                    summary.append((fo_cmd, None))
                    continue

                # filtering
                f_res = self.filtered_by_version(fo_cmd, fmt_ver, groups)
                if f_res[0]:
                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' skipped.")
                    log.debug(f"skip: Requires ProxySQL >= {f_res[1]}, current version: {fmt_ver}")
                    summary.append((fo_cmd, None))
                    continue

                # group membership (only check if TAP_GROUP is set and group has tests)
                if TAP_GROUP and groups and group_has_tests and TAP_GROUP not in groups.get(os.path.basename(fo_cmd), []):
                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' ignored.")
                    log.debug(f"ignored: not member of test group: '{TAP_GROUP}'")
                    summary.append((fo_cmd, None))
                    continue

                # includes
                pattern_var = 'TEST_PY_TAP' + internal * 'INT' + '_INCL'
                f_res = self.filtered_by_regex(fo_cmd, pattern_var)
                if not f_res[0]:
                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' skipped.")
                    log.debug(f"skip: Excluded by NOT matching {pattern_var} regex: '{f_res[1]}'")
                    summary.append((fo_cmd, None))
                    continue

                # excludes
                pattern_var = 'TEST_PY_TAP' + internal * 'INT' + '_EXCL'
                f_res = self.filtered_by_regex(fo_cmd, pattern_var)
                if f_res[0]:
                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' skipped.")
                    log.debug(f"skip: Excluded by matching {pattern_var} regex: '{f_res[1]}'")
                    summary.append((fo_cmd, None))
                    continue

                # missing test executable
                if not os.path.isfile(fo_cmd):
                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' missing.")
                    log.debug(f"missing: file or symlink target does not exist: '{os.path.realpath(fo_cmd)}'")
                    summary.append((fo_cmd, None))
                    continue

                logh = logging.FileHandler(f'{log_path}/{os.path.basename(fo_cmd)}.log', 'w')
                logf = logging.Formatter(fmt='[%(asctime)s] %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
                logh.setFormatter(logf)
                log.addHandler(logh)

                # Get timeout for TAP test (0 = no timeout)
                tap_timeout = int(os.environ.get('TEST_TAP_TIMEOUT', 0))
                log.info(f"TEST_TAP_TIMEOUT environment variable = '{os.environ.get('TEST_TAP_TIMEOUT')}', using timeout = {tap_timeout}")

                time.sleep(random.randint(5, 15))
                log.debug("================================================================================")
                log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' to be executed now ...")
                log.debug("================================================================================")
                self.padmin_command(f"LOGENTRY '{TAP} test {fo_num+1}/{len(tap_tests)} \'{os.path.basename(fo_cmd)}\' to be executed now ...'")

                shuffle_certs('cert-bundle-rnd.pem')
                shuffle_certs('cert-bundle-rnd1.pem')
                shuffle_certs('cert-bundle-rnd2.pem')
                shuffle_certs('cert-bundle-rnd3.pem')

                # Reconnect with ProxySQL Admin, just in case test is issuing
                try:
                    self.padmin_conn = utils.open_mysql_conn(**padmin_conn_args)
                except Exception as e:
                    log.critical(f"TAP test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' - admin connection failed !!!")
                    #logging.error(e, exc_info=True)
                    log.exception(e, exc_info=True)
                    rc = rc + 1
                    summary.append((fo_cmd, None))
                    if rc and int(os.environ['TEST_PY_EXIT_ON_FAIL_TEST']):
                        sys.exit(1)
                    continue

                reconfigure_proxysql()
                dump_runtime(f"ProxySQL RUNTIME dump before:", f"{tests_folder}_before_{fo_num+1:04d}")
                dump_stats(f"ProxySQL STATS dump before:", f"{tests_folder}_before_{fo_num+1:04d}")
                dump_monitor(f"ProxySQL MONITOR dump before")

                # Set the env required for specific tests
                #log.debug(f"os.environ.get('LD_LIBRARY_PATH') = {os.environ.get('LD_LIBRARY_PATH')}")
                os.environ['LD_LIBRARY_PATH'] = f"{os.environ.get('TEST_DEPS_PATH')}:{os.environ.get('TAP_DEPS_PATH')}"
                # disable leak detection for TAP tests
                os.environ['ASAN_OPTIONS'] = "abort_on_error=0:disable_coredump=0:unmap_shadow_on_exit=1:halt_on_error=0:fast_unwind_on_fatal=1:detect_leaks=0:detect_stack_use_after_return=0"
                tap_env = os.environ.copy()
                test_file = os.path.split(fo_cmd)[1]

                if test_file:
                    test_file = str(test_file.strip())

                if test_file in zero_sec_level_tap_tests:
                    tap_env["OPENSSL_CONF"] = (
                        os.environ.get("WORKSPACE", ".") + "/test-scripts/datadir/openssl_level_zero.cnf"
                    )

                try:
                    fop = subprocess.Popen(fo_cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0, env=tap_env)
                except Exception as e:
                    log.critical(f"TAP test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' - test threw an exception !!!: {e}")
                    self.padmin_command(f"LOGENTRY '{TAP} test {fo_num+1}/{len(tap_tests)} \'{os.path.basename(fo_cmd)}\' - test threw an exception !!!'")
                    log.exception(e, exc_info=True)
                    rc = rc + 1
                    summary.append((fo_cmd, None))
                    log.removeHandler(log.handlers[-1])
                    if rc and int(os.environ['TEST_PY_EXIT_ON_FAIL_TEST']):
                        sys.exit(1)
                    continue

                # Run test with timeout if specified.
                #
                # The read has to be non-blocking for tap_timeout to mean
                # anything. readline() blocks until a full line arrives, so on
                # a test that hangs while producing no output -- precisely the
                # case this timeout exists to catch -- the deadline check below
                # it was simply never reached, and the test ran until CI killed
                # the job. select() bounds the wait so the check always runs,
                # and reading raw chunks rather than lines means a test that
                # stops mid-line cannot wedge us either.
                try:
                    start_time = time.time()
                    buf = b''
                    while True:
                        if tap_timeout > 0 and (time.time() - start_time) > tap_timeout:
                            raise subprocess.TimeoutExpired(fop.args, tap_timeout)

                        wait = 1.0
                        if tap_timeout > 0:
                            wait = max(0.0, min(1.0, tap_timeout - (time.time() - start_time)))
                        ready, _, _ = select.select([fop.stdout], [], [], wait)

                        if ready:
                            chunk = os.read(fop.stdout.fileno(), 65536)
                            if not chunk:
                                break                     # EOF: test finished
                            buf += chunk
                            while b'\n' in buf:
                                line, buf = buf.split(b'\n', 1)
                                log.debug(f"msg: {line.decode('utf-8', 'replace').strip()}")
                        elif fop.poll() is not None:
                            break

                    if buf:                               # trailing partial line
                        log.debug(f"msg: {buf.decode('utf-8', 'replace').strip()}")

                    fop.wait()
                except subprocess.TimeoutExpired:
                    fop.kill()
                    log.critical(f"TAP test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' timed out after {tap_timeout} seconds")
                    self.padmin_command(f"LOGENTRY '{TAP} test {fo_num+1}/{len(tap_tests)} \'{os.path.basename(fo_cmd)}\' timed out after {tap_timeout} seconds'")
                    # Drain any remaining output
                    for line in fop.stdout:
                        log.debug(f"msg: {line.decode('utf-8', 'replace').strip()}")
                    # Reap the child. kill() signals but does not wait, so
                    # returncode stays None until we do -- and the shared exit
                    # path below evaluates abs(int(fop.returncode)), which
                    # raises TypeError on None. That path was unreachable while
                    # the timeout could never fire; now that it can, a timed-out
                    # test would abort the whole group instead of failing one
                    # test. wait() yields -SIGKILL, so the test scores non-zero.
                    fop.wait()
                except Exception as e:
                    log.critical(f"TAP test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' - test threw an exception !!!: {e}")
                    self.padmin_command(f"LOGENTRY '{TAP} test {fo_num+1}/{len(tap_tests)} \'{os.path.basename(fo_cmd)}\' - test threw an exception !!!'")
                    log.exception(e, exc_info=True)
                    rc = rc + 1
                    summary.append((fo_cmd, None))
                    log.removeHandler(log.handlers[-1])
                    if rc and int(os.environ['TEST_PY_EXIT_ON_FAIL_TEST']):
                        sys.exit(1)
                    continue

                self.padmin_command(f"LOGENTRY '{TAP} test {fo_num+1}/{len(tap_tests)} \'{os.path.basename(fo_cmd)}\' RC: {fop.returncode}'")
                self.padmin_command(f"PROXYSQL FLUSH LOGS")
                log.debug(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' RC: {fop.returncode}")

                # if returncode print extra info
                if fop.returncode != 0:
                    log.info(f"FAIL log '{os.path.basename(fo_cmd)}' {log_url_prefix}/{script}/{tests_folder}/{os.path.basename(fo_cmd)}.log")
                    log.debug("================================================================================")
                    time.sleep(1)
                    # Try to extract relevant proxysql.log entries, but handle missing log gracefully
                    try:
                        proxysql_log_path = f'{os.environ["REGULAR_INFRA_DATADIR"]}/proxysql.log'
                        if os.path.exists(proxysql_log_path):
                            with open(proxysql_log_path, 'rb') as px_log:
                                for line in px_log:
                                    if bytes(os.path.basename(fo_cmd), 'utf-8') in line:
                                        break
                                with open(f'{log_path}/{os.path.basename(fo_cmd)}.proxysql.log', 'wb') as test_px_log:
                                    test_px_log.write(line)
                                    for line in px_log:
                                        test_px_log.write(line)
                                        if bytes(os.path.basename(fo_cmd), 'utf-8') in line:
                                            break
                            log.info(f"FAIL log 'proxysql' {log_url_prefix}/{script}/{tests_folder}/{os.path.basename(fo_cmd)}.proxysql.log")
                        else:
                            log.error(f"ProxySQL log file not found at {proxysql_log_path}")
                            log.error(f"To fix: Ensure ProxySQL is configured to log to {proxysql_log_path}")
                            # Create empty proxysql log file to avoid missing file issues
                            with open(f'{log_path}/{os.path.basename(fo_cmd)}.proxysql.log', 'w') as test_px_log:
                                test_px_log.write(f"# ProxySQL log file not found at: {proxysql_log_path}\n")
                                test_px_log.write(f"# Expected to contain logs for test: {os.path.basename(fo_cmd)}\n")
                    except Exception as log_error:
                        log.error(f"Failed to read ProxySQL log: {log_error}")
                        # Continue without proxysql log extraction
#                    with open(f'{log_path}/{os.path.basename(fo_cmd)}.log', 'r') as test_log:
#                        for line in test_log:
#                            print(line, end='')
                log.handlers[-1].flush()
                log.removeHandler(log.handlers[-1])
                if fop.returncode == 0:
                    subprocess.run(f"gzip {log_path}/{os.path.basename(fo_cmd)}.log", shell=True)

                rc += abs(int(fop.returncode))
                summary.append((fo_cmd, fop.returncode))

                # create the coverage report for the executed test
#                if self.coverage:
#                    log.info(f"{TAP} test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' generating coverage report ...")
#
#                    generate_stage_coverage_report(
#                        padmin_conn_args,
#                        self,
#                        f"3_6_{internal*'internal_'}tap_test_{fo_num+1}_{os.path.basename(fo_cmd)}"
#                    )

                dump_runtime(f"ProxySQL RUNTIME dump after:", f"{tests_folder}_after_{fo_num+1:04d}")
                dump_stats(f"ProxySQL STATS dump after:", f"{tests_folder}_after_{fo_num+1:04d}")
                dump_monitor(f"ProxySQL MONITOR dump after")
                disk_usage()

                if rc and int(os.environ['TEST_PY_EXIT_ON_FAIL_TEST']):
                    sys.exit(1)

        except Exception as e:
            log.critical(f"TAP test {fo_num+1}/{len(tap_tests)} '{os.path.basename(fo_cmd)}' - Python exception !!!")
            #logging.error(e, exc_info=True)
            log.exception("Exception occurred during TAP test execution")
            rc = rc + 1
            summary.append((fo_cmd, None))

            if rc and int(os.environ['TEST_PY_EXIT_ON_FAIL_TEST']):
                sys.exit(1)

        return rc, logs, summary

    def collect_tap_workdirs(self, tap_workdir):
        # use predefined folders
        tap_workdirs = [ os.path.realpath(twd) for twd in tap_workdir.strip('() ').split() ]
        to_del = set()
        to_add = set()
        # discover sibling tap_tests* folders
        for twd in tap_workdirs:
            for ttg in sorted(glob.glob(f"{os.path.dirname(twd.rstrip('/'))}/tap_tests_*")):
                to_del.update(set( os.path.dirname(os.path.realpath(tt)) for tt in sorted(glob.glob(f"{ttg}/*-t")) ))
                to_add.add(os.path.realpath(ttg))

        tap_workdirs = [ twd for twd in tap_workdirs if twd not in to_del ]
        tap_workdirs.extend(to_add)

        return tap_workdirs

    def execute_hooks(self, glob_pattern):
        TAP_GROUP = os.environ.get('TAP_GROUP', '')
        if TAP_GROUP:
            log.info(f"TAP_GROUP: '{TAP_GROUP}'")
            hooks = glob.glob(f"{WORKSPACE}/test/tap/groups/{TAP_GROUP}/{os.path.basename(glob_pattern)}.bash")
            hooks += glob.glob(f"{WORKSPACE}/test/tap/groups/{re.compile('-g[0123456789]$').sub('', TAP_GROUP)}/{os.path.basename(glob_pattern)}.bash")
            hooks += glob.glob(f"{WORKSPACE}/test/tap/groups/{TAP_GROUP}/{os.path.basename(glob_pattern)}.sql")
            hooks += glob.glob(f"{WORKSPACE}/test/tap/groups/{re.compile('-g[0123456789]$').sub('', TAP_GROUP)}/{os.path.basename(glob_pattern)}.sql")
            log.info(f"TAP_GROUP_HOOKS_PTRN: test/tap/groups/{TAP_GROUP}/{os.path.basename(glob_pattern)}@(.bash|.sql)")
            log.info("TAP_GROUP_HOOKS: " + repr([os.path.basename(h).replace(WORKSPACE, '') for h in sorted(hooks)]))
        else:
            hooks = glob.glob(glob_pattern + ".bash")
            hooks += glob.glob(glob_pattern + ".sql")
            log.info(f"TAP_WORKDIR_HOOKS_PTRN: {glob_pattern.replace(WORKSPACE, '')}@(.bash|.sql)")
            log.info("TAP_WORKDIR_HOOKS: " + repr([os.path.basename(h).replace(WORKSPACE, '') for h in sorted(hooks)]))

        tap_env = os.environ.copy()
        for hook in sorted(hooks):
            if hook.endswith('.bash'):
                log.info(f"TAP {os.path.basename(hook).split('-')[0]}-hook executing: {os.path.basename(hook)}")
                log.info(f"executing hook: {hook.replace(WORKSPACE, '')}")
                p = subprocess.Popen(hook, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=tap_env)

#                fo_stdout, fo_stderr = p.communicate()
#                p.wait()

#                log.info(f"TAP {os.path.basename(hook).split('-')[0]}-hook executing: {os.path.basename(hook)}")
#                level = logging.CRITICAL if p.returncode else logging.DEBUG
#                log.log(level, f"executing hook: {hook}")
#                for l in fo_stdout.decode('utf-8').split('\n'):
#                    log.log(level, f"stdout: {l}")
#                for l in fo_stderr.decode('utf-8').split('\n'):
#                    log.log(level, f"stderr: {l}")

                # read stdout on the fly
                fop_buff = []
                while p.poll() is None:
                    for l in p.stdout:
                        l = l.decode('utf-8').strip()
                        log.info(f"msg: {l}")
                        fop_buff.append(f"msg: {l}")
                    time.sleep(1)
                assert p.returncode is not None

            if hook.endswith('.sql'):
                log.info(f"TAP {os.path.basename(hook).split('-')[0]}-hook executing: {os.path.basename(hook)}")
                log.info(f"executing hook: {hook.replace(WORKSPACE, '')}")
                with open(hook, 'rb') as sql:
                    for l in sql:
                        l = l.decode('utf-8').strip()
                        log.info(f"msg: {l}")
                        if not l:
                            continue
                        if l.startswith('#'):
                            continue
                        if l.startswith('--'):
                            continue
                        if l.startswith('//'):
                            continue
                        self.padmin_command(l)

#            if p.returncode:
#                return p.returncode

    def run_tap_tests(self):
        # Store original environment config for tap tests
        orig_workdir = os.environ['TAP_WORKDIR']

        ret_rc = 0
        ret_logs = []
        ret_summary = []
#        tap_workdirs = os.environ['TAP_WORKDIRS'].strip('() ').split()
        tap_workdirs = self.collect_tap_workdirs(os.environ['TAP_WORKDIRS'])
        discovered_tests = [
            os.path.basename(test_path)
            for tap_dir in tap_workdirs
            for test_path in sorted(glob.glob(tap_dir.rstrip('/') + '/*-t'))
        ]
        log.info("Discovering workdirs ...")
        for tap_dir in tap_workdirs:
            log.info("TAP_WORKDIR: " + tap_dir.replace(WORKSPACE, '').rstrip('/') + '/')
        log.info(f"Discovered {len(tap_workdirs)} workdirs.")
        # DISABLED: Infrastructure is now pre-configured by the host orchestrator
#        self.execute_hooks('pre-*')
        for tap_dir in tap_workdirs:
            for repeat in range(int(os.environ['TEST_PY_TAP_REPEAT'] or 1)):
                log.info("TAP_WORKDIR: " + tap_dir.replace(WORKSPACE, '').rstrip('/') + '/')
                os.environ['TAP_WORKDIR'] = tap_dir.rstrip('/') + '/'
#                log.info("TAP_WORKDIR: " + tap_dir.replace(WORKSPACE, '').rstrip('/') + '/')
#                if not self.execute_hooks(tap_dir + '/pre-*'):
                rc, logs, summary = self.execute_tap_tests(tap_dir + '/*-t', False)
#                self.execute_hooks(tap_dir + '/post-*')
                ret_rc += rc
                ret_logs.extend(logs)
                ret_summary.extend(summary)
                display_test_summary(os.path.basename(tap_dir.rstrip('/')), rc, summary)
#                log.info(f"ret_rc = {ret_rc}    rc = {rc}")
        self.execute_hooks('post-*')

        tap_group = os.environ.get('TAP_GROUP', '')
        if tap_group:
            groups_json_path = f"{WORKSPACE}/test/tap/groups/groups.json"
            with open(groups_json_path) as groups_file:
                groups = json.load(groups_file)

            declared_tests = {
                test_name
                for test_name, test_groups in groups.items()
                if tap_group in test_groups
            }
            declared_tests = {
                test_name
                for test_name in declared_tests
                if not self.filtered_by_version(
                    test_name, getattr(self, 'padmin_vers', '9999.0.0'), groups
                )[0]
                and self.filtered_by_regex(test_name, 'TEST_PY_TAP_INCL')[0]
                and not self.filtered_by_regex(test_name, 'TEST_PY_TAP_EXCL')[0]
            }

            # A shuffle limit deliberately selects a random subset from the
            # discovered programs. Reconcile only the names selected by that
            # mode; an unfiltered group still reconciles every declaration.
            if int(os.environ.get('TEST_PY_TAP_SHUFFLE_LIMIT', 0)) > 0:
                selected_names = {
                    os.path.basename(test_path)
                    for test_path, _ in ret_summary
                }
                declared_tests &= selected_names

            result_basenames = [
                (os.path.basename(test_path), status)
                for test_path, status in ret_summary
            ]
            reconciliation = reconcile_group_results(
                declared_tests, discovered_tests, result_basenames
            )
            discovered_declared = {
                name for name in discovered_tests if name in declared_tests
            }
            executed = reconciliation.passed | reconciliation.failed
            log.info(
                f"TAP_GROUP '{tap_group}' reconciliation: "
                f"declared={len(declared_tests)}, "
                f"discovered={len(discovered_declared)}, "
                f"executed={len(executed)}, "
                f"passed={len(reconciliation.passed)}"
            )

            error_sets = {
                'missing': reconciliation.missing,
                'duplicates': reconciliation.duplicates,
                'skipped': reconciliation.skipped,
                'failed': reconciliation.failed,
            }
            for category, names in error_sets.items():
                message = (
                    f"TAP_GROUP '{tap_group}' reconciliation {category}: "
                    f"{sorted(names)}"
                )
                if names:
                    log.critical(message)
                else:
                    log.info(message)

            if not reconciliation.ok:
                distinct_errors = set().union(*error_sets.values())
                ret_rc += max(1, len(distinct_errors))

        # Restore the original environment config
        os.environ['TAP_WORKDIR'] = orig_workdir

        # Safety net: if glob(*-t) in every TAP workdir returned zero
        # binaries, ret_summary is empty. That almost always means the
        # TAP test binaries were never built (e.g. CI-builds running the
        # wrong make target, docker-compose volume not writing through
        # to the host, or a broken sed rewrite of the build command),
        # not that there are legitimately no tests to run. Before this
        # safety net existed the pipeline would silently report 0/0
        # PASS and exit 0, producing a fake-green TAP suite that hid
        # real regressions for weeks.
        #
        # Rule: if TAP_GROUP is set and groups.json declares that group
        # has N > 0 tests, but zero binaries were discovered across all
        # workdirs, treat it as a hard failure. Version-filter skips and
        # INCL/EXCL filters still produce summary entries with rc=None,
        # so legitimate "everything skipped" runs are not affected -- only
        # the "nothing was even found on disk" case trips the safety net.
        if len(ret_summary) == 0:
            tap_group = os.environ.get('TAP_GROUP', '')
            expected_tests = 0
            if tap_group:
                groups_json_path = f"{WORKSPACE}/test/tap/groups/groups.json"
                if os.path.isfile(groups_json_path):
                    try:
                        with open(groups_json_path) as jf:
                            groups = json.load(jf)
                        expected_tests = sum(
                            1 for _, test_groups in groups.items()
                            if tap_group in test_groups
                        )
                    except Exception as e:
                        log.warning(f"Safety net: could not parse groups.json: {e}")
            if not tap_group or expected_tests > 0:
                log.critical(
                    f"SAFETY NET FAIL: zero TAP test binaries were discovered "
                    f"across all workdirs. TAP_GROUP='{tap_group}' "
                    f"expects {expected_tests} tests per groups.json. "
                    f"This typically means test/tap/tests/**/*-t binaries "
                    f"were never built -- check the CI-builds log for "
                    f"'dirname: missing operand' right after the build "
                    f"container exits, or verify make ubuntu22-tap "
                    f"actually produced binaries on the host filesystem."
                )
                ret_rc = max(ret_rc, 1)

        return ret_rc, ret_logs, ret_summary

    def run_internal_tap_tests(self):
        # Store original environment config for tap tests
        orig_workdir = os.environ['TAP_WORKDIR']

        ret_rc = 0
        ret_logs = []
        ret_summary = []
#        tap_workdirs = os.environ['INTERNAL_TAP_WORKDIR'].strip('() ').split()
        # NOTE: Don't know the logic behind 'collect_tap_workdirs' this probably needs to be revisited. For
        # now we disable this logic for 'INTERNAL_TAP_WORKDIR' tests.
        # tap_workdirs = self.collect_tap_workdirs(os.environ['INTERNAL_TAP_WORKDIR'])

        tap_workdir = os.environ['INTERNAL_TAP_WORKDIR']
        if os.path.exists(tap_workdir):
            for entry in os.listdir(tap_workdir):
                tap_dir = os.path.join(tap_workdir, entry)

                if os.path.isdir(tap_dir):
                    os.environ['TAP_WORKDIR'] = tap_dir.rstrip('/') + '/'
                    log.info("INTERNAL_TAP_WORKDIR: " + tap_dir)
                    # DISABLED: Pre-hooks managed by host
#                    self.execute_hooks(tap_dir + '/pre-*.bash')
                    rc, logs, summary = self.execute_tap_tests(tap_dir + '/*-t', True)
                    self.execute_hooks(tap_dir + '/post-*.bash')
                    ret_rc += rc
                    ret_logs.extend(logs)
                    ret_summary.extend(summary)
                    display_test_summary(os.path.basename(tap_dir.rstrip('/')), rc, summary)
        else:
            log.info(f"TAP workdir not found for TESTS_WITH_DEPS. Expected path: {tap_workdir}")

        # Restore the original environment config
        os.environ['TAP_WORKDIR'] = orig_workdir

        return ret_rc, ret_logs, ret_summary

    def pre_failover_tests(self):
        # check query is logged in `monitor.mysql_server_read_only_log` table
        return 0

    def post_failover_tests(self):
        # verify that read_only changes in the `monitor.mysql_server_read_only_log` table
        return 0

    def run_failover(self):
        rc = 1
        logs = []
        summary = []

        self.pre_failover_tests()
        mysql_infra = os.environ.get('DEFAULT_MYSQL_INFRA', 'infra-mysql57')
        if os.environ['DOCKER_MODE'].endswith('dns'):
            orc_prefix = 'ORCHESTRATOR_API="http://orc1.{infra}:3000/api http://orc2.{infra}:3000/api http://orc3.{infra}:3000/api"'.format(infra=mysql_infra)
            mysql1_alias = 'mysql1.{}'.format(mysql_infra)
        else:
            orc_prefix = 'ORCHESTRATOR_API="http://localhost:23101/api http://localhost:23102/api http://localhost:23103/api"'
            mysql1_alias = 'mysql1'
        fo_cmd = '{} orchestrator-client -c graceful-master-takeover-auto -a {}'.format(orc_prefix, mysql1_alias)
        fop = subprocess.Popen(fo_cmd,
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        fo_stdout, fo_stderr = fop.communicate()
        log.debug('Failover output is - {} / {}'.format(fo_stdout, fo_stderr))
        cf_cmd = '{} orchestrator-client -c topology -i {}:3306'.format(orc_prefix, mysql1_alias)
        cfp = subprocess.Popen(cf_cmd,
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        cf_stdout, cf_stderr = cfp.communicate()
        log.debug('Topology verification - {} / {}'.format(cf_stdout, cf_stderr))
        self.post_failover_tests()
        if b"mysql2" in fo_stdout or b"mysql3" in fo_stdout:
            rc = 0
        return rc, logs, summary

    def run_proxysql_internal_test(self):
        rc = 1
        logs = []
        summary = []
        try:
            ver = self.padmin_command('select variable_value from global_variables where variable_name = "admin-version";')[0]
            fmt_ver = ver['variable_value'].replace('_', '-').split('-')[0]
            log.debug('Version {} detected...'.format(fmt_ver))

            if version.parse(fmt_ver) < version.parse("2.0.6"):
                log.debug('Skipping internal tests since version {} is less than 2.0.6'.format(fmt_ver))
                rc = 0
                return rc, logs, summary
            # Declare and test parameters (use test number in variable name)
            params_1 = ['2000']
            # Declare any post test statements (use test number in variable name)
            cmd = ['SELECT COUNT(*) FROM stats_mysql_query_digest;',
                   'SELECT COUNT(*) FROM stats_mysql_query_digest_reset;',
                   'SELECT schemaname, COUNT(*) FROM stats_mysql_query_digest GROUP BY schemaname;',
                   'SELECT schemaname, COUNT(*) FROM stats_mysql_query_digest_reset GROUP BY schemaname;',
                   'TRUNCATE TABLE stats.stats_mysql_query_digest_reset;',
                   'TRUNCATE TABLE stats.stats_mysql_query_digest;',
                   'PROXYSQLTEST 2',
                   'PROXYSQLTEST 3',
                   'PROXYSQLTEST 4',
                   'PROXYSQLTEST 5',
                   'PROXYSQLTEST 6']

            for lp in range(25):
                test_picker = ['2','3','4','5','6']
                pit_iterations = random.randint(10, 2000)
                log.debug('Running "PROXYSQLTEST 1 {}"'.format(pit_iterations))
                pit_iterations = random.randint(10, 2000)
                pit = self.padmin_command('PROXYSQLTEST 1 {}'.format(pit_iterations))
                log.debug('Returned [OK] - {}'.format(pit))
                summary.append(('PROXYSQLTEST 1', 0))
                for rp in range(3):
                    rt = random.randrange(11)
                    log.debug('Running "{}"'.format(cmd[rt]))
                    pit = self.padmin_command(cmd[rt])
                    log.debug('Returns "{}"'.format(pit))
                    summary.append((cmd[rt], 0))
            rc = 0
            return rc, logs, summary
        except Exception as e:
            log.critical('ProxySQL Internal Tests failed due to {}'.format(e))
            return 1, logs, summary

    def run_proxysql_warming_con_test(self, host):
        rc = 1
        logs = []
        summary = []
        l_max_conn = 100
        connfree_query = 'select ConnFree from stats_mysql_connection_pool'

        try:
            # Check if connection_warming is supported
            conn_warming = self.padmin_command('select count(*) from global_variables WHERE variable_name="mysql-connection_warming"')
            if conn_warming[0]["count(*)"] == "0":
                return 0, logs

            # Activate the connection_warming capability
            self.padmin_command('set mysql-connection_warming="true"')
            self.padmin_command('LOAD MYSQL VARIABLES TO RUNTIME')

            # Set the number of connections for mysql_servers
            update_max_con_query = 'UPDATE mysql_servers SET max_connections="{}" WHERE hostname="{}"'
            self.padmin_command(update_max_con_query.format(l_max_conn, host))
            self.padmin_command('LOAD MYSQL SERVERS TO RUNTIME')

            # Percentages to test
            pcts = [20, 40, 60, 80]
            failed_pcts = []
            timeout = 30

            # First, make simple queries to trigger the purgin
            # of connections after reducting the value of `mysql-free_connections_pct`
            self.padmin_command('set mysql-free_connections_pct={}'.format(pcts[0]))
            self.padmin_command('LOAD MYSQL VARIABLES TO RUNTIME')
            init_confree = 0

            while init_confree != pcts[0]:
                if timeout == 0:
                    log.critical('ProxySQL proxysql_warming_con_test failed because timeout expired.')
                    break
                for _ in range(l_max_conn - 1):
                    self.proot_command('SELECT 1')
                init_confree = int(self.padmin_command(connfree_query)[0]['ConnFree'])
                time.sleep(1)
                timeout -= 1

            if timeout != 0:
                for pct in pcts:
                    self.padmin_command('set mysql-free_connections_pct={}'.format(pct))
                    self.padmin_command('LOAD MYSQL VARIABLES TO RUNTIME')

                    # Execute a number of queries equal to the max_connections
                    for _ in range(l_max_conn - 1):
                        self.proot_command('SELECT 1')

                    confree = int(self.padmin_command(connfree_query)[0]['ConnFree'])

                    if confree != pct:
                        failed_pcts.append((pct, confree))

            if not failed_pcts:
                if timeout != 0:
                    rc = 0
            else:
                for (pct, confree) in failed_pcts:
                    log.critical('ProxySQL proxysql_warming_con_test failed expected pct {} != {}'.format(pct, confree))

            # Recover initial number of connections for mysql_servers
            self.padmin_command(update_max_con_query.format(10000, host))
            self.padmin_command('LOAD MYSQL SERVERS TO RUNTIME')

            return rc, logs, summary
        except Exception as e:
            log.critical('ProxySQL proxysql_warming_con_test failed due to {}'.format(e))
            return 1, logs, summary


def display_test_logs(test_title, test_rc, test_result):
    if test_rc != 0:
        log.critical("{} RC{}:{}".format(test_title, test_rc, test_result))
        if int(os.environ['TEST_PY_EXIT_ON_FAIL_SECTION']):
            sys.exit(1)
    else:
        log.info("{} RC{}:{}".format(test_title, test_rc, test_result))


def display_test_summary(test_title, test_rc, test_summary):
    summ_pass = sum( 1 for cmd, rc in test_summary if rc == 0 )
    summ_fail = sum( 1 for cmd, rc in test_summary if bool(rc) != 0 )
    summ_skip = sum( 1 for cmd, rc in test_summary if rc is None )
    log.info("SUMMARY: '{}' PASS {}/{} : FAIL {}/{} : SKIP {}/{}".format(test_title, summ_pass, len(test_summary), summ_fail, len(test_summary), summ_skip, len(test_summary)))
    for cmd, rc in test_summary:
        # show only FAILs
        if bool(rc) != 0:
            log.info("SUMMARY: {} '{}'".format(('FAIL' if bool(rc) else 'PASS'), os.path.basename(cmd)))


def create_coverage_report(stage):
    """
    Calls 'fastcov' with the appropiate parameters for generating a coverage
    report including:

       - Incremental coverage: --process-gcno
       - Most useful branches coverage: -b
       - Using the maximum number of jobs the CPU can handle in parallel.
       - Only targgeting the useful directories

    Parameters
    ----------
    stage: str
        The name of the stage for which the report is going to be generated.

    Returns
    -------
    retcode: int
        The resulting error code of the call to 'fastcov'.
    """

    stage = stage + ".info"
    jobs = subprocess.check_output("nproc").decode('utf-8').rstrip()

    '''
    retcode = subprocess.call(
        args=[
            "fastcov",
            "-b",
            "-j", str(jobs),
            "--process-gcno",
            "-l",
            "-e", "/usr/include", "test/tap/tests",
            "-d", ".",
            "-i", "include", "lib", "src",
            "-o", os.path.join(COVERAGE_REPORTS_DIR, stage)
        ],
        cwd=WORKSPACE,
        shell=False
    )
    '''
    fop = subprocess.Popen([
            "fastcov",
            "-b",
            "-j", str(jobs),
            "--process-gcno",
            "-l",
            "-e", "/usr/include", "test/tap/tests",
            "-d", ".",
            "-i", "include", "lib", "src",
            "-o", os.path.join(COVERAGE_REPORTS_DIR, stage)
        ],
        cwd=WORKSPACE,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    fo_stdout, fo_stderr = fop.communicate()
    fop.wait()

    level = logging.CRITICAL if fop.returncode else logging.DEBUG
    for l in fo_stdout.decode('utf-8').split('\n'):
        log.log(level, f"stdout: {l}")
    for l in fo_stderr.decode('utf-8').split('\n'):
        log.log(level, f"stderr: {l}")

    return bool(fop.returncode)


def stop_proxysql(conn_args, max_conn_retries):
    """
    Stops a running instance of ProxySQL, issuing the command:
      - 'PROXYSQL SHUTDOWN SLOW'

    Parameters
    ----------
    conn_args : dict
        Dictionary holding the following attributes required
        to perform connection: { 'host', 'port', 'user',
        'passwd' }
    max_conn_retries: int
        The maximun number of attempts to stablish a connection
        to ProxySQL admin, performing a waiting of 1s between
        each retry.

    Returns
    -------
        None in case of success, launch an exception in case
        any of the operations failed to complete.
    """

    conn_retries = 0

    while conn_retries < max_conn_retries:
        try:
            padmin_conn = utils.open_mysql_conn(**conn_args)
            break
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args

            if err_code != 2013:
                raise

            if conn_retries == max_conn_retries:
                raise

            time.sleep(1)
            conn_retries += 1

    with padmin_conn.cursor() as cursor:
        try:
            log.debug("Stopping ProxySQL to get coverage update...")
            cursor.execute('PROXYSQL SHUTDOWN SLOW')
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args

            if err_code != 2013:
                raise

    padmin_conn.close()


def dump_gcov_proxysql(conn_args, max_conn_retries):
    """
    dumps gcov counters of a running instance of ProxySQL, issuing the command:
      - 'PROXYSQL GCOV DUMP'
    """

    conn_retries = 0

    while conn_retries < max_conn_retries:
        try:
            padmin_conn = utils.open_mysql_conn(**conn_args)
            break
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args

            if err_code != 2013:
                raise

            if conn_retries == max_conn_retries:
                raise

            time.sleep(1)
            conn_retries += 1

    with padmin_conn.cursor() as cursor:
        try:
            log.debug("Dump ProxySQL gcov counters ...")
            cursor.execute('PROXYSQL GCOV DUMP')
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args
            log.error("ERROR: {err_code} - {message}")

            if err_code != 2013:
                raise

    padmin_conn.close()


def reset_gcov_proxysql(conn_args, max_conn_retries):
    """
    resets gcov counters of a running instance of ProxySQL, issuing the command:
      - 'PROXYSQL GCOV RESET'
    """

    conn_retries = 0

    while conn_retries < max_conn_retries:
        try:
            padmin_conn = utils.open_mysql_conn(**conn_args)
            break
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args

            if err_code != 2013:
                raise

            if conn_retries == max_conn_retries:
                raise

            time.sleep(1)
            conn_retries += 1

    with padmin_conn.cursor() as cursor:
        try:
            log.debug("Reseting ProxySQL gcov counters ...")
            cursor.execute('PROXYSQL GCOV RESET')
        except pymysql.err.OperationalError as op_err:
            err_code, message = op_err.args
            log.error("ERROR: {err_code} - {message}")

            if err_code != 2013:
                raise

    padmin_conn.close()


def start_proxysql(conn_args, timeout):
    """
    Launches and wait for ProxySQL to be fully started.

    Parameters
    ----------
    conn_args : dict
        Dictionary holding the following attributes required
        to performa connection: { 'host', 'port', 'user',
        'passwd' }
    timeout: int
        Max timeout to be waited in seconds for ProxySQL to be
        fully started.

    Returns
    -------
    success : bool
        True in case ProxySQL was correctly launched and reachable,
        False otherwise.
    """

    log.debug("Launching ProxySQL after coverage update...")
    subprocess.call(
#        args='./proxysql -f -c "$DOCKER_SCRIPT_PATH/conf/proxysql/proxysql.cnf" -D . >> proxysql.log 2>&1 &',
#        args="./proxysql --clickhouse-server --sqlite3-server --idle-threads -f -c $DOCKER_SCRIPT_PATH/conf/proxysql/proxysql.cnf -D $REGULAR_INFRA_DATADIR >> proxysql.log 2>&1 &",
        args="./proxysql -f -c $DOCKER_SCRIPT_PATH/conf/proxysql/proxysql.cnf -D $REGULAR_INFRA_DATADIR >> proxysql.log 2>&1 &",
#        args="./proxysql -f -c $DOCKER_SCRIPT_PATH/conf/proxysql/proxysql.cnf -D . >> proxysql.log 2>&1 &",
        shell=True,
        cwd=os.path.join(WORKSPACE, 'src'),
        env=os.environ.copy()
    )

    waited = 0
    success = False

    while waited < timeout:
        log.debug("Waiting for ProxySQL to be ready...")
        check_proxysql_command = str(
            'mysql -e"SELECT 1" -h{host} -P{port} -u{user} -p{passwd}'
            ' --default-auth=mysql_native_password > /dev/null 2>&1'
        ).format(**conn_args)

        # Try to connect to ProxySQL
        errcode = os.system(check_proxysql_command)

        if errcode == 0:
            success = True
            log.debug("ProxySQL ready.")
            break
        else:
            # Wait before next iteration
            time.sleep(1)
            waited += 1

    log.debug("Init ProxySQL for cluster...")
    subprocess.call(
        args="./test-scripts/proxysql_cluster_init.sh",
        shell=True,
        cwd=os.environ.get("WORKSPACE", "."),
        env=os.environ.copy()
    )

    return success


def generate_stage_coverage_report(conn_args, psqlt, stage, options={}):
    """
    Generates the coverage report for the previously executed state for ProxySQL testing.

    Parameters
    ----------
    conn_args : dict
        Dictionary holding the following attributes required
        to perform connection: { 'host', 'port', 'user',
        'passwd' }
    stage : str
        The previous stage for which the coverage is going to be generated.
    options : dict
        Dictionary with the following keys:
            - gen_delay: Sensible delay in 'ms' to introduce after stopping ProxySQL
              before starting the generation of the report. NOTE: Since the generation
              is dependent of the files written by the coverage runtime after the
              execution has finished, this operation isn't atomic and can take a minimal
              ammout of time, this delay aims to avoid issues related to starting
              the generation before this files has been fully generated.

    Returns
    -------
    success: bool
        True if the report has been properly generated, False otherwise, in case
        of failing. And exception can be generated in case of failure.
    """

    # Create defaults for the possible options
#    stop_retries = options['stop_retries'] if 'stop_retries' in options else 10
    stop_retries = options.get('stop_retries', 10)
#    gen_delay = options['gen_delay'] if 'gen_delay' in options else 500
    gen_delay = options.get('gen_delay', 500)
#    start_timeout = options['start_timeout'] if 'start_timeout' in options else 10
    start_timeout = options.get('start_timeout', 10)

    # Stop currently running ProxySQL with a default return value of
#    stop_proxysql(conn_args, stop_retries)

    # Sleep the supplied 'gen_delay'
    time.sleep(gen_delay / 1000)

    dump_gcov_proxysql(conn_args, stop_retries)

    # Generate the stage coverage
    create_coverage_report(stage)

    # Start ProxySQL again after report has been generated
#    start_proxysql(conn_args, start_timeout)

    # Reconnect to ProxySQL
#    psqlt.reconnect()

    reset_gcov_proxysql(conn_args, stop_retries)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hc:", ["help", "coverage"])
    except getopt.GetoptError:
        print('proxysql-tester.py [OPTION]...')
        sys.exit(2)

    log.debug("Working enviroment vars:")
    for env_var in sorted(os.environ):
        log.debug(f">>> {env_var} = '{os.environ[env_var]}'")

    # Log shuffle configuration
    shuffle_limit = os.environ.get('TEST_PY_TAP_SHUFFLE_LIMIT', 0)
    if shuffle_limit and int(shuffle_limit) > 0:
        log.info(f"TEST_PY_TAP_SHUFFLE_LIMIT is enabled: {shuffle_limit} tests will be shuffled and executed")
    else:
        log.debug(f"TEST_PY_TAP_SHUFFLE_LIMIT is disabled (current value: {shuffle_limit})")

    # Options
    # When MULTI_GROUP=1, coverage collection is handled centrally by
    # run-multi-group.bash after all groups finish — skip it here.
    multi_group = int(os.environ.get('MULTI_GROUP', 0))
    coverage = (int(os.environ.get('WITHGCOV', 0)) or int(os.environ.get('COVERAGE_MODE', 0))) and not multi_group

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: proxysql-tester.py [OPTION]...')
            print('Launches several tests for ProxySQL.')
            print('')
            print('proxysql-tester.py -h --help Shows this help')
            print('proxysql-tester.py -c --coverage Runs all the tests generating coverage reports for each stage.')
            sys.exit()
        elif opt in ("-c", "--coverage") or coverage:
            log.info("Launching 'COVERAGE' build")
            coverage = True

    ret_rc = []

#    try:
    # Create ProxySQLTester Object and output config file:
    psqlt = ProxySQLTester('proxysql-tester.yml', coverage)
    log.debug(f"Configuration file settings: {psqlt.jsonify(psqlt.get_config())}")

    if int(os.environ['TEST_PY_INTERNAL']):
        run = "proxysql_internal_test"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs(run, rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)
        # Generate coverage report for 'proxysql_internal_test'
        if coverage:
            generate_stage_coverage_report(padmin_conn_args, psqlt, f'3_1_{run}')

        log.info(f"Running '{run}' DONE")
        log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_BENCHMARK']):
        run = "benchmark"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # Perform initial benchmark, verify RW Split:
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs(run, rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)
        # Generate coverage report for 'benchmark_test'
        if coverage:
            generate_stage_coverage_report(padmin_conn_args, psqlt, '3_2_benchmark')

        log.info(f"Running '{run}' DONE")
        log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_CHUSER']):
        run = "change_user_test"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # Perform change user test:
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs(run, rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)
        # Generate coverage report for 'change_user_test'
        if coverage:
            generate_stage_coverage_report(padmin_conn_args, psqlt, '3_3_change_user_test')

        log.info(f"Running '{run}' DONE")
        log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_STATS']):
        run = "stats_table_check"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # Perform stats table check test:
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs('Stats table check', rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)
        # Generate coverage report for 'stats_table_test'
        if coverage:
            generate_stage_coverage_report(padmin_conn_args, psqlt, '3_4_stats_table')

        log.info(f"Running '{run}' DONE")
        log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_TAP']):
        run = "tap_tests"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        #log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # run the test from psqlt
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
#        log.info(f"ret_rc = {ret_rc}    rc = {rc}")
        display_test_logs(run, rc, psqlt.jsonify(result))
#            display_test_summary(run, rc, summary)
        # TAP tests generate their own 'coverage_report' in a per-test basis

        log.info(f"Running '{run}' DONE")
        #log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_TAPINT']):
        run = "internal_tap_tests"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        #log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # Run internal tap tests:
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs(run, rc, psqlt.jsonify(result))
#            display_test_summary(run, rc, summary)
        # Internal TAP tests generate their own 'coverage_report' in a per-test basis

        log.info(f"Running '{run}' DONE")
        #log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_FAILOVER']):
        run = "failover"
        log_path = f'{tests_logs_path}/{script}'
        os.makedirs(log_path, exist_ok=True)
        log.addHandler(logging.FileHandler(f'{log_path}/{run}.log', 'w'))
        log.info(f"Running '{run}' ...")
        log.info(f"Fulllog '{run}' {log_url_prefix}/{script}/{run}.log")

        # Do failover:
        rc, result, summary = getattr(psqlt, f'run_{run}')()
        ret_rc.append(rc)
        display_test_logs(run, rc, psqlt.jsonify(result))
        display_test_summary(run, rc, summary)
        # Generate coverage report for 'failover_test_test'
        if coverage:
            generate_stage_coverage_report(padmin_conn_args, psqlt, '3_7_failover_test')

        log.info(f"Running '{run}' DONE")
        log.removeHandler(log.handlers[-1])

    if int(os.environ['TEST_PY_WARMING']):
        # Execute the global-warming test
        rc, result = psqlt.run_proxysql_warming_con_test("0.0.0.0")
        ret_rc.append(rc)
        log.info('Warming test results RC{}:\n{}'.format(rc, psqlt.jsonify(result)))

    if int(os.environ['TEST_PY_READONLY']):
        # Test RO variable
        rc, result = psqlt.do_readonly_test()
        ret_rc.append(rc)
        log.info('Read-only test results RC{}:\n{}'.format(rc, psqlt.jsonify(result)))

    # Summarize test return codes:
    log.info(f"SUMMARY: ret_rc = {ret_rc}")
    sys.exit(int(any(ret_rc)))

#    except Exception as e:
#        # Fail and return non-zero RC on any general or unhandled exception
#        log.critical('Process failed due to a general, unhandled exception')
#        # Log the exception
#        log.exception('Exception: ' + str(e))
#        log.exception('Backtrace: ' + traceback.format_exc())

#        sys.exit(255)


if __name__ == '__main__':
    main(sys.argv[1:])
