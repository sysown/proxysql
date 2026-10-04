#!/usr/bin/env python3
"""Live Admin transport and cluster synchronization across query-rule tiers.

Requires pymysql and explicit v3.0, v3.1 and v4.0 binaries. Starts only private
processes with fresh datadirs and dynamic loopback listeners; no backend is
needed. Each tier is represented by two nodes so both same-tier and cross-tier
pulls are real cluster operations. Logs and SQLite databases remain in artifacts.

Example:
  python3 pgsql_lsn_cluster_schema_smoke.py --proxy30 /path/30/proxysql \
    --proxy31 /path/31/proxysql --proxy40 /path/40/proxysql --artifacts /tmp/tier-smoke
"""
import argparse
import json
import shutil
import socket
import sqlite3
import subprocess
import time
from pathlib import Path

import pymysql

COLUMNS = ('rule_id username database flagIN client_addr proxy_addr proxy_port digest '
           'match_digest match_pattern negate_match_pattern re_modifiers flagOUT '
           'replace_pattern destination_hostgroup cache_ttl cache_empty_result '
           'cache_timeout reconnect timeout retries delay next_query_flagIN mirror_flagOUT '
           'mirror_hostgroup error_msg ok_msg sticky_conn multiplex').split()
TAIL = ['log', 'apply', 'attributes', 'comment']
FAST = ('PROXY_SELECT username, database, flagIN, destination_hostgroup, comment '
        'FROM runtime_pgsql_query_rules_fast_routing ORDER BY username, database, flagIN')


def projection(extended):
    columns = COLUMNS + (['lsn_from_hostgroup'] if extended else []) + TAIL
    return 'PROXY_SELECT ' + ', '.join(columns) + ' FROM runtime_pgsql_query_rules ORDER BY rule_id'


def freeport():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait(fn, timeout=20):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, pymysql.MySQLError) as error:
            last = error
        time.sleep(.05)
    raise TimeoutError(str(last) if last else 'condition not reached')


class Node:
    def __init__(self, tier, binary, directory, database=None, seed=True):
        self.tier, self.directory = tier, directory
        self.extended = tier != '30'
        directory.mkdir(parents=True)
        if database:
            shutil.copy2(database, directory / 'proxysql.db')
        self.port = freeport()
        cfg = directory / 'proxysql.cnf'
        cfg.write_text('''admin_variables={admin_credentials="admin:admin;cluster:cluster";mysql_ifaces="127.0.0.1:%d";cluster_username="cluster";cluster_password="cluster";cluster_check_interval_ms=50;cluster_check_status_frequency=1;}
mysql_variables={threads=1;interfaces="127.0.0.1:%d";monitor_enabled=false;}
pgsql_variables={threads=1;interfaces="127.0.0.1:%d";monitor_enabled=false;}
''' % (self.port, freeport(), freeport()))
        self.log_path = directory / 'proxy.log'
        self.log = self.log_path.open('w')
        command = [str(binary), '-f', '-e', '--no-version-check', '-c', str(cfg), '-D', str(directory)]
        if database:
            # Keep the legacy rows while replacing persisted listener addresses
            # with this invocation's new isolated ports.
            command.append('--reload')
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT)
        self.admin = None
        try:
            self.admin = wait(self.connect)
            self.sql("UPDATE global_variables SET variable_value='0' WHERE variable_name LIKE 'admin-cluster_%_diffs_before_sync'")
            self.sql('LOAD ADMIN VARIABLES TO RUNTIME')
            self.sql('DELETE FROM pgsql_query_rules_fast_routing')
            if seed:
                self.seed('initial-' + directory.name)
        except BaseException:
            self.stop()
            raise

    def connect(self):
        if self.process.poll() is not None:
            raise RuntimeError('proxy exited: ' + str(self.log_path))
        return pymysql.connect(host='127.0.0.1', port=self.port, user='admin', password='admin',
                               autocommit=True, connect_timeout=1, read_timeout=3, write_timeout=3)

    def sql(self, query):
        with self.admin.cursor() as cursor:
            cursor.execute(query)
            return cursor.fetchall(), [column[0].lower() for column in cursor.description] if cursor.description else []

    def seed(self, marker):
        self.sql('DELETE FROM pgsql_query_rules')
        if self.extended:
            self.sql("INSERT INTO pgsql_query_rules(rule_id,active,destination_hostgroup,multiplex,lsn_from_hostgroup,log,apply,comment) VALUES(-7,1,20,2,17,1,1,'%s'),(8,1,21,2,0,1,1,'%s-zero'),(9,1,22,2,NULL,1,1,'%s-null')" % (marker, marker, marker))
        else:
            self.sql("INSERT INTO pgsql_query_rules(rule_id,active,destination_hostgroup,multiplex,log,apply,comment) VALUES(-7,1,20,2,1,1,'%s'),(8,1,21,2,1,1,'%s-zero'),(9,1,22,2,1,1,'%s-null')" % (marker, marker, marker))
        self.sql('LOAD PGSQL QUERY RULES TO RUNTIME')
        self.sql('SAVE PGSQL QUERY RULES TO DISK')

    def state(self):
        # Selecting runtime checksums refreshes the table from live checksum state.
        return {name: self.sql(query) for name, query in {
            'runtime': projection(self.extended),
            'memory': 'SELECT * FROM pgsql_query_rules ORDER BY rule_id',
            'disk': 'SELECT * FROM disk.pgsql_query_rules ORDER BY rule_id',
            'checksum': "SELECT name,version,epoch,checksum FROM runtime_checksums_values WHERE name='pgsql_query_rules'",
            'fast': FAST,
        }.items()}

    def counter(self, status, module="pgsql_query_rules"):
        rows, _ = self.sql('SHOW PROMETHEUS METRICS')
        text = '\n'.join(value.decode() if isinstance(value, bytes) else str(value) for row in rows for value in row)
        for line in text.splitlines():
            if line.startswith('proxysql_cluster_pulled_total{') and 'module_name="%s"' % module in line and 'status="%s"' % status in line:
                return float(line.rsplit(' ', 1)[1])
        raise AssertionError(module + ' cluster pull counter not found')

    def seed_unrelated(self, marker, timeout):
        self.sql('DELETE FROM mysql_query_rules')
        self.sql("INSERT INTO mysql_query_rules(rule_id,active,apply,comment) VALUES(77,1,1,'%s')" % marker)
        self.sql('LOAD MYSQL QUERY RULES TO RUNTIME')
        self.sql('SAVE MYSQL QUERY RULES TO DISK')
        self.sql("UPDATE global_variables SET variable_value='%d' WHERE variable_name='mysql-default_query_timeout'" % timeout)
        self.sql('LOAD MYSQL VARIABLES TO RUNTIME')
        self.sql('SAVE MYSQL VARIABLES TO DISK')

    def unrelated(self):
        return {name: self.sql(query) for name, query in {
            'runtime': 'SELECT * FROM runtime_mysql_query_rules ORDER BY rule_id',
            'memory': 'SELECT * FROM mysql_query_rules ORDER BY rule_id',
            'disk': 'SELECT * FROM disk.mysql_query_rules ORDER BY rule_id',
            'runtime-var': "SELECT * FROM runtime_global_variables WHERE variable_name='mysql-default_query_timeout'",
            'memory-var': "SELECT * FROM global_variables WHERE variable_name='mysql-default_query_timeout'",
            'disk-var': "SELECT * FROM disk.global_variables WHERE variable_name='mysql-default_query_timeout'",
            'checksums': "SELECT name,version,epoch,checksum FROM runtime_checksums_values WHERE name IN ('mysql_query_rules','mysql_variables') ORDER BY name",
        }.items()}

    def detach(self):
        self.sql("UPDATE global_variables SET variable_value='0' WHERE variable_name LIKE 'admin-cluster_%_diffs_before_sync'")
        self.sql('LOAD ADMIN VARIABLES TO RUNTIME')
        self.sql('DELETE FROM proxysql_servers')
        self.sql('LOAD PROXYSQL SERVERS TO RUNTIME')

    def follow(self, source):
        self.sql("INSERT INTO proxysql_servers(hostname,port,weight,comment) VALUES('127.0.0.1',%d,1,'tier-test')" % source.port)
        self.sql('LOAD PROXYSQL SERVERS TO RUNTIME')
        self.sql("UPDATE global_variables SET variable_value='1' WHERE variable_name='admin-cluster_pgsql_query_rules_diffs_before_sync'")
        self.sql('LOAD ADMIN VARIABLES TO RUNTIME')

    def stop(self):
        if getattr(self, 'admin', None):
            self.admin.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for tier in ('30', '31', '40'):
        parser.add_argument('--proxy' + tier, type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=20)
    args = parser.parse_args()
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=True)
    checks = 0
    def check(condition, description):
        nonlocal checks
        checks += 1
        print(('ok' if condition else 'not ok'), checks, '-', description, flush=True)
        if not condition:
            raise AssertionError(description)
    nodes = []
    versions = {}
    try:
        # Freeze every executable before starting nodes so a concurrent caller
        # rebuild cannot change the binaries being exercised midway through.
        for tier in ('30', '31', '40'):
            original = getattr(args, 'proxy' + tier).resolve()
            binary = out / ('proxysql' + tier)
            shutil.copy2(original, binary)
            versions[tier] = subprocess.run([str(binary), '--version'], capture_output=True, text=True, check=True).stdout.strip()
            major_minor = {'30':'3.0', '31':'3.1', '40':'4.0'}[tier]
            check('ProxySQL version ' + major_minor + '.' in versions[tier], tier + ': explicit binary release tier confirmed')
        for tier in ('30', '31', '40'):
            binary = out / ('proxysql' + tier)
            for suffix in ('a', 'b'):
                node = Node(tier, binary, out / (tier + suffix))
                nodes.append(node)
                state = node.state()
                rows, columns = state['runtime']
                check(len(columns) == (34 if node.extended else 33), tier + suffix + ': selected runtime transport column count')
                check(len(state['memory'][1]) == (35 if node.extended else 34), tier + suffix + ': full schema column count')
                check(bool(state['checksum'][0]), tier + suffix + ': live checksum exists')
                check(str(rows[0][0]) == '-7', tier + suffix + ': signed negative rule ID survives LOAD')
                variables, _ = node.sql("SELECT variable_name FROM global_variables WHERE variable_name IN ('pgsql-monitor_lsn_poll_interval','pgsql-monitor_lsn_poll_timeout','pgsql-monitor_lsn_history')")
                check(len(variables) == (3 if node.extended else 0), tier + suffix + ': tier-specific monitor variables')
                retired, _ = node.sql("SELECT variable_name FROM global_variables WHERE variable_name IN ('pgsql-lsn_wait_timeout','pgsql-lsn_poll_interval','pgsql-lsn_poll_timeout')")
                check(not retired, tier + suffix + ': rejected/draft settings absent')
                if not node.extended:
                    try:
                        node.sql('SELECT * FROM stats_pgsql_lsn')
                    except pymysql.MySQLError as error:
                        check('no such table' in str(error).lower(), tier + suffix + ': v3.0 LSN stats absent')
                    else:
                        check(False, tier + suffix + ': v3.0 unexpectedly exposes LSN stats')
                if node.extended:
                    check(columns[28:32] == ['multiplex', 'lsn_from_hostgroup', 'log', 'apply'], tier + suffix + ': ordered LSN neighbors')
                    check(tuple(map(str, rows[0][28:32])) == ('2', '17', '1', '1') and str(rows[1][29]) == '0' and rows[2][29] is None,
                          tier + suffix + ': endpoint Admin transport retains HG17/HG0/NULL')
                try:
                    node.sql(projection(not node.extended))
                except pymysql.MySQLError as error:
                    check('Incompatible PostgreSQL query rules schema tier' in str(error), tier + suffix + ': actual opposite-tier PROXY_SELECT is explicitly rejected')
                else:
                    check(False, tier + suffix + ': incompatible request unexpectedly succeeded')
                check(node.state() == state, tier + suffix + ': direct rejection preserves runtime/memory/disk/checksums')
        (out / 'versions.json').write_text(json.dumps(versions, indent=2))
        # Exercise startup migration using a real populated v3.0 config DB.
        legacy = next(node for node in nodes if node.directory.name == '30a')
        legacy.sql("INSERT INTO disk.pgsql_query_rules(rule_id) VALUES(120000)")
        legacy.sql("DELETE FROM disk.pgsql_query_rules WHERE rule_id=120000")
        legacy_rows, _ = legacy.sql('SELECT * FROM disk.pgsql_query_rules ORDER BY rule_id')
        backup_path = out / 'legacy-populated.db'
        with sqlite3.connect(legacy.directory / 'proxysql.db') as source_db, sqlite3.connect(backup_path) as backup_db:
            source_db.backup(backup_db)
        for tier in ('31', '40'):
            upgraded = Node(tier, out / ('proxysql' + tier), out / (tier + '-upgraded'), database=backup_path, seed=False)
            try:
                rows, columns = upgraded.sql('SELECT * FROM pgsql_query_rules ORDER BY rule_id')
                expected_rows = tuple(tuple(row[:30]) + (None,) + tuple(row[30:]) for row in legacy_rows)
                check(len(columns) == 35 and columns[30] == 'lsn_from_hostgroup', tier + ': populated legacy DB upgrades before loading')
                check(rows == expected_rows, tier + ': live startup migration preserves all legacy values and fills NULL')
                disk_rows, _ = upgraded.sql('SELECT * FROM disk.pgsql_query_rules ORDER BY rule_id')
                check(disk_rows == expected_rows, tier + ': canonical migrated disk table survives generic verification')
                upgraded.sql('INSERT INTO pgsql_query_rules(active) VALUES(1)')
                disk_sequence, _ = upgraded.sql("SELECT seq FROM disk.sqlite_sequence WHERE name='pgsql_query_rules'")
                check(str(disk_sequence[0][0]) == '120000', tier + ': disk AUTOINCREMENT watermark preserved')
            finally:
                upgraded.stop()
        by_name = {node.directory.name: node for node in nodes}
        pairs = [('30a','30b'), ('31a','31b'), ('40a','40b'),
                 ('31a','40b'), ('40a','31b'),
                 ('30a','31b'), ('31a','30b'), ('30a','40b'), ('40a','30b')]
        for number, (source_name, target_name) in enumerate(pairs):
            source, target = by_name[source_name], by_name[target_name]
            for node in nodes:
                node.detach()
            target.seed('preserved-target-%d' % number)
            cross_extended = source.extended and target.extended and source.tier != target.tier
            if cross_extended:
                target.seed_unrelated('preserved-non-pg-%d' % number, 11111)
                unrelated_before = target.unrelated()
            before = target.state()
            successes = target.counter('success')
            # Cluster sync deliberately uses a newer epoch to avoid equal-time conflict.
            time.sleep(1.05)
            source.seed('source-%d' % number)
            if cross_extended:
                source.seed_unrelated('newer-non-pg-%d' % number, 22222)
            expected = source.state()
            target.follow(source)
            if cross_extended:
                target.sql("UPDATE global_variables SET variable_value='1' WHERE variable_name IN ('admin-cluster_mysql_query_rules_diffs_before_sync','admin-cluster_mysql_variables_diffs_before_sync')")
                target.sql('LOAD ADMIN VARIABLES TO RUNTIME')
            compatible = source.extended == target.extended
            if compatible:
                wait(lambda: target.state()['runtime'] == expected['runtime'], args.timeout)
                actual = target.state()
                check(actual['memory'] == expected['memory'] and actual['disk'] == expected['disk'], source_name + ' -> ' + target_name + ': real cluster pull preserves complete rules in memory and disk')
                check(actual['checksum'][0][0][3] == expected['checksum'][0][0][3], source_name + ' -> ' + target_name + ': transported checksum agrees')
                check(target.counter('success') > successes, source_name + ' -> ' + target_name + ': successful pull recorded')
                if target.extended:
                    check(actual['runtime'][0][0][29] == expected['runtime'][0][0][29] and actual['runtime'][0][1][29] == expected['runtime'][0][1][29] and actual['runtime'][0][2][29] is None,
                          source_name + ' -> ' + target_name + ': LSN HG17/HG0/NULL survive live synchronization')
                if cross_extended:
                    # Let several additional checksum cycles attempt every enabled
                    # unrelated module after the PostgreSQL pull has completed.
                    time.sleep(.5)
                    check(target.unrelated() == unrelated_before, source_name + ' -> ' + target_name + ': newer MySQL rules and variables remain unchanged with synchronization enabled')
                    check('PostgreSQL query-rules-only peer' in target.log_path.read_text(), source_name + ' -> ' + target_name + ': narrowly scoped bridge logged')
            else:
                rejection = 'different ProxySQL version with peer 127.0.0.1:%d' % source.port
                wait(lambda: rejection in target.log_path.read_text(), args.timeout)
                time.sleep(.15)
                check(True, source_name + ' -> ' + target_name + ': legacy/extended handshake rejected before module synchronization')
                check(target.state() == before, source_name + ' -> ' + target_name + ': rejected cluster pull preserves runtime/memory/disk/checksums')
                check(target.counter('success') == successes, source_name + ' -> ' + target_name + ': rejected pull records no success')
            target.detach()
        print('1..%d' % checks, flush=True)
        return 0
    finally:
        for node in reversed(nodes):
            node.stop()

if __name__ == '__main__':
    raise SystemExit(main())
