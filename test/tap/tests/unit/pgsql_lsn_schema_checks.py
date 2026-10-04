#!/usr/bin/env python3
"""Standalone tier/schema checks, independent of daemon link dependencies."""
import pathlib, re, sqlite3, subprocess, unittest
ROOT = pathlib.Path(__file__).resolve().parents[4]
HEADER = ROOT / 'include/ProxySQL_Admin_Tables_Definitions.h'

def definitions(tier):
    out = subprocess.check_output(['g++', '-E', '-P', '-x', 'c++', *(['-DPROXYSQL31'] if tier else []), str(HEADER)], text=True)
    defs = {name: sql for name, sql in re.findall(r'const char \*(\w+) = "([^"]*)";', out)}
    if not tier: defs['ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES'] = defs['ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_V3_0']
    return defs

class SchemaTests(unittest.TestCase):
    def test_tiers(self):
        for tier in (False, True):
            defs = definitions(tier)
            db = sqlite3.connect(':memory:')
            for table, macro in [('pgsql_query_rules','ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES'),('runtime_pgsql_query_rules','ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES')]:
                db.execute(defs[macro])
                columns = [r[1].lower() for r in db.execute(f'pragma table_info({table})')]
                self.assertEqual(len(columns), 35 if tier else 34)
                self.assertEqual(columns[29:33], ['multiplex','lsn_from_hostgroup','log','apply'] if tier else ['multiplex','log','apply','attributes'])
                if tier:
                    db.execute(f'insert into {table}(rule_id,multiplex,lsn_from_hostgroup,log,apply) values(1,2,17,1,1)')
                    self.assertEqual(db.execute(f'select multiplex,lsn_from_hostgroup,log,apply from {table}').fetchone(), (2,17,1,1))
                    db.execute(f'insert into {table}(rule_id,lsn_from_hostgroup) values(2,0)')
                    db.execute(f'insert into {table}(rule_id) values(3)')
                    self.assertIsNone(db.execute(f'select lsn_from_hostgroup from {table} where rule_id=3').fetchone()[0])
                    with self.assertRaises(sqlite3.IntegrityError): db.execute(f'insert into {table}(lsn_from_hostgroup) values(-1)')
            self.assertEqual('STATS_SQLITE_TABLE_PGSQL_LSN' in defs, tier)
            for value in defs.values():
                self.assertNotIn('lsn_causal_reads', value)

if __name__ == '__main__': unittest.main()
