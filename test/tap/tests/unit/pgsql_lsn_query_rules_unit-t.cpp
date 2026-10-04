#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "cpp.h"
#include "PgSQL_Query_Processor.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "ProxySQL_Cluster.hpp"
#ifdef PROXYSQL31
#include "PgSQL_LSN_Routing.h"
#endif
extern PgSQL_Query_Processor* GloPgQPro;
extern ProxySQL_Cluster* GloProxyCluster;
#include <memory>
#include <string>
#include <cstring>

static std::unique_ptr<SQLite3_result> projection(SQLite3DB& db) {
 std::string query = CLUSTER_QUERY_PGSQL_QUERY_RULES;
 query.replace(0, strlen("PROXY_SELECT"), "SELECT");
 char* error = nullptr;
 auto* result = db.execute_statement(query.c_str(), &error);
 ok(!error && result, "selected tier transport projection");
 free(error);
 return std::unique_ptr<SQLite3_result>(result);
}

int main() {
 plan(NO_PLAN);
 test_init_minimal();
 test_init_query_processor();
#ifdef PROXYSQL31
 ok(proxysql_cluster_pgsql_query_rules_cross_tier("3.1.12_DEBUG","4.0.12_DEBUG") && proxysql_cluster_pgsql_query_rules_cross_tier("4.0.12_DEBUG","3.1.12_DEBUG"), "only extended cross-release tiers may bridge PostgreSQL rules");
 for (auto peer : {"3.0.12_DEBUG","3.1.13_DEBUG","4.1.0_DEBUG","other"})
  ok(!proxysql_cluster_pgsql_query_rules_cross_tier("3.1.12_DEBUG",peer), "normal compatibility gate retained for peer %s",peer);
 ok(!proxysql_cluster_pgsql_query_rules_cross_tier("4.0.12_DEBUG","4.0.12_DEBUG") && !proxysql_cluster_pgsql_query_rules_cross_tier(nullptr,"4.0.12_DEBUG"), "same-version plugin mismatch and missing version cannot use bridge");
 {
  auto cluster = std::make_unique<ProxySQL_Cluster>();
  GloProxyCluster = cluster.get();
  cluster->cluster_pgsql_query_rules_diffs_before_sync = 0;
  char host[]="127.0.0.1", comment[]="restricted peer";
  ProxySQL_Node_Entry peer(host,1,1,comment,host);
  auto& stale=peer.checksums_values.mysql_query_rules;
  stale.version=9; stale.epoch=999; stale.diff_check=99; strcpy(stale.checksum,"old-full-peer");
  // An empty real MYSQL_RES avoids the NULL polling path's checksum comparisons.
  MYSQL_RES empty{};
  auto& stale_pg=peer.checksums_values.pgsql_query_rules;
  stale_pg.version=8; stale_pg.epoch=998; stale_pg.diff_check=98; strcpy(stale_pg.checksum,"old-pg-peer");
  peer.global_checksum=12345;
  peer.set_sync_capability(true);
  ok(!peer.supports_sync_module("mysql_query_rules") && !stale.version && !stale_pg.version, "capability transition revokes all old donors before any checksum fetch");
  ok(!peer.global_checksum && peer.needs_checksum_snapshot(), "capability change forces fresh snapshot even when remote global checksum is unchanged");
  peer.set_sync_capability(true);
  ok(peer.needs_checksum_snapshot(), "failed fetch/repeated handshake preserves fresh-snapshot requirement");
  peer.set_checksums(&empty,true);
  ok(!peer.needs_checksum_snapshot(), "successful snapshot completes capability transition");
  ok(!stale.version && !stale.epoch && !stale.diff_check && !stale.checksum[0], "restricted endpoint clears stale non-PG donor eligibility");
  ok(peer.supports_sync_module("pgsql_query_rules"), "restricted endpoint remains eligible for PostgreSQL rules");
  for (auto module : {"admin_variables","mysql_variables","ldap_variables","mysql_query_rules","runtime_mysql_servers","mysql_servers_v2","mysql_users","proxysql_servers","pgsql_variables","pgsql_users","runtime_pgsql_servers","pgsql_servers_v2"})
   ok(!peer.supports_sync_module(module), "restricted endpoint excluded from donor selection for %s",module);
  peer.set_checksums(&empty,false);
  ok(peer.supports_sync_module("mysql_query_rules"), "normal handshake restores full module eligibility");
  GloProxyCluster=nullptr;
 }
#endif
 SQLite3DB db;
 db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
 ok(db.execute(ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES), "runtime schema created");
#ifdef PROXYSQL31
 ok(db.execute("INSERT INTO runtime_pgsql_query_rules(rule_id,active,multiplex,lsn_from_hostgroup,log,apply,destination_hostgroup) VALUES(7,1,2,17,1,1,20),(8,1,2,0,1,1,21),(9,1,2,NULL,1,1,22)"), "insert source HG17, HG0, NULL");
#else
 ok(db.execute("INSERT INTO runtime_pgsql_query_rules(rule_id,active,multiplex,log,apply) VALUES(7,1,2,1,1)"), "insert legacy rule");
#endif
 auto rules = projection(db);
 std::string error;
 ok(rules && ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules, error), "selected projection validates");
#ifdef PROXYSQL31
 ok(rules->columns == 34, "extended active projection has 34 columns");
 auto* row = rules->rows[0];
 ok(!strcmp(row->fields[28], "2") && !strcmp(row->fields[29], "17") && !strcmp(row->fields[30], "1") && !strcmp(row->fields[31], "1"), "transport neighbors preserve values");
 ok(!strcmp(rules->rows[1]->fields[29], "0") && !rules->rows[2]->fields[29], "transport preserves zero and NULL");
 PgSQL_Query_Processor_Output output;
 PgSQL_Query_Processor_Rule_t rule{};
 ok(output.lsn_from_hostgroup == -1, "new output has no source");
 rule.lsn_from_hostgroup = 17;
 GloPgQPro->process_query_extended(&output, &rule);
 ok(output.lsn_from_hostgroup == 17, "source rule updates output");
 rule.lsn_from_hostgroup = -1;
 GloPgQPro->process_query_extended(&output, &rule);
 ok(output.lsn_from_hostgroup == 17, "NULL source preserves chained output");
 rule.lsn_from_hostgroup = 0;
 GloPgQPro->process_query_extended(&output, &rule);
 ok(output.lsn_from_hostgroup == 0, "HG0 overrides chained output");
 output.init();
 ok(output.lsn_from_hostgroup == -1, "next request resets source");
 SQLite3_result fast(5);
 for (auto name : {"username","database","flagIN","destination_hostgroup","comment"}) fast.add_column_definition(SQLITE_TEXT,name);
 auto interests = collect_pgsql_lsn_interests(*rules,fast);
 ok(interests.size()==2 && interests[0].source_hostgroup==0 && interests[1].source_hostgroup==17, "NULL source creates no interest; HG0 is retained");
 ok(interests[1].any_destination && interests[1].destination_hostgroups == std::vector<uint32_t>{20}, "explicit relationship retained alongside SQL-comment routing wildcard");
 db.execute("UPDATE runtime_pgsql_query_rules SET apply=0 WHERE rule_id=7");
 rules = projection(db);
 interests = collect_pgsql_lsn_interests(*rules,fast);
 ok(interests[1].any_destination, "continued rule chain conservatively includes all destinations");
 char* saved = rules->rows[0]->fields[29];
 for (const char* value : {"-1","x","17x","2147483648",""}) {
  rules->rows[0]->fields[29] = const_cast<char*>(value);
  ok(!ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "reject malformed source '%s'",value);
 }
 rules->rows[0]->fields[29] = saved;
#else
 ok(rules->columns == 33, "legacy active projection has 33 columns");
#endif
 const auto checksum = rules->raw_checksum();
 auto* original = rules->column_definition[0];
 std::swap(rules->column_definition[0],rules->column_definition[1]);
 ok(!ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "reordered projection rejected");
 std::swap(rules->column_definition[0],rules->column_definition[1]);
 ok(rules->column_definition[0]==original && rules->raw_checksum()==checksum, "validation preserves snapshot and checksum");
 --rules->columns;
 ok(!ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "truncated projection rejected");
 rules->columns += 2;
 ok(!ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "extra projection rejected");
 --rules->columns;
 // Invalid incoming snapshots must be rejected before admin/runtime/disk
 // mutation. This path uses supplied snapshots and needs no Admin startup.
 db.execute(ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES);
 db.execute("INSERT INTO pgsql_query_rules(rule_id,comment) VALUES(88,'admin marker')");
 db.execute("ATTACH DATABASE ':memory:' AS disk");
 std::string disk_ddl = ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES;
 disk_ddl.replace(disk_ddl.find("pgsql_query_rules"),strlen("pgsql_query_rules"),"disk.pgsql_query_rules");
 db.execute(disk_ddl.c_str());
 db.execute("INSERT INTO disk.pgsql_query_rules(rule_id,comment) VALUES(99,'disk marker')");
 auto* admin = reinterpret_cast<ProxySQL_Admin*>(calloc(1,sizeof(ProxySQL_Admin)));
 admin->admindb = &db;
 std::unique_ptr<SQLite3_result> runtime_before(GloPgQPro->get_current_query_rules());
 const auto version_before = GloVars.checksums_values.pgsql_query_rules.version;
 SQLite3_result empty_fast(5);
 for (auto name : {"username","database","flagIN","destination_hostgroup","comment"}) empty_fast.add_column_definition(SQLITE_TEXT,name);
 --rules->columns;
 char* load_error = admin->load_pgsql_query_rules_to_runtime(rules.get(),&empty_fast,"untrusted",123);
 ok(load_error != nullptr,"loader rejects invalid incoming snapshot");
 free(load_error);
 ++rules->columns;
 std::unique_ptr<SQLite3_result> runtime_after(GloPgQPro->get_current_query_rules());
 ok(runtime_before->raw_checksum()==runtime_after->raw_checksum(),"rejected load preserves runtime rules");
 ok(version_before==GloVars.checksums_values.pgsql_query_rules.version,"rejected load preserves checksum version");
 ok(db.return_one_int("SELECT COUNT(*) FROM pgsql_query_rules WHERE rule_id=88 AND comment='admin marker'")==1,"rejected load preserves admin rows");
 ok(db.return_one_int("SELECT COUNT(*) FROM disk.pgsql_query_rules WHERE rule_id=99 AND comment='disk marker'")==1,"rejected load preserves disk rows");
 free(admin);
 char* saved_id = rules->rows[0]->fields[0];
 rules->rows[0]->fields[0] = const_cast<char*>("invalid");
 ok(!ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "malformed source rule ID rejected");
 rules->rows[0]->fields[0] = const_cast<char*>("-7");
 ok(ProxySQL_Admin::validate_pgsql_query_rules_projection(*rules,error), "signed negative rule ID remains valid in both tiers");
 rules->rows[0]->fields[0] = saved_id;
 std::string incompatible = CLUSTER_QUERY_PGSQL_QUERY_RULES_INCOMPATIBLE;
 incompatible.replace(0,strlen("PROXY_SELECT"),"SELECT");
 char* sql_error = nullptr;
 std::unique_ptr<SQLite3_result> other(db.execute_statement(incompatible.c_str(),&sql_error));
 ok(sql_error || (other && !ProxySQL_Admin::validate_pgsql_query_rules_projection(*other,error)), "opposite tier cannot sync");
 free(sql_error);
 test_cleanup_query_processor();
 test_cleanup_minimal();
 return exit_status();
}
