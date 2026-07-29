/**
 * @file config_write_unit-t.cpp
 * @brief Unit tests for ProxySQL_Config Write_*_to_configfile() functions.
 *
 * Tests ALL writers with real data (not empty tables):
 * - Write_MySQL_Users_to_configfile / Write_PgSQL_Users_to_configfile
 * - Write_Scheduler_to_configfile
 * - Write_Restapi_to_configfile
 * - Write_MySQL_Query_Rules_to_configfile / Write_PgSQL_Query_Rules_to_configfile
 * - Write_MySQL_Query_Rules_Fast_Routing_to_configfile / Write_PgSQL_Query_Rules_Fast_Routing_to_configfile
 * - Write_MySQL_Firewall_to_configfile (users+rules+sqli) / Write_PgSQL_Firewall_to_configfile
 * - Write_MySQL_Servers_to_configfile (with all sub-tables populated) / Write_PgSQL_Servers_to_configfile
 * - Write_Global_Variables_to_configfile
 * - Write_ProxySQL_Servers_to_configfile
 *
 * Every test uses the canonical ADMIN_SQLITE_TABLE_* macros and inserts
 * actual data (including into sub-tables) so that serialization is exercised.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "proxysql_config.h"
#include "configfile.hpp"
#include "sqlite3db.h"
#include "ProxySQL_Admin_Tables_Definitions.h"

#include <string>
#include <cstring>

// ============================================================
// Helper: create in-memory SQLite3DB
// ============================================================

static SQLite3DB* create_test_db() {
	SQLite3DB* db = new SQLite3DB();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	return db;
}

// ============================================================
// Helpers for Write -> Read round-trip tests
// ============================================================

// The Read_*_from_configfile() methods parse the global GloVars.confFile.
// This helper parses a writer's output string back into a throwaway
// ProxySQL_ConfigFile and points GloVars.confFile at it for the duration
// of the read. The caller must restore the prior value afterwards.
static ProxySQL_ConfigFile* load_config_from_string(const std::string& s) {
	ProxySQL_ConfigFile* cf = new ProxySQL_ConfigFile();
	cf->cfg.readString(s.c_str());
	return cf;
}

// Count rows in a table (single integer column) of the in-memory DB.
static int db_count_rows(SQLite3DB* db, const char* table) {
	char* error = NULL;
	std::string q = std::string("SELECT COUNT(*) FROM ") + table;
	SQLite3_result* res = db->execute_statement(q.c_str(), &error);
	int n = -1;
	if (res && res->rows_count > 0 && res->rows[0]->fields[0]) {
		n = atoi(res->rows[0]->fields[0]);
	}
	if (error) free(error);
	if (res) delete res;
	return n;
}

// Fetch a single string value: SELECT <col> FROM <table> WHERE <where>
// Returns "" if no row or NULL field.
static std::string db_select_string(SQLite3DB* db, const char* col, const char* table, const char* where) {
	char* error = NULL;
	std::string q = std::string("SELECT ") + col + " FROM " + table + " WHERE " + where;
	SQLite3_result* res = db->execute_statement(q.c_str(), &error);
	std::string val;
	if (res && res->rows_count > 0 && res->rows[0]->fields[0]) {
		val = res->rows[0]->fields[0];
	}
	if (error) free(error);
	if (res) delete res;
	return val;
}

// ============================================================
// Write_MySQL_Users_to_configfile()
// ============================================================

static void test_write_mysql_users_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Users_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Users: returns 0 on empty table");
	ok(data.find("mysql_users:") != std::string::npos,
		"Write_MySQL_Users: section header present for empty table");
	ok(data.find("username") == std::string::npos,
		"Write_MySQL_Users: no user fields in empty table");

	delete db;
}

static void test_write_mysql_users_single() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db->execute("INSERT INTO mysql_users (username, password, active, use_ssl, "
		"default_hostgroup, default_schema, schema_locked, transaction_persistent, "
		"fast_forward, backend, frontend, max_connections, attributes, comment) "
		"VALUES ('testuser', 'testpass', 1, 0, 1, 'mydb', 0, 1, 0, 1, 1, 1000, '', 'test comment')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Users_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Users single: returns 0");
	ok(data.find("mysql_users:") != std::string::npos,
		"Write_MySQL_Users single: section header present");
	ok(data.find("\"testuser\"") != std::string::npos,
		"Write_MySQL_Users single: username value quoted");
	ok(data.find("\"testpass\"") != std::string::npos,
		"Write_MySQL_Users single: password value quoted");
	ok(data.find("default_hostgroup=1") != std::string::npos,
		"Write_MySQL_Users single: default_hostgroup unquoted integer");
	ok(data.find("\"mydb\"") != std::string::npos,
		"Write_MySQL_Users single: default_schema quoted");
	ok(data.find("\"test comment\"") != std::string::npos,
		"Write_MySQL_Users single: comment quoted");

	delete db;
}

static void test_write_mysql_users_multiple() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db->execute("INSERT INTO mysql_users (username, password, backend, frontend) "
		"VALUES ('user1', 'pass1', 1, 1)");
	db->execute("INSERT INTO mysql_users (username, password, backend, frontend) "
		"VALUES ('user2', 'pass2', 1, 0)");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Users_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Users multiple: returns 0");
	ok(data.find("\"user1\"") != std::string::npos,
		"Write_MySQL_Users multiple: first user present");
	ok(data.find("\"user2\"") != std::string::npos,
		"Write_MySQL_Users multiple: second user present");
	// Multiple entries are comma-separated
	ok(data.find(",\n") != std::string::npos,
		"Write_MySQL_Users multiple: entries are comma-separated");

	delete db;
}

// ============================================================
// Write_Scheduler_to_configfile()
// ============================================================

static void test_write_scheduler_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Scheduler_to_configfile(data);

	ok(rc == 0, "Write_Scheduler empty: returns 0");
	ok(data.find("scheduler:") != std::string::npos,
		"Write_Scheduler empty: section header present");

	delete db;
}

static void test_write_scheduler_single() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER);
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, arg1, arg2, arg3, arg4, arg5, comment) "
		"VALUES (1, 1, 5000, '/usr/bin/check.sh', 'arg_one', NULL, NULL, NULL, NULL, 'health check')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Scheduler_to_configfile(data);

	ok(rc == 0, "Write_Scheduler single: returns 0");
	ok(data.find("scheduler:") != std::string::npos,
		"Write_Scheduler single: section header present");
	ok(data.find("id=1") != std::string::npos,
		"Write_Scheduler single: id unquoted");
	ok(data.find("interval_ms=5000") != std::string::npos,
		"Write_Scheduler single: interval_ms present");
	ok(data.find("\"/usr/bin/check.sh\"") != std::string::npos,
		"Write_Scheduler single: filename quoted");
	ok(data.find("\"arg_one\"") != std::string::npos,
		"Write_Scheduler single: arg1 quoted");
	ok(data.find("\"health check\"") != std::string::npos,
		"Write_Scheduler single: comment quoted");

	delete db;
}

static void test_write_scheduler_null_args() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER);
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, comment) "
		"VALUES (2, 1, 1000, '/usr/bin/run.sh', '')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Scheduler_to_configfile(data);

	ok(rc == 0, "Write_Scheduler null args: returns 0");
	// NULL args should not produce output (addField skips NULL)
	ok(data.find("arg1") == std::string::npos,
		"Write_Scheduler null args: arg1 absent when NULL");
	ok(data.find("arg2") == std::string::npos,
		"Write_Scheduler null args: arg2 absent when NULL");

	delete db;
}

// ============================================================
// Write_Restapi_to_configfile()
// ============================================================

static void test_write_restapi_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Restapi_to_configfile(data);

	ok(rc == 0, "Write_Restapi empty: returns 0");
	ok(data.find("restapi_routes:") != std::string::npos,
		"Write_Restapi empty: section header present");

	delete db;
}

static void test_write_restapi_single() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);
	db->execute("INSERT INTO restapi_routes (id, active, timeout_ms, method, uri, script, comment) "
		"VALUES (1, 1, 5000, 'GET', '/v1/health', '/usr/bin/health.sh', 'health endpoint')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Restapi_to_configfile(data);

	ok(rc == 0, "Write_Restapi single: returns 0");
	ok(data.find("id=1") != std::string::npos,
		"Write_Restapi single: id unquoted");
	ok(data.find("timeout_ms=5000") != std::string::npos,
		"Write_Restapi single: timeout_ms unquoted");
	// method is field[3] which uses empty dq="" so unquoted
	ok(data.find("method=") != std::string::npos,
		"Write_Restapi single: method present");
	ok(data.find("\"/v1/health\"") != std::string::npos,
		"Write_Restapi single: uri quoted");
	ok(data.find("\"/usr/bin/health.sh\"") != std::string::npos,
		"Write_Restapi single: script quoted");
	ok(data.find("\"health endpoint\"") != std::string::npos,
		"Write_Restapi single: comment quoted");

	delete db;
}

// ============================================================
// Write_MySQL_Query_Rules_to_configfile()
// ============================================================

static void test_write_query_rules_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Query_Rules_to_configfile(data);

	ok(rc == 0, "Write_Query_Rules empty: returns 0");
	ok(data.find("mysql_query_rules:") != std::string::npos,
		"Write_Query_Rules empty: section header present");

	delete db;
}

static void test_write_query_rules_single() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	db->execute("INSERT INTO mysql_query_rules "
		"(rule_id, active, username, schemaname, flagIN, match_digest, "
		"destination_hostgroup, apply, comment) "
		"VALUES (1, 1, 'admin', 'testdb', 0, '^SELECT', 10, 1, 'route selects')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Query_Rules_to_configfile(data);

	ok(rc == 0, "Write_Query_Rules single: returns 0");
	ok(data.find("mysql_query_rules:") != std::string::npos,
		"Write_Query_Rules single: section header present");
	ok(data.find("rule_id=1") != std::string::npos,
		"Write_Query_Rules single: rule_id unquoted");
	ok(data.find("active=1") != std::string::npos,
		"Write_Query_Rules single: active unquoted");
	ok(data.find("\"admin\"") != std::string::npos,
		"Write_Query_Rules single: username quoted");
	ok(data.find("\"^SELECT\"") != std::string::npos,
		"Write_Query_Rules single: match_digest quoted");
	ok(data.find("destination_hostgroup=10") != std::string::npos,
		"Write_Query_Rules single: destination_hostgroup unquoted");
	ok(data.find("apply=1") != std::string::npos,
		"Write_Query_Rules single: apply unquoted");

	delete db;
}

static void test_write_query_rules_null_fields() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	// Insert a minimal rule — many optional fields will be NULL
	db->execute("INSERT INTO mysql_query_rules (rule_id, active, apply) "
		"VALUES (5, 0, 0)");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Query_Rules_to_configfile(data);

	ok(rc == 0, "Write_Query_Rules nulls: returns 0");
	ok(data.find("rule_id=5") != std::string::npos,
		"Write_Query_Rules nulls: rule_id present");
	// NULL fields should not appear (addField skips them)
	ok(data.find("username") == std::string::npos,
		"Write_Query_Rules nulls: NULL username absent");
	ok(data.find("match_digest") == std::string::npos,
		"Write_Query_Rules nulls: NULL match_digest absent");
	ok(data.find("error_msg") == std::string::npos,
		"Write_Query_Rules nulls: NULL error_msg absent");

	delete db;
}

// ============================================================
// Write_MySQL_Servers_to_configfile()
// ============================================================

static void test_write_mysql_servers_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	// Use the exact same table definitions as the real code (no hard-coded strings)
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_RDS_BGD_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Servers empty: returns 0");
	ok(data.find("mysql_servers:") != std::string::npos,
		"Write_MySQL_Servers empty: mysql_servers section present");
	ok(data.find("mysql_replication_hostgroups:") != std::string::npos,
		"Write_MySQL_Servers empty: replication_hostgroups section present");
	ok(data.find("mysql_group_replication_hostgroups:") != std::string::npos,
		"Write_MySQL_Servers empty: group_replication_hostgroups section present");
	ok(data.find("mysql_galera_hostgroups:") != std::string::npos,
		"Write_MySQL_Servers empty: galera_hostgroups section present");
	ok(data.find("mysql_aws_aurora_hostgroups:") != std::string::npos,
		"Write_MySQL_Servers empty: aws_aurora_hostgroups section present");
	ok(data.find("mysql_hostgroup_attributes:") != std::string::npos,
		"Write_MySQL_Servers empty: hostgroup_attributes section present");

	delete db;
}

static void test_write_mysql_servers_with_data() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, status, "
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) "
		"VALUES (1, '127.0.0.1', 3306, 0, 'ONLINE', 100, 0, 500, 10, 1, 50, 'primary')");

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_RDS_BGD_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);
	// Populate sub-tables with data (not empty!)
	db->execute("INSERT INTO mysql_replication_hostgroups VALUES (10,20,'read_only','repl')");
	db->execute("INSERT INTO mysql_group_replication_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (30,31,32,33,1,2,0,100,'gr')");
	db->execute("INSERT INTO mysql_galera_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (40,41,42,43,1,3,1,50,'galera')");
	db->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (50,51,1,3306,'.aurora.example',100,1000,800,0,1,0,0,1,'aurora')");
	db->execute("INSERT INTO mysql_aws_rds_bgd_hostgroups (writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,active,writer_is_also_reader,check_interval_ms,check_timeout_ms,comment) VALUES (70,71,72,73,1,0,1000,800,'rds')");
	db->execute("INSERT INTO mysql_hostgroup_attributes (hostgroup_id,max_num_online_servers,autocommit,free_connections_pct,init_connect,multiplex,connection_warming,throttle_connections_per_sec,ignore_session_variables,hostgroup_settings,servers_defaults,comment) VALUES (60,100,-1,50,'SET autocommit=1',1,0,100,'','{}','{}','hg60')");
	db->execute("INSERT INTO mysql_servers_ssl_params (hostname,port,username,ssl_ca,ssl_cert,ssl_key,ssl_capath,ssl_crl,ssl_crlpath,ssl_cipher,tls_version,comment) VALUES ('h1',3306,'u1','/ca','/cert','/key','','','','','TLSv1.2','ssl1')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Servers data: returns 0");
	ok(data.find("hostgroup_id=1") != std::string::npos,
		"Write_MySQL_Servers data: hostgroup_id unquoted");
	ok(data.find("\"127.0.0.1\"") != std::string::npos,
		"Write_MySQL_Servers data: hostname quoted");
	ok(data.find("port=3306") != std::string::npos,
		"Write_MySQL_Servers data: port unquoted");
	ok(data.find("weight=100") != std::string::npos,
		"Write_MySQL_Servers data: weight unquoted");
	ok(data.find("\"ONLINE\"") != std::string::npos,
		"Write_MySQL_Servers data: status quoted");
	ok(data.find("use_ssl=1") != std::string::npos,
		"Write_MySQL_Servers data: use_ssl unquoted");
	ok(data.find("\"primary\"") != std::string::npos,
		"Write_MySQL_Servers data: comment quoted");

	delete db;
}

static void test_write_mysql_servers_replication_hostgroups() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	db->execute("INSERT INTO mysql_replication_hostgroups VALUES (10, 20, 'read_only', 'repl group')");
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_RDS_BGD_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);
	// Also populate one more sub for good measure
	db->execute("INSERT INTO mysql_hostgroup_attributes (hostgroup_id, comment) VALUES (99, 'hg99')");
	db->execute("INSERT INTO mysql_servers_ssl_params (hostname,port,username,comment) VALUES ('h99',3306,'u99','ssl99')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_Servers repl hg: returns 0");
	ok(data.find("mysql_replication_hostgroups:") != std::string::npos,
		"Write_Servers repl hg: section header present");
	ok(data.find("writer_hostgroup=10") != std::string::npos,
		"Write_Servers repl hg: writer_hostgroup present");
	ok(data.find("reader_hostgroup=20") != std::string::npos,
		"Write_Servers repl hg: reader_hostgroup present");
	ok(data.find("\"read_only\"") != std::string::npos,
		"Write_Servers repl hg: check_type quoted");
	ok(data.find("\"repl group\"") != std::string::npos,
		"Write_Servers repl hg: comment quoted");
	// Verify other subs are also serialized when present
	ok(data.find("mysql_hostgroup_attributes:") != std::string::npos,
		"Write_Servers repl hg: hostgroup_attributes section present");
	ok(data.find("hostgroup_id=99") != std::string::npos,
		"Write_Servers repl hg: hostgroup_attributes data present");
	ok(data.find("mysql_servers_ssl_params:") != std::string::npos,
		"Write_Servers repl hg: ssl_params section present");
	ok(data.find("\"ssl99\"") != std::string::npos,
		"Write_Servers repl hg: ssl_params data present");

	delete db;
}

// ============================================================
// Write_Global_Variables_to_configfile()
// ============================================================

static void test_write_global_variables_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Global_Variables_to_configfile(data);

	ok(rc == 0, "Write_Global_Vars empty: returns 0");
	ok(data.empty(), "Write_Global_Vars empty: no output for empty table");

	delete db;
}

static void test_write_global_variables_single_prefix() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	db->execute("INSERT INTO global_variables VALUES ('mysql-max_connections', '2048')");
	db->execute("INSERT INTO global_variables VALUES ('mysql-default_query_delay', '0')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Global_Variables_to_configfile(data);

	ok(rc == 0, "Write_Global_Vars single prefix: returns 0");
	ok(data.find("mysql_variables") != std::string::npos,
		"Write_Global_Vars single prefix: section header uses underscore");
	// The variable name should have the prefix stripped
	ok(data.find("max_connections=\"2048\"") != std::string::npos,
		"Write_Global_Vars single prefix: variable name has prefix stripped");
	ok(data.find("default_query_delay=\"0\"") != std::string::npos,
		"Write_Global_Vars single prefix: second variable present");
	// Section should start with { and end with }
	ok(data.find("{\n") != std::string::npos,
		"Write_Global_Vars single prefix: opening brace present");
	ok(data.find("}\n") != std::string::npos,
		"Write_Global_Vars single prefix: closing brace present");

	delete db;
}

static void test_write_global_variables_multiple_prefixes() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	db->execute("INSERT INTO global_variables VALUES ('admin-admin_credentials', 'admin:admin')");
	db->execute("INSERT INTO global_variables VALUES ('mysql-max_connections', '1024')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Global_Variables_to_configfile(data);

	ok(rc == 0, "Write_Global_Vars multi prefix: returns 0");
	ok(data.find("admin_variables") != std::string::npos,
		"Write_Global_Vars multi prefix: admin section present");
	ok(data.find("mysql_variables") != std::string::npos,
		"Write_Global_Vars multi prefix: mysql section present");
	ok(data.find("admin_credentials=\"admin:admin\"") != std::string::npos,
		"Write_Global_Vars multi prefix: admin var present with prefix stripped");
	ok(data.find("max_connections=\"1024\"") != std::string::npos,
		"Write_Global_Vars multi prefix: mysql var present with prefix stripped");

	delete db;
}

static void test_write_global_variables_empty_value() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	db->execute("INSERT INTO global_variables VALUES ('mysql-blank_val', '')");
	db->execute("INSERT INTO global_variables VALUES ('mysql-nonempty_var', 'value')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Global_Variables_to_configfile(data);

	ok(rc == 0, "Write_Global_Vars empty val: returns 0");
	// Empty values should be skipped (the code checks strlen)
	ok(data.find("blank_val") == std::string::npos,
		"Write_Global_Vars empty val: empty value variable skipped");
	ok(data.find("nonempty_var=\"value\"") != std::string::npos,
		"Write_Global_Vars empty val: non-empty variable present");

	delete db;
}

// ============================================================
// Write_ProxySQL_Servers_to_configfile()
// ============================================================

static void test_write_proxysql_servers_empty() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_ProxySQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_ProxySQL_Servers empty: returns 0");
	ok(data.find("proxysql_servers:") != std::string::npos,
		"Write_ProxySQL_Servers empty: section header present");

	delete db;
}

static void test_write_proxysql_servers_single() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);
	db->execute("INSERT INTO proxysql_servers VALUES ('proxy1.example.com', 6032, 100, 'node 1')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_ProxySQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_ProxySQL_Servers single: returns 0");
	ok(data.find("\"proxy1.example.com\"") != std::string::npos,
		"Write_ProxySQL_Servers single: hostname quoted");
	ok(data.find("port=6032") != std::string::npos,
		"Write_ProxySQL_Servers single: port unquoted");
	ok(data.find("weight=100") != std::string::npos,
		"Write_ProxySQL_Servers single: weight unquoted");
	ok(data.find("\"node 1\"") != std::string::npos,
		"Write_ProxySQL_Servers single: comment quoted");

	delete db;
}

// ============================================================
// Edge cases: special characters and quoting
// ============================================================

static void test_write_mysql_users_special_chars() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	// Username with a double-quote character to test escaping
	db->execute("INSERT INTO mysql_users (username, password, backend, frontend, comment) "
		"VALUES ('test\"user', 'pass', 1, 1, 'comment with \"quotes\"')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Users_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Users special chars: returns 0");
	// addField escapes " to \"
	ok(data.find("\\\"") != std::string::npos,
		"Write_MySQL_Users special chars: double quotes escaped in output");

	delete db;
}

static void test_write_scheduler_multiple() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER);
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, comment) "
		"VALUES (1, 1, 1000, '/check1.sh', 'first')");
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, comment) "
		"VALUES (2, 0, 2000, '/check2.sh', 'second')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Scheduler_to_configfile(data);

	ok(rc == 0, "Write_Scheduler multiple: returns 0");
	ok(data.find("\"/check1.sh\"") != std::string::npos,
		"Write_Scheduler multiple: first entry present");
	ok(data.find("\"/check2.sh\"") != std::string::npos,
		"Write_Scheduler multiple: second entry present");
	ok(data.find(",\n") != std::string::npos,
		"Write_Scheduler multiple: entries comma-separated");
	// Verify proper structure: opening and closing
	ok(data.find("(\n") != std::string::npos,
		"Write_Scheduler multiple: list opening paren");
	ok(data.find("\n)\n") != std::string::npos,
		"Write_Scheduler multiple: list closing paren");

	delete db;
}

static void test_write_restapi_multiple() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);
	db->execute("INSERT INTO restapi_routes (id, active, timeout_ms, method, uri, script, comment) "
		"VALUES (1, 1, 1000, 'GET', '/v1/a', '/a.sh', 'route a')");
	db->execute("INSERT INTO restapi_routes (id, active, timeout_ms, method, uri, script, comment) "
		"VALUES (2, 1, 2000, 'POST', '/v1/b', '/b.sh', 'route b')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Restapi_to_configfile(data);

	ok(rc == 0, "Write_Restapi multiple: returns 0");
	ok(data.find("\"/v1/a\"") != std::string::npos,
		"Write_Restapi multiple: first route URI present");
	ok(data.find("\"/v1/b\"") != std::string::npos,
		"Write_Restapi multiple: second route URI present");
	ok(data.find(",\n") != std::string::npos,
		"Write_Restapi multiple: entries comma-separated");

	delete db;
}

// ============================================================
// Nonexistent table error handling
// ============================================================

static void test_write_mysql_users_no_table() {
	SQLite3DB* db = create_test_db();
	// Do NOT create the mysql_users table

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Users_to_configfile(data);

	ok(rc == -1, "Write_MySQL_Users no table: returns -1 on missing table");

	delete db;
}

static void test_write_scheduler_no_table() {
	SQLite3DB* db = create_test_db();

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Scheduler_to_configfile(data);

	ok(rc == -1, "Write_Scheduler no table: returns -1 on missing table");

	delete db;
}

static void test_write_restapi_no_table() {
	SQLite3DB* db = create_test_db();

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Restapi_to_configfile(data);

	ok(rc == -1, "Write_Restapi no table: returns -1 on missing table");

	delete db;
}

static void test_write_query_rules_no_table() {
	SQLite3DB* db = create_test_db();

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Query_Rules_to_configfile(data);

	ok(rc == -1, "Write_Query_Rules no table: returns -1 on missing table");

	delete db;
}

static void test_write_global_vars_no_table() {
	SQLite3DB* db = create_test_db();

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_Global_Variables_to_configfile(data);

	ok(rc == -1, "Write_Global_Vars no table: returns -1 on missing table");

	delete db;
}

// ============================================================
// Tests for new writers (fast_routing + firewall) - REAL DATA
// ============================================================

static void test_write_mysql_query_rules_fast_routing() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING);
	db->execute("INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ('u1','s1',0,10,'r1')");
	db->execute("INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ('u2','s2',1,20,'r2')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Query_Rules_Fast_Routing_to_configfile(data);

	ok(rc == 0, "Write_MySQL_QRFR: returns 0");
	ok(data.find("mysql_query_rules_fast_routing:") != std::string::npos, "Write_MySQL_QRFR: section present");
	ok(data.find("\"u1\"") != std::string::npos && data.find("\"s1\"") != std::string::npos && data.find("destination_hostgroup=10") != std::string::npos, "Write_MySQL_QRFR: row1");
	ok(data.find("\"u2\"") != std::string::npos && data.find("\"s2\"") != std::string::npos && data.find("destination_hostgroup=20") != std::string::npos, "Write_MySQL_QRFR: row2");
	ok(data.find("comment=\"r1\"") != std::string::npos && data.find("comment=\"r2\"") != std::string::npos, "Write_MySQL_QRFR: comments");

	delete db;
}

static void test_write_pgsql_query_rules_fast_routing() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_FAST_ROUTING);
	db->execute("INSERT INTO pgsql_query_rules_fast_routing (username, database, flagIN, destination_hostgroup, comment) VALUES ('pu1','pd1',0,11,'pr1')");
	db->execute("INSERT INTO pgsql_query_rules_fast_routing (username, database, flagIN, destination_hostgroup, comment) VALUES ('pu2','pd2',2,22,'pr2')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_PgSQL_Query_Rules_Fast_Routing_to_configfile(data);

	ok(rc == 0, "Write_PgSQL_QRFR: returns 0");
	ok(data.find("pgsql_query_rules_fast_routing:") != std::string::npos, "Write_PgSQL_QRFR: section present");
	ok(data.find("\"pu1\"") != std::string::npos && data.find("\"pd1\"") != std::string::npos && data.find("destination_hostgroup=11") != std::string::npos, "Write_PgSQL_QRFR: row1");
	ok(data.find("\"pu2\"") != std::string::npos && data.find("\"pd2\"") != std::string::npos && data.find("destination_hostgroup=22") != std::string::npos, "Write_PgSQL_QRFR: row2");

	delete db;
}

static void test_write_mysql_firewall() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	db->execute("INSERT INTO mysql_firewall_whitelist_users (active,username,client_address,mode,comment) VALUES (1,'fwu','10.0.0.1','PROTECTING','u')");
	db->execute("INSERT INTO mysql_firewall_whitelist_rules (active,username,client_address,schemaname,flagIN,digest,comment) VALUES (1,'fwu','10.0.0.1','dbx',0,'d1','r1')");
	db->execute("INSERT INTO mysql_firewall_whitelist_sqli_fingerprints (active,fingerprint) VALUES (1,'sqli1')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_MySQL_Firewall_to_configfile(data);

	ok(rc == 0, "Write_MySQL_Firewall: returns 0");
	ok(data.find("mysql_firewall_whitelist_users:") != std::string::npos, "Write_MySQL_Firewall: users section");
	ok(data.find("mysql_firewall_whitelist_rules:") != std::string::npos, "Write_MySQL_Firewall: rules section");
	ok(data.find("mysql_firewall_whitelist_sqli_fingerprints:") != std::string::npos, "Write_MySQL_Firewall: sqli section");
	ok(data.find("\"fwu\"") != std::string::npos && data.find("\"d1\"") != std::string::npos && data.find("\"sqli1\"") != std::string::npos, "Write_MySQL_Firewall: data rows");

	delete db;
}

static void test_write_pgsql_firewall() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_USERS);
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_RULES);
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	db->execute("INSERT INTO pgsql_firewall_whitelist_users (active,username,client_address,mode,comment) VALUES (1,'pfu','10.0.0.2','DETECTING','pu')");
	db->execute("INSERT INTO pgsql_firewall_whitelist_rules (active,username,client_address,database,flagIN,digest,comment) VALUES (1,'pfu','10.0.0.2','pdb',3,'pd1','pr1')");
	db->execute("INSERT INTO pgsql_firewall_whitelist_sqli_fingerprints (active,fingerprint) VALUES (1,'psqli1')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_PgSQL_Firewall_to_configfile(data);

	ok(rc == 0, "Write_PgSQL_Firewall: returns 0");
	ok(data.find("pgsql_firewall_whitelist_users:") != std::string::npos, "Write_PgSQL_Firewall: users section");
	ok(data.find("pgsql_firewall_whitelist_rules:") != std::string::npos, "Write_PgSQL_Firewall: rules section");
	ok(data.find("pgsql_firewall_whitelist_sqli_fingerprints:") != std::string::npos, "Write_PgSQL_Firewall: sqli section");
	ok(data.find("\"pfu\"") != std::string::npos && data.find("\"pd1\"") != std::string::npos && data.find("\"psqli1\"") != std::string::npos, "Write_PgSQL_Firewall: data rows");

	delete db;
}

static void test_write_pgsql_users() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_USERS);
	db->execute("INSERT INTO pgsql_users (username,password,backend,frontend,default_hostgroup,comment) VALUES ('pgu','pgp',1,1,5,'pg comment')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_PgSQL_Users_to_configfile(data);

	ok(rc == 0, "Write_PgSQL_Users: returns 0");
	ok(data.find("pgsql_users:") != std::string::npos, "Write_PgSQL_Users: section");
	ok(data.find("\"pgu\"") != std::string::npos && data.find("default_hostgroup=5") != std::string::npos, "Write_PgSQL_Users: data");

	delete db;
}

static void test_write_pgsql_query_rules() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES);
	db->execute("INSERT INTO pgsql_query_rules (rule_id,active,username,database,flagIN,destination_hostgroup,apply,comment) VALUES (1,1,'pu','pdb',0,7,1,'pqr')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_PgSQL_Query_Rules_to_configfile(data);

	ok(rc == 0, "Write_PgSQL_Query_Rules: returns 0");
	ok(data.find("pgsql_query_rules:") != std::string::npos, "Write_PgSQL_Query_Rules: section");
	ok(data.find("rule_id=1") != std::string::npos && data.find("destination_hostgroup=7") != std::string::npos && data.find("\"pqr\"") != std::string::npos, "Write_PgSQL_Query_Rules: data");

	delete db;
}

static void test_write_pgsql_servers() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_SERVERS);
	db->execute("INSERT INTO pgsql_servers (hostgroup_id,hostname,port,status,weight,comment) VALUES (1,'pgs',5432,'ONLINE',200,'pgs1')");
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS);
	db->execute("INSERT INTO pgsql_replication_hostgroups (writer_hostgroup,reader_hostgroup,check_type,comment) VALUES (10,20,'read_only','pgr')");
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES);
	db->execute("INSERT INTO pgsql_hostgroup_attributes (hostgroup_id,comment) VALUES (30,'pgha')");
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_SERVERS_SSL_PARAMS);
	db->execute("INSERT INTO pgsql_servers_ssl_params (hostname,port,username,comment) VALUES ('pgssl',5432,'pu','pssl')");

	ProxySQL_Config cfg(db);
	std::string data;
	int rc = cfg.Write_PgSQL_Servers_to_configfile(data);

	ok(rc == 0, "Write_PgSQL_Servers: returns 0");
	ok(data.find("pgsql_servers:") != std::string::npos, "Write_PgSQL_Servers: servers section");
	ok(data.find("pgsql_replication_hostgroups:") != std::string::npos && data.find("writer_hostgroup=10") != std::string::npos, "Write_PgSQL_Servers: repl hg");
	ok(data.find("pgsql_hostgroup_attributes:") != std::string::npos && data.find("hostgroup_id=30") != std::string::npos, "Write_PgSQL_Servers: hg attrs");
	ok(data.find("pgsql_servers_ssl_params:") != std::string::npos && data.find("\"pssl\"") != std::string::npos, "Write_PgSQL_Servers: ssl params");

	delete db;
}

// ============================================================
// Write -> Read round-trip tests for the new tables.
// These exercise the import (Read_*_from_configfile) half, which had
// zero coverage. Flow: Write table to a config string -> parse the
// string with libconfig -> Read_*_from_configfile into a fresh DB ->
// verify the rows landed correctly.
// ============================================================

static void test_roundtrip_mysql_query_rules_fast_routing() {
	// Write side: populate + serialize
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING);
	db->execute("INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ('u1','s1',0,10,'r1')");
	db->execute("INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ('u2','s2',1,20,'r2')");
	ProxySQL_Config cfg(db);
	std::string data;
	cfg.Write_MySQL_Query_Rules_Fast_Routing_to_configfile(data);

	// Read side: clear the table, reload from the serialized string
	db->execute("DELETE FROM mysql_query_rules_fast_routing");
	ProxySQL_ConfigFile* cf = load_config_from_string(data);
	ProxySQL_ConfigFile* saved = GloVars.confFile;
	GloVars.confFile = cf;
	int rows = cfg.Read_MySQL_Query_Rules_Fast_Routing_from_configfile();
	GloVars.confFile = saved;
	delete cf;

	ok(rows == 2, "RT MySQL_QRFR: Read returns 2 rows (got %d)", rows);
	ok(db_count_rows(db, "mysql_query_rules_fast_routing") == 2, "RT MySQL_QRFR: table has 2 rows");
	std::string hg = db_select_string(db, "destination_hostgroup", "mysql_query_rules_fast_routing",
		"username='u2' AND schemaname='s2'");
	ok(hg == "20", "RT MySQL_QRFR: u2/s2 -> hg 20 (got '%s')", hg.c_str());

	delete db;
}

static void test_roundtrip_pgsql_query_rules_fast_routing() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_FAST_ROUTING);
	db->execute("INSERT INTO pgsql_query_rules_fast_routing (username, database, flagIN, destination_hostgroup, comment) VALUES ('pu1','pd1',0,11,'pr1')");
	db->execute("INSERT INTO pgsql_query_rules_fast_routing (username, database, flagIN, destination_hostgroup, comment) VALUES ('pu2','pd2',2,22,'pr2')");
	ProxySQL_Config cfg(db);
	std::string data;
	cfg.Write_PgSQL_Query_Rules_Fast_Routing_to_configfile(data);

	db->execute("DELETE FROM pgsql_query_rules_fast_routing");
	ProxySQL_ConfigFile* cf = load_config_from_string(data);
	ProxySQL_ConfigFile* saved = GloVars.confFile;
	GloVars.confFile = cf;
	int rows = cfg.Read_PgSQL_Query_Rules_Fast_Routing_from_configfile();
	GloVars.confFile = saved;
	delete cf;

	ok(rows == 2, "RT PgSQL_QRFR: Read returns 2 rows (got %d)", rows);
	ok(db_count_rows(db, "pgsql_query_rules_fast_routing") == 2, "RT PgSQL_QRFR: table has 2 rows");
	std::string hg = db_select_string(db, "destination_hostgroup", "pgsql_query_rules_fast_routing",
		"username='pu2' AND database='pd2'");
	ok(hg == "22", "RT PgSQL_QRFR: pu2/pd2 -> hg 22 (got '%s')", hg.c_str());

	delete db;
}

static void test_roundtrip_mysql_firewall() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	db->execute("INSERT INTO mysql_firewall_whitelist_users (active,username,client_address,mode,comment) VALUES (1,'fwu','10.0.0.1','PROTECTING','u')");
	db->execute("INSERT INTO mysql_firewall_whitelist_rules (active,username,client_address,schemaname,flagIN,digest,comment) VALUES (1,'fwu','10.0.0.1','dbx',0,'d1','r1')");
	db->execute("INSERT INTO mysql_firewall_whitelist_sqli_fingerprints (active,fingerprint) VALUES (1,'sqli1')");
	ProxySQL_Config cfg(db);
	std::string data;
	cfg.Write_MySQL_Firewall_to_configfile(data);

	db->execute("DELETE FROM mysql_firewall_whitelist_users");
	db->execute("DELETE FROM mysql_firewall_whitelist_rules");
	db->execute("DELETE FROM mysql_firewall_whitelist_sqli_fingerprints");
	ProxySQL_ConfigFile* cf = load_config_from_string(data);
	ProxySQL_ConfigFile* saved = GloVars.confFile;
	GloVars.confFile = cf;
	int rows = cfg.Read_MySQL_Firewall_from_configfile();
	GloVars.confFile = saved;
	delete cf;

	// 2 inserts (users+rules) + 1 fingerprint = 3 rows reported
	ok(rows == 3, "RT MySQL_Firewall: Read returns 3 rows (got %d)", rows);
	ok(db_count_rows(db, "mysql_firewall_whitelist_users") == 1, "RT MySQL_Firewall: users row restored");
	ok(db_count_rows(db, "mysql_firewall_whitelist_rules") == 1, "RT MySQL_Firewall: rules row restored");
	ok(db_count_rows(db, "mysql_firewall_whitelist_sqli_fingerprints") == 1, "RT MySQL_Firewall: sqli fingerprint restored");
	std::string mode = db_select_string(db, "mode", "mysql_firewall_whitelist_users", "username='fwu'");
	ok(mode == "PROTECTING", "RT MySQL_Firewall: mode PROTECTING restored (got '%s')", mode.c_str());

	delete db;
}

static void test_roundtrip_pgsql_firewall() {
	SQLite3DB* db = create_test_db();
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_USERS);
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_RULES);
	db->execute(ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	db->execute("INSERT INTO pgsql_firewall_whitelist_users (active,username,client_address,mode,comment) VALUES (1,'pfu','10.0.0.2','DETECTING','pu')");
	db->execute("INSERT INTO pgsql_firewall_whitelist_rules (active,username,client_address,database,flagIN,digest,comment) VALUES (1,'pfu','10.0.0.2','pdb',3,'pd1','pr1')");
	db->execute("INSERT INTO pgsql_firewall_whitelist_sqli_fingerprints (active,fingerprint) VALUES (1,'psqli1')");
	ProxySQL_Config cfg(db);
	std::string data;
	cfg.Write_PgSQL_Firewall_to_configfile(data);

	db->execute("DELETE FROM pgsql_firewall_whitelist_users");
	db->execute("DELETE FROM pgsql_firewall_whitelist_rules");
	db->execute("DELETE FROM pgsql_firewall_whitelist_sqli_fingerprints");
	ProxySQL_ConfigFile* cf = load_config_from_string(data);
	ProxySQL_ConfigFile* saved = GloVars.confFile;
	GloVars.confFile = cf;
	int rows = cfg.Read_PgSQL_Firewall_from_configfile();
	GloVars.confFile = saved;
	delete cf;

	ok(rows == 3, "RT PgSQL_Firewall: Read returns 3 rows (got %d)", rows);
	ok(db_count_rows(db, "pgsql_firewall_whitelist_users") == 1, "RT PgSQL_Firewall: users row restored");
	ok(db_count_rows(db, "pgsql_firewall_whitelist_rules") == 1, "RT PgSQL_Firewall: rules row restored");
	ok(db_count_rows(db, "pgsql_firewall_whitelist_sqli_fingerprints") == 1, "RT PgSQL_Firewall: sqli fingerprint restored");
	std::string mode = db_select_string(db, "mode", "pgsql_firewall_whitelist_users", "username='pfu'");
	ok(mode == "DETECTING", "RT PgSQL_Firewall: mode DETECTING restored (got '%s')", mode.c_str());

	delete db;
}

// ============================================================
// Main
// ============================================================

int main() {
	plan(161);  // matches exact number of ok() assertions in this file
	test_init_minimal();

	// MySQL side - existing + new data-driven tests
	test_write_mysql_users_empty();
	test_write_mysql_users_single();
	test_write_mysql_users_multiple();
	test_write_mysql_users_special_chars();

	test_write_scheduler_empty();
	test_write_scheduler_single();
	test_write_scheduler_null_args();
	test_write_scheduler_multiple();

	test_write_restapi_empty();
	test_write_restapi_single();
	test_write_restapi_multiple();

	test_write_query_rules_empty();
	test_write_query_rules_single();
	test_write_query_rules_null_fields();

	// NEW: fast routing + firewall (MySQL)
	test_write_mysql_query_rules_fast_routing();
	test_write_mysql_firewall();

	test_write_mysql_servers_empty();
	test_write_mysql_servers_with_data();
	test_write_mysql_servers_replication_hostgroups();

	test_write_global_variables_empty();
	test_write_global_variables_single_prefix();
	test_write_global_variables_multiple_prefixes();
	test_write_global_variables_empty_value();

	test_write_proxysql_servers_empty();
	test_write_proxysql_servers_single();

	// PgSQL side - all of them with real data
	test_write_pgsql_users();
	test_write_pgsql_query_rules();
	test_write_pgsql_query_rules_fast_routing();
	test_write_pgsql_firewall();
	test_write_pgsql_servers();

	// Write -> Read round-trip for the new tables (covers the import half)
	test_roundtrip_mysql_query_rules_fast_routing();
	test_roundtrip_pgsql_query_rules_fast_routing();
	test_roundtrip_mysql_firewall();
	test_roundtrip_pgsql_firewall();

	// Error handling (still useful)
	test_write_mysql_users_no_table();
	test_write_scheduler_no_table();
	test_write_restapi_no_table();
	test_write_query_rules_no_table();
	test_write_global_vars_no_table();

	test_cleanup_minimal();
	return exit_status();
}
