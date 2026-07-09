/**
 * @file config_write_unit-t.cpp
 * @brief Unit tests for ProxySQL_Config Write_*_to_configfile() functions.
 *
 * Tests the following functions:
 * - Write_MySQL_Users_to_configfile()
 * - Write_Scheduler_to_configfile()
 * - Write_Restapi_to_configfile()
 * - Write_MySQL_Query_Rules_to_configfile()
 * - Write_MySQL_Servers_to_configfile()
 * - Write_Global_Variables_to_configfile()
 * - Write_ProxySQL_Servers_to_configfile()
 *
 * Each test creates an in-memory SQLite3DB, populates it with the
 * appropriate table schema and test data, constructs a ProxySQL_Config,
 * and verifies the formatted output string.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "proxysql_config.h"
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
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);
	// Populate sub-tables with data (not empty!)
	db->execute("INSERT INTO mysql_replication_hostgroups VALUES (10,20,'read_only','repl')");
	db->execute("INSERT INTO mysql_group_replication_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (30,31,32,33,1,2,0,100,'gr')");
	db->execute("INSERT INTO mysql_galera_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (40,41,42,43,1,3,1,50,'galera')");
	db->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (50,51,1,3306,'aurora.example',100,1000,5000,0,1,0,0,1,'aurora')");
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
// Main
// ============================================================

int main() {
	plan(111);
	test_init_minimal();

	// Write_MySQL_Users_to_configfile
	test_write_mysql_users_empty();          // 3
	test_write_mysql_users_single();         // 7
	test_write_mysql_users_multiple();       // 4
	test_write_mysql_users_special_chars();  // 2

	// Write_Scheduler_to_configfile
	test_write_scheduler_empty();            // 2
	test_write_scheduler_single();           // 7
	test_write_scheduler_null_args();        // 3
	test_write_scheduler_multiple();         // 6

	// Write_Restapi_to_configfile
	test_write_restapi_empty();              // 2
	test_write_restapi_single();             // 7
	test_write_restapi_multiple();           // 4

	// Write_MySQL_Query_Rules_to_configfile
	test_write_query_rules_empty();          // 2
	test_write_query_rules_single();         // 8
	test_write_query_rules_null_fields();    // 5

	// Write_MySQL_Servers_to_configfile
	test_write_mysql_servers_empty();        // 7
	test_write_mysql_servers_with_data();    // 8
	test_write_mysql_servers_replication_hostgroups();  // 6

	// Write_Global_Variables_to_configfile
	test_write_global_variables_empty();            // 2
	test_write_global_variables_single_prefix();    // 6
	test_write_global_variables_multiple_prefixes();// 5
	test_write_global_variables_empty_value();      // 3

	// Write_ProxySQL_Servers_to_configfile
	test_write_proxysql_servers_empty();     // 2
	test_write_proxysql_servers_single();    // 5

	// Error handling: missing tables
	test_write_mysql_users_no_table();       // 1
	test_write_scheduler_no_table();         // 1
	test_write_restapi_no_table();           // 1
	test_write_query_rules_no_table();       // 1
	test_write_global_vars_no_table();       // 1

	test_cleanup_minimal();
	return exit_status();
}
