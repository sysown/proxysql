/**
 * @file admin_disk_upgrade_unit-t.cpp
 * @brief Unit tests for ProxySQL_Admin disk upgrade functions.
 *
 * Tests the schema migration functions in ProxySQL_Admin_Disk_Upgrade.cpp:
 *   - disk_upgrade_scheduler()
 *   - disk_upgrade_mysql_users()
 *   - disk_upgrade_mysql_servers()
 *   - disk_upgrade_rest_api_routes()
 *   - disk_upgrade_mysql_query_rules()
 *   - disk_upgrade_pgsql_replication_hostgroups()
 *
 * Each function upgrades old table schemas to the current version by:
 *   1. Detecting the old schema via check_table_structure()
 *   2. Renaming the old table
 *   3. Creating a new table with the current schema
 *   4. Copying data from the old table to the new one
 *
 * Strategy: We cannot call the ProxySQL_Admin constructor (it requires
 * many initialized globals). Instead we allocate raw memory, zero it,
 * set configdb to an in-memory SQLite3DB, and call the upgrade methods
 * via a friend class wrapper. The upgrade methods only access this->configdb.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "cpp.h"
#include "ProxySQL_Admin_Tables_Definitions.h"

#include <cstring>
#include <string>
#include <cstdlib>

// ---------------------------------------------------------------------------
// TestDiskUpgrade: friend class that accesses private disk_upgrade methods
// ---------------------------------------------------------------------------

/**
 * @brief Friend class wrapper for ProxySQL_Admin private disk_upgrade methods.
 *
 * The ProxySQL_Admin constructor requires many initialized globals
 * (GloProxyStats, scheduler, etc.) that are unavailable in the unit test
 * harness. Since the disk_upgrade_* methods only use this->configdb, we
 * allocate zeroed memory (skipping the constructor) and set configdb to
 * an in-memory SQLite3DB.
 */
class TestDiskUpgrade {
public:
	ProxySQL_Admin *admin;

	TestDiskUpgrade() {
		// NOTE: We intentionally skip the ProxySQL_Admin constructor because it
		// requires GloProxyStats, GloAdmin, and other daemon globals that are
		// unavailable in unit tests. The disk_upgrade_*() methods only access
		// this->configdb (a SQLite3DB pointer), so zeroed memory + setting
		// configdb is sufficient for these tests. This is technically UB in
		// C++ but is a pragmatic choice for test-only code.
		void *mem = calloc(1, sizeof(ProxySQL_Admin));
		admin = reinterpret_cast<ProxySQL_Admin*>(mem);
		SQLite3DB *db_ = new SQLite3DB();
		db_->open((char *)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		admin->configdb = db_;
	}

	~TestDiskUpgrade() {
		if (admin->configdb) {
			delete admin->configdb;
			admin->configdb = nullptr;
		}
		free(admin);
	}

	SQLite3DB* db() { return admin->configdb; }

	void upgrade_scheduler() { admin->disk_upgrade_scheduler(); }
	void upgrade_mysql_users() { admin->disk_upgrade_mysql_users(); }
	void upgrade_mysql_servers() { admin->disk_upgrade_mysql_servers(); }
	void upgrade_rest_api_routes() { admin->disk_upgrade_rest_api_routes(); }
	void upgrade_mysql_query_rules() { admin->disk_upgrade_mysql_query_rules(); }
	void upgrade_pgsql_replication_hostgroups() { admin->disk_upgrade_pgsql_replication_hostgroups(); }
};

// ---------------------------------------------------------------------------
// Helper: query a single integer from the database
// ---------------------------------------------------------------------------
static int query_int(SQLite3DB *db, const char *sql) {
	return db->return_one_int(sql);
}

// ---------------------------------------------------------------------------
// Helper: query a single string value from the database
// ---------------------------------------------------------------------------
static std::string query_string(SQLite3DB *db, const char *sql) {
	char *error = nullptr;
	SQLite3_result *result = db->execute_statement(sql, &error);
	std::string val;
	if (result && result->rows_count > 0 && result->rows[0]->fields[0]) {
		val = result->rows[0]->fields[0];
	}
	if (error) {
		free(error);
	}
	delete result;
	return val;
}

// ---------------------------------------------------------------------------
// Helper: check that a table matches the current (latest) schema
// ---------------------------------------------------------------------------
static bool table_matches_current(SQLite3DB *db, const char *tbl, const char *def) {
	return db->check_table_structure(tbl, def) == 1;
}

// ============================================================================
// disk_upgrade_scheduler() tests
// ============================================================================

static void test_scheduler_upgrade_from_v1_2_0() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0);
	db->execute("INSERT INTO scheduler (id, interval_ms, filename) VALUES (1, 1000, '/usr/bin/test.sh')");
	db->execute("INSERT INTO scheduler (id, interval_ms, filename, arg1) VALUES (2, 5000, '/usr/bin/check.sh', '--verbose')");

	t.upgrade_scheduler();

	ok(table_matches_current(db, "scheduler", ADMIN_SQLITE_TABLE_SCHEDULER),
		"scheduler: upgrade from v1.2.0 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM scheduler");
	ok(count == 2, "scheduler: v1.2.0 upgrade preserves 2 rows (got %d)", count);

	std::string filename = query_string(db, "SELECT filename FROM scheduler WHERE id=1");
	ok(filename == "/usr/bin/test.sh",
		"scheduler: v1.2.0 upgrade preserves filename field");

	std::string arg1 = query_string(db, "SELECT arg1 FROM scheduler WHERE id=2");
	ok(arg1 == "--verbose",
		"scheduler: v1.2.0 upgrade preserves arg1 field");

	int old_exists = query_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scheduler_v120'");
	ok(old_exists == 1, "scheduler: v1.2.0 old table renamed to scheduler_v120");
}

static void test_scheduler_upgrade_from_v1_2_2a() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2a);
	db->execute("INSERT INTO scheduler (id, interval_ms, filename, comment) VALUES (1, 2000, '/usr/bin/job.sh', 'nightly job')");

	t.upgrade_scheduler();

	ok(table_matches_current(db, "scheduler", ADMIN_SQLITE_TABLE_SCHEDULER),
		"scheduler: upgrade from v1.2.2a produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM scheduler");
	ok(count == 1, "scheduler: v1.2.2a upgrade preserves 1 row (got %d)", count);

	std::string comment = query_string(db, "SELECT comment FROM scheduler WHERE id=1");
	ok(comment == "nightly job",
		"scheduler: v1.2.2a upgrade preserves comment field");
}

static void test_scheduler_upgrade_from_v1_2_2b() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2b);
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, comment) VALUES (1, 1, 3000, '/usr/bin/task.sh', 'test task')");

	t.upgrade_scheduler();

	ok(table_matches_current(db, "scheduler", ADMIN_SQLITE_TABLE_SCHEDULER),
		"scheduler: upgrade from v1.2.2b produces current schema");

	int active = query_int(db, "SELECT active FROM scheduler WHERE id=1");
	ok(active == 1, "scheduler: v1.2.2b upgrade preserves active field (got %d)", active);
}

static void test_scheduler_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("scheduler", ADMIN_SQLITE_TABLE_SCHEDULER, false);
	db->execute("INSERT INTO scheduler (id, active, interval_ms, filename, comment) VALUES (1, 1, 1000, '/usr/bin/ok.sh', 'current')");

	t.upgrade_scheduler();

	ok(table_matches_current(db, "scheduler", ADMIN_SQLITE_TABLE_SCHEDULER),
		"scheduler: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM scheduler");
	ok(count == 1, "scheduler: data unchanged when no upgrade needed (got %d)", count);
}

// ============================================================================
// disk_upgrade_mysql_users() tests
// ============================================================================

static void test_mysql_users_upgrade_from_v1_3_0() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_3_0);
	db->execute("INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, "
		"schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections) "
		"VALUES ('testuser', 'secret123', 1, 0, 0, 'test_db', 0, 0, 0, 1, 1, 5000)");

	t.upgrade_mysql_users();

	ok(table_matches_current(db, "mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS),
		"mysql_users: upgrade from v1.3.0 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_users");
	ok(count == 1, "mysql_users: v1.3.0 upgrade preserves 1 row (got %d)", count);

	std::string username = query_string(db, "SELECT username FROM mysql_users");
	ok(username == "testuser", "mysql_users: v1.3.0 upgrade preserves username");

	std::string password = query_string(db, "SELECT password FROM mysql_users");
	ok(password == "secret123", "mysql_users: v1.3.0 upgrade preserves password");

	int max_conn = query_int(db, "SELECT max_connections FROM mysql_users");
	ok(max_conn == 5000, "mysql_users: v1.3.0 upgrade preserves max_connections (got %d)", max_conn);

	int old_exists = query_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mysql_users_v130'");
	ok(old_exists == 1, "mysql_users: v1.3.0 old table renamed to mysql_users_v130");
}

static void test_mysql_users_upgrade_from_v1_4_0() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0);
	db->execute("INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, "
		"schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections) "
		"VALUES ('user2', 'pass2', 1, 0, 1, NULL, 0, 1, 0, 1, 1, 10000)");

	t.upgrade_mysql_users();

	ok(table_matches_current(db, "mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS),
		"mysql_users: upgrade from v1.4.0 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_users");
	ok(count == 1, "mysql_users: v1.4.0 upgrade preserves 1 row (got %d)", count);
}

static void test_mysql_users_upgrade_from_v2_0_0() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_0_0);
	db->execute("INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, "
		"schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, comment) "
		"VALUES ('user3', 'pass3', 1, 0, 2, 'mydb', 0, 1, 0, 1, 1, 8000, 'test comment')");

	t.upgrade_mysql_users();

	ok(table_matches_current(db, "mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS),
		"mysql_users: upgrade from v2.0.0 produces current schema");

	std::string comment = query_string(db, "SELECT comment FROM mysql_users WHERE username='user3'");
	ok(comment == "test comment", "mysql_users: v2.0.0 upgrade preserves comment field");
}

static void test_mysql_users_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS, false);
	db->execute("INSERT INTO mysql_users (username, password, backend, frontend) VALUES ('current', 'pw', 1, 1)");

	t.upgrade_mysql_users();

	ok(table_matches_current(db, "mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS),
		"mysql_users: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_users");
	ok(count == 1, "mysql_users: data unchanged when no upgrade needed (got %d)", count);
}

// ============================================================================
// disk_upgrade_rest_api_routes() tests
// ============================================================================

static void test_restapi_routes_upgrade_from_v2_0_15() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_V2_0_15);
	db->execute("INSERT INTO restapi_routes (id, active, interval_ms, method, uri, script, comment) "
		"VALUES (1, 1, 5000, 'GET', '/v1/health', '/usr/bin/health.sh', 'health check')");

	t.upgrade_rest_api_routes();

	ok(table_matches_current(db, "restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES),
		"restapi_routes: upgrade from v2.0.15 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM restapi_routes");
	ok(count == 1, "restapi_routes: v2.0.15 upgrade preserves 1 row (got %d)", count);

	int timeout = query_int(db, "SELECT timeout_ms FROM restapi_routes WHERE id=1");
	ok(timeout == 5000, "restapi_routes: interval_ms mapped to timeout_ms (got %d)", timeout);

	std::string uri = query_string(db, "SELECT uri FROM restapi_routes WHERE id=1");
	ok(uri == "/v1/health", "restapi_routes: v2.0.15 upgrade preserves uri field");

	std::string method = query_string(db, "SELECT method FROM restapi_routes WHERE id=1");
	ok(method == "GET", "restapi_routes: v2.0.15 upgrade preserves method field");

	int old_exists = query_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='restapi_routes_v2015'");
	ok(old_exists == 1, "restapi_routes: v2.0.15 old table renamed to restapi_routes_v2015");
}

static void test_restapi_routes_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES, false);
	db->execute("INSERT INTO restapi_routes (id, active, timeout_ms, method, uri, script) "
		"VALUES (1, 1, 3000, 'POST', '/v1/action', '/usr/bin/action.sh')");

	t.upgrade_rest_api_routes();

	ok(table_matches_current(db, "restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES),
		"restapi_routes: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM restapi_routes");
	ok(count == 1, "restapi_routes: data unchanged when no upgrade needed (got %d)", count);
}

// ============================================================================
// disk_upgrade_mysql_servers() tests
// ============================================================================

static void test_mysql_servers_upgrade_from_v1_1_0() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0);
	// Insert data with weight > 10000000 (test bug #1224 fix) and compression > 1 (test bug #962 fix)
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag) "
		"VALUES (0, '127.0.0.1', 3306, 'ONLINE', 99999999, 2, 100, 0)");
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag) "
		"VALUES (1, '127.0.0.2', 3306, 'ONLINE', 1000, 0, 200, 5)");

	t.upgrade_mysql_servers();

	ok(table_matches_current(db, "mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS),
		"mysql_servers: upgrade from v1.1.0 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_servers");
	ok(count == 2, "mysql_servers: v1.1.0 upgrade preserves 2 rows (got %d)", count);

	int weight = query_int(db, "SELECT weight FROM mysql_servers WHERE hostname='127.0.0.1'");
	ok(weight == 10000000, "mysql_servers: v1.1.0 upgrade caps weight at 10000000 (got %d)", weight);

	int compression = query_int(db, "SELECT compression FROM mysql_servers WHERE hostname='127.0.0.1'");
	ok(compression == 1, "mysql_servers: v1.1.0 upgrade caps compression at 1 (got %d)", compression);

	std::string hostname = query_string(db, "SELECT hostname FROM mysql_servers WHERE hostgroup_id=1");
	ok(hostname == "127.0.0.2", "mysql_servers: v1.1.0 upgrade preserves hostname");
}

static void test_mysql_servers_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS, false);
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '10.0.0.1', 3306)");

	t.upgrade_mysql_servers();

	ok(table_matches_current(db, "mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS),
		"mysql_servers: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_servers");
	ok(count == 1, "mysql_servers: data unchanged when no upgrade needed (got %d)", count);
}

static void test_aurora_hostgroups_upgrade_from_v2_0_10() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_10);
	db->execute(
		"INSERT INTO mysql_aws_aurora_hostgroups ("
			"writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,"
			"check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,"
			"add_lag_ms,min_lag_ms,lag_num_checks,autopurge_missing_checks,comment"
		") VALUES (10,20,1,3307,'.cluster.example',125,1500,900,1,7,40,20,3,9,'existing Aurora row')"
	);

	t.upgrade_mysql_servers();

	ok(table_matches_current(db, "mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS),
		"mysql_aws_aurora_hostgroups: v2.0.10 upgrade produces current schema");
	ok(query_int(db, "SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups") == 1,
		"mysql_aws_aurora_hostgroups: v2.0.10 upgrade preserves the row");
	ok(query_int(db, "SELECT green_writer_hostgroup IS NULL FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=10") == 1,
		"mysql_aws_aurora_hostgroups: migrated green writer is NULL");
	ok(query_int(db, "SELECT green_reader_hostgroup IS NULL FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=10") == 1,
		"mysql_aws_aurora_hostgroups: migrated green reader is NULL");
	ok(query_string(db, "SELECT domain_name FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=10") == ".cluster.example",
		"mysql_aws_aurora_hostgroups: migration preserves configured values");
	ok(query_int(db, "SELECT autopurge_missing_checks FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=10") == 9,
		"mysql_aws_aurora_hostgroups: migration preserves autopurge_missing_checks");
	ok(query_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mysql_aws_aurora_hostgroups_v2010'") == 1,
		"mysql_aws_aurora_hostgroups: v2.0.10 table is retained as v2010");
}

// ============================================================================
// disk_upgrade_pgsql_replication_hostgroups() tests
// ============================================================================

static void test_pgsql_repl_hg_upgrade_from_v3_0_1() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS_V3_0_1);
	db->execute("INSERT INTO pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment) "
		"VALUES (10, 20, 'primary-replica pair')");

	t.upgrade_pgsql_replication_hostgroups();

	ok(table_matches_current(db, "pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS),
		"pgsql_replication_hostgroups: upgrade from v3.0.1 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM pgsql_replication_hostgroups");
	ok(count == 1, "pgsql_replication_hostgroups: v3.0.1 upgrade preserves 1 row (got %d)", count);

	std::string check_type = query_string(db, "SELECT check_type FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10");
	ok(check_type == "read_only",
		"pgsql_replication_hostgroups: v3.0.1 upgrade sets check_type to 'read_only'");

	std::string comment = query_string(db, "SELECT comment FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10");
	ok(comment == "primary-replica pair",
		"pgsql_replication_hostgroups: v3.0.1 upgrade preserves comment field");

	int old_exists = query_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pgsql_replication_hostgroups_v301'");
	ok(old_exists == 1,
		"pgsql_replication_hostgroups: v3.0.1 old table renamed to pgsql_replication_hostgroups_v301");
}

static void test_pgsql_repl_hg_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS, false);
	db->execute("INSERT INTO pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment) "
		"VALUES (30, 40, 'read_only', 'already current')");

	t.upgrade_pgsql_replication_hostgroups();

	ok(table_matches_current(db, "pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS),
		"pgsql_replication_hostgroups: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM pgsql_replication_hostgroups");
	ok(count == 1, "pgsql_replication_hostgroups: data unchanged when no upgrade needed (got %d)", count);
}

// ============================================================================
// disk_upgrade_mysql_query_rules() tests
// ============================================================================

static void test_mysql_query_rules_upgrade_from_v1_2_2() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_2);
	db->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, "
		"client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, "
		"negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, "
		"reconnect, timeout, retries, delay, mirror_flagOUT, mirror_hostgroup, error_msg, "
		"log, apply, comment) "
		"VALUES (1, 1, 'testuser', 'testdb', 0, '', '', NULL, '', '^SELECT', '', "
		"0, NULL, '', 1, 5000, "
		"0, 3000, 3, 0, NULL, NULL, '', "
		"0, 1, 'route reads')");

	t.upgrade_mysql_query_rules();

	ok(table_matches_current(db, "mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES),
		"mysql_query_rules: upgrade from v1.2.2 produces current schema");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_query_rules");
	ok(count == 1, "mysql_query_rules: v1.2.2 upgrade preserves 1 row (got %d)", count);

	std::string username = query_string(db, "SELECT username FROM mysql_query_rules WHERE rule_id=1");
	ok(username == "testuser", "mysql_query_rules: v1.2.2 upgrade preserves username");

	int dest_hg = query_int(db, "SELECT destination_hostgroup FROM mysql_query_rules WHERE rule_id=1");
	ok(dest_hg == 1, "mysql_query_rules: v1.2.2 upgrade preserves destination_hostgroup (got %d)", dest_hg);

	std::string comment = query_string(db, "SELECT comment FROM mysql_query_rules WHERE rule_id=1");
	ok(comment == "route reads", "mysql_query_rules: v1.2.2 upgrade preserves comment");
}

static void test_mysql_query_rules_no_upgrade_needed() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->build_table("mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES, false);
	db->execute("INSERT INTO mysql_query_rules (rule_id, active, apply) VALUES (1, 1, 1)");

	t.upgrade_mysql_query_rules();

	ok(table_matches_current(db, "mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES),
		"mysql_query_rules: no upgrade needed when schema is current");

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_query_rules");
	ok(count == 1, "mysql_query_rules: data unchanged when no upgrade needed (got %d)", count);
}

// ============================================================================
// Multi-row data preservation tests
// ============================================================================

static void test_scheduler_upgrade_preserves_multiple_rows() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0);
	for (int i = 1; i <= 10; i++) {
		char sql[256];
		snprintf(sql, sizeof(sql),
			"INSERT INTO scheduler (id, interval_ms, filename) VALUES (%d, %d, '/usr/bin/job%d.sh')",
			i, 1000 * i, i);
		db->execute(sql);
	}

	t.upgrade_scheduler();

	int count = query_int(db, "SELECT COUNT(*) FROM scheduler");
	ok(count == 10, "scheduler: v1.2.0 upgrade preserves all 10 rows (got %d)", count);

	int interval = query_int(db, "SELECT interval_ms FROM scheduler WHERE id=5");
	ok(interval == 5000, "scheduler: v1.2.0 upgrade preserves interval_ms for row 5 (got %d)", interval);
}

static void test_mysql_servers_upgrade_multiple_rows_with_fixes() {
	TestDiskUpgrade t;
	SQLite3DB *db = t.db();

	db->execute(ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0);
	// Row with weight > 10000000 and compression > 1
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag) "
		"VALUES (0, 'host1', 3306, 'ONLINE', 20000000, 5, 100, 0)");
	// Row with normal values
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag) "
		"VALUES (0, 'host2', 3306, 'ONLINE', 500, 0, 50, 10)");
	// Row with compression=0 (should remain 0)
	db->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag) "
		"VALUES (1, 'host3', 3307, 'SHUNNED', 1000, 0, 200, 0)");

	t.upgrade_mysql_servers();

	int count = query_int(db, "SELECT COUNT(*) FROM mysql_servers");
	ok(count == 3, "mysql_servers: v1.1.0 upgrade preserves all 3 rows (got %d)", count);

	int w1 = query_int(db, "SELECT weight FROM mysql_servers WHERE hostname='host1'");
	ok(w1 == 10000000, "mysql_servers: weight capped at 10000000 for over-weight row (got %d)", w1);

	int c1 = query_int(db, "SELECT compression FROM mysql_servers WHERE hostname='host1'");
	ok(c1 == 1, "mysql_servers: compression capped at 1 for over-compression row (got %d)", c1);

	int c3 = query_int(db, "SELECT compression FROM mysql_servers WHERE hostname='host3'");
	ok(c3 == 0, "mysql_servers: compression=0 not changed (got %d)", c3);

	int w2 = query_int(db, "SELECT weight FROM mysql_servers WHERE hostname='host2'");
	ok(w2 == 500, "mysql_servers: normal weight preserved (got %d)", w2);
}

// ============================================================================
// main
// ============================================================================

int main() {
	plan(67);
	test_init_minimal();

	// scheduler tests
	test_scheduler_upgrade_from_v1_2_0();
	test_scheduler_upgrade_from_v1_2_2a();
	test_scheduler_upgrade_from_v1_2_2b();
	test_scheduler_no_upgrade_needed();

	// mysql_users tests
	test_mysql_users_upgrade_from_v1_3_0();
	test_mysql_users_upgrade_from_v1_4_0();
	test_mysql_users_upgrade_from_v2_0_0();
	test_mysql_users_no_upgrade_needed();

	// restapi_routes tests
	test_restapi_routes_upgrade_from_v2_0_15();
	test_restapi_routes_no_upgrade_needed();

	// mysql_servers tests
	test_mysql_servers_upgrade_from_v1_1_0();
	test_mysql_servers_no_upgrade_needed();
	test_aurora_hostgroups_upgrade_from_v2_0_10();

	// pgsql_replication_hostgroups tests
	test_pgsql_repl_hg_upgrade_from_v3_0_1();
	test_pgsql_repl_hg_no_upgrade_needed();

	// mysql_query_rules tests
	test_mysql_query_rules_upgrade_from_v1_2_2();
	test_mysql_query_rules_no_upgrade_needed();

	// Multi-row tests
	test_scheduler_upgrade_preserves_multiple_rows();
	test_mysql_servers_upgrade_multiple_rows_with_fixes();

	test_cleanup_minimal();
	return exit_status();
}
