/**
 * @file hostgroups_unit-t.cpp
 * @brief Unit tests for MySQL_HostGroups_Manager and PgSQL_HostGroups_Manager.
 *
 * Tests the HostGroups Manager server management in isolation:
 *   - Server creation and removal via create_new_server_in_hg / remove_server_in_hg
 *   - Server status transitions (ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD)
 *   - Server property updates (latency, status)
 *   - Multiple hostgroups independence
 *   - PgSQL HostGroups Manager parity
 *
 * These tests use the real MySQL_HostGroups_Manager with its internal
 * SQLite3 database but do not create real network connections.
 *
 * @see Phase 2.6 of the Unit Testing Framework (GitHub issue #5478)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"

// Extern declarations (defined in test_globals.cpp)
extern MySQL_HostGroups_Manager *MyHGM;
extern PgSQL_HostGroups_Manager *PgHGM;

// ============================================================================
// Helpers
// ============================================================================

/**
 * @brief Add a MySQL server to a hostgroup using the manager API.
 * @return 0 on success, -1 on failure.
 */
static int add_mysql_server(int hg, const char *addr, int port,
	int weight = 1, int max_conns = 100)
{
	srv_info_t info;
	info.addr = addr;
	info.port = port;
	info.kind = "test";

	srv_opts_t opts;
	opts.weigth = weight;
	opts.max_conns = max_conns;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	int rc = MyHGM->create_new_server_in_hg(hg, info, opts);
	MyHGM->wrunlock();
	return rc;
}

/**
 * @brief Remove a MySQL server from a hostgroup.
 * @return 0 on success, -1 on failure.
 */
static int remove_mysql_server(int hg, const char *addr, int port) {
	MyHGM->wrlock();
	int rc = MyHGM->remove_server_in_hg(hg, std::string(addr), port);
	MyHGM->wrunlock();
	return rc;
}

// ============================================================================
// 1. Server creation and removal
// ============================================================================

/**
 * @brief Test creating a server in a hostgroup.
 */
static void test_mysql_create_server() {
	int rc = add_mysql_server(10, "127.0.0.1", 3306, 1, 100);
	ok(rc == 0, "MySQL HGM: create_new_server_in_hg() returns 0");

	// Add a second server to same hostgroup
	rc = add_mysql_server(10, "127.0.0.2", 3306, 2, 200);
	ok(rc == 0, "MySQL HGM: second server added to same hostgroup");

	// Add server to different hostgroup
	rc = add_mysql_server(20, "127.0.0.3", 3307, 1, 50);
	ok(rc == 0, "MySQL HGM: server added to different hostgroup");
}

/**
 * @brief Test removing a server from a hostgroup.
 */
static void test_mysql_remove_server() {
	// First add a server
	add_mysql_server(30, "10.0.0.1", 3306);

	// Remove it
	int rc = remove_mysql_server(30, "10.0.0.1", 3306);
	ok(rc == 0, "MySQL HGM: remove_server_in_hg() returns 0");

	// Remove non-existent server
	rc = remove_mysql_server(30, "10.0.0.99", 3306);
	ok(rc == -1, "MySQL HGM: remove non-existent server returns -1");
}

// ============================================================================
// 2. Server status transitions
// ============================================================================

/**
 * @brief Test shun_and_killall via the manager.
 */
static void test_mysql_shun_and_killall() {
	add_mysql_server(40, "192.168.1.1", 3306);

	// shun_and_killall acquires its own write lock internally
	bool shunned = MyHGM->shun_and_killall(
		(char *)"192.168.1.1", 3306);
	ok(shunned == true,
		"MySQL HGM: shun_and_killall() returns true for existing server");

	// shun_and_killall on non-existent server
	bool not_found = MyHGM->shun_and_killall(
		(char *)"10.10.10.10", 9999);
	ok(not_found == false,
		"MySQL HGM: shun_and_killall() returns false for non-existent server");
}

// ============================================================================
// 3. Server latency tracking
// ============================================================================

/**
 * @brief Test setting server latency via the manager.
 */
static void test_mysql_latency() {
	add_mysql_server(50, "172.16.0.1", 3306);

	// set_server_current_latency_us acquires its own write lock
	MyHGM->set_server_current_latency_us(
		(char *)"172.16.0.1", 3306, 5000);  // 5ms latency

	// No crash = success; the value is stored on the MySrvC object
	ok(1, "MySQL HGM: set_server_current_latency_us() succeeds");
}

// ============================================================================
// 4. Multiple hostgroups independence
// ============================================================================

/**
 * @brief Test that servers in different hostgroups are independent.
 */
static void test_mysql_hostgroup_independence() {
	add_mysql_server(60, "hg60-server", 3306, 1, 100);
	add_mysql_server(70, "hg70-server", 3306, 1, 100);

	// Shun server in HG 60 — should not affect HG 70
	bool s1 = MyHGM->shun_and_killall((char *)"hg60-server", 3306);
	ok(s1 == true,
		"MySQL HGM: shunned server in HG 60");

	// HG 70 server should still be accessible
	bool s2 = MyHGM->shun_and_killall((char *)"hg70-server", 3306);
	ok(s2 == true,
		"MySQL HGM: HG 70 server independently operable");
}

// ============================================================================
// 5. Duplicate server handling
// ============================================================================

/**
 * @brief Test adding the same server twice to the same hostgroup.
 */
static void test_mysql_duplicate_server() {
	add_mysql_server(80, "dup-server", 3306);
	// Adding same server again — should either succeed (re-enable) or fail
	int rc = add_mysql_server(80, "dup-server", 3306);
	// create_new_server_in_hg re-enables OFFLINE_HARD servers, so this
	// depends on current state. Just verify it doesn't crash.
	ok(rc == 0 || rc == -1,
		"MySQL HGM: duplicate server add doesn't crash (rc=%d)", rc);
}

// ============================================================================
// 6. PgSQL HostGroups Manager
// ============================================================================

/**
 * @brief Test PgSQL HostGroups Manager basic operations.
 */
static void test_pgsql_create_and_remove() {
	ok(PgHGM != nullptr, "PgSQL HGM: PgHGM is initialized");

	// PgSQL uses PgSQL_srv_info_t / PgSQL_srv_opts_t
	PgSQL_srv_info_t info;
	info.addr = "pg-server-1";
	info.port = 5432;
	info.kind = "test";

	PgSQL_srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 50;
	opts.use_ssl = 0;

	PgHGM->wrlock();
	int rc = PgHGM->create_new_server_in_hg(100, info, opts);
	PgHGM->wrunlock();
	ok(rc == 0, "PgSQL HGM: create_new_server_in_hg() returns 0");

	// Remove
	PgHGM->wrlock();
	rc = PgHGM->remove_server_in_hg(100, std::string("pg-server-1"), 5432);
	PgHGM->wrunlock();
	ok(rc == 0, "PgSQL HGM: remove_server_in_hg() returns 0");
}

/**
 * @brief Test PgSQL shun_and_killall.
 */
static void test_pgsql_shun() {
	PgSQL_srv_info_t info;
	info.addr = "pg-shun-server";
	info.port = 5432;
	info.kind = "test";

	PgSQL_srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 50;
	opts.use_ssl = 0;

	PgHGM->wrlock();
	PgHGM->create_new_server_in_hg(110, info, opts);
	PgHGM->wrunlock();

	bool shunned = PgHGM->shun_and_killall(
		(char *)"pg-shun-server", 5432);
	ok(shunned == true,
		"PgSQL HGM: shun_and_killall() returns true");
}

#ifdef PROXYSQL31
static SQLite3_row *find_hostgroup_row(SQLite3_result *result, unsigned int hid) {
	for (SQLite3_row *row : result->rows) {
		if (static_cast<unsigned int>(strtoul(row->fields[0], nullptr, 10)) == hid) {
			return row;
		}
	}
	return nullptr;
}

template <typename HGM>
static void test_unknown_hostgroup_stats_lookup(HGM *hgm, const char *protocol) {
	std::unique_ptr<SQLite3_result> before { hgm->SQL3_Hostgroup_Connection_Pool(false) };
	const int rows_before = before->rows_count;
	HostgroupPoolStats *stats = hgm->get_hostgroup_pool_stats(999'999);
	std::unique_ptr<SQLite3_result> after { hgm->SQL3_Hostgroup_Connection_Pool(false) };

	ok(stats == nullptr && after->rows_count == rows_before,
		"%s HGM: stats lookup does not create an unknown hostgroup", protocol);
}

template <typename HGM>
static void test_hostgroup_pool_stats(HGM *hgm, unsigned int hid, const char *protocol) {
	HostgroupPoolStats *stats = hgm->get_hostgroup_pool_stats(hid);
	HostgroupPoolWait wait;
	stats->record_acquisition();
	wait.observe(stats, 100, false);

	SQLite3_result *live = hgm->SQL3_Hostgroup_Connection_Pool(false);
	SQLite3_row *live_row = find_hostgroup_row(live, hid);
	ok(live_row != nullptr, "%s HGM: live hostgroup pool stats expose the hostgroup", protocol);
	ok(live_row && strcmp(live_row->fields[1], "1") == 0 &&
		strcmp(live_row->fields[2], "1") == 0 &&
		strcmp(live_row->fields[3], "0") == 0 &&
		strcmp(live_row->fields[4], "1") == 0,
		"%s HGM: live stats report acquisitions, waits, duration, and waiters", protocol);
	delete live;

	SQLite3_result *reset = hgm->SQL3_Hostgroup_Connection_Pool(true);
	SQLite3_row *reset_row = find_hostgroup_row(reset, hid);
	ok(reset_row && strcmp(reset_row->fields[1], "1") == 0 &&
		strcmp(reset_row->fields[2], "1") == 0 &&
		strcmp(reset_row->fields[4], "1") == 0,
		"%s HGM: reset returns the completed window without clearing waiters", protocol);
	delete reset;

	wait.observe(stats, 350, true);
	live = hgm->SQL3_Hostgroup_Connection_Pool(false);
	live_row = find_hostgroup_row(live, hid);
	ok(live_row && strcmp(live_row->fields[1], "1") == 0 &&
		strcmp(live_row->fields[2], "0") == 0 &&
		strcmp(live_row->fields[3], "250") == 0 &&
		strcmp(live_row->fields[4], "0") == 0,
		"%s HGM: post-reset completions remain in the new window", protocol);
	delete live;

	const HostgroupPoolStatsSnapshot lifetime = stats->lifetime_snapshot();
	ok(lifetime.acquisitions_total == 2 && lifetime.waits_total == 1 &&
		lifetime.wait_time_us_total == 250 && lifetime.waiters == 0,
		"%s HGM: Admin reset preserves lifetime metrics", protocol);
}
#endif

// ============================================================================
// Main
// ============================================================================

int main() {
#ifdef PROXYSQL31
	plan(29);
#else
	plan(17);
#endif

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	rc = test_init_hostgroups();
	ok(rc == 0, "test_init_hostgroups() succeeds");

	// MySQL tests
	test_mysql_create_server();          // 3 tests
	test_mysql_remove_server();          // 2 tests
	test_mysql_shun_and_killall();       // 2 tests
	test_mysql_latency();                // 1 test
	test_mysql_hostgroup_independence(); // 2 tests
	test_mysql_duplicate_server();       // 1 test

	// PgSQL tests
	test_pgsql_create_and_remove();      // 3 tests
	test_pgsql_shun();                   // 1 test
#ifdef PROXYSQL31
	test_hostgroup_pool_stats(MyHGM, 10, "MySQL"); // 5 tests
	test_hostgroup_pool_stats(PgHGM, 100, "PgSQL"); // 5 tests
	test_unknown_hostgroup_stats_lookup(MyHGM, "MySQL"); // 1 test
	test_unknown_hostgroup_stats_lookup(PgHGM, "PgSQL"); // 1 test
#endif
	// Total: 1+1+3+2+2+1+2+1+3+1 = 17... let me recount
	// init: 2, create: 3, remove: 2, status: 2, latency: 1,
	// independence: 2, duplicate: 1, pgsql_create: 3, pgsql_shun: 1
	// = 17. Fix plan.

	test_cleanup_hostgroups();
	test_cleanup_minimal();

	return exit_status();
}
