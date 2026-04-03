/**
 * @file test_binlog_dump_multi_backend_crash-t.cpp
 * @brief Regression test for issue #5556.
 * @details When a session has backend connections to multiple hostgroups and
 *   then receives COM_BINLOG_DUMP, ProxySQL switches the session to
 *   FAST_FORWARD mode but only manages the active backend. The idle backend
 *   from another hostgroup remains in the session. If that idle backend
 *   receives a POLLIN event (e.g. from MySQL wait_timeout closing the
 *   connection), MySQL_Connection::handler() is called with
 *   async_state_machine==ASYNC_IDLE, which has no case in the switch and
 *   hits assert(0).
 *
 *   Reproduction steps:
 *   1. Use the existing replication hostgroups (writer_hg / reader_hg).
 *      Add a query rule routing SELECTs to reader_hg with multiplex=0.
 *   2. Disable set_query_lock_on_hostgroup so SET @user_var doesn't
 *      prevent cross-hostgroup routing.
 *   3. Connect to ProxySQL and run SELECT (creates reader_hg backend)
 *      then DO 1 (creates writer_hg backend).
 *   4. Send COM_BINLOG_DUMP via mariadb_rpl (uses writer_hg via
 *      previous_hostgroup).
 *   5. Wait for MySQL wait_timeout to close the idle reader_hg backend.
 *   6. Verify ProxySQL did not crash.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <string>
#include <vector>

#include "mysql.h"
#include "mariadb_rpl.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

// Short wait_timeout to trigger idle backend closure quickly
#define SHORT_WAIT_TIMEOUT 5
// How long to sleep waiting for the idle backend to be closed by MySQL
#define SLEEP_SECONDS (SHORT_WAIT_TIMEOUT + 3)

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1);
	diag("Testing issue #5556: COM_BINLOG_DUMP crash with idle backends from other hostgroups");

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	// ========================================================================
	// Step 0: Connect to ProxySQL admin
	// ========================================================================
	MYSQL* admin = mysql_init(NULL);
	if (!admin || !mysql_real_connect(admin, cl.admin_host, cl.admin_username,
			cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "Admin connection failed: %s\n", admin ? mysql_error(admin) : "mysql_init failed");
		return exit_status();
	}

	// ========================================================================
	// Step 1: Connect to MySQL backend directly, check binlog, set wait_timeout
	// ========================================================================
	MYSQL* backend = mysql_init(NULL);
	if (!backend || !mysql_real_connect(backend, cl.mysql_host, cl.mysql_username,
			cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
		fprintf(stderr, "Backend connection failed: %s\n", backend ? mysql_error(backend) : "mysql_init failed");
		mysql_close(admin);
		return exit_status();
	}

	// Verify binlog is available
	bool binlog_ok = false;
	if (mysql_query(backend, "SHOW MASTER STATUS") == 0) {
		MYSQL_RES* res = mysql_store_result(backend);
		if (res) {
			if (mysql_fetch_row(res)) binlog_ok = true;
			mysql_free_result(res);
		}
	}
	if (!binlog_ok) {
		diag("Binary logging not available. Skipping.");
		ok(1, "SKIP: Binary logging not available");
		mysql_close(backend);
		mysql_close(admin);
		return exit_status();
	}

	// ========================================================================
	// Step 2: Discover hostgroup topology
	// ========================================================================
	int writer_hg = -1;
	int reader_hg = -1;
	{
		const char* q = "SELECT writer_hostgroup, reader_hostgroup "
			"FROM mysql_replication_hostgroups LIMIT 1";
		if (mysql_query(admin, q) == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			if (res) {
				MYSQL_ROW row = mysql_fetch_row(res);
				if (row && row[0] && row[1]) {
					writer_hg = atoi(row[0]);
					reader_hg = atoi(row[1]);
				}
				mysql_free_result(res);
			}
		}
	}
	if (writer_hg < 0 || reader_hg < 0) {
		diag("Could not discover replication hostgroups. Skipping.");
		ok(1, "SKIP: No replication hostgroups configured");
		mysql_close(backend);
		mysql_close(admin);
		return exit_status();
	}
	diag("Discovered hostgroups: writer=%d, reader=%d", writer_hg, reader_hg);

	// Save and lower wait_timeout (after skip checks so early returns don't
	// leave it modified — addresses Copilot review feedback)
	long orig_wait_timeout = 28800;
	if (mysql_query(backend, "SELECT @@global.wait_timeout") == 0) {
		MYSQL_RES* res = mysql_store_result(backend);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row && row[0]) orig_wait_timeout = strtol(row[0], NULL, 10);
			mysql_free_result(res);
		}
	}
	diag("Original wait_timeout: %ld, setting to %d", orig_wait_timeout, SHORT_WAIT_TIMEOUT);

	std::string set_wt = "SET GLOBAL wait_timeout=" + std::to_string(SHORT_WAIT_TIMEOUT);
	if (mysql_query(backend, set_wt.c_str()) != 0) {
		diag("Failed to set wait_timeout: %s", mysql_error(backend));
		mysql_close(backend);
		mysql_close(admin);
		return exit_status();
	}

	// Set up query rules: ^SELECT → reader_hg (multiplex=0), all else → writer_hg (default)
	MYSQL_QUERY(admin, "DELETE FROM mysql_query_rules");
	{
		std::string q = "INSERT INTO mysql_query_rules "
			"(rule_id, active, match_digest, destination_hostgroup, multiplex, apply) "
			"VALUES (1, 1, '^SELECT', " + std::to_string(reader_hg) + ", 0, 1)";
		MYSQL_QUERY(admin, q.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Disable hostgroup locking so SET @user_var queries don't prevent
	// routing to different hostgroups within the same session
	MYSQL_QUERY(admin, "SET mysql-set_query_lock_on_hostgroup=0");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("ProxySQL configured: SELECT→HG%d (reader), default→HG%d (writer), multiplex=0, lock_on_hg=0",
		reader_hg, writer_hg);

	// ========================================================================
	// Step 3: Connect to ProxySQL and create backends in both hostgroups
	// ========================================================================
	MYSQL* proxy = mysql_init(NULL);
	if (!proxy) {
		diag("mysql_init failed for proxy connection");
		goto cleanup;
	}
	// Force CLIENT_DEPRECATE_EOF to match backend capabilities for fast-forward
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(proxy, cl.root_host, cl.root_username,
			cl.root_password, NULL, cl.root_port, NULL, 0)) {
		diag("Proxy connection failed: %s", mysql_error(proxy));
		goto cleanup;
	}

	// SELECT → creates backend in reader_hg
	diag("Sending SELECT to create backend in reader HG%d", reader_hg);
	if (mysql_query(proxy, "SELECT 1") != 0) {
		diag("SELECT failed: %s", mysql_error(proxy));
		goto cleanup;
	}
	{
		MYSQL_RES* res = mysql_store_result(proxy);
		mysql_free_result(res);
	}

	// DO 1 → creates backend in writer_hg, also sets previous_hostgroup
	diag("Sending DO to create backend in writer HG%d (and set previous_hostgroup)", writer_hg);
	if (mysql_query(proxy, "DO 1") != 0) {
		diag("DO 1 failed: %s", mysql_error(proxy));
		goto cleanup;
	}

	// Verify connections were established to both hostgroups.
	// We check ConnOK (total connections ever made) rather than ConnUsed,
	// because the writer backend may already be returned to the pool after
	// DO completes (it's still in the session's mybes array though).
	{
		bool has_writer = false, has_reader = false;
		std::string pool_q = "SELECT hostgroup, ConnOK FROM stats_mysql_connection_pool "
			"WHERE hostgroup IN (" + std::to_string(writer_hg) + "," + std::to_string(reader_hg) + ") "
			"AND ConnOK > 0";
		if (mysql_query(admin, pool_q.c_str()) == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			if (res) {
				MYSQL_ROW row;
				while ((row = mysql_fetch_row(res))) {
					int hg = atoi(row[0]);
					diag("  Connection pool: HG%d has %s total connections (ConnOK)", hg, row[1]);
					if (hg == writer_hg) has_writer = true;
					if (hg == reader_hg) has_reader = true;
				}
				mysql_free_result(res);
			}
		}
		if (!has_writer || !has_reader) {
			diag("PRECONDITION FAILED: Connections not established to both hostgroups "
				"(writer=%s, reader=%s). Test cannot reproduce #5556.",
				has_writer ? "yes" : "NO", has_reader ? "yes" : "NO");
			goto cleanup;
		}
		diag("Confirmed connections to both writer HG%d and reader HG%d", writer_hg, reader_hg);
	}

	// ========================================================================
	// Step 4: Send COM_BINLOG_DUMP via mariadb_rpl
	// ========================================================================
	{
		// Set up replication parameters on the same connection
		diag("Setting replication parameters");
		if (mysql_query(proxy, "SET @master_binlog_checksum='NONE'") != 0) {
			diag("SET checksum failed: %s", mysql_error(proxy));
			goto cleanup;
		}
		if (mysql_query(proxy, "SET @master_heartbeat_period=1000000000") != 0) {
			diag("SET heartbeat failed: %s", mysql_error(proxy));
			goto cleanup;
		}

		MARIADB_RPL* rpl = mariadb_rpl_init(proxy);
		if (!rpl) {
			diag("mariadb_rpl_init failed");
			goto cleanup;
		}
		rpl->server_id = 99999; // unique server ID for test
		rpl->start_position = 4; // start from beginning of first binlog
		rpl->flags = MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

		diag("Sending COM_BINLOG_DUMP: pos=4 server_id=%d", rpl->server_id);
		if (mariadb_rpl_open(rpl)) {
			diag("mariadb_rpl_open failed: %s", mysql_error(proxy));
			mariadb_rpl_close(rpl);
			goto cleanup;
		}

		// Fetch a couple of events to confirm replication is working
		diag("Replication started, fetching initial events...");
		MARIADB_RPL_EVENT* event = NULL;
		int num_events = 0;
		for (int i = 0; i < 5; i++) {
			event = mariadb_rpl_fetch(rpl, event);
			if (!event) break;
			num_events++;
			diag("  Event %d: type=%d", num_events, event->event_type);
		}
		if (event) mariadb_free_rpl_event(event);
		diag("Received %d initial events", num_events);

		// ====================================================================
		// Step 5: Wait for the idle backend (reader_hg) to be closed by MySQL
		// ====================================================================
		diag("Sleeping %d seconds for wait_timeout to close idle reader HG%d backend...",
			SLEEP_SECONDS, reader_hg);
		sleep(SLEEP_SECONDS);

		// Fetch one more event to force ProxySQL to process the POLLIN on the
		// idle backend's fd. This is the point where the crash would occur.
		diag("Fetching another event (this triggers processing of idle backend POLLIN)...");
		event = mariadb_rpl_fetch(rpl, NULL);
		if (event) {
			diag("  Got event: type=%d", event->event_type);
			mariadb_free_rpl_event(event);
		}

		mariadb_rpl_close(rpl);
	}

	// ========================================================================
	// Step 6: Verify ProxySQL did not crash
	// ========================================================================
	{
		// Try to query the admin interface. If ProxySQL crashed and restarted,
		// our admin connection would be broken.
		int admin_ok = 0;

		// First check our existing admin connection
		if (mysql_query(admin, "SELECT 1") == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			if (res) {
				mysql_free_result(res);
				admin_ok = 1;
			}
		}

		// If the existing connection is broken, try a fresh one
		if (!admin_ok) {
			diag("Existing admin connection broken, trying fresh connection...");
			MYSQL* admin2 = mysql_init(NULL);
			if (admin2 && mysql_real_connect(admin2, cl.admin_host, cl.admin_username,
					cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
				// ProxySQL restarted after crash - the bug is present
				diag("ProxySQL appears to have restarted (crash detected)");
				mysql_close(admin2);
				admin_ok = 0;
			} else {
				diag("Cannot connect to ProxySQL admin at all");
				admin_ok = 0;
			}
		}

		ok(admin_ok, "ProxySQL should not crash when idle backend receives POLLIN during FAST_FORWARD (issue #5556)");
	}

cleanup:
	// Restore original wait_timeout
	{
		std::string restore_wt = "SET GLOBAL wait_timeout=" + std::to_string(orig_wait_timeout);
		if (mysql_query(backend, restore_wt.c_str()) != 0) {
			mysql_close(backend);
			backend = mysql_init(NULL);
			if (backend && mysql_real_connect(backend, cl.mysql_host, cl.mysql_username,
					cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
				mysql_query(backend, restore_wt.c_str());
			}
		}
		diag("Restored wait_timeout to %ld", orig_wait_timeout);
	}

	// Clean up query rules and ProxySQL variables
	{
		MYSQL* admin_cleanup = admin;
		bool need_new = false;
		if (mysql_query(admin, "SELECT 1") != 0) {
			need_new = true;
			admin_cleanup = mysql_init(NULL);
			if (admin_cleanup) {
				mysql_real_connect(admin_cleanup, cl.admin_host, cl.admin_username,
					cl.admin_password, NULL, cl.admin_port, NULL, 0);
			}
		} else {
			MYSQL_RES* res = mysql_store_result(admin);
			mysql_free_result(res);
		}

		if (admin_cleanup) {
			MYSQL_QUERY_err(admin_cleanup, "SET mysql-set_query_lock_on_hostgroup=1");
			MYSQL_QUERY_err(admin_cleanup, "LOAD MYSQL VARIABLES TO RUNTIME");
			MYSQL_QUERY_err(admin_cleanup, "DELETE FROM mysql_query_rules");
			MYSQL_QUERY_err(admin_cleanup, "LOAD MYSQL QUERY RULES TO RUNTIME");
			if (need_new) mysql_close(admin_cleanup);
		}
	}

	mysql_close(backend);
	mysql_close(admin);

	return exit_status();
}
