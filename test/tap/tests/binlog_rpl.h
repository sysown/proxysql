/**
 * @file binlog_rpl.h
 * @brief Runs binlog replication sessions via MARIADB_RPL with COM_REGISTER_SLAVE.
 * @details Uses the MariaDB client replication API to exercise binlog streaming
 *   functionality. Setting rpl->host before mariadb_rpl_open() triggers
 *   COM_REGISTER_SLAVE registration.
 *
 *   The helper runs two replication sessions. Each session:
 *     1. Opens a fresh connection to ProxySQL
 *     2. Issues a lightweight pre-replication query
 *     3. Configures replication session variables (checksum, heartbeat)
 *     4. Initializes MARIADB_RPL with rpl->host set (triggers COM_REGISTER_SLAVE)
 *     5. Opens replication and fetches events to verify the stream is active
 *     6. Closes the replication session cleanly
 *
 *   Returns EXIT_SUCCESS only if both sessions succeed.
 */

#ifndef BINLOG_RPL_H
#define BINLOG_RPL_H

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "mysql.h"
#include "mariadb_rpl.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

// Number of heartbeats to wait per replication session to confirm stream is active
#define BINLOG_RPL_NHB 3

/**
 * @brief Run a replication session against ProxySQL.
 * @details Opens a connection, issues a pre-query, configures replication
 *   variables, then uses MARIADB_RPL with rpl->host set to send
 *   COM_REGISTER_SLAVE. Fetches events until BINLOG_RPL_NHB heartbeats
 *   are received, verifying the binlog stream is active.
 *
 * @param cl CommandLine with connection parameters.
 * @param session_id A label for diagnostic output (e.g. 1 or 2).
 * @param server_id Unique server_id for the replication registration.
 * @return EXIT_SUCCESS if the session completes successfully, EXIT_FAILURE otherwise.
 */
static int run_replication_session(const CommandLine& cl, int session_id, int server_id) {
	int rc = EXIT_FAILURE;
	MYSQL* mysql = NULL;
	MYSQL_RES* res = NULL;
	MARIADB_RPL* rpl = NULL;
	MARIADB_RPL_EVENT* event = NULL;
	int num_heartbeats = 0;
	int num_events = 0;

	diag("Session %d: Connecting to ProxySQL at %s:%d as %s",
		session_id, cl.host, cl.port, cl.username);

	mysql = mysql_init(NULL);
	if (!mysql) {
		diag("Session %d: mysql_init failed", session_id);
		goto cleanup;
	}

	// Force CLIENT_DEPRECATE_EOF to match backend capabilities for fast-forward
	mysql->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Session %d: Connection failed: %s", session_id, mysql_error(mysql));
		goto cleanup;
	}

	// Issue a pre-replication query that disables multiplexing. This ensures the
	// backend connection stays pinned to the session so that when COM_REGISTER_SLAVE
	// triggers fast_forward, the existing backend is reused instead of requiring a
	// new connection.
	if (run_q(mysql, "SELECT @@hostname")) {
		goto cleanup;
	}
	res = mysql_store_result(mysql);
	mysql_free_result(res);

	// Configure replication session variables
	if (run_q(mysql, "SET @master_binlog_checksum = 'NONE'")) {
		goto cleanup;
	}
	if (run_q(mysql, "SET @master_heartbeat_period = 2000000000")) {
		goto cleanup;
	}

	// Initialize replication handle
	rpl = mariadb_rpl_init(mysql);
	if (!rpl) {
		diag("Session %d: mariadb_rpl_init failed", session_id);
		goto cleanup;
	}

	rpl->server_id = server_id;
	rpl->start_position = 4;
	rpl->flags = MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

	// KEY: Setting rpl->host causes mariadb_rpl_open() to send COM_REGISTER_SLAVE
	// before proceeding with the binlog dump. This is the core mechanism under test.
	rpl->host = strdup("127.0.0.1");
	rpl->port = cl.port;

	diag("Session %d: Opening replication with server_id=%d (COM_REGISTER_SLAVE will be sent)",
		session_id, server_id);

	if (mariadb_rpl_open(rpl)) {
		diag("Session %d: mariadb_rpl_open failed: [%d] %s",
			session_id, mysql_errno(rpl->mysql), mysql_error(rpl->mysql));
		goto cleanup;
	}

	// Fetch events until we receive enough heartbeats to confirm the stream is active
	diag("Session %d: Fetching binlog events, waiting for %d heartbeats...",
		session_id, BINLOG_RPL_NHB);

	while (num_heartbeats < BINLOG_RPL_NHB &&
		   (event = mariadb_rpl_fetch(rpl, event))) {
		num_events++;
		if (event->event_type == HEARTBEAT_LOG_EVENT_V2 ||
			event->event_type == HEARTBEAT_LOG_EVENT) {
			num_heartbeats++;
			diag("Session %d: Heartbeat %d/%d received (total events: %d)",
				session_id, num_heartbeats, BINLOG_RPL_NHB, num_events);
		}
	}

	if (num_heartbeats < BINLOG_RPL_NHB && event == NULL) {
		diag("Session %d: Replication stream ended prematurely: %s",
			session_id, mysql_error(mysql));
	}

	if (num_heartbeats < BINLOG_RPL_NHB) {
		diag("Session %d: FAILED - received only %d/%d heartbeats",
			session_id, num_heartbeats, BINLOG_RPL_NHB);
		goto cleanup;
	}

	diag("Session %d: SUCCESS - received %d heartbeats across %d events",
		session_id, num_heartbeats, num_events);
	rc = EXIT_SUCCESS;

cleanup:
	mariadb_free_rpl_event(event);
	if (rpl) {
		mariadb_rpl_close(rpl);
	}
	if (mysql) {
		mysql_close(mysql);
	}
	return rc;
}

/**
 * @brief Run two binlog replication sessions via MARIADB_RPL.
 * @details Executes two independent replication sessions, each sending
 *   COM_REGISTER_SLAVE. Used by TAP tests:
 *     - test_com_register_slave_enables_fast_forward-t: verifies COM_REGISTER_SLAVE
 *       enables fast-forward mode and binlog streaming works
 *     - test_binlog_reader_uses_previous_hostgroup-t: verifies fast-forward
 *       connections use the hostgroup from prior COM_QUERY
 *
 * @param cl CommandLine with connection parameters.
 * @return EXIT_SUCCESS if both sessions succeed, EXIT_FAILURE otherwise.
 */
static int run_binlog_rpl(const CommandLine& cl) {
	diag("=== Binlog RPL test: Starting ===");
	diag("Running two replication sessions to exercise COM_REGISTER_SLAVE");

	// Session 1
	int rc = run_replication_session(cl, 1, 100001);
	if (rc != EXIT_SUCCESS) {
		diag("=== Binlog RPL test: FAILED (session 1) ===");
		return EXIT_FAILURE;
	}

	// Session 2
	rc = run_replication_session(cl, 2, 100002);
	if (rc != EXIT_SUCCESS) {
		diag("=== Binlog RPL test: FAILED (session 2) ===");
		return EXIT_FAILURE;
	}

	diag("=== Binlog RPL test: SUCCESS (both sessions completed) ===");
	return EXIT_SUCCESS;
}

#endif // BINLOG_RPL_H