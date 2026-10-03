/**
 * @file pgsql-wait_timeout-t.cpp
 * @brief This TAP test validates if session idle timeouts are working correctly, and that
 *   the termination is reported with the SQLSTATE PostgreSQL uses for it.
 */

#include <unistd.h>
#include <cstring>
#include <sstream>

#include "libpq-fe.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

PGconn* init_pgsql_conn(const char* host, const char* user, const char* pass, int port) {
	diag("Creating PgSQL conn host=\"%s\" port=\"%d\" user=\"%s\"", host, port, user);

	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user
	   << " password=" << pass << " dbname=postgres sslmode=disable";

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		PQfinish(conn);
		return nullptr;
	}

	return conn;
}

int run_q(PGconn* conn, const char* q) {
	PGresult* res = PQexec(conn, q);
	const ExecStatusType st = PQresultStatus(res);
	PQclear(res);
	return (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK) ? 0 : 1;
}

int admin_q(PGconn* admin, const char* q) {
	if (run_q(admin, q)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, PQerrorMessage(admin));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void check_terminated_with(PGconn* proxy, const char* expected_sqlstate) {
	PGresult* res = PQexec(proxy, "SELECT 1");
	const ExecStatusType st = PQresultStatus(res);

	ok(st != PGRES_TUPLES_OK, (st == PGRES_TUPLES_OK ? "Connection alive" : "Connection killed"));

	const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
	ok(sqlstate != nullptr && strcmp(sqlstate, expected_sqlstate) == 0,
		"Termination reported as SQLSTATE %s (got '%s')",
		expected_sqlstate, sqlstate ? sqlstate : "<none>");

	PQclear(res);
}

int test_session_timeout(CommandLine* cl, PGconn* admin) {
	diag("Test: %s", __func__);

	diag("Setting pgsql-wait_timeout=4000");
	if (admin_q(admin, "SET pgsql-wait_timeout=4000")) {
		return EXIT_FAILURE;
	}
	diag("Setting pgsql-poll_timeout=500 , required for more precise timeout");
	if (admin_q(admin, "SET pgsql-poll_timeout=500")) {
		return EXIT_FAILURE;
	}
	if (admin_q(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		return EXIT_FAILURE;
	}

	PGconn* proxy = init_pgsql_conn(cl->pgsql_host, cl->pgsql_username, cl->pgsql_password, cl->pgsql_port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: connection failed\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	int rc = run_q(proxy, "SELECT 1");
	ok(rc == 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	sleep(9);

	check_terminated_with(proxy, "57P05");

	PQfinish(proxy);
	return EXIT_SUCCESS;
}

int test_transaction_idle_timeout(CommandLine* cl, PGconn* admin) {
	diag("Test: %s", __func__);

	// wait_timeout is left high so only max_transaction_idle_time can fire here.
	diag("Setting pgsql-max_transaction_idle_time=3000");
	if (admin_q(admin, "SET pgsql-max_transaction_idle_time=3000")) {
		return EXIT_FAILURE;
	}
	if (admin_q(admin, "SET pgsql-wait_timeout=60000")) {
		return EXIT_FAILURE;
	}
	if (admin_q(admin, "SET pgsql-poll_timeout=500")) {
		return EXIT_FAILURE;
	}
	if (admin_q(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		return EXIT_FAILURE;
	}

	PGconn* proxy = init_pgsql_conn(cl->pgsql_host, cl->pgsql_username, cl->pgsql_password, cl->pgsql_port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: connection failed\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	int rc = run_q(proxy, "BEGIN");
	ok(rc == 0, (rc == 0 ? "Transaction started" : "Failed to start transaction"));

	sleep(9);

	check_terminated_with(proxy, "25P03");

	PQfinish(proxy);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(6);

	PGconn* admin = init_pgsql_conn(cl.pgsql_admin_host, cl.admin_username, cl.admin_password, cl.pgsql_admin_port);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: admin connection failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	int rc = test_session_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	rc = test_transaction_idle_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	// restore defaults so the short timeouts don't leak into later tests in the group
	admin_q(admin, "SET pgsql-wait_timeout=28800000");
	admin_q(admin, "SET pgsql-max_transaction_idle_time=14400000");
	admin_q(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	PQfinish(admin);
	return exit_status();
}
