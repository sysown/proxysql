/**
 * @file pgsql-reg_test_6345_admin_extended_query_sync-t.cpp
 * @brief Regression test for issue #6345.
 *
 * The PostgreSQL-protocol Admin interface does not implement the extended
 * query protocol (Parse/Bind/Describe/Execute/Close). It must reject it the
 * way a PostgreSQL server reports an error inside an extended-query batch:
 *  - exactly one ErrorResponse, sent when the first unsupported message
 *    arrives (so a client waiting after Flush is not left hanging);
 *  - every following message up to Sync is discarded;
 *  - Sync is answered with exactly one ReadyForQuery.
 *
 * Issue #6345: every P/B/D/E message got its own ErrorResponse +
 * ReadyForQuery, and Sync got another pair through the generic
 * "Not implemented yet" branch. A single libpq PQexecParams() therefore
 * received five error/ready pairs; libpq consumed the first and the other
 * four desynchronised every following query on the connection.
 *
 * The test counts the messages on the wire with pg_lite_client and checks
 * that a real libpq client keeps working after an extended-query attempt.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "pg_lite_client.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Time without traffic after which no further message is expected.
static const int QUIET_TIMEOUT_MS = 1500;

struct MsgCounts {
	int errors = 0;
	int ready = 0;
	int other = 0;
	char last = 0;
	std::string sequence {};
};

/**
 * @brief Reads messages until the socket stays quiet for QUIET_TIMEOUT_MS.
 */
static MsgCounts drain(PgConnection& c) {
	MsgCounts counts {};
	while (true) {
		char type = 0;
		std::vector<uint8_t> buf {};
		try {
			c.readMessage(type, buf);
		} catch (const PgException&) {
			break; // read timed out: nothing more is coming
		}
		counts.sequence += type;
		counts.last = type;
		if (type == 'E') {
			counts.errors++;
		} else if (type == 'Z') {
			counts.ready++;
		} else {
			counts.other++;
		}
	}
	return counts;
}

static std::unique_ptr<PgConnection> admin_lite_connect() {
	std::unique_ptr<PgConnection> c(new PgConnection(QUIET_TIMEOUT_MS));
	try {
		c->connect(cl.pgsql_admin_host, cl.pgsql_admin_port, "main", cl.admin_username, cl.admin_password);
	} catch (const std::exception& e) {
		diag("pg_lite admin connect failed: %s", e.what());
		return nullptr;
	}
	return c;
}

static void send_parse(PgConnection& c, const char* query) {
	std::vector<uint8_t> d {};
	d.push_back(0); // unnamed statement
	d.insert(d.end(), query, query + strlen(query) + 1);
	d.push_back(0); // no parameter types
	d.push_back(0);
	c.sendMessage('P', d);
}

static void send_bind(PgConnection& c) {
	// unnamed portal, unnamed statement, 0 param formats, 0 params, 0 result formats
	const std::vector<uint8_t> d { 0, 0, 0, 0, 0, 0, 0, 0 };
	c.sendMessage('B', d);
}

static void send_describe_portal(PgConnection& c) {
	const std::vector<uint8_t> d { 'P', 0 };
	c.sendMessage('D', d);
}

static void send_execute(PgConnection& c) {
	const std::vector<uint8_t> d { 0, 0, 0, 0, 0 }; // unnamed portal, no row limit
	c.sendMessage('E', d);
}

static bool simple_select_1(PgConnection& c, MsgCounts& counts) {
	c.sendQuery("SELECT 1");
	counts = drain(c);
	return counts.errors == 0 && counts.ready == 1 && counts.last == 'Z' && counts.other >= 1;
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(15);

	// 1. A full libpq-style batch: Parse/Bind/Describe/Execute/Sync.
	{
		auto c = admin_lite_connect();
		if (!c) {
			BAIL_OUT("Cannot connect to the PgSQL admin interface");
		}
		send_parse(*c, "SELECT 1");
		send_bind(*c);
		send_describe_portal(*c);
		send_execute(*c);
		c->sendSync();
		const MsgCounts counts = drain(*c);
		diag("P/B/D/E/S -> '%s'", counts.sequence.c_str());
		ok(counts.errors == 1, "P/B/D/E/S batch: exactly one ErrorResponse (got %d)", counts.errors);
		ok(counts.ready == 1, "P/B/D/E/S batch: exactly one ReadyForQuery (got %d)", counts.ready);
		ok(counts.last == 'Z' && counts.other == 0, "P/B/D/E/S batch: ReadyForQuery is the last message and nothing else is sent");

		MsgCounts after {};
		ok(simple_select_1(*c, after), "A simple query after the batch gets its own clean response: '%s'", after.sequence.c_str());
	}

	// 2. Parse + Flush without Sync: the error must arrive immediately, the
	//    ReadyForQuery only once Sync is sent.
	{
		auto c = admin_lite_connect();
		if (!c) {
			BAIL_OUT("Cannot connect to the PgSQL admin interface");
		}
		send_parse(*c, "SELECT 1");
		c->sendMessage('H', std::vector<uint8_t>());
		const MsgCounts before_sync = drain(*c);
		diag("P/H -> '%s'", before_sync.sequence.c_str());
		ok(before_sync.errors == 1 && before_sync.ready == 0,
			"Parse+Flush: one ErrorResponse and no ReadyForQuery before Sync (errors=%d ready=%d)",
			before_sync.errors, before_sync.ready);

		send_describe_portal(*c); // discarded: still before Sync
		c->sendSync();
		const MsgCounts at_sync = drain(*c);
		diag("D/S -> '%s'", at_sync.sequence.c_str());
		ok(at_sync.errors == 0 && at_sync.ready == 1 && at_sync.other == 0,
			"Parse+Flush: Sync is answered by exactly one ReadyForQuery (errors=%d ready=%d other=%d)",
			at_sync.errors, at_sync.ready, at_sync.other);

		MsgCounts after {};
		ok(simple_select_1(*c, after), "A simple query after Sync gets its own clean response: '%s'", after.sequence.c_str());
	}

	// A simple Query inside a rejected batch must also be discarded.
	{
		auto c = admin_lite_connect();
		if (!c) BAIL_OUT("Cannot connect to the PgSQL admin interface");
		c->sendQuery("DROP TABLE IF EXISTS reg_test_6345_discarded");
		const MsgCounts reset = drain(*c);
		if (reset.errors || reset.ready != 1) BAIL_OUT("Cannot reset the discarded-query fixture");
		send_parse(*c, "SELECT 1");
		c->sendQuery("CREATE TABLE reg_test_6345_discarded (id INTEGER)");
		c->sendSync();
		const MsgCounts counts = drain(*c);
		ok(counts.sequence == "EZ", "P/Q/S discards Query and returns exactly E/Z: '%s'", counts.sequence.c_str());

		// If the discarded Query ran, creating the same table would fail.
		c->sendQuery("CREATE TABLE reg_test_6345_discarded (id INTEGER)");
		const MsgCounts created = drain(*c);
		ok(created.errors == 0 && created.ready == 1,
			"The discarded Query had no side effects: '%s'", created.sequence.c_str());
		c->sendQuery("DROP TABLE IF EXISTS reg_test_6345_discarded");
		drain(*c);
		MsgCounts after {};
		ok(simple_select_1(*c, after), "A simple query after P/Q/S works: '%s'", after.sequence.c_str());
	}

	// 3. A bare Sync is answered with ReadyForQuery only.
	{
		auto c = admin_lite_connect();
		if (!c) {
			BAIL_OUT("Cannot connect to the PgSQL admin interface");
		}
		c->sendSync();
		const MsgCounts counts = drain(*c);
		diag("S -> '%s'", counts.sequence.c_str());
		ok(counts.errors == 0 && counts.ready == 1 && counts.other == 0,
			"Bare Sync: exactly one ReadyForQuery and no error (errors=%d ready=%d other=%d)",
			counts.errors, counts.ready, counts.other);
	}

	// 4. A real libpq client: the extended-query attempt fails cleanly and the
	//    connection stays usable.
	{
		std::stringstream ss;
		ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
		   << " user=" << cl.admin_username << " password=" << cl.admin_password
		   << " dbname=main sslmode=disable";
		PGconn* conn = PQconnectdb(ss.str().c_str());
		if (PQstatus(conn) != CONNECTION_OK) {
			diag("libpq admin connect failed: %s", PQerrorMessage(conn));
			PQfinish(conn);
			BAIL_OUT("Cannot connect to the PgSQL admin interface with libpq");
		}

		PGresult* r = PQexecParams(conn, "SELECT 1", 0, NULL, NULL, NULL, NULL, 0);
		const ExecStatusType st = PQresultStatus(r);
		const char* sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		diag("PQexecParams -> %s, SQLSTATE=%s, error='%s'", PQresStatus(st), sqlstate ? sqlstate : "(null)",
			PQresultErrorMessage(r));
		ok(st == PGRES_FATAL_ERROR && sqlstate && strcmp(sqlstate, "0A000") == 0,
			"libpq PQexecParams on admin fails with SQLSTATE 0A000 (feature not supported)");
		PQclear(r);

		bool all_good = true;
		for (int i = 0; i < 3; i++) {
			r = PQexec(conn, "SELECT 1");
			const bool good = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
				&& strcmp(PQgetvalue(r, 0, 0), "1") == 0;
			if (!good) {
				diag("Follow-up PQexec #%d -> %s, error='%s'", i, PQresStatus(PQresultStatus(r)), PQresultErrorMessage(r));
				all_good = false;
			}
			PQclear(r);
		}
		ok(all_good, "libpq simple queries after the extended-query attempt return correct results");

		r = PQprepare(conn, "s1", "SELECT 1", 0, NULL);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "libpq PQprepare on admin fails cleanly: %s", PQresultErrorMessage(r));
		PQclear(r);

		r = PQexec(conn, "SELECT 1");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1,
			"libpq simple query after PQprepare still works: %s", PQresStatus(PQresultStatus(r)));
		PQclear(r);
		PQfinish(conn);
	}

	return exit_status();
}
