/**
 * @file pgsql-extq_rule_error_stops_batch-t.cpp
 * @brief An error ProxySQL gives an extended-query message itself must end the batch, as PostgreSQL
 * does: nothing after it may run, and the client gets one ReadyForQuery.
 *
 * Covers each place that answers a message with its own error: a query rule's error_msg (on a Parse
 * that starts the batch, on a later Parse of a pipelined batch, and in native mode on the Execute of
 * a statement or portal prepared before the rule existed), a Parse over pgsql-max_allowed_packet, a
 * query routed away from the hostgroup the session is locked to, DEALLOCATE of an unknown statement,
 * SET with an invalid value and RESET ALL inside a transaction (native mode: the transaction must end
 * up failed, not lost), and RESET on a locked session whose backend was started with other settings. A reply sent after the batch ended reaches libpq "while idle", which it
 * reports as a notice, so every notice on the probe connections is counted: the probe statements raise
 * none of their own.
 */

#include <poll.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <vector>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType { ADMIN, BACKEND };

static int stray_replies = 0;

static void count_stray(void*, const char* message) {
	stray_replies++;
	diag("libpq notice: %s", message);
}

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "") {
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << username << " password=" << password << " sslmode=disable";
	if (options.empty() == false) {
		ss << " options='" << options << "'";
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static bool exec_ok(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	const bool good = PQresultStatus(res) == PGRES_COMMAND_OK || PQresultStatus(res) == PGRES_TUPLES_OK;
	if (!good) diag("'%s' failed: %s", q.c_str(), PQerrorMessage(conn));
	PQclear(res);
	return good;
}

static std::string single_value(PGresult* res) {
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
		out = PQgetvalue(res, 0, 0);
	} else if (PQresultStatus(res) == PGRES_COMMAND_OK) {
		out = "OK";
	} else {
		out = std::string("ERROR: ") + PQresultErrorMessage(res);
	}
	PQclear(res);
	return out;
}

// Runs 'q' with the unnamed statement. Returns the single value, "OK", or "ERROR: <message>".
static std::string run_extended(PGconn* conn, const std::string& q) {
	return single_value(PQexecParams(conn, q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0));
}

// Runs the named statement 'name', prepared earlier.
static std::string run_prepared(PGconn* conn, const std::string& name) {
	return single_value(PQexecPrepared(conn, name.c_str(), 0, nullptr, nullptr, nullptr, 0));
}

static PGConnPtr probe_connection(const std::string& options = "") {
	PGConnPtr conn = createNewConnection(BACKEND, options);
	if (conn) PQsetNoticeProcessor(conn.get(), count_stray, nullptr);
	return conn;
}

// Takes in whatever else arrives for a batch that already ended, then runs the next query. Returns the
// notices libpq raised meanwhile: replies that arrived after the batch ended.
static int strays_then_next(PGconn* conn, std::string& next_value) {
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	PQconsumeInput(conn);
	next_value = run_extended(conn, "SELECT 1");
	return stray_replies;
}

// Runs a statement ProxySQL refuses (the named statement 'q' when 'prepared' is set), then the next query.
static int run_refused(PGconn* conn, const std::string& q, std::string& err, std::string& next_value,
	bool prepared = false) {
	stray_replies = 0;
	err = prepared ? run_prepared(conn, q) : run_extended(conn, q);
	return strays_then_next(conn, next_value);
}

// Sends the statements as one pipelined batch with a single Sync and returns what libpq reported for
// each, in order: T rows, C command, E error, A skipped after an earlier error, S the Sync.
static std::string run_pipeline(PGconn* conn, const std::vector<std::string>& stmts) {
	if (PQenterPipelineMode(conn) != 1) return "no pipeline mode";
	for (const auto& q : stmts) {
		PQsendQueryParams(conn, q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
	}
	PQpipelineSync(conn);
	PQflush(conn);
	std::string out;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (out.find('S') == std::string::npos && std::chrono::steady_clock::now() < deadline) {
		if (PQisBusy(conn)) {
			pollfd p { PQsocket(conn), POLLIN, 0 };
			poll(&p, 1, 200);
			if (PQconsumeInput(conn) == 0) break;
			continue;
		}
		PGresult* res = PQgetResult(conn);
		if (res == nullptr) continue;   // the end of one statement's results
		switch (PQresultStatus(res)) {
		case PGRES_TUPLES_OK: out += 'T'; break;
		case PGRES_COMMAND_OK: out += 'C'; break;
		case PGRES_FATAL_ERROR: out += 'E'; diag("pipeline error: %s", PQresultErrorMessage(res)); break;
		case PGRES_PIPELINE_ABORTED: out += 'A'; break;
		case PGRES_PIPELINE_SYNC: out += 'S'; break;
		default: out += '?'; break;
		}
		PQclear(res);
	}
	PQexitPipelineMode(conn);
	return out;
}

static std::string current_value(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	std::string v = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) ? PQgetvalue(res, 0, 0) : "?";
	PQclear(res);
	return v;
}

// Reads one batch's replies up to its ReadyForQuery as message types, e.g. "2Z(T)" or "EZ(E)". Anything
// that arrives after it within the read timeout is appended as "+<type>".
static std::string raw_batch(PgConnection& c) {
	std::string out;
	char type = 0;
	std::vector<uint8_t> body;
	try {
		while (type != 'Z') {
			c.readMessage(type, body);
			if (type == 'N' || type == 'S') continue;
			out += type;
			if (type == 'Z' && body.empty() == false) out += std::string("(") + (char)body[0] + ")";
		}
		c.readMessage(type, body);
		out += std::string("+") + type;
	} catch (const PgException& e) {
		if (std::string(e.what()) != "Read timed out") out += std::string("<") + e.what() + ">";
	}
	return out;
}

// The servers of a hostgroup, each as SQL values ready for an INSERT into pgsql_servers.
static std::vector<std::string> server_rows(PGconn* admin, const std::string& hg) {
	std::vector<std::string> rows;
	PGresult* res = PQexec(admin, ("SELECT hostgroup_id, hostname, port, status, weight, compression, max_connections, "
		"max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_pgsql_servers WHERE hostgroup_id=" + hg).c_str());
	for (int i = 0; PQresultStatus(res) == PGRES_TUPLES_OK && i < PQntuples(res); i++) {
		std::string row;
		for (int j = 0; j < PQnfields(res); j++) {
			std::string v = PQgetvalue(res, i, j);
			for (size_t p = v.find('\''); p != std::string::npos; p = v.find('\'', p + 2)) v.insert(p, "'");
			row += (j ? "," : "") + (PQgetisnull(res, i, j) ? std::string("NULL") : "'" + v + "'");
		}
		rows.push_back(row);
	}
	PQclear(res);
	return rows;
}

// Puts the hostgroup's servers back at runtime, with max_connections set to 'max_conn' when given.
// Removing them first closes every backend pooled for them.
static bool reload_servers(PGconn* admin, const std::string& hg, const std::vector<std::string>& rows,
	const std::string& max_conn = "") {
	if (!exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg) ||
		!exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		return false;
	}
	for (const auto& row : rows) {
		if (!exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, compression, "
			"max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (" + row + ")")) {
			return false;
		}
	}
	if (max_conn.empty() == false &&
		!exec_ok(admin, "UPDATE pgsql_servers SET max_connections=" + max_conn + " WHERE hostgroup_id=" + hg)) {
		return false;
	}
	const bool loaded = exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	return loaded;
}

static bool wait_free_connections(PGconn* admin, const std::string& hg, int at_least) {
	for (int i = 0; i < 50; i++) {
		const std::string v = current_value(admin, "SELECT IFNULL(SUM(ConnFree),0) FROM stats_pgsql_connection_pool "
			"WHERE hostgroup=" + hg);
		if (v != "?" && atoi(v.c_str()) >= at_least) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	return false;
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	plan(25);

	PGConnPtr admin = createNewConnection(ADMIN);
	PGConnPtr setup = createNewConnection(BACKEND);
	if (!admin || !setup) {
		BAIL_OUT("Failed to connect");
		return exit_status();
	}

	const bool native = current_value(admin.get(), "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'") == "true";
	diag("Backend protocol: %s", native ? "native" : "libpq");

	const int rule_id = 9733;
	const int route_rule_id = 9734;
	const std::string seq = "extq_rule_error_seq";
	const std::string blocked = "SELECT nextval('" + seq + "')";
	exec_ok(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(rule_id) + "," +
		std::to_string(route_rule_id) + ")");
	exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	if (!exec_ok(setup.get(), "DROP SEQUENCE IF EXISTS " + seq) || !exec_ok(setup.get(), "CREATE SEQUENCE " + seq)) {
		BAIL_OUT("Failed to create the sequence");
		return exit_status();
	}
	auto sequence_value = [&]() { return current_value(setup.get(), "SELECT last_value FROM " + seq); };

	std::string r, next;
	int strays = 0;
	{
		// The connection's unnamed statement holds the text before the rule exists.
		PGConnPtr conn1 = probe_connection();
		ok(run_extended(conn1.get(), blocked) == "1", "Before the rule, the statement runs: nextval = 1");
		// Prepared before the rule too, and from then on only executed: Bind, Execute, Sync.
		PGConnPtr conn4 = probe_connection();
		PGresult* prep = PQprepare(conn4.get(), "blocked_stmt", blocked.c_str(), 0, nullptr);
		if (PQresultStatus(prep) != PGRES_COMMAND_OK) diag("Prepare failed: %s", PQerrorMessage(conn4.get()));
		PQclear(prep);
		// Native mode: a named portal of it, executed on its own in a later batch.
		PgConnection raw(1000);
		std::string raw_prepared;
		if (native) {
			try {
				raw.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
				raw.prepareStatement("blocked_portal_stmt", blocked, false);
				raw.sendSync();
				raw_prepared = raw_batch(raw);
			} catch (const std::exception& e) {
				raw_prepared = std::string("<") + e.what() + ">";
			}
		}

		exec_ok(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (" +
			std::to_string(rule_id) + ",1,'nextval\\(.extq_rule_error_seq','blocked by rule',1)");
		exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");

		strays = run_refused(conn1.get(), blocked, r, next);
		ok(r.find("blocked by rule") != std::string::npos, "The rule blocks the Parse: '%s'", r.c_str());
		ok(strays == 0 && next == "1", "Nothing follows the error: %d stray replies, next query returned '%s'",
			strays, next.c_str());
		ok(sequence_value() == "1", "The blocked statement did not run on the backend: sequence last_value = %s",
			sequence_value().c_str());

		if (native) {
			strays = run_refused(conn4.get(), "blocked_stmt", r, next, true);
			ok(r.find("blocked by rule") != std::string::npos, "Statement prepared before the rule: its Execute is blocked: '%s'",
				r.c_str());
			ok(strays == 0 && next == "1", "Prepared statement: nothing follows the error: %d stray replies, next query returned '%s'",
				strays, next.c_str());
			ok(sequence_value() == "1", "The prepared statement did not run on the backend: sequence last_value = %s",
				sequence_value().c_str());
		} else {
			skip(3, "libpq mode checks a rule's error_msg on the Parse only");
		}

		// Nothing cached: the Bind after the blocked Parse has no statement to use.
		PGConnPtr conn2 = probe_connection();
		strays = run_refused(conn2.get(), blocked, r, next);
		ok(r.find("blocked by rule") != std::string::npos, "New connection: the rule blocks the Parse: '%s'", r.c_str());
		ok(strays == 0 && next == "1", "New connection: nothing follows the error: %d stray replies, next query returned '%s'",
			strays, next.c_str());

		// A later Parse of a pipelined batch: the statement after it must be skipped, as PostgreSQL does.
		PGConnPtr conn5 = probe_connection();
		stray_replies = 0;
		r = run_pipeline(conn5.get(), { "SELECT 1", blocked, "SELECT 2" });
		ok(r == "TEAS", "Pipelined batch, blocked second Parse: results '%s', expected 'TEAS'", r.c_str());
		strays = strays_then_next(conn5.get(), next);
		ok(strays == 0 && next == "1", "Pipelined batch: nothing follows the error: %d stray replies, next query returned '%s'",
			strays, next.c_str());

		if (native) {
			// The Bind starts its own batch, so the Execute starts the next one: the rule is checked there.
			std::string bound, executed, rolled_back;
			try {
				raw.sendQuery("BEGIN");
				raw_batch(raw);
				raw.bindStatement("blocked_portal_stmt", "blocked_portal", {}, {}, false);
				raw.sendSync();
				bound = raw_batch(raw);
				raw.executePortal("blocked_portal");
				executed = raw_batch(raw);
				raw.sendQuery("ROLLBACK");
				rolled_back = raw_batch(raw);
			} catch (const std::exception& e) {
				executed += std::string("<") + e.what() + ">";
			}
			ok(raw_prepared == "1Z(I)" && bound == "2Z(T)" && executed == "EZ(E)" && rolled_back == "CZ(I)",
				"Portal of a statement prepared before the rule, executed alone: prepared '%s', bound '%s', executed '%s' "
				"(expected EZ(E), nothing after), rolled back '%s'", raw_prepared.c_str(), bound.c_str(), executed.c_str(),
				rolled_back.c_str());
			ok(sequence_value() == "1", "The portal did not run on the backend: sequence last_value = %s",
				sequence_value().c_str());
		} else {
			skip(2, "named portals are native mode only");
		}

		exec_ok(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id));
		exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	}

	{
		// A session locked to its hostgroup (SET of a variable ProxySQL cannot track), then a query a rule
		// routes elsewhere: refused before any backend is used.
		PGConnPtr conn6 = probe_connection();
		exec_ok(conn6.get(), "SET extq_test.lock_probe = 'on'");
		exec_ok(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) "
			"VALUES (" + std::to_string(route_rule_id) + ",1,'locked_hg_probe',9999,1)");
		exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
		strays = run_refused(conn6.get(), "SELECT 7 AS locked_hg_probe", r, next);
		ok(r.find("locked to hostgroup") != std::string::npos, "Locked session routed elsewhere: refused: '%s'", r.c_str());
		ok(strays == 0 && next == "1", "Locked session: nothing follows the error: %d stray replies, next query returned '%s'",
			strays, next.c_str());
		exec_ok(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(route_rule_id));
		exec_ok(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	}

	{
		PGConnPtr conn7 = probe_connection();
		r = run_extended(conn7.get(), "DEALLOCATE extq_no_such_stmt");
		ok(r.find("does not exist") != std::string::npos, "DEALLOCATE of an unknown statement is refused: '%s'", r.c_str());
		// What follows it in the same batch must be skipped.
		stray_replies = 0;
		r = run_pipeline(conn7.get(), { "DEALLOCATE extq_no_such_stmt", "SELECT 2" });
		strays = strays_then_next(conn7.get(), next);
		ok(r == "EAS" && strays == 0 && next == "1", "Pipelined DEALLOCATE of an unknown statement: results '%s' "
			"(expected 'EAS'), %d stray replies, next query returned '%s'", r.c_str(), strays, next.c_str());

		// Inside a transaction an error fails it, and the work before it is still there: rolling back to a
		// savepoint taken before the error, as drivers with autosave do, recovers it. A lost transaction
		// has no savepoint left, and the temp table created in it is gone.
		if (native) {
			for (const char* refused : { "SET DateStyle = 'extq_bogus_style'", "RESET ALL" }) {
				exec_ok(conn7.get(), "BEGIN");
				exec_ok(conn7.get(), "CREATE TEMP TABLE extq_txn_probe (a int)");
				exec_ok(conn7.get(), "SAVEPOINT extq_sp");
				r = run_extended(conn7.get(), refused);
				const bool failed = PQtransactionStatus(conn7.get()) == PQTRANS_INERROR;
				const bool recovered = exec_ok(conn7.get(), "ROLLBACK TO SAVEPOINT extq_sp");
				const std::string rows = current_value(conn7.get(), "SELECT count(*) FROM extq_txn_probe");
				ok(r.rfind("ERROR: ", 0) == 0 && failed && recovered && rows == "0",
					"'%s' refused inside a transaction leaves it failed but intact: transaction %s, rolled back to "
					"the savepoint: %s, temp table rows '%s'", refused, failed ? "failed" : "NOT failed",
					recovered ? "yes" : "no", rows.c_str());
				exec_ok(conn7.get(), "ROLLBACK");
			}
		} else {
			skip(2, "libpq mode: an error ProxySQL gives itself inside a transaction still drops the transaction");
		}
	}

	// A Parse over max_allowed_packet. Runtime only: the harness reloads variables before the next test.
	const std::string max_packet = current_value(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-max_allowed_packet'");
	exec_ok(admin.get(), "SET pgsql-max_allowed_packet=8192");
	exec_ok(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	{
		const std::string oversized = "SELECT 2 /* " + std::string(9000, 'x') + " */";
		PGConnPtr conn3 = probe_connection();
		strays = run_refused(conn3.get(), oversized, r, next);
		ok(r.find("max_allowed_packet") != std::string::npos, "An oversized Parse is refused: '%.80s'", r.c_str());
		ok(strays == 0 && next == "1", "Oversized Parse: nothing follows the error: %d stray replies, next query returned '%s'",
			strays, next.c_str());

		stray_replies = 0;
		r = run_pipeline(conn3.get(), { "SELECT 1", oversized, "SELECT 3" });
		ok(r == "TEAS", "Pipelined batch, oversized second Parse: results '%s', expected 'TEAS'", r.c_str());
		strays = strays_then_next(conn3.get(), next);
		ok(strays == 0 && next == "1", "Pipelined oversized Parse: nothing follows the error: %d stray replies, "
			"next query returned '%s'", strays, next.c_str());
	}
	exec_ok(admin.get(), "SET pgsql-max_allowed_packet=" + max_packet);
	exec_ok(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	{
		// RESET on a locked session whose backend was started for another client with other settings: the
		// backend's own default is not the client's, so ProxySQL refuses it. One backend at a time makes the
		// next client get the one the first client started, so no other session may hold it.
		setup.reset();
		const std::string hg = current_value(admin.get(), "SELECT default_hostgroup FROM runtime_pgsql_users "
			"WHERE username='" + std::string(cl.pgsql_username) + "' LIMIT 1");
		const std::vector<std::string> servers = server_rows(admin.get(), hg);
		bool ready = servers.empty() == false && reload_servers(admin.get(), hg, servers, "1");
		const std::string pool = current_value(admin.get(), "SELECT GROUP_CONCAT(status || ' used=' || ConnUsed || "
			"' free=' || ConnFree, '; ') FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
		std::string stale_datestyle;
		if (ready) {
			PGConnPtr stale = createNewConnection(BACKEND, "-c DateStyle=SQL,\\\\ DMY");
			if (stale) {
				PGresult* res = PQexec(stale.get(), "SHOW DateStyle");
				stale_datestyle = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1 ?
					PQgetvalue(res, 0, 0) : std::string("ERROR: ") + PQresultErrorMessage(res);
				PQclear(res);
			} else {
				stale_datestyle = "no connection";
			}
		}
		ready = ready && stale_datestyle == "SQL, DMY" && wait_free_connections(admin.get(), hg, 1);
		if (ready) {
			PGConnPtr conn8 = probe_connection();
			exec_ok(conn8.get(), "SET extq_test.lock_probe = 'on'");
			strays = run_refused(conn8.get(), "RESET DateStyle", r, next);
			ok(r.find("hostgroup is locked") != std::string::npos, "RESET on a locked session with other startup settings "
				"is refused: '%s'", r.c_str());
			ok(strays == 0 && next == "1", "RESET refused: nothing follows the error: %d stray replies, next query returned '%s'",
				strays, next.c_str());
		} else {
			ok(false, "RESET on a locked session: setup failed (hostgroup '%s', %zu server(s), pool '%s', stale DateStyle '%s')",
				hg.c_str(), servers.size(), pool.c_str(), stale_datestyle.c_str());
			ok(false, "RESET refused: not run");
		}
		if (servers.empty() == false) {
			reload_servers(admin.get(), hg, servers);
		}
	}

	setup = createNewConnection(BACKEND);
	if (setup) exec_ok(setup.get(), "DROP SEQUENCE IF EXISTS " + seq);
	return exit_status();
}
