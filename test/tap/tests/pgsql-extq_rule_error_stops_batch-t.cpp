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
 *
 * The refusals ProxySQL answers itself (an invalid SET value, RESET ALL, COPY, DISCARD ALL, a bad
 * pg_terminate_backend() parameter, RESET on a locked session, a query rule's error_msg) and a backend's
 * own error are also sent with no Sync and closed by a simple Query, an implicit Sync: the client must get
 * one ReadyForQuery, after the Query. With another statement and a Sync behind them, the error carries the
 * one ReadyForQuery. A Flush or a FunctionCall in the middle of a unit is refused too, and only the Sync
 * after it may be answered with a ReadyForQuery.
 *
 * A matrix then varies the rest: where in the unit the error comes (Parse, Bind, Describe, Execute, after a
 * statement that ran, before one queued behind it), what the closing simple Query is (one that fails itself,
 * an empty one, several statements, one ProxySQL answers, BEGIN), a Sync after the Query, inside a
 * transaction, units back to back on one connection, and in native mode the path that sends one message at
 * a time and the one that cuts the batch short before a statement ProxySQL handles itself.
 */

#include <poll.h>
#include <ctime>
#include <fstream>
#include <functional>
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
// that arrives after it within the read timeout is appended as "+<type>". 'err' gets the first error's message.
static std::string raw_batch(PgConnection& c, std::string* err = nullptr) {
	std::string out;
	char type = 0;
	std::vector<uint8_t> body;
	try {
		while (type != 'Z') {
			c.readMessage(type, body);
			if (type == 'N' || type == 'S') continue;
			out += type;
			if (type == 'Z' && body.empty() == false) out += std::string("(") + (char)body[0] + ")";
			if (type == 'E' && err && err->empty()) {
				for (size_t i = 0; i < body.size() && body[i]; i += strlen((const char*)&body[i + 1]) + 2) {
					if (body[i] == 'M') *err = (const char*)&body[i + 1];
				}
			}
		}
		c.readMessage(type, body);
		out += std::string("+") + type;
	} catch (const PgException& e) {
		if (std::string(e.what()) != "Read timed out") out += std::string("<") + e.what() + ">";
	}
	return out;
}

// Parse/Bind/Execute of a statement that fails, on a new connection ('lock' first locks it to its
// hostgroup), and of 'behind' when given, then either a simple Query, which closes the unit with an
// implicit Sync, or ('pipelined') another statement and a Sync. The client must get one ReadyForQuery:
// after the Query, "...ETDCZ(I)", or with the error, "...EZ(I)", the statements queued behind it discarded.
// Nothing may follow it. An extra one leaves the client a reply out of step for the rest of the session, a
// missing one leaves it waiting.
static void check_refusal(const std::string& q, const std::string& expected_err, bool pipelined,
	const std::vector<PgConnection::Param>& params = {}, bool lock = false, const std::string& behind = "") {
	PgConnection c(1000);
	std::string r, err;
	try {
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		if (lock) {
			c.sendQuery("SET extq_test.lock_probe = 'on'");
			raw_batch(c);
		}
		c.prepareStatement("", q, false);
		c.bindStatement("", "", params, {}, false);
		c.executePortal("", 0, false);
		if (behind.empty() == false) {
			c.prepareStatement("", behind, false);
			c.bindStatement("", "", {}, {}, false);
			c.executePortal("", 0, false);
		}
		if (pipelined) {
			c.prepareStatement("", "SELECT 2", false);
			c.bindStatement("", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
		} else {
			c.sendQuery("SELECT 13");
		}
		r = raw_batch(c, &err);
	} catch (const std::exception& e) {
		r += std::string("<") + e.what() + ">";
	}
	const std::string end = pipelined ? "EZ(I)" : "TDCZ(I)";
	const bool one_ready = r.size() >= end.size() && r.compare(r.size() - end.size(), end.size(), end) == 0;
	ok(err.find(expected_err) != std::string::npos && one_ready, "'%s' fails%s%s, then %s: one ReadyForQuery: "
		"replies '%s' (expected ...%s, nothing after), error '%s'", q.c_str(), behind.empty() ? "" : " before ",
		behind.c_str(), pipelined ? "another statement and Sync" : "a simple Query (implicit Sync)", r.c_str(),
		pipelined ? "EZ(I)" : "ETDCZ(I)", err.c_str());
}

static void pbe(PgConnection& c, const std::string& q) {
	c.prepareStatement("", q, false);
	c.bindStatement("", "", {}, {}, false);
	c.executePortal("", 0, false);
}

// Sends the messages 'send' writes on a new connection, started with 'options' and after 'before' as a
// simple Query when given, and returns the replies as raw_batch() reads them.
static std::string run_unit(const std::function<void(PgConnection&)>& send, const std::string& options = "",
	const std::string& before = "") {
	PgConnection c(1000);
	std::string r;
	try {
		c.setOptions(options);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		if (before.empty() == false) {
			c.sendQuery(before);
			raw_batch(c);
		}
		send(c);
		r = raw_batch(c);
	} catch (const std::exception& e) {
		r += std::string("<") + e.what() + ">";
	}
	return r;
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

	plan(75);

	PGConnPtr admin = createNewConnection(ADMIN);
	PGConnPtr setup = createNewConnection(BACKEND);
	if (!admin || !setup) {
		BAIL_OUT("Failed to connect");
		return exit_status();
	}

	const bool native = current_value(admin.get(), "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'") == "true";
	diag("Backend protocol: %s", native ? "native" : "libpq");
	const std::string hg = current_value(admin.get(), "SELECT default_hostgroup FROM runtime_pgsql_users "
		"WHERE username='" + std::string(cl.pgsql_username) + "' LIMIT 1");
	const std::vector<std::string> servers = server_rows(admin.get(), hg);
	std::fstream proxysql_log;
	if (open_file_and_seek_end(get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log", proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open the ProxySQL log");
		return exit_status();
	}

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

		// Native mode sends the unit as one batch, and the rule's error on its second Parse fails the batch
		// on the backend. After an implicit Sync the backend's ReadyForQuery for it is not the client's: the
		// client's comes after its simple Query.
		{
			PgConnection c(1000);
			std::string r2, err;
			try {
				c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
				for (const std::string& q : { std::string("SELECT 1"), blocked }) {
					c.prepareStatement("", q, false);
					c.bindStatement("", "", {}, {}, false);
					c.executePortal("", 0, false);
				}
				c.sendQuery("SELECT 13");
				r2 = raw_batch(c, &err);
			} catch (const std::exception& e) {
				r2 += std::string("<") + e.what() + ">";
			}
			const bool one_ready = r2.size() >= 7 && r2.compare(r2.size() - 7, 7, "TDCZ(I)") == 0;
			ok(err == "blocked by rule" && one_ready, "Batched unit, blocked second Parse, then a simple Query (implicit "
				"Sync): one ReadyForQuery, after the Query: replies '%s' (expected ...ETDCZ(I), nothing after), error '%s'",
				r2.c_str(), err.c_str());
		}

		// The simple Query that closes a failed unit is refused by the rule: its own error ends with the
		// one ReadyForQuery.
		r = run_unit([&](PgConnection& c) { pbe(c, "SELECT 1/(random()*0)::int"); c.sendQuery(blocked); });
		ok(r == "12EEZ(I)", "Failed unit, then a simple Query the rule refuses: replies '%s' (expected 12EEZ(I), "
			"nothing after)", r.c_str());

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

	{
		const std::vector<std::pair<std::string, std::string>> refusals = {
			{ "SET DateStyle = 'extq_bogus_style'", "invalid value for parameter" },
			{ "RESET ALL", "RESET ALL is not supported in pipeline mode" },
			{ "COPY extq_copy_probe FROM STDIN", "Feature not supported" },
			{ "DISCARD ALL", "DISCARD ALL is not supported" },
			{ "SELECT 1/0", "division by zero" },
		};
		for (const bool pipelined : { false, true }) {
			for (const auto& [q, expected] : refusals) {
				check_refusal(q, expected, pipelined);
			}
			check_refusal("SELECT pg_terminate_backend($1)", "PID must be a positive integer", pipelined,
				{ { std::string("0"), 0 } });
			// Native mode sends the part before the SET, which ProxySQL handles itself, as its own batch with
			// no Sync. Failing, it gets the Sync ProxySQL adds.
			check_refusal("SELECT 1/0", "division by zero", pipelined, {}, false, "SET DateStyle = 'ISO'");
		}

		// A message ProxySQL does not support (a Flush, a FunctionCall) in the middle of a unit: its error
		// must not carry a ReadyForQuery of its own. The client's Sync gets the only one.
		for (const char type : { 'H', 'F' }) {
			PgConnection c(1000);
			std::string r, err;
			try {
				c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
				c.prepareStatement("", "SELECT 1", false);
				c.bindStatement("", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendMessage(type, {});
				c.sendSync();
				r = raw_batch(c, &err);
			} catch (const std::exception& e) {
				r += std::string("<") + e.what() + ">";
			}
			ok(r == "EZ(I)" && err.find("Feature not supported") != std::string::npos,
				"'%c' refused in the middle of a unit, then Sync: one ReadyForQuery, the Sync's: replies '%s' "
				"(expected EZ(I), nothing after), error '%s'", type, r.c_str(), err.c_str());
		}
	}

	{
		// The matrix. Replies as raw_batch() reads them: 1 ParseComplete, 2 BindComplete, T RowDescription,
		// D DataRow, C CommandComplete, I EmptyQueryResponse, E ErrorResponse, Z(s) ReadyForQuery, "+x" what
		// came after it. The closing Query gets the one ReadyForQuery, a Sync after it gets its own.
		// The constant in "SELECT 1/0" is folded at Bind, so that one is a Bind error; this one fails at Execute.
		// An expected value starting with "..." is checked as the end of the replies: before a Bind error
		// ProxySQL sends its own BindComplete, which PostgreSQL does not (a separate issue).
		static const std::string exec_err = "SELECT 1/(random()*0)::int";
		using Send = std::function<void(PgConnection&)>;
		// Untracked: the session's first message is not batched. It stays that way while that Parse goes to the
		// backend; a Parse ProxySQL answers itself lets the rest batch, so these texts are new to this run.
		const std::string unbatched = "-c work_mem=4MB";
		const std::string fresh = " /* extq_one_at_a_time_" + std::to_string(time(nullptr)) + "_";
		struct Case { const char* label; std::string options; std::string before; Send send; std::string expected; };
		const std::vector<Case> cases = {
			// Where the error comes.
			{ "backend Parse error", "", "", [](PgConnection& c) {
				pbe(c, "SELEC 1"); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "backend Bind error (a parameter missing)", "", "", [](PgConnection& c) {
				c.prepareStatement("", "SELECT $1::int", false);
				c.bindStatement("", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendQuery("SELECT 13"); }, "...ETDCZ(I)" },
			{ "backend Bind error (a folded constant)", "", "", [](PgConnection& c) {
				pbe(c, "SELECT 1/0"); c.sendQuery("SELECT 13"); }, "...ETDCZ(I)" },
			{ "backend Execute error", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SELECT 13"); }, "12ETDCZ(I)" },
			{ "backend Execute error after a statement that ran", "", "", [](PgConnection& c) {
				pbe(c, "SELECT 1"); pbe(c, exec_err); c.sendQuery("SELECT 13"); }, "12DC12ETDCZ(I)" },
			{ "backend Execute error, a statement queued behind it", "", "", [](PgConnection& c) {
				pbe(c, exec_err); pbe(c, "SELECT 2"); c.sendQuery("SELECT 13"); }, "12ETDCZ(I)" },
			{ "failing Parse alone", "", "", [](PgConnection& c) {
				c.prepareStatement("", "SELEC 1", false); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "Describe of a statement that does not exist", "", "", [](PgConnection& c) {
				c.describeStatement("extq_no_stmt", false); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "Bind of a statement that does not exist", "", "", [](PgConnection& c) {
				c.bindStatement("extq_no_stmt", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "Execute of a portal that does not exist", "", "", [](PgConnection& c) {
				c.executePortal("extq_no_portal", 0, false); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "Describe of the portal, then its Execute fails", "", "", [](PgConnection& c) {
				c.prepareStatement("", exec_err, false);
				c.bindStatement("", "", {}, {}, false);
				c.describePortal("", false);
				c.executePortal("", 0, false);
				c.sendQuery("SELECT 13"); },
				// libpq gives ProxySQL the columns only with rows, so its RowDescription is lost (a separate issue).
				native ? "12TETDCZ(I)" : "...ETDCZ(I)" },
			{ "Flush refused mid-unit, then the simple Query", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendMessage('H', {}); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			// What closes the unit.
			{ "closing Query fails itself", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SELECT 1/0"); }, "12EEZ(I)" },
			{ "closing Query is empty", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery(""); }, "12EIZ(I)" },
			{ "closing Query has two statements", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SELECT 1; SELECT 2"); }, "12ETDCTDCZ(I)" },
			{ "closing Query is a SET", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SET DateStyle = 'ISO'"); }, "12ECZ(I)" },
			{ "closing Query is BEGIN", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("BEGIN"); }, "12ECZ(T)" },
			{ "a Sync after the closing Query", "", "", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SELECT 13"); c.sendSync(); }, "12ETDCZ(I)+Z" },
			// Inside a transaction.
			{ "in a transaction, backend error", "", "BEGIN", [](PgConnection& c) {
				pbe(c, exec_err); c.sendQuery("SELECT 13"); }, "12EEZ(E)" },
			{ "in a transaction, ProxySQL's own error", "", "BEGIN", [](PgConnection& c) {
				c.bindStatement("extq_no_stmt", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendQuery("SELECT 13"); }, "EEZ(E)" },
			{ "in a transaction, no error", "", "BEGIN", [](PgConnection& c) {
				pbe(c, "SELECT 1"); c.sendQuery("SELECT 13"); }, "12DCTDCZ(T)" },
			// Native mode, one message at a time.
			{ "one at a time, Parse error", unbatched, "", [&](PgConnection& c) {
				pbe(c, "SELEC 1" + fresh + "1 */"); pbe(c, "SELECT 2"); c.sendQuery("SELECT 13"); }, "ETDCZ(I)" },
			{ "one at a time, Execute error", unbatched, "", [&](PgConnection& c) {
				pbe(c, exec_err + fresh + "2 */"); c.sendQuery("SELECT 13"); }, "12ETDCZ(I)" },
			{ "one at a time, Execute error after a statement that ran", unbatched, "", [&](PgConnection& c) {
				pbe(c, "SELECT 1" + fresh + "3 */"); pbe(c, exec_err + fresh + "3b */"); c.sendQuery("SELECT 13"); },
				"12DC12ETDCZ(I)" },
			{ "one at a time, Execute error, a statement queued behind it", unbatched, "", [&](PgConnection& c) {
				pbe(c, exec_err + fresh + "4 */"); pbe(c, "SELECT 2"); c.sendQuery("SELECT 13"); }, "12ETDCZ(I)" },
			{ "one at a time, Execute error, a statement queued behind it, then Sync", unbatched, "", [&](PgConnection& c) {
				pbe(c, exec_err + fresh + "5 */"); pbe(c, "SELECT 2"); c.sendSync(); }, "12EZ(I)" },
			{ "one at a time, no error", unbatched, "", [&](PgConnection& c) {
				pbe(c, "SELECT 1" + fresh + "6 */"); c.sendQuery("SELECT 13"); }, "12DCTDCZ(I)" },
			// Native mode, the batch cut short before a statement ProxySQL handles, the error after it.
			{ "error after a SET that cuts the batch", "", "", [](PgConnection& c) {
				pbe(c, "SELECT 1"); pbe(c, "SET DateStyle = 'ISO'"); pbe(c, exec_err); c.sendQuery("SELECT 13"); },
				"12DC12C12ETDCZ(I)" },
		};
		for (const Case& k : cases) {
			const std::string got = run_unit(k.send, k.options, k.before);
			const bool tail = k.expected.rfind("...", 0) == 0;
			const std::string want = tail ? k.expected.substr(3) : k.expected;
			const bool good = tail ? got.size() >= want.size() && got.compare(got.size() - want.size(), want.size(), want) == 0 :
				got == want;
			ok(good, "Matrix, %s: replies '%s' (expected %s, nothing after)", k.label, got.c_str(), k.expected.c_str());
		}

		// Native mode only: the one-at-a-time path really ran. The error with a statement queued behind it
		// goes out Flush-terminated there, and ProxySQL logs the Sync it adds, once per backend connection,
		// so the pool is emptied first.
		if (native) {
			reload_servers(admin.get(), hg, servers);
			get_matching_lines(proxysql_log, "__skip_to_end__");
			r = run_unit([&](PgConnection& c) { pbe(c, exec_err + fresh + "7 */"); pbe(c, "SELECT 2"); c.sendQuery("SELECT 13"); },
				unbatched);
			const bool logged = wait_for_log_match(proxysql_log, ".*native extq: mid-frame stmt-step error.*");
			ok(r == "12ETDCZ(I)" && logged, "Matrix, one at a time: the path ran (Sync added after the error: %s), "
				"replies '%s' (expected 12ETDCZ(I))", logged ? "logged" : "NOT logged", r.c_str());
		} else {
			skip(1, "the one-at-a-time path is native mode only");
		}

		// Units back to back on one connection: what the failed one leaves behind must not change the next.
		PgConnection c(1000);
		std::string r1, r2, r3;
		try {
			c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
			pbe(c, exec_err);
			c.sendQuery("SELECT 13");
			r1 = raw_batch(c);
			pbe(c, "SELECT 5");
			c.sendSync();
			r2 = raw_batch(c);
			pbe(c, "SELECT 6");
			c.sendQuery("SELECT 7");
			r3 = raw_batch(c);
		} catch (const std::exception& e) {
			r3 += std::string("<") + e.what() + ">";
		}
		ok(r1 == "12ETDCZ(I)" && r2 == "12DCZ(I)" && r3 == "12DCTDCZ(I)", "Matrix, units back to back: failed unit "
			"then Query '%s', unit then Sync '%s', unit then Query '%s' (expected 12ETDCZ(I), 12DCZ(I), 12DCTDCZ(I))",
			r1.c_str(), r2.c_str(), r3.c_str());
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
		std::string pool, stale_datestyle;
		// Empties the pool, then has a client started with DateStyle 'SQL, DMY' leave its backend there, the
		// only one. Each RESET case needs a fresh one: in libpq mode the refusal drops the backend it was
		// given, and the next one is started with the defaults.
		auto stale_backend = [&]() {
			if (reload_servers(admin.get(), hg, servers, "1") == false) return false;
			pool = current_value(admin.get(), "SELECT GROUP_CONCAT(status || ' used=' || ConnUsed || "
				"' free=' || ConnFree, '; ') FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
			{
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
			return stale_datestyle == "SQL, DMY" && wait_free_connections(admin.get(), hg, 1);
		};
		bool ready = servers.empty() == false && stale_backend();
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
		for (const char* reset : { "RESET DateStyle", "RESET ALL" }) {
			if (ready && stale_backend()) {
				check_refusal(reset, "hostgroup is locked", false, {}, true);
			} else {
				ok(false, "%s on a locked session, implicit Sync: setup failed (stale DateStyle '%s')", reset,
					stale_datestyle.c_str());
			}
		}
		if (servers.empty() == false) {
			reload_servers(admin.get(), hg, servers);
		}
	}

	setup = createNewConnection(BACKEND);
	if (setup) exec_ok(setup.get(), "DROP SEQUENCE IF EXISTS " + seq);
	return exit_status();
}
