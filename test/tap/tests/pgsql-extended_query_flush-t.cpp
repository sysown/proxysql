/**
 * @file pgsql-extended_query_flush-t.cpp
 * @brief Client Flush ('H') in the extended query protocol.
 *
 * A client may send Flush instead of Sync to get the replies to what it has sent so far,
 * e.g. Parse + Describe(statement) + Flush to learn the parameter types of a statement
 * before binding it. postgres.js does this for every query with a parameter whose type it
 * cannot infer (any string), so it could not run such a query through ProxySQL: Flush was
 * answered with "Feature not supported" and the connection got out of step.
 *
 * Expected behaviour, as PostgreSQL:
 *  - Flush with Parse/Describe/Bind/Close queued: their replies are sent, without ReadyForQuery;
 *    the client then continues the cycle (Bind/Execute) and its Sync gets the ReadyForQuery.
 *  - A Close queued before Flush gets its CloseComplete there, in order behind the replies before
 *    it, and the statement or portal is gone afterwards.
 *  - A Bind of the unnamed portal outlives the Flush (Parse + Bind + Flush, then Execute + Sync):
 *    it stays until its Execute, a replacement Bind, a Close of the portal, the client's Sync or a
 *    simple Query.
 *  - Flush with nothing queued: no reply.
 *  - An error in the messages run for Flush: one ErrorResponse and no ReadyForQuery; every
 *    message up to the client's Sync is discarded, and that Sync gets one ReadyForQuery.
 *  - Flush after Execute is not supported: it fails the same way (one ErrorResponse, the rest
 *    discarded up to Sync, one ReadyForQuery) and the connection stays usable.
 *
 * The test counts the messages on the wire with pg_lite_client. A reply is over only when the
 * socket stays quiet; a connection ProxySQL closes or corrupts fails the test.
 */

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include <poll.h>
#include <unistd.h>

#include "command_line.h"
#include "pg_lite_client.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Time without traffic after which no further message is expected.
static const int QUIET_TIMEOUT_MS = 1500;

/**
 * @brief Waits up to QUIET_TIMEOUT_MS for the socket to have something to read.
 * @return false when it stayed quiet: the reply is over. True when readable, which includes the
 *         peer closing the connection or a socket error -- the read that follows reports those.
 */
static bool wait_readable(PgConnection& c) {
	struct pollfd pfd {};
	pfd.fd = c.getSocket();
	pfd.events = POLLIN;
	while (true) {
		const int r = poll(&pfd, 1, QUIET_TIMEOUT_MS);
		if (r > 0) return true;
		if (r == 0) return false;
		if (errno != EINTR) throw PgException(std::string("poll() failed: ") + strerror(errno));
	}
}

/**
 * @brief Reads messages until the socket stays quiet for QUIET_TIMEOUT_MS.
 *
 * Only that quiet wait, before a message starts, ends the reply. Anything else is a failure and
 * propagates as PgException: the connection closed by ProxySQL, a socket error, a message cut
 * short (pg_lite_client's own read timeout, inside a message) or a malformed one. A test must not
 * pass by reading a dropped or corrupted connection as "no more replies".
 *
 * @return The message types received, in order.
 */
static std::string drain(PgConnection& c, std::vector<std::string>* rows = nullptr) {
	std::string seq {};
	while (wait_readable(c)) {
		char type = 0;
		std::vector<uint8_t> buf {};
		c.readMessage(type, buf);
		seq += type;
		// DataRow: int16 column count, then per column int32 length (-1: NULL) and the bytes.
		// Only the first column is kept.
		if (rows && type == 'D') {
			if (buf.size() < 6) throw PgException("malformed DataRow");
			const int32_t len = (int32_t)(((uint32_t)buf[2] << 24) | ((uint32_t)buf[3] << 16) |
				((uint32_t)buf[4] << 8) | (uint32_t)buf[5]);
			if (len < 0) {
				rows->push_back("<NULL>");
			} else if (buf.size() >= 6 + (size_t)len) {
				rows->emplace_back((const char*)buf.data() + 6, (size_t)len);
			} else {
				throw PgException("malformed DataRow");
			}
		}
	}
	return seq;
}

static size_t count(const std::string& seq, char type) {
	size_t n = 0;
	for (char t : seq) {
		if (t == type) n++;
	}
	return n;
}

static void put_cstr(std::vector<uint8_t>& d, const char* s) {
	d.insert(d.end(), s, s + strlen(s) + 1);
}

static void put_u16(std::vector<uint8_t>& d, uint16_t v) {
	d.push_back((uint8_t)(v >> 8));
	d.push_back((uint8_t)v);
}

static void put_u32(std::vector<uint8_t>& d, uint32_t v) {
	for (int i = 3; i >= 0; i--) d.push_back((uint8_t)(v >> (i * 8)));
}

static void send_parse(PgConnection& c, const char* query, const char* stmt = "") {
	std::vector<uint8_t> d {};
	put_cstr(d, stmt);
	put_cstr(d, query);
	put_u16(d, 0); // no parameter types: the server infers them
	c.sendMessage('P', d);
}

static void send_describe_statement(PgConnection& c, const char* stmt = "") {
	std::vector<uint8_t> d { 'S' };
	put_cstr(d, stmt);
	c.sendMessage('D', d);
}

static void send_bind(PgConnection& c, const std::vector<std::string>& params, const char* stmt = "") {
	std::vector<uint8_t> d {};
	put_cstr(d, "");   // unnamed portal
	put_cstr(d, stmt);
	put_u16(d, 0);     // all parameters in text format
	put_u16(d, (uint16_t)params.size());
	for (const std::string& p : params) {
		put_u32(d, (uint32_t)p.size());
		d.insert(d.end(), p.begin(), p.end());
	}
	put_u16(d, 0);     // all results in text format
	c.sendMessage('B', d);
}

static void send_execute(PgConnection& c, uint32_t max_rows = 0) {
	std::vector<uint8_t> d {};
	put_cstr(d, "");   // unnamed portal
	put_u32(d, max_rows);
	c.sendMessage('E', d);
}

static void send_flush(PgConnection& c) {
	c.sendMessage('H', {});
}

/**
 * @brief Close of a statement (kind 'S') or a portal (kind 'P').
 */
static void send_close(PgConnection& c, char kind, const char* name = "") {
	std::vector<uint8_t> d { (uint8_t)kind };
	put_cstr(d, name);
	c.sendMessage('C', d);
}

/**
 * @brief A statement text no earlier run has prepared, so its Parse goes to the backend instead
 *        of being answered from ProxySQL's statement cache.
 */
static std::string unique_text(const char* base) {
	static int seq = 0;
	return std::string(base) + " AS c_" + std::to_string((long long)getpid()) + "_" +
		std::to_string((long long)time(nullptr)) + "_" + std::to_string(++seq);
}

static std::unique_ptr<PgConnection> lite_connect() {
	std::unique_ptr<PgConnection> c(new PgConnection(QUIET_TIMEOUT_MS));
	try {
		c->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	} catch (const std::exception& e) {
		diag("pg_lite connect failed: %s", e.what());
		return nullptr;
	}
	return c;
}

/**
 * @brief The connection is still in step: a simple query gets its rows and one ReadyForQuery.
 */
static void check_usable(PgConnection& c, const char* what) {
	c.sendQuery("SELECT 1");
	const std::string seq = drain(c);
	ok(seq == "TDCZ", "%s: a simple query afterwards works (got '%s')", what, seq.c_str());
}

static void run_cases() {
	// 1. Parse + Describe + Flush, then Bind + Execute + Sync: what postgres.js sends for a
	//    query with a string parameter.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT $1::text");
		send_describe_statement(*c);
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P D H -> '%s'", seq.c_str());
		ok(seq == "1tT", "P/D/H: ParseComplete, ParameterDescription, RowDescription, no ReadyForQuery (got '%s')", seq.c_str());
		send_bind(*c, { "hello" });
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		diag("B E S -> '%s'", seq.c_str());
		ok(seq == "2DCZ", "then B/E/S: BindComplete, DataRow, CommandComplete, ReadyForQuery (got '%s')", seq.c_str());
		check_usable(*c, "P/D/H then B/E/S");
	}

	// 2. A Parse that fails under Flush: one error, no ReadyForQuery until the client's Sync,
	//    and what the client sends before that Sync is discarded.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELEC $1");
		send_describe_statement(*c);
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P(bad) D H -> '%s'", seq.c_str());
		ok(seq == "E", "failing P/D/H: one ErrorResponse, no ReadyForQuery (got '%s')", seq.c_str());
		send_bind(*c, { "x" });
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		diag("B E S -> '%s'", seq.c_str());
		ok(count(seq, 'E') == 0, "then B/E/S: discarded, no further ErrorResponse (got '%s')", seq.c_str());
		ok(seq == "Z", "then B/E/S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		check_usable(*c, "failing P/D/H");
	}

	// 3. The second queued message fails: the first one's reply still goes out.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT 1");
		send_parse(*c, "SELEC $1");
		send_describe_statement(*c);
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P P(bad) D H -> '%s'", seq.c_str());
		ok(seq == "1E", "P/P(bad)/D/H: ParseComplete then one ErrorResponse, no ReadyForQuery (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
	}

	// 4. Flush with nothing queued.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_flush(*c);
		std::string seq = drain(*c);
		ok(seq.empty(), "H alone: no reply (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
	}

	// 5. Flush after Execute (a cursor fetching a few rows at a time) is not supported. It must
	//    fail like any other error, and leave the connection in step.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT g FROM generate_series(1, 10) g");
		send_describe_statement(*c);
		send_bind(*c, {});
		send_execute(*c, 3);
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P D B E(3) H -> '%s'", seq.c_str());
		ok(count(seq, 'E') == 1, "P/D/B/E/H: one ErrorResponse (got '%s')", seq.c_str());
		ok(count(seq, 'Z') == 0, "P/D/B/E/H: no ReadyForQuery before the client's Sync (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		check_usable(*c, "P/D/B/E/H");
	}

	// 6. Named statement: Parse + Describe + Flush, then the statement is used, then closed with
	//    Close + Flush. The Close is answered by ProxySQL alone, so this Flush frame completes
	//    without the backend.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT $1::text || 'x'", "flush_stmt");
		send_describe_statement(*c, "flush_stmt");
		send_flush(*c);
		std::string seq = drain(*c);
		ok(seq == "1tT", "named P/D/H: ParseComplete, ParameterDescription, RowDescription (got '%s')", seq.c_str());
		send_bind(*c, { "a" }, "flush_stmt");
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "2DCZ", "then named B/E/S: BindComplete, DataRow, CommandComplete, ReadyForQuery (got '%s')", seq.c_str());
		send_close(*c, 'S', "flush_stmt");
		send_flush(*c);
		seq = drain(*c);
		diag("C(S) H -> '%s'", seq.c_str());
		ok(seq == "3", "then C(S)/H: CloseComplete, no ReadyForQuery (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		send_bind(*c, { "a" }, "flush_stmt");
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "EZ", "then B/E/S: the statement is closed, ErrorResponse + ReadyForQuery (got '%s')", seq.c_str());
	}

	// 7. Parse + Bind + Flush, then Execute + Sync: the Bind must outlive the Flush. Run twice on
	//    one connection: the first Parse goes to the backend, the second is answered by ProxySQL
	//    itself (the statement is known), so the whole Flush frame completes without the backend.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		for (int round = 1; round <= 2; round++) {
			send_parse(*c, "SELECT $1::text || '_flush_bind'");
			send_bind(*c, { "kept" });
			send_flush(*c);
			std::string seq = drain(*c);
			diag("round %d: P B H -> '%s'", round, seq.c_str());
			ok(seq == "12", "round %d: P/B/H: ParseComplete, BindComplete, no ReadyForQuery (got '%s')", round, seq.c_str());
			send_execute(*c);
			c->sendSync();
			std::vector<std::string> rows {};
			seq = drain(*c, &rows);
			diag("round %d: E S -> '%s'", round, seq.c_str());
			ok(seq == "DCZ", "round %d: then E/S: DataRow, CommandComplete, ReadyForQuery (got '%s')", round, seq.c_str());
			ok(rows.size() == 1 && rows[0] == "kept_flush_bind",
				"round %d: then E/S: runs the Bind sent before the Flush (got '%s')", round, rows.empty() ? "" : rows[0].c_str());
		}
	}

	// 8. Parse + Bind + Flush, then a replacement Bind + Execute + Sync: the later Bind wins.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT $1::text || '_replaced'");
		send_bind(*c, { "first" });
		send_flush(*c);
		std::string seq = drain(*c);
		ok(seq == "12", "P/B/H: ParseComplete, BindComplete (got '%s')", seq.c_str());
		send_bind(*c, { "second" });
		send_execute(*c);
		c->sendSync();
		std::vector<std::string> rows {};
		seq = drain(*c, &rows);
		ok(seq == "2DCZ", "then B/E/S: BindComplete, DataRow, CommandComplete, ReadyForQuery (got '%s')", seq.c_str());
		ok(rows.size() == 1 && rows[0] == "second_replaced",
			"then B/E/S: runs the replacement Bind (got '%s')", rows.empty() ? "" : rows[0].c_str());
	}

	// 9. Parse + Bind + Flush, then Sync: the Sync ends the unnamed portal, so a later Execute
	//    finds no portal, as on PostgreSQL.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT $1::text || '_synced'");
		send_bind(*c, { "x" });
		send_flush(*c);
		std::string seq = drain(*c);
		ok(seq == "12", "P/B/H: ParseComplete, BindComplete (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "EZ", "then E/S: portal does not exist, ErrorResponse + ReadyForQuery (got '%s')", seq.c_str());
	}

	// 10. Parse + Bind + Flush, then a simple Query: it ends the unnamed portal too.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELECT $1::text || '_query'");
		send_bind(*c, { "x" });
		send_flush(*c);
		std::string seq = drain(*c);
		ok(seq == "12", "P/B/H: ParseComplete, BindComplete (got '%s')", seq.c_str());
		check_usable(*c, "P/B/H then Q");
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "EZ", "then E/S: portal does not exist, ErrorResponse + ReadyForQuery (got '%s')", seq.c_str());
	}

	// 11. Two Parses of one named statement, then Flush: the second fails in ProxySQL itself while
	//     the first is on its way to the backend. The error goes to the backend in the same batch,
	//     which ends in the Sync added for the Flush; its ReadyForQuery must not reach the client,
	//     whose own Sync gets exactly one. The text is new on every run so that the first Parse
	//     really goes to the backend instead of being answered from the statement cache.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		const std::string query = unique_text("SELECT 1");
		send_parse(*c, query.c_str(), "flush_dup");
		send_parse(*c, query.c_str(), "flush_dup");
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P P(same name) H -> '%s'", seq.c_str());
		ok(seq == "1E", "P/P(same name)/H: ParseComplete then one ErrorResponse, no ReadyForQuery (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		check_usable(*c, "P/P(same name)/H");
	}

	// 12. A batch cut short without a Sync: a Parse ProxySQL must run on its own (SET) stops the
	//     batch, which goes out ending in a Flush. The backend fails the Parse before it, so the
	//     connection sends a Sync to end the batch; that Sync's ReadyForQuery must not reach the
	//     client either.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		send_parse(*c, "SELEC 1");
		send_parse(*c, "SET application_name = 'flush_cut'");
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P(bad) P(SET) H -> '%s'", seq.c_str());
		ok(seq == "E", "P(bad)/P(SET)/H: one ErrorResponse, no ReadyForQuery (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		check_usable(*c, "P(bad)/P(SET)/H");
	}

	// 13. Close of the unnamed portal queued before Flush, behind a Parse that goes to the backend:
	//     its CloseComplete follows the backend's ParseComplete, and it ends the Bind kept across
	//     the Flush. The statement stays, which tells the Execute's error apart from a lost one.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		const std::string query = unique_text("SELECT $1::text");
		send_parse(*c, query.c_str());
		send_bind(*c, { "x" });
		send_close(*c, 'P');
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P B C(P) H -> '%s'", seq.c_str());
		ok(seq == "123", "P/B/C(P)/H: ParseComplete, BindComplete, CloseComplete, no ReadyForQuery (got '%s')", seq.c_str());
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "EZ", "then E/S: the portal is closed, ErrorResponse + ReadyForQuery (got '%s')", seq.c_str());
		send_bind(*c, { "y" });
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "2DCZ", "then B/E/S: the statement is still there (got '%s')", seq.c_str());
	}

	// 14. Close of a named statement queued before Flush, behind its own Parse going to the backend:
	//     the CloseComplete follows the ParseComplete, and the statement is gone afterwards.
	{
		auto c = lite_connect();
		if (!c) BAIL_OUT("Cannot connect to ProxySQL");
		const std::string query = unique_text("SELECT 1");
		send_parse(*c, query.c_str(), "flush_close");
		send_close(*c, 'S', "flush_close");
		send_flush(*c);
		std::string seq = drain(*c);
		diag("P C(S) H -> '%s'", seq.c_str());
		ok(seq == "13", "P/C(S)/H: ParseComplete, CloseComplete, no ReadyForQuery (got '%s')", seq.c_str());
		c->sendSync();
		seq = drain(*c);
		ok(seq == "Z", "then S: exactly one ReadyForQuery (got '%s')", seq.c_str());
		send_bind(*c, {}, "flush_close");
		send_execute(*c);
		c->sendSync();
		seq = drain(*c);
		ok(seq == "EZ", "then B/E/S: the statement is closed, ErrorResponse + ReadyForQuery (got '%s')", seq.c_str());
	}
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(47);

	try {
		run_cases();
	} catch (const std::exception& e) {
		// drain() only takes a quiet socket for the end of a reply: a closed, broken or corrupted
		// connection is a failure of the case that was running, never a pass.
		diag("Connection failure: %s", e.what());
		return EXIT_FAILURE;
	}

	return exit_status();
}
