/**
 * @file reg_test_6421_parsersql_kill-t.cpp
 * @brief MySQL KILL [CONNECTION|QUERY] is intercepted identically with and without ParserSQL (#6421).
 *
 * ParserSQL has no statement type for KILL, so with
 * mysql-query_processor_parser=1 KILL was classified as UNKNOWN instead of
 * MYSQL_COM_QUERY_KILL. MySQL_Session did not intercept it and forwarded it to
 * a backend, where the ProxySQL session id returned by SELECT CONNECTION_ID()
 * is meaningless: the client got ERR 1094 (or an unrelated backend thread with
 * the same id was killed) and the targeted ProxySQL session kept running.
 *
 * For query_processor_parser=0 and =1 this test checks, through ProxySQL, that:
 * - KILL QUERY <id> succeeds and promptly interrupts a SELECT SLEEP() running
 *   on the target session, which stays usable;
 * - KILL <id> and KILL CONNECTION <id> succeed and close the target session;
 * - the statements are counted under KILL in stats_mysql_commands_counters.
 */
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

static constexpr int SLEEP_SECONDS = 30;
static constexpr double MAX_INTERRUPT_SECONDS = 10.0;

static bool execute(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return false;
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return true;
}

static std::string scalar(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return "";
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (!result) return "";
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}

static Connection connect_client(const CommandLine& cl) {
	Connection conn(mysql_init(nullptr), &mysql_close);
	if (conn && !mysql_real_connect(conn.get(), cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Client connection failed: %s", mysql_error(conn.get()));
		conn.reset();
	}
	return conn;
}

// Restore the saved variables even after an early return.
struct Fixture {
	MYSQL* admin;
	bool saved = false;
	explicit Fixture(MYSQL* conn) : admin(conn) {}
	Fixture(const Fixture&) = delete;
	Fixture& operator=(const Fixture&) = delete;
	Fixture(Fixture&&) = delete;
	Fixture& operator=(Fixture&&) = delete;
	bool restore() {
		if (!saved) return true;
		bool good = execute(admin, "UPDATE global_variables SET variable_value=(SELECT variable_value FROM kill6421_vars v "
			"WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM kill6421_vars)");
		good = execute(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && good;
		saved = !good;
		if (good) good = execute(admin, "DROP TABLE temp.kill6421_vars");
		return good;
	}
	~Fixture() noexcept {
		try {
			if (!restore()) std::fputs("KILL fixture cleanup failed\n", stderr);
		} catch (const std::exception& e) {
			std::fprintf(stderr, "KILL fixture cleanup failed: %s\n", e.what());
		} catch (...) {
			std::fputs("KILL fixture cleanup threw an unknown exception\n", stderr);
		}
	}
};

static bool configure(Fixture& fixture) {
	MYSQL* admin = fixture.admin;
	// Admin temporary tables live in the single shared admin SQLite handle and outlive client
	// disconnects; drop leftovers of an interrupted run (temp.-qualified: never touches main).
	if (!execute(admin, "DROP TABLE IF EXISTS temp.kill6421_vars") ||
		!execute(admin, "CREATE TEMPORARY TABLE kill6421_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('mysql-query_processor_parser','mysql-query_digests','mysql-commands_stats')")) return false;
	fixture.saved = true;
	// Both are required for KILL interception in either parser mode.
	return execute(admin, "SET mysql-query_digests=1") && execute(admin, "SET mysql-commands_stats=1");
}

static long long kill_counter(MYSQL* admin) {
	const auto count = scalar(admin, "SELECT COALESCE(SUM(Total_cnt),0) FROM stats_mysql_commands_counters WHERE Command='KILL'");
	return count.empty() ? -1 : std::atoll(count.c_str());
}

static unsigned long long session_id(MYSQL* conn) {
	const auto id = scalar(conn, "SELECT CONNECTION_ID()");
	return id.empty() ? 0ULL : std::strtoull(id.c_str(), nullptr, 10);
}

/**
 * True if @p conn is closed by ProxySQL within about five seconds. A killed
 * session is closed when its worker thread next processes it; a session parked
 * in an idle thread can still serve one query that arrives before that, so
 * probe a few times instead of expecting the first query to fail.
 */
static bool closed_soon(MYSQL* conn) {
	for (int i = 0; i < 10; i++) {
		usleep(500000);
		if (mysql_query(conn, "DO 1")) {
			diag("Session closed (%u): %s", mysql_errno(conn), mysql_error(conn));
			return true;
		}
	}
	return false;
}

static constexpr int CHECKS_PER_MODE = 12;

static void run_mode(const CommandLine& cl, MYSQL* admin, int parser) {
	const std::string mode = "parser=" + std::to_string(parser);
	const bool configured = execute(admin, "SET mysql-query_processor_parser=" + std::to_string(parser)) &&
		execute(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(configured, "%s: configured", mode.c_str());
	if (!configured) {
		skip(CHECKS_PER_MODE - 1, "%s: configuration failed", mode.c_str());
		return;
	}
	Connection killer = connect_client(cl);
	Connection target = connect_client(cl);
	Connection other = connect_client(cl);
	if (!killer || !target || !other) {
		ok(false, "%s: client connections opened", mode.c_str());
		skip(CHECKS_PER_MODE - 2, "%s: client connection failed", mode.c_str());
		return;
	}
	const unsigned long long target_id = session_id(target.get());
	const unsigned long long other_id = session_id(other.get());
	ok(target_id != 0 && target_id == mysql_thread_id(target.get()) && other_id != 0,
		"%s: CONNECTION_ID() returns the ProxySQL session id (target: %llu, other: %llu)",
		mode.c_str(), target_id, other_id);
	const long long kills_before = kill_counter(admin);

	// KILL QUERY interrupts a running query; the session stays usable.
	bool sleep_ok = false;
	double sleep_seconds = 0;
	std::thread sleeper([&]() {
		const auto start = std::chrono::steady_clock::now();
		sleep_ok = execute(target.get(), "SELECT SLEEP(" + std::to_string(SLEEP_SECONDS) + ")");
		sleep_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
	});
	sleep(2);
	const bool kill_query_ok = execute(killer.get(), "KILL QUERY " + std::to_string(target_id));
	sleeper.join();
	ok(kill_query_ok, "%s: KILL QUERY %llu succeeds (%u: %s)", mode.c_str(), target_id,
		mysql_errno(killer.get()), mysql_error(killer.get()));
	ok(sleep_seconds < MAX_INTERRUPT_SECONDS, "%s: SELECT SLEEP(%d) interrupted after %.1fs (completed: %d)",
		mode.c_str(), SLEEP_SECONDS, sleep_seconds, sleep_ok);
	ok(execute(target.get(), "DO 1"), "%s: session survives KILL QUERY", mode.c_str());

	// KILL <id> closes the target session.
	const bool kill_ok = execute(killer.get(), "KILL " + std::to_string(target_id));
	ok(kill_ok, "%s: KILL %llu succeeds (%u: %s)", mode.c_str(), target_id,
		mysql_errno(killer.get()), mysql_error(killer.get()));
	ok(closed_soon(target.get()), "%s: session closed by KILL", mode.c_str());

	// KILL CONNECTION <id> closes the target session.
	const bool kill_conn_ok = execute(killer.get(), "KILL CONNECTION " + std::to_string(other_id));
	ok(kill_conn_ok, "%s: KILL CONNECTION %llu succeeds (%u: %s)", mode.c_str(), other_id,
		mysql_errno(killer.get()), mysql_error(killer.get()));
	ok(closed_soon(other.get()), "%s: session closed by KILL CONNECTION", mode.c_str());
	ok(execute(killer.get(), "DO 1"), "%s: killing session is unaffected", mode.c_str());

	// Commands counters are aggregated periodically by the worker threads.
	long long kills_after = kill_counter(admin);
	for (int i = 0; i < 20 && kills_after - kills_before < 3; i++) {
		usleep(250000);
		kills_after = kill_counter(admin);
	}
	ok(kills_before >= 0 && kills_after - kills_before == 3,
		"%s: three statements counted under KILL (before: %lld, after: %lld)", mode.c_str(), kills_before, kills_after);
	ok(execute(killer.get(), "SELECT 1"), "%s: regular queries still work", mode.c_str());
}

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(1 + 2 * CHECKS_PER_MODE);
	Connection admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.host, cl.admin_username, cl.admin_password, nullptr,
		cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", admin ? mysql_error(admin.get()) : "mysql_init");
		return exit_status();
	}
	{
		Fixture fixture(admin.get());
		const bool configured = configure(fixture);
		ok(configured, "Fixture configured");
		if (!configured) {
			skip(2 * CHECKS_PER_MODE, "fixture configuration failed");
		} else {
			run_mode(cl, admin.get(), 0);
			run_mode(cl, admin.get(), 1);
		}
	}
	return exit_status();
}
