/**
 * @file pgsql-init_connect_mock-t.cpp
 * @brief A backend that drops the connection while init_connect runs: ProxySQL retries.
 *
 * A real PostgreSQL cannot be told to vanish exactly while init_connect is in flight, so a
 * scripted mock (pgsql_mock_backend.h) does it. The first connection reads the init_connect
 * statement and closes; the client's query must then succeed on a second connection, in
 * native and libpq backend mode. v3.1+ (PROXYSQL31).
 *
 * The monitor is disabled for the duration: its probes would connect to the mock too.
 *
 * State touched (restored on exit): hostgroup 6700 in pgsql_servers and
 * pgsql_hostgroup_attributes, pgsql_query_rules rule_id 6700, 'pgsql-monitor_enabled',
 * 'pgsql-use_native_backend_protocol'.
 */

#include "pgsql_init_connect_common.h"
#include "pgsql_mock_backend.h"

#include <unistd.h>
#include <string>
#include <vector>

CommandLine cl;

static constexpr int kHg = 6700;
static const char* const kQuery = "SELECT 'ic_mock_query'";   // routed to kHg by match_pattern

static std::string global_value(PGconn* admin, const char* name) {
	return ic_admin_value(admin, std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'");
}

static void set_global(PGconn* admin, const char* name, const std::string& value) {
	ic_admin(admin, std::string("UPDATE global_variables SET variable_value=") + ic_literal(value) +
		" WHERE variable_name='" + name + "'");
	ic_admin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static void run_mode(PGconn* admin, bool native) {
	set_global(admin, "pgsql-use_native_backend_protocol", native ? "true" : "false");

	PgSQL_Mock_Backend mock;
	if (!mock.start()) BAIL_OUT("mock backend could not listen");
	const std::string mockhost = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
	if (mockhost.empty()) BAIL_OUT("cannot discover the mock's address");

	// First connection: read the init_connect statement, then go away.
	std::vector<Step> drop = pgmb_script_accept_trust();
	drop.push_back(step_expect_query(true));
	drop.push_back(step_sleep(300));   // time to install the second script
	drop.push_back(step_close());
	// Second connection: acknowledge init_connect (and any SET), answer the client's query.
	std::vector<Step> answer = pgmb_script_accept_trust();
	answer.push_back(step_expect_query());
	answer.push_back(step_send(pgmb_simple_result("v", "retried", 1)));
	answer.push_back(step_expect_message());
	mock.set_script(drop);

	ic_admin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(kHg));
	ic_admin(admin, "INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(" + std::to_string(kHg) +
		",'" + mockhost + "'," + std::to_string(mock.port()) + ")");
	ic_admin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	mock.reset_stats();

	PGConnPtr client = ic_connect_client(cl);
	PGconn* c = client.get();
	const unsigned long long start = monotonic_time();
	if (!PQsendQuery(c, kQuery)) diag("PQsendQuery failed: %s", PQerrorMessage(c));
	for (int i = 0; i < 500 && mock.connections_accepted() < 1; i++) usleep(10000);
	mock.set_script(answer);
	const IcResult r = ic_wait(c, 10000, start);

	ok(!r.timed_out && r.ok && r.value == "retried",
	   "[native=%d] query succeeds after the backend dropped during init_connect (got '%s')%s",
	   native, r.value.c_str(), r.ok ? "" : mock.last_error().c_str());
	ok(mock.connections_accepted() == 2,
	   "[native=%d] ProxySQL retried on a new connection (%d connections)", native, mock.connections_accepted());

	client.reset();
	ic_admin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(kHg));
	ic_admin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	mock.stop();
}

int main(int, char**) {
	alarm(120);
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}
	PGConnPtr admin_conn = ic_connect_admin(cl);
	PGconn* admin = admin_conn.get();
	if (PQstatus(admin) != CONNECTION_OK) return exit_status();
	plan(4);
	if (!ic_is_v31(admin)) {
		skip(4, "init_connect needs ProxySQL v3.1+");
		return exit_status();
	}

	const std::string orig_monitor = global_value(admin, "pgsql-monitor_enabled");
	const std::string orig_native = global_value(admin, "pgsql-use_native_backend_protocol");
	set_global(admin, "pgsql-monitor_enabled", "false");
	ic_admin(admin, "INSERT OR REPLACE INTO pgsql_hostgroup_attributes(hostgroup_id, init_connect) VALUES(" +
		std::to_string(kHg) + ", 'SET ic.marker TO ''mock''')");
	ic_admin(admin, "INSERT OR REPLACE INTO pgsql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) "
		"VALUES(6700,1,'ic_mock_query'," + std::to_string(kHg) + ",1)");
	ic_admin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	for (bool native : {true, false}) run_mode(admin, native);

	ic_admin(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=6700");
	ic_admin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	ic_admin(admin, "DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=" + std::to_string(kHg));
	ic_admin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	set_global(admin, "pgsql-use_native_backend_protocol", orig_native);
	set_global(admin, "pgsql-monitor_enabled", orig_monitor);
	return exit_status();
}
