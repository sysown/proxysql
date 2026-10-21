/**
 * Regression #6375: retry an unanswered native operation while preserving the
 * remaining extended frame. A relation lock makes the offline event deterministic.
 * Transactions and earlier unsynced operations must refuse replay with FATAL 57P01.
 *
 * A completed Sync is an independent boundary: the multi-Sync case consumes the
 * first batch's reply and verifies its INSERT happens exactly once when the next
 * batch retries. This refines the issue's proposed blanket pipeline refusal:
 * only the current retained operation is replayed, never earlier completed batches.
 * libpq's existing stricter in-flight pipeline guard is intentionally unchanged.
 * A buffered CommandComplete must prevent replay in either driver, including
 * disconnects before ReadyForQuery and backend shutdown errors.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "pgsql_mock_backend.h"
#include "pgsql_native_tier.h"
#include "tap.h"
#include <arpa/inet.h>
#include <cstdlib>
#include <netdb.h>
#include <string>
#include <unistd.h>

static CommandLine cl;
static PGconn *connect(const char *host, int port, const char *user, const char *pass) {
	std::string s = "host=" + std::string(host) + " port=" + std::to_string(port) + " user=" + user +
					" password=" + pass + " sslmode=disable connect_timeout=5";
	PGconn *c = PQconnectdb(s.c_str());
	if (PQstatus(c) != CONNECTION_OK)
		BAIL_OUT("connect: %s", PQerrorMessage(c));
	return c;
}
static std::string value(PGconn *c, const std::string &q) {
	PGresult *r = PQexec(c, q.c_str());
	if (PQresultStatus(r) != PGRES_TUPLES_OK && PQresultStatus(r) != PGRES_COMMAND_OK)
		BAIL_OUT("query '%s': %s", q.c_str(), PQresultErrorMessage(r));
	std::string s = PQntuples(r) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return s;
}
static bool wait_locked(PGconn *db) {
	for (int i = 0; i < 500; i++) {
		if (value(
				db,
				"SELECT count(*) FROM pg_locks WHERE relation='issue6375_lock'::regclass AND NOT granted") !=
			"0")
			return true;
		usleep(10000);
	}
	return false;
}
int main() {
	alarm(120);
	plan(69);
	if (cl.getEnv())
		return exit_status();
	PGconn *admin = connect(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password);
	if (!pgsql_native_supported(admin)) {
		skip(69, "native backend protocol is unavailable");
		PQfinish(admin);
		return exit_status();
	}
	const std::string oldretries = value(
		admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_retries_on_failure'");
	value(admin, "SET pgsql-query_retries_on_failure='1'");
	const std::string host = value(admin, "SELECT hostname FROM pgsql_servers ORDER BY hostgroup_id LIMIT 1");
	const int port =
		atoi(value(admin, "SELECT port FROM pgsql_servers ORDER BY hostgroup_id LIMIT 1").c_str());
	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo *resolved = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &resolved) != 0 || !resolved)
		BAIL_OUT("resolve backend");
	char address[INET_ADDRSTRLEN]{};
	inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(resolved->ai_addr)->sin_addr, address,
			  sizeof(address));
	freeaddrinfo(resolved);
	std::string alias = address;
	if (alias == host) {
		// An IPv4 integer literal resolves to the same endpoint under getaddrinfo
		// while supplying a distinct ProxySQL pool key.
		in_addr numeric{};
		inet_pton(AF_INET, host.c_str(), &numeric);
		alias = std::to_string(ntohl(numeric.s_addr));
	}

	PGconn *db = connect(host.c_str(), port, cl.pgsql_username, cl.pgsql_password);
	value(db, "CREATE TABLE IF NOT EXISTS issue6375_lock (id integer)");
	value(db, "CREATE TABLE IF NOT EXISTS issue6375_effects (marker text)");
	const std::string oldmode = value(admin, "SELECT variable_value FROM global_variables WHERE "
											 "variable_name='pgsql-use_native_backend_protocol'");
	value(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=6375");
	value(admin, "INSERT INTO pgsql_servers(hostgroup_id,hostname,port,status) VALUES(6375,'" + host + "'," +
					 std::to_string(port) + ",'ONLINE'),(6375,'" + alias + "'," + std::to_string(port) +
					 ",'OFFLINE_HARD')");
	value(
		admin,
		"INSERT OR REPLACE INTO pgsql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) "
		"VALUES(6375,1,'issue6375',6375,1)");
	value(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	for (bool native : {true, false}) {
		value(admin,
			  std::string("SET pgsql-use_native_backend_protocol='") + (native ? "true" : "false") + "'");
		value(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		for (int scenario = 0; scenario < 6; scenario++) {
			value(admin, "UPDATE pgsql_servers SET status=CASE WHEN hostname='" + host +
							 "' THEN 'ONLINE' ELSE 'OFFLINE_HARD' END WHERE hostgroup_id=6375");
			value(admin, "LOAD PGSQL SERVERS TO RUNTIME");
			PGconn *c = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
			const std::string marker = "issue6375_pid" + std::to_string(getpid()) + "_mode" +
									   std::to_string(native) + "_case" + std::to_string(scenario);
			if (scenario == 1)
				value(c, "BEGIN /* issue6375 */");
			const std::string query = "SELECT * FROM issue6375_lock /* " + marker + " */";
			if (scenario == 4) {
				PGresult *prepared = PQprepare(c, "second", query.c_str(), 0, nullptr);
				if (PQresultStatus(prepared) != PGRES_COMMAND_OK)
					BAIL_OUT("prepare before Execute failed");
				PQclear(prepared);
			}
			value(db, "BEGIN");
			value(db, "LOCK issue6375_lock IN ACCESS EXCLUSIVE MODE");
			if (scenario == 2) {
				// Two statements run in one frame: the first may have run before the second waits on
				// the lock, so the frame must not be replayed.
				if (!PQenterPipelineMode(c) ||
					!PQsendQueryParams(c, ("SELECT 1 /* " + marker + "_first */").c_str(), 0, nullptr, nullptr,
									   nullptr, nullptr, 0) ||
					!PQsendQueryParams(c, query.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0) ||
					!PQpipelineSync(c))
					BAIL_OUT("pipeline send failed");
			} else if (scenario == 3) {
				// The held operation is first: its remaining frame must survive the retry.
				if (!PQenterPipelineMode(c) || !PQsendPrepare(c, "second", query.c_str(), 0, nullptr) ||
					!PQsendPrepare(c, "after", ("SELECT 1 /* " + marker + "_after */").c_str(), 0, nullptr) ||
					!PQpipelineSync(c))
					BAIL_OUT("pipeline send failed");
			} else if (scenario == 5) {
				// Both Sync batches are queued before receiving the first answer.
				// A retry of the second must never repeat the first INSERT.
				const std::string effect =
					"INSERT INTO issue6375_effects VALUES ('" + marker + "') RETURNING 1";
				if (!PQenterPipelineMode(c) ||
					!PQsendQueryParams(c, effect.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0) ||
					!PQpipelineSync(c) || !PQsendPrepare(c, "second", query.c_str(), 0, nullptr) ||
					!PQpipelineSync(c))
					BAIL_OUT("multi-Sync pipeline send failed");
			} else if (scenario == 4) {
				if (!PQsendQueryPrepared(c, "second", 0, nullptr, nullptr, nullptr, 0))
					BAIL_OUT("Execute send failed");
			} else if (!PQsendPrepare(c, "second", query.c_str(), 0, nullptr))
				BAIL_OUT("prepare send failed");
			PQflush(c);
			bool earlier_answered = false;
			if (scenario == 5) {
				bool synced = false;
				while (!synced && PQstatus(c) == CONNECTION_OK) {
					PGresult *first = PQgetResult(c);
					if (!first)
						continue;
					synced = PQresultStatus(first) == PGRES_PIPELINE_SYNC;
					if (PQresultStatus(first) == PGRES_TUPLES_OK && PQntuples(first) == 1)
						earlier_answered = std::string(PQgetvalue(first, 0, 0)) == "1";
					PQclear(first);
				}
				earlier_answered = earlier_answered && synced;
			}
			const bool locked = wait_locked(db);
			ok(locked, "mode=%s scenario=%d: operation reached S1 and waits for relation lock",
			   native ? "native" : "libpq", scenario);
			value(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=6375");
			value(admin, "LOAD PGSQL SERVERS TO RUNTIME");
			const long target_before =
				atol(value(admin, "SELECT COALESCE(SUM(Queries),0) FROM stats_pgsql_connection_pool WHERE "
								  "hostgroup=6375 AND srv_host='" +
									  alias + "'")
						 .c_str());
			value(admin, "UPDATE pgsql_servers SET status=CASE WHEN hostname='" + host +
							 "' THEN 'OFFLINE_HARD' ELSE 'ONLINE' END WHERE hostgroup_id=6375");
			value(admin, "LOAD PGSQL SERVERS TO RUNTIME");
			// The proxy polls the in-flight backend and processes its OFFLINE_HARD status
			// before the lock is released. Wait on its public counter, not a guessed delay.
			for (int i = 0; i < 100; i++) {
				if (value(admin, "SELECT COALESCE(SUM(ConnUsed),0) FROM stats_pgsql_connection_pool WHERE "
								 "hostgroup=6375 AND srv_host='" +
									 host + "'") == "0")
					break;
				usleep(10000);
			}
			value(db, "COMMIT");
			PGresult *r = PQgetResult(c);
			if (scenario == 5 && !r)
				r = PQgetResult(c);
			if (scenario == 2 && r && PQresultStatus(r) == PGRES_TUPLES_OK) {
				PQclear(r);
				r = PQgetResult(c);
				if (!r)
					r = PQgetResult(c);
			}
			const bool retry = native && (scenario == 0 || scenario == 3 || scenario == 4 || scenario == 5);
			const char *state = r ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : nullptr;
			ok(retry ? r && PQresultStatus(r) == (scenario == 4 ? PGRES_TUPLES_OK : PGRES_COMMAND_OK)
					 : state && std::string(state) == "57P01",
			   "mode=%s scenario=%d: %s (state=%s error=%s)", native ? "native" : "libpq", scenario,
			   retry ? "unanswered operation retried" : "retry refused with admin_shutdown",
			   state ? state : "none", r ? PQresultErrorMessage(r) : PQerrorMessage(c));
			const char *severity = r ? PQresultErrorField(r, PG_DIAG_SEVERITY) : nullptr;
			ok(retry ? PQstatus(c) == CONNECTION_OK : severity && std::string(severity) == "FATAL",
			   "mode=%s scenario=%d: %s", native ? "native" : "libpq", scenario,
			   retry ? "client remains usable" : "client receives FATAL before close");
			PQclear(r);
			const long target_after =
				atol(value(admin, "SELECT COALESCE(SUM(Queries),0) FROM stats_pgsql_connection_pool WHERE "
								  "hostgroup=6375 AND srv_host='" +
									  alias + "'")
						 .c_str());
			ok(retry ? target_after > target_before : target_after == target_before,
			   "mode=%s scenario=%d: %s", native ? "native" : "libpq", scenario,
			   retry ? "retry ran on S2" : "no replay on S2");
			if (retry) {
				bool remainder_ok = true;
				if (scenario == 3 || scenario == 5) {
					bool synced = false;
					int completed = 0;
					while (!synced && PQstatus(c) == CONNECTION_OK) {
						r = PQgetResult(c);
						if (!r)
							continue;
						synced = PQresultStatus(r) == PGRES_PIPELINE_SYNC;
						if (PQresultStatus(r) == PGRES_COMMAND_OK)
							completed++;
						else if (!synced)
							remainder_ok = false;
						PQclear(r);
					}
					remainder_ok = remainder_ok && synced && completed == (scenario == 3 ? 1 : 0) &&
								   PQexitPipelineMode(c);
				} else {
					while ((r = PQgetResult(c)))
						PQclear(r);
				}
				r = PQexecPrepared(c, "second", 0, nullptr, nullptr, nullptr, 0);
				ok(remainder_ok && r && PQresultStatus(r) == PGRES_TUPLES_OK,
				   "frame remainder completed and retried statement executes on the new backend");
				PQclear(r);
			} else {
				while ((r = PQgetResult(c)))
					PQclear(r);
				for (int i = 0; i < 100 && PQstatus(c) == CONNECTION_OK; ++i) {
					PQconsumeInput(c);
					usleep(10000);
				}
				ok(PQstatus(c) == CONNECTION_BAD, "fatal refusal closes the connection after its error");
			}
			if (scenario == 5) {
				const std::string effects =
					value(db, "SELECT count(*) FROM issue6375_effects WHERE marker='" + marker + "'");
				ok(earlier_answered && effects == "1",
				   "mode=%s: earlier Sync reply was consumed and its INSERT happened exactly once",
				   native ? "native" : "libpq");
			}
			PQfinish(c);
		}
	}
	// A completed command is no longer an unanswered operation, even while its
	// small response remains buffered and ReadyForQuery has not arrived. The
	// scriptable peer makes the completion/disconnect ordering deterministic;
	// PostgreSQL itself cannot be asked to omit its ReadyForQuery on demand.
	const std::string oldmonitor = value(admin, "SELECT variable_value FROM global_variables WHERE "
											 "variable_name='pgsql-monitor_enabled'");
	value(admin, "SET pgsql-monitor_enabled='false'");
	for (bool native : {true, false}) {
		value(admin,
			  std::string("SET pgsql-use_native_backend_protocol='") + (native ? "true" : "false") + "'");
		value(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		for (int scenario = 0; scenario < 3; ++scenario) {
			PgSQL_Mock_Backend mock;
			if (!mock.start())
				BAIL_OUT("completion mock could not listen");
			std::vector<Step> script = pgmb_script_accept_trust();
			script.push_back(step_expect_query());
			// The unanswered control must still retry: observing a send alone
			// does not prove that the backend completed the current operation.
			const bool completed = scenario != 2;
			std::string reply = completed ? pgmb_command_complete("INSERT 0 1") : "";
			if (scenario != 0)
				reply += pgmb_error_response("57P01", "shutdown after command") + pgmb_ready_for_query('I');
			script.push_back(step_send(reply));
			if (scenario == 0)
				script.push_back(step_close());
			else
				// Leave the socket usable so the error-code retry branch runs.
				script.push_back(step_expect_message());
			mock.set_script(script);
			const std::string mockhost = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
			if (mockhost.empty())
				BAIL_OUT("cannot discover mock address");
			value(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=6375");
			value(admin, "INSERT INTO pgsql_servers(hostgroup_id,hostname,port) VALUES(6375,'" +
						 mockhost + "'," + std::to_string(mock.port()) + ")");
			value(admin, "LOAD PGSQL SERVERS TO RUNTIME");
			PGconn *c = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password);
			PGresult *r = PQexec(c, "INSERT INTO issue6375_effects VALUES ('completion_boundary')");
			const int expected = completed ? 1 : 2;
			ok(mock.queries_observed() == expected,
			   "mode=%s completion scenario=%d: %s (backend executions=%d, expected=%d)",
			   native ? "native" : "libpq", scenario,
			   completed ? "CommandComplete prevents replay" : "unanswered operation still retries",
			   mock.queries_observed(), expected);
			PQclear(r);
			PQfinish(c);
			mock.stop();
		}
	}
	const std::string old_ping_interval = value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-monitor_ping_interval'");
	const std::string ping_counter_query =
		"SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='PgSQL_Monitor_ping_check_OK'";
	const long pings_before_restore = std::stol(value(admin, ping_counter_query));
	// Bound the restoration check independently of the suite's normal interval.
	if (oldmonitor == "true")
		value(admin, "SET pgsql-monitor_ping_interval=100");
	value(admin, "SET pgsql-monitor_enabled='" + oldmonitor + "'");
	value(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=6375");
	value(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=6375");
	value(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	value(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	value(admin, "SET pgsql-use_native_backend_protocol='" + oldmode + "'");
	value(admin, "SET pgsql-query_retries_on_failure='" + oldretries + "'");
	value(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (oldmonitor == "true") {
		bool resumed = false;
		for (int i = 0; i < 100; ++i) {
			if (std::stol(value(admin, ping_counter_query)) > pings_before_restore) {
				resumed = true;
				break;
			}
			usleep(100000);
		}
		ok(resumed, "restoring monitor_enabled resumes successful monitoring checks (#6389)");
		value(admin, "SET pgsql-monitor_ping_interval='" + old_ping_interval + "'");
		value(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	} else {
		skip(1, "monitoring was disabled before this test");
	}
	value(db, "DROP TABLE issue6375_lock");
	value(db, "DROP TABLE issue6375_effects");
	PQfinish(db);
	PQfinish(admin);
	return exit_status();
}
