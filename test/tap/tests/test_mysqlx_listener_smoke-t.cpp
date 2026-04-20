/**
 * test_mysqlx_listener_smoke-t.cpp
 *
 * Verify that the mysqlx plugin opens TCP listeners when started with
 * active routes, and that plain TCP connections succeed.
 *
 * This is a hybrid unit test: it links against libproxysql.a and loads
 * the mysqlx plugin .so without a running ProxySQL daemon.
 *
 * Stub implementations are provided for session/config/stats symbols
 * referenced by MysqlxWorker::run() so that only mysqlx_worker.cpp
 * needs to be compiled directly.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"

#include "mysqlx_config_store.h"
#include "mysqlx_frontend_session.h"
#include "mysqlx_backend_session.h"
#include "mysqlx_plugin.h"
#include "mysqlx_stats.h"
#include "mysqlx_protocol.h"

#ifndef PROXYSQL_MYSQLX_PLUGIN_PATH
#error "PROXYSQL_MYSQLX_PLUGIN_PATH must be defined at compile time"
#endif

static const uint16_t TEST_MYSQLX_PORT = 16603;
static const uint16_t TEST_MYSQLX_PORT_A = 46101;
static const uint16_t TEST_MYSQLX_PORT_B = 46102;

extern bool mysqlx_start_listeners_from_runtime_routes(SQLite3DB& db);
extern size_t mysqlx_listener_count();
extern void mysqlx_stop_listeners();

static bool seed_route(SQLite3DB& db, const char* name, const char* bind, int hg) {
	char sql[256];
	snprintf(sql, sizeof(sql),
		"INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
		"VALUES ('%s', '%s', %d, 'first_available', 1)",
		name, bind, hg);
	return db.execute(sql);
}

// ---------------------------------------------------------------------------
// Stub implementations for symbols referenced by MysqlxWorker::run().
// The smoke test only verifies listener lifecycle and TCP connectivity;
// it does not exercise the X Protocol session path.
// ---------------------------------------------------------------------------

MysqlxFrontendSession::MysqlxFrontendSession(int fd) : client_fd_(fd) {}
MysqlxFrontendSession::~MysqlxFrontendSession() { if (client_fd_ >= 0) close(client_fd_); }
bool MysqlxFrontendSession::run_handshake_and_auth(MysqlxConfigStore&) { return false; }

MysqlxBackendSession::MysqlxBackendSession() = default;
MysqlxBackendSession::~MysqlxBackendSession() = default;
bool MysqlxBackendSession::connect(const MysqlxResolvedIdentity&, const MysqlxBackendEndpoint&, std::string&) { return false; }
bool MysqlxBackendSession::relay(int) { return false; }

static MysqlxPluginContext g_stub_context {};
MysqlxPluginContext& mysqlx_context() { return g_stub_context; }

static MysqlxStatsStore g_stub_stats;
MysqlxStatsStore& mysqlx_stats() { return g_stub_stats; }
void MysqlxStatsStore::record_conn_ok(const std::string&, int) {}
void MysqlxStatsStore::record_conn_err(const std::string&, int) {}
void MysqlxStatsStore::record_conn_used(const std::string&, int) {}

uint64_t MysqlxConfigStore::topology_generation() const { return 0; }
MysqlxBackendEndpoint MysqlxConfigStore::pick_endpoint(const std::string&) const { return {}; }
int MysqlxConfigStore::route_hostgroup(const std::string&) const { return 0; }

// Stub Mysqlx_Thread dtor so the vector<unique_ptr<Mysqlx_Thread>> in
// MysqlxPluginContext (g_stub_context) compiles its destructor even
// though we never link mysqlx_thread.cpp.  The vector is empty in the
// stub context so this never actually runs, but the compiler still
// emits the unique_ptr deleter template.
Mysqlx_Thread::~Mysqlx_Thread() {}

bool mysqlx_send_error(int, uint16_t, const std::string&, const std::string&) { return false; }

int main() {
	plan(16);

	ProxySQL_PluginManager mgr;
	std::string err {};

	ok(mgr.load(PROXYSQL_MYSQLX_PLUGIN_PATH, err),
	   "load mysqlx plugin succeeds: %s", err.c_str());

	SQLite3DB admindb;
	int dbrc = admindb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(dbrc == 0, "admin sqlite opens");

	// Schema registration moved to register_schemas() (Phase B); init() now
	// only wires plugin context.
	ok(mgr.invoke_register_schemas_phase(err),
	   "register_schemas publishes mysqlx admin tables: %s", err.c_str());
	ok(mgr.init_all(err), "init_all completes after register_schemas: %s", err.c_str());

	admindb.execute(
		"CREATE TABLE IF NOT EXISTS runtime_mysqlx_routes ("
		" name VARCHAR NOT NULL PRIMARY KEY,"
		" bind VARCHAR NOT NULL,"
		" destination_hostgroup INT NOT NULL,"
		" fallback_hostgroup INT,"
		" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
		" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
		" attributes VARCHAR NOT NULL DEFAULT '',"
		" comment VARCHAR NOT NULL DEFAULT ''"
		" )"
	);

	// ok 4: No listeners before any start_listeners call.
	ok(mysqlx_listener_count() == 0, "listener count is 0 before any listeners start");

	// ok 5: Start with empty routes table.
	{
		bool rc = mysqlx_start_listeners_from_runtime_routes(admindb);
		ok(rc == true && mysqlx_listener_count() == 0,
		   "start with empty routes table: succeeds, count stays 0");
	}
	mysqlx_stop_listeners();

	// ok 6-10: Existing single-route test.
	ok(seed_route(admindb, "smoke_route", "127.0.0.1:16603", 0),
	   "seed route row");

	ok(mysqlx_start_listeners_from_runtime_routes(admindb),
	   "start_listeners_from_runtime_routes succeeds");
	ok(mysqlx_listener_count() == 1, "one listener opened");

	usleep(100000);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ok(fd >= 0, "client socket created");

	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TEST_MYSQLX_PORT);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	ok(rc == 0, "TCP connect to mysqlx listener on port %u succeeds", TEST_MYSQLX_PORT);
	close(fd);

	mysqlx_stop_listeners();

	// ok 11: Count drops to 0 after stop.
	ok(mysqlx_listener_count() == 0, "count drops to 0 after stop");

	// ok 12: Re-start with two routes on different ports.
	admindb.execute("DELETE FROM runtime_mysqlx_routes");
	seed_route(admindb, "route_a", "127.0.0.1:46101", 1);
	seed_route(admindb, "route_b", "127.0.0.1:46102", 2);

	mysqlx_start_listeners_from_runtime_routes(admindb);
	usleep(100000);
	ok(mysqlx_listener_count() == 2, "re-start: two listeners on ports %u and %u",
	   TEST_MYSQLX_PORT_A, TEST_MYSQLX_PORT_B);

	// ok 13: TCP connect to first listener.
	{
		int fd2 = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons(TEST_MYSQLX_PORT_A);
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		int r = connect(fd2, reinterpret_cast<sockaddr*>(&a), sizeof(a));
		ok(r == 0, "TCP connect to listener on port %u succeeds", TEST_MYSQLX_PORT_A);
		close(fd2);
	}

	// ok 14: TCP connect to second listener.
	{
		int fd3 = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in b {};
		b.sin_family = AF_INET;
		b.sin_port = htons(TEST_MYSQLX_PORT_B);
		inet_pton(AF_INET, "127.0.0.1", &b.sin_addr);
		int r = connect(fd3, reinterpret_cast<sockaddr*>(&b), sizeof(b));
		ok(r == 0, "TCP connect to listener on port %u succeeds", TEST_MYSQLX_PORT_B);
		close(fd3);
	}

	// ok 15: Stop when already stopped.
	mysqlx_stop_listeners();
	mysqlx_stop_listeners();
	ok(mysqlx_listener_count() == 0, "stop when no listeners active: no crash, count stays 0");

	return exit_status();
}
