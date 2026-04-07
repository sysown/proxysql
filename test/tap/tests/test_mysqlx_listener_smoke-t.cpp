/**
 * test_mysqlx_listener_smoke-t.cpp
 *
 * Verify that the mysqlx plugin opens a TCP listener when started with
 * an active route, and that a plain TCP connection succeeds.
 *
 * This is a hybrid unit test: it links against libproxysql.a and loads
 * the mysqlx plugin .so without a running ProxySQL daemon.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"

#ifndef PROXYSQL_MYSQLX_PLUGIN_PATH
#error "PROXYSQL_MYSQLX_PLUGIN_PATH must be defined at compile time"
#endif

// Pick a high ephemeral port unlikely to collide.
static const uint16_t TEST_MYSQLX_PORT = 16603;

int main() {
	plan(8);

	// Step 1: Load the plugin.
	ProxySQL_PluginManager mgr;
	std::string err {};

	ok(mgr.load(PROXYSQL_MYSQLX_PLUGIN_PATH, err),
	   "load mysqlx plugin succeeds: %s", err.c_str());

	// Step 2: Create in-memory admin DB and register plugin schema.
	SQLite3DB admindb;
	int dbrc = admindb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(dbrc == 0, "admin sqlite opens");

	// Wire the admin DB into plugin services so init and start can use it.
	ok(mgr.init_all(err), "init_all registers schema: %s", err.c_str());

	// Step 3: Create the runtime_mysqlx_routes table and seed a route.
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

	char insert_sql[256];
	snprintf(insert_sql, sizeof(insert_sql),
		"INSERT INTO runtime_mysqlx_routes (name, bind, destination_hostgroup, strategy, active) "
		"VALUES ('smoke_route', '127.0.0.1:%u', 0, 'first_available', 1)",
		TEST_MYSQLX_PORT);
	ok(admindb.execute(insert_sql), "seed route row");

	// Step 4: Start listeners from the runtime routes table.
	// We call the worker API directly rather than through plugin start,
	// because plugin start needs the service wiring which is complex
	// in a unit test. This tests the listener code path directly.
	{
		// Include the worker header via the plugin header.
		extern bool mysqlx_start_listeners_from_runtime_routes(SQLite3DB& db);
		extern size_t mysqlx_listener_count();

		ok(mysqlx_start_listeners_from_runtime_routes(admindb),
		   "start_listeners_from_runtime_routes succeeds");
		ok(mysqlx_listener_count() == 1, "one listener opened");
	}

	// Step 5: TCP connect to the listener port.
	// Give the accept thread a moment to start.
	usleep(100000); // 100ms

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ok(fd >= 0, "client socket created");

	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TEST_MYSQLX_PORT);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	ok(rc == 0, "TCP connect to mysqlx listener on port %u succeeds", TEST_MYSQLX_PORT);
	close(fd);

	// Step 6: Clean up.
	{
		extern void mysqlx_stop_listeners();
		mysqlx_stop_listeners();
	}

	return exit_status();
}
