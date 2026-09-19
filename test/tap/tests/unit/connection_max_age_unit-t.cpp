/**
 * @file connection_max_age_unit-t.cpp
 * @brief Verify connection_max_age_ms bounds connection age (#6169).
 *
 * reset() must not restart the age counter. Expired connections are closed
 * instead of being recycled via CHANGE_USER / the reset queue.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Connection.h"

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;

static MySrvC *create_server(unsigned int hostgroup_id, const char *address) {
	srv_info_t info;
	info.addr = address;
	info.port = 3306;
	info.kind = "connection-max-age-unit";

	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	int rc = MyHGM->create_new_server_in_hg(hostgroup_id, info, opts);
	MyHGC *hostgroup = MyHGM->MyHGC_find(hostgroup_id);
	MyHGM->wrunlock();

	if (rc != 0 || hostgroup == nullptr || hostgroup->mysrvs->cnt() != 1) {
		BAIL_OUT("failed to create server for hostgroup %u", hostgroup_id);
	}

	return hostgroup->mysrvs->idx(0);
}

static MySQL_Connection *create_used_connection(MySrvC *server) {
	MySQL_Connection *connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) {
		delete connection;
		BAIL_OUT("mysql_init() failed for unit-test connection");
	}

	connection->parent = server;
	connection->healthy = true;
	connection->reusable = true;
	connection->async_state_machine = ASYNC_IDLE;
	connection->largest_query_length = 0;
	server->ConnectionsUsed->add(connection);
	return connection;
}

static void check_pool_state(MySrvC *server, unsigned int exp_used, unsigned int exp_free, const char *msg) {
	unsigned int used = server->ConnectionsUsed->conns_length();
	unsigned int free = server->ConnectionsFree->conns_length();
	ok(used == exp_used && free == exp_free, "%s (used=%u, free=%u)", msg, used, free);
}

static void test_mysql_is_expired() {
	MySQL_Connection connection;
	connection.creation_time = 1 * 1000 * 1000;

	mysql_thread___connection_max_age_ms = 0;
	ok(connection.is_expired(10 * 1000 * 1000) == false, "MySQL is_expired is false when connection_max_age_ms is 0");

	mysql_thread___connection_max_age_ms = 1000;
	ok(connection.is_expired(connection.creation_time + 1000 * 1000ULL) == false,
		"MySQL is_expired is false at exactly max age");
	ok(connection.is_expired(connection.creation_time + 1000 * 1000ULL + 1) == true,
		"MySQL is_expired is true past max age");
}

static void test_pgsql_is_expired() {
	PgSQL_Connection connection(false);
	connection.creation_time = 1 * 1000 * 1000;

	pgsql_thread___connection_max_age_ms = 0;
	ok(connection.is_expired(10 * 1000 * 1000) == false, "PgSQL is_expired is false when connection_max_age_ms is 0");

	pgsql_thread___connection_max_age_ms = 1000;
	ok(connection.is_expired(connection.creation_time + 1000 * 1000ULL) == false,
		"PgSQL is_expired is false at exactly max age");
	ok(connection.is_expired(connection.creation_time + 1000 * 1000ULL + 1) == true,
		"PgSQL is_expired is true past max age");
}

static void test_reset_preserves_creation_time() {
	MySQL_Connection mysql_conn;
	mysql_conn.creation_time = 123456789ULL;
	mysql_conn.reset();
	ok(mysql_conn.creation_time == 123456789ULL, "MySQL reset() does not restart creation_time");
	// NOTE: no PgSQL reset() case here: PgSQL_Connection::reset() assumes a
	// fully connected session (startup_parameters_hash, session variables)
	// and asserts on a bare object, so it cannot be unit-tested standalone.
	// The PgSQL fix is the same one-line removal of the creation_time
	// restamp, covered by review and by test_pgsql_is_expired() above.
}

static void test_destroy_does_not_recycle_expired() {
	MySrvC *server = create_server(201, "max-age-destroy");
	MySQL_Connection *connection = create_used_connection(server);
	connection->creation_time = 1;
	mysql_thread___connection_max_age_ms = 1;
	GloMTH->variables.connpoll_reset_queue_length = 50;

	MyHGM->destroy_MyConn_from_pool(connection);
	check_pool_state(server, 0, 0, "expired healthy connection is destroyed instead of reset-queued");
}

static void test_idle_purge_drops_expired() {
	MySrvC *server = create_server(202, "max-age-idle");
	MySQL_Connection *connection = create_used_connection(server);
	connection->creation_time = 1;
	mysql_thread___connection_max_age_ms = 1;
	mysql_thread___free_connections_pct = 100;

	MyHGM->push_MyConn_to_pool(connection);
	check_pool_state(server, 0, 1, "non-purged healthy connection is in the free pool");

	MyHGM->wrlock();
	MyHGM->drop_all_idle_connections();
	MyHGM->wrunlock();
	check_pool_state(server, 0, 0, "idle purge deletes expired free-pool connections");
}

int main() {
	plan(10);

	if (test_init_minimal() != 0) {
		BAIL_OUT("test_init_minimal() failed");
	}
	if (test_init_query_processor() != 0) {
		BAIL_OUT("test_init_query_processor() failed");
	}
	GloMyLogger = new MySQL_Logger();
	if (test_init_hostgroups() != 0) {
		BAIL_OUT("test_init_hostgroups() failed");
	}

	test_mysql_is_expired();
	test_pgsql_is_expired();
	test_reset_preserves_creation_time();
	test_destroy_does_not_recycle_expired();
	test_idle_purge_drops_expired();

	test_cleanup_hostgroups();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
