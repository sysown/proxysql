/**
 * @file connection_unhealthy_unit-t.cpp
 * @brief Verify unhealthy MySQL connections cannot re-enter connection pools.
 *
 * Exercises the real MySQL connection, thread-local cache, and HostGroups
 * Manager boundaries without opening a backend network connection.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Logger.hpp"

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;

static MySrvC *create_server(unsigned int hostgroup_id, const char *address) {
	srv_info_t info;
	info.addr = address;
	info.port = 3306;
	info.kind = "connection-unhealthy-unit";

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

static MySQL_Connection *create_used_connection(MySrvC *server, bool healthy) {
	MySQL_Connection *connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) {
		delete connection;
		BAIL_OUT("mysql_init() failed for unit-test connection");
	}

	connection->parent = server;
	connection->healthy = healthy;
	connection->reusable = healthy;
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

static void test_unhealthy_global_pool() {
	MySrvC *server = create_server(101, "unhealthy-global");
	MySQL_Connection *connection = create_used_connection(server, false);

	connection->reset();
	MyHGM->push_MyConn_to_pool(connection);

	check_pool_state(server, 0, 0, "reset unhealthy connection is destroyed at the global pool boundary");
}

static void test_unhealthy_local_pool(MySQL_Thread &worker) {
	MySrvC *server = create_server(102, "unhealthy-local");
	MySQL_Connection *connection = create_used_connection(server, false);

	connection->reset();
	worker.push_MyConn_local(connection);

	check_pool_state(server, 0, 0, "reset unhealthy connection is destroyed at the local pool boundary");

	// If the assertion failed because the connection entered the local cache,
	// return it before continuing so later cases remain isolated.
	worker.return_local_connections();
}

static void test_healthy_global_pool() {
	MySrvC *server = create_server(103, "healthy-global");
	MySQL_Connection *connection = create_used_connection(server, true);

	MyHGM->push_MyConn_to_pool(connection);

	check_pool_state(server, 0, 1, "healthy connection enters the global free pool");
}

static void test_healthy_local_pool(MySQL_Thread &worker) {
	MySrvC *server = create_server(104, "healthy-local");
	MySQL_Connection *connection = create_used_connection(server, true);

	worker.push_MyConn_local(connection);
	check_pool_state(server, 1, 0, "healthy connection remains used while cached locally");

	worker.return_local_connections();
	check_pool_state(server, 0, 1, "healthy local connection enters the global free pool when returned");
}

int main() {
	plan(5);

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

	// Make the local-cache decision deterministic: with one worker, every
	// otherwise eligible connection is cached locally.
	GloMTH->num_threads = 1;
	{
		MySQL_Thread worker;
		if (!worker.init()) {
			BAIL_OUT("MySQL_Thread::init() failed");
		}

		test_unhealthy_global_pool();
		test_unhealthy_local_pool(worker);
		test_healthy_global_pool();
		test_healthy_local_pool(worker);
	}

	test_cleanup_hostgroups();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
