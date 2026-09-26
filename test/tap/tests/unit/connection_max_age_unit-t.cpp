/**
 * @file connection_max_age_unit-t.cpp
 * @brief Verify connection_max_age_ms bounds connection age (#6169).
 *
 * reset() must not restart the age counter. Expired connections are closed
 * instead of being recycled via CHANGE_USER / the reset queue, and the
 * PINGING_SERVER exemption must not keep an expired connection in the pool.
 */

#include <atomic>
#include <pthread.h>
#include <unistd.h>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
#include "MySQL_Data_Stream.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Session.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Session.h"

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Threads_Handler *GloMTH;
extern PgSQL_HostGroups_Manager *PgHGM;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

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

static PgSQL_SrvC *create_pgsql_server(unsigned int hostgroup_id, const char *address) {
	PgSQL_srv_info_t info;
	info.addr = address;
	info.port = 5432;
	info.kind = "connection-max-age-unit";

	PgSQL_srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	PgHGM->wrlock();
	int rc = PgHGM->create_new_server_in_hg(hostgroup_id, info, opts);
	PgSQL_HGC *hostgroup = PgHGM->MyHGC_find(hostgroup_id);
	PgHGM->wrunlock();

	if (rc != 0 || hostgroup == nullptr || hostgroup->mysrvs->cnt() != 1) {
		BAIL_OUT("failed to create PgSQL server for hostgroup %u", hostgroup_id);
	}

	return (PgSQL_SrvC *)hostgroup->mysrvs->idx(0);
}

static PgSQL_Connection *create_used_pgsql_connection(PgSQL_SrvC *server) {
	PgSQL_Connection *connection = new PgSQL_Connection(false);
	connection->parent = server;
	connection->healthy = true;
	connection->reusable = true;
	connection->async_state_machine = ASYNC_IDLE;
	server->ConnectionsUsed->add(connection);
	return connection;
}

static void check_pgsql_pool_state(PgSQL_SrvC *server, unsigned int exp_used, unsigned int exp_free, const char *msg) {
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

struct ReadLockProbe {
	std::atomic<bool> reader_attempting{false};
	std::atomic<bool> reader_acquired{false};
};

static void *read_lock_probe_thread(void *arg) {
	ReadLockProbe *probe = (ReadLockProbe *)arg;
	probe->reader_attempting.store(true);
	GloMTH->rdlock();
	probe->reader_acquired.store(true);
	GloMTH->rdunlock();
	return NULL;
}

static void test_glomth_read_lock_accessors() {
	const unsigned int saved_max_age = GloMTH->variables.connection_max_age_ms;

	GloMTH->wrlock();
	GloMTH->variables.connection_max_age_ms = 4242;
	GloMTH->wrunlock();

	GloMTH->rdlock();
	const unsigned int observed = GloMTH->variables.connection_max_age_ms;
	GloMTH->rdunlock();
	ok(observed == 4242, "GloMTH read lock exposes the current connection_max_age_ms (%u)", observed);

	ReadLockProbe probe;
	pthread_t reader;
	GloMTH->wrlock();
	if (pthread_create(&reader, NULL, read_lock_probe_thread, &probe) != 0) {
		GloMTH->wrunlock();
		BAIL_OUT("pthread_create() failed for the read-lock probe");
	}
	while (!probe.reader_attempting.load()) {
		usleep(1000);
	}
	usleep(200 * 1000);
	const bool blocked = probe.reader_acquired.load() == false;
	ok(blocked, "GloMTH read lock is held back while a writer owns the handler lock");
	GloMTH->wrunlock();
	pthread_join(reader, NULL);
	ok(probe.reader_acquired.load(), "GloMTH read lock is released after the writer unlocks");

	GloMTH->wrlock();
	GloMTH->variables.connection_max_age_ms = saved_max_age;
	GloMTH->wrunlock();
}

static void test_mysql_pinging_still_destroys_expired(MySQL_Thread &worker) {
	MySrvC *server = create_server(203, "max-age-pinging");
	MySQL_Connection *connection = create_used_connection(server);
	connection->creation_time = 1;
	mysql_thread___connection_max_age_ms = 1;

	MySQL_Session session;
	session.thread = &worker;
	session.status = PINGING_SERVER;
	session.connections_handler = true;

	MySQL_Data_Stream myds;
	myds.sess = &session;
	myds.myconn = connection;
	worker.mypolls.add(POLLIN, -1, &myds, worker.curtime);

	myds.return_MySQL_Connection_To_Pool();

	check_pool_state(server, 0, 0, "MySQL PINGING_SERVER session still destroys an expired connection");
}

static void test_mysql_pinging_keeps_stmts_exemption(MySQL_Thread &worker) {
	MySrvC *server = create_server(204, "max-age-pinging-stmts");
	MySQL_Connection *connection = create_used_connection(server);
	connection->creation_time = monotonic_time();
	mysql_thread___connection_max_age_ms = 0;
	mysql_thread___reset_connection_algorithm = 0;
	// Keep the reset queue out of the picture, so a connection that lost the
	// PINGING_SERVER exemption would be destroyed rather than re-queued. Both
	// overrides are process-global: restore the values the earlier cases left
	// behind instead of leaking them into the rest of the run.
	const unsigned int saved_queue_length = GloMTH->variables.connpoll_reset_queue_length;
	const unsigned int saved_max_stmts = GloMTH->variables.max_stmts_per_connection;
	GloMTH->variables.connpoll_reset_queue_length = 0;
	GloMTH->variables.max_stmts_per_connection = 0;
	connection->local_stmts->backend_stmt_to_global_ids[1] = 2;

	MySQL_Session session;
	session.thread = &worker;
	session.status = PINGING_SERVER;
	session.connections_handler = true;

	MySQL_Data_Stream myds;
	myds.sess = &session;
	myds.myconn = connection;
	worker.mypolls.add(POLLIN, -1, &myds, worker.curtime);

	myds.return_MySQL_Connection_To_Pool();
	check_pool_state(server, 1, 0, "MySQL PINGING_SERVER session keeps a too_many_stmts connection in the pool");
	worker.return_local_connections();

	GloMTH->variables.connpoll_reset_queue_length = saved_queue_length;
	GloMTH->variables.max_stmts_per_connection = saved_max_stmts;
}

static void test_pgsql_pinging_still_destroys_expired() {
	PgSQL_Thread worker;
	if (!worker.init()) {
		BAIL_OUT("PgSQL_Thread::init() failed");
	}
	worker.curtime = monotonic_time();

	PgSQL_SrvC *server = create_pgsql_server(211, "max-age-pinging-pg");
	PgSQL_Connection *connection = create_used_pgsql_connection(server);
	connection->creation_time = 1;
	pgsql_thread___connection_max_age_ms = 1;

	PgSQL_Session session;
	session.thread = &worker;
	session.status = PINGING_SERVER;
	session.connections_handler = true;

	PgSQL_Data_Stream myds;
	myds.sess = &session;
	myds.myconn = connection;
	worker.mypolls.add(POLLIN, -1, &myds, worker.curtime);

	myds.return_MySQL_Connection_To_Pool();

	check_pgsql_pool_state(server, 0, 0, "PgSQL PINGING_SERVER session still destroys an expired connection");
}

int main() {
	plan(16);

	if (test_init_minimal() != 0) {
		BAIL_OUT("test_init_minimal() failed");
	}
	if (test_init_query_processor() != 0) {
		BAIL_OUT("test_init_query_processor() failed");
	}
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	if (test_init_hostgroups() != 0) {
		BAIL_OUT("test_init_hostgroups() failed");
	}

	test_mysql_is_expired();
	test_pgsql_is_expired();
	test_reset_preserves_creation_time();
	test_destroy_does_not_recycle_expired();
	test_idle_purge_drops_expired();
	test_glomth_read_lock_accessors();
	{
		MySQL_Thread worker;
		if (!worker.init()) {
			BAIL_OUT("MySQL_Thread::init() failed");
		}
		worker.curtime = monotonic_time();

		test_mysql_pinging_still_destroys_expired(worker);
		test_mysql_pinging_keeps_stmts_exemption(worker);
	}
	test_pgsql_pinging_still_destroys_expired();

	test_cleanup_hostgroups();
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
