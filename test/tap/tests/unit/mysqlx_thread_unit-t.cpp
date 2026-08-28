#include "mysqlx_thread.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

static int find_free_port() {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	bind(fd, (struct sockaddr*)&addr, sizeof(addr));
	socklen_t len = sizeof(addr);
	getsockname(fd, (struct sockaddr*)&addr, &len);
	int port = ntohs(addr.sin_port);
	close(fd);
	return port;
}

static void test_thread_init() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);
	ok(thr.get_thread_index() == 0, "thread index is 0");
	ok(thr.get_session_count() == 0, "no sessions initially");
	ok(!thr.is_running(), "not running initially");
}

static void test_thread_listener() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);

	int rc = thr.add_listener("127.0.0.1", 0);
	ok(rc == 0, "listener added on port 0");
	ok(thr.get_listener_count() == 1, "1 listener");

	thr.remove_listeners();
	ok(thr.get_listener_count() == 0, "listeners removed");
}

static void test_thread_start_stop() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.add_listener("127.0.0.1", 0);

	bool started = thr.start();
	ok(started, "thread started");
	usleep(100000);
	ok(thr.is_running(), "thread is running");

	thr.stop();
	ok(!thr.is_running(), "thread stopped after stop()");

	thr.remove_listeners();
	ok(thr.get_listener_count() == 0, "listeners removed after stop");
}

static void test_thread_accept_connection() {
	diag(">>> %s", __func__);
	int port = find_free_port();

	Mysqlx_Thread thr;
	thr.init(0);
	int rc = thr.add_listener("127.0.0.1", port);
	ok(rc == 0, "listener added on port %d", port);

	thr.start();
	usleep(100000);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	ok(rc == 0, "client connected to port %d", port);

	usleep(300000);
	size_t sc = thr.get_session_count();
	ok(sc >= 1, "session created after connect (count=%zu)", sc);

	close(fd);
	usleep(300000);

	thr.stop();
	ok(!thr.is_running(), "thread stopped cleanly");
	thr.remove_listeners();
}

static void test_connection_cache() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_max_cached_connections(3);

	ok(thr.get_cached_connection_count() == 0, "cache empty initially");

	MysqlxConnection* c1 = new MysqlxConnection();
	c1->set_hostgroup(0);
	c1->set_user("user1");
	c1->set_schema("db1");
	c1->set_reusable(true);
	c1->set_state(MysqlxConnection::IDLE);

	thr.return_connection_to_cache(c1);
	ok(thr.get_cached_connection_count() == 1, "cache has 1 connection");

	MysqlxConnection* found = thr.get_connection_from_cache(0, "user1", "db1", /*tls_active=*/false);
	ok(found != nullptr, "found connection in cache");
	ok(found == c1, "got the same connection back");
	ok(thr.get_cached_connection_count() == 0, "cache empty after get");

	thr.return_connection_to_cache(found);
	ok(thr.get_cached_connection_count() == 1, "cache has 1 again");

	MysqlxConnection* nf = thr.get_connection_from_cache(0, "wrong", "db1", /*tls_active=*/false);
	ok(nf == nullptr, "not found with wrong user");

	for (int i = 0; i < 3; i++) {
		MysqlxConnection* c = new MysqlxConnection();
		c->set_hostgroup(0);
		c->set_user("evict");
		c->set_schema("db");
		c->set_reusable(true);
		c->set_state(MysqlxConnection::IDLE);
		thr.return_connection_to_cache(c);
	}
	ok(thr.get_cached_connection_count() == 3, "cache at max capacity after eviction");
}

// Connection-cache key: tls_active is a hard partition. A plaintext-
// pooled connection MUST NOT be returned to a TLS-frontend session
// (and vice versa); the encryption posture is part of the cache
// identity. Without this dimension the AsClient/required modes would
// hand TLS-required sessions plaintext backends and corrupt the wire
// protocol.
static void test_connection_cache_tls_partition() {
	diag(">>> %s", __func__);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_max_cached_connections(10);

	// Insert one plaintext and one encrypted connection at the same
	// (hostgroup, user, schema) key.
	MysqlxConnection* plaintext = new MysqlxConnection();
	plaintext->set_hostgroup(7);
	plaintext->set_user("u");
	plaintext->set_schema("s");
	plaintext->set_reusable(true);
	plaintext->set_state(MysqlxConnection::IDLE);
	plaintext->set_tls_active(false);
	thr.return_connection_to_cache(plaintext);

	MysqlxConnection* encrypted = new MysqlxConnection();
	encrypted->set_hostgroup(7);
	encrypted->set_user("u");
	encrypted->set_schema("s");
	encrypted->set_reusable(true);
	encrypted->set_state(MysqlxConnection::IDLE);
	encrypted->set_tls_active(true);
	thr.return_connection_to_cache(encrypted);

	// Plaintext lookup must return the plaintext connection only.
	MysqlxConnection* got_pt = thr.get_connection_from_cache(7, "u", "s", /*tls_active=*/false);
	ok(got_pt == plaintext, "plaintext lookup returns the plaintext-pooled conn");

	// Now only the encrypted one is left. A plaintext lookup must miss.
	MysqlxConnection* miss_pt = thr.get_connection_from_cache(7, "u", "s", /*tls_active=*/false);
	ok(miss_pt == nullptr, "plaintext lookup misses an encrypted-pooled conn");

	// The encrypted lookup picks up the remaining one.
	MysqlxConnection* got_tls = thr.get_connection_from_cache(7, "u", "s", /*tls_active=*/true);
	ok(got_tls == encrypted, "tls lookup returns the encrypted-pooled conn");

	// Cleanup: tests own the conns once pulled out of the cache.
	delete got_pt;
	delete got_tls;
}

static void test_timeout_elapsed_is_future_safe() {
	diag(">>> %s", __func__);
	ok(!Mysqlx_Thread::elapsed_exceeds_for_test(1000, 1001, 10),
	   "timeout comparison does not underflow when last-active is newer than now");
	ok(!Mysqlx_Thread::elapsed_exceeds_for_test(1000, 990, 10),
	   "timeout comparison is strict at the timeout boundary");
	ok(Mysqlx_Thread::elapsed_exceeds_for_test(1001, 990, 10),
	   "timeout comparison fires after the timeout boundary");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(28);
	diag("=== mysqlx_thread_unit-t starting ===");

	test_thread_init();
	test_thread_listener();
	test_thread_start_stop();
	test_thread_accept_connection();
	test_connection_cache();
	test_connection_cache_tls_partition();
	test_timeout_elapsed_is_future_safe();

	return exit_status();
}
