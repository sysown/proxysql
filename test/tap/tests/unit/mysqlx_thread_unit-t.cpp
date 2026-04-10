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
	Mysqlx_Thread thr;
	thr.init(0);
	ok(thr.get_thread_index() == 0, "thread index is 0");
	ok(thr.get_session_count() == 0, "no sessions initially");
	ok(!thr.is_running(), "not running initially");
}

static void test_thread_listener() {
	Mysqlx_Thread thr;
	thr.init(0);

	int rc = thr.add_listener("127.0.0.1", 0);
	ok(rc == 0, "listener added on port 0");
	ok(thr.get_listener_count() == 1, "1 listener");

	thr.remove_listeners();
	ok(thr.get_listener_count() == 0, "listeners removed");
}

static void test_thread_start_stop() {
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

	MysqlxConnection* found = thr.get_connection_from_cache(0, "user1", "db1");
	ok(found != nullptr, "found connection in cache");
	ok(found == c1, "got the same connection back");
	ok(thr.get_cached_connection_count() == 0, "cache empty after get");

	thr.return_connection_to_cache(found);
	ok(thr.get_cached_connection_count() == 1, "cache has 1 again");

	MysqlxConnection* nf = thr.get_connection_from_cache(0, "wrong", "db1");
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

int main() {
	plan(22);

	test_thread_init();
	test_thread_listener();
	test_thread_start_stop();
	test_thread_accept_connection();
	test_connection_cache();

	return exit_status();
}
