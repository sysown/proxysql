/**
 * Native mode must retain libpq transport for PostgreSQL Unix-socket hosts.
 * These listeners check the real connect_start() path without requiring a
 * PostgreSQL server: accepting the socket proves which endpoint was dialed.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

static bool accepted(int listener) {
	struct pollfd pfd { listener, POLLIN, 0 };
	if (poll(&pfd, 1, 1000) <= 0) return false;
	int peer = accept(listener, nullptr, nullptr);
	if (peer < 0) return false;
	close(peer);
	return true;
}

static PgSQL_Connection* start(const std::string& host, unsigned short port) {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	char comment[] = "";
	c->parent = new PgSQL_SrvC(const_cast<char*>(host.c_str()), port, 1,
		MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 0, 0, comment);
	c->userinfo->username = strdup("endpoint_test");
	c->userinfo->password = strdup("endpoint_test");
	c->userinfo->dbname = strdup("endpoint_test");
	c->native_mode = true; // runtime setting selected native before connect_start()
	c->connect_start();
	return c;
}

static void release(PgSQL_Connection* c) {
	PgSQL_SrvC* server = c->parent;
	delete c;
	delete server;
}

static int unix_listener(const std::string& directory, unsigned short port,
	bool abstract_socket) {
	std::string path = directory + "/.s.PGSQL." + std::to_string(port);
	struct sockaddr_un addr {};
	addr.sun_family = AF_UNIX;
	socklen_t len;
	if (abstract_socket) {
		if (path.size() >= sizeof(addr.sun_path)) return -1;
		addr.sun_path[0] = '\0';
		memcpy(addr.sun_path + 1, path.data() + 1, path.size() - 1);
		len = offsetof(sockaddr_un, sun_path) + path.size();
	} else {
		if (path.size() >= sizeof(addr.sun_path)) return -1;
		memcpy(addr.sun_path, path.c_str(), path.size() + 1);
		len = offsetof(sockaddr_un, sun_path) + path.size() + 1;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0 || listen(fd, 2) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void check_unix(const std::string& host, unsigned short configured_port,
	unsigned short socket_port, bool abstract_socket, const char* description) {
	int listener = unix_listener(host, socket_port, abstract_socket);
	if (listener < 0) BAIL_OUT("could not create %s listener", description);
	PgSQL_Connection* c = start(host, configured_port);
	bool reached = accepted(listener);
	ok(reached && !c->native_mode && c->get_pg_connection() != nullptr,
		"%s uses libpq and reaches the expected Unix socket", description);
	release(c);
	close(listener);
	if (!abstract_socket) {
		std::string path = host + "/.s.PGSQL." + std::to_string(socket_port);
		unlink(path.c_str());
	}
}

int main() {
	plan(4);
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");
	char dir[] = "/tmp/pgsql_native_unix_XXXXXX";
	if (!mkdtemp(dir)) BAIL_OUT("mkdtemp failed");
	check_unix(dir, 0, 5432, false, "filesystem socket with default port");
	check_unix(dir, 6543, 6543, false, "filesystem socket with nondefault port");
	std::string abstract_host = std::string("@pgsql_native_") + std::to_string(getpid());
	check_unix(abstract_host, 6544, 6544, true, "abstract socket with nondefault port");

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) BAIL_OUT("TCP socket failed");
	struct sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
		listen(listener, 2) != 0) BAIL_OUT("TCP listener failed");
	socklen_t len = sizeof(addr);
	if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
		BAIL_OUT("getsockname failed");
	PgSQL_Connection* tcp = start("127.0.0.1", ntohs(addr.sin_port));
	ok(tcp->native_mode && tcp->get_pg_connection() == nullptr && accepted(listener),
		"TCP host still uses native transport and reaches its configured port");
	release(tcp);
	close(listener);
	rmdir(dir);
	test_cleanup_minimal();
	return exit_status();
}
