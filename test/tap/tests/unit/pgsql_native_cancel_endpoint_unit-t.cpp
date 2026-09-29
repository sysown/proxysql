/**
 * Native CancelRequest must go to the peer of the original backend socket.
 * The configured target deliberately points at a second listener, so a
 * resolver retry or a stale hostname/port can never pass these assertions.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

struct Listener {
	int fd = -1;
	unsigned short port = 0;
	Listener() {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) return;
		struct sockaddr_in addr {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
			listen(fd, 2) != 0) return;
		socklen_t len = sizeof(addr);
		if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
			port = ntohs(addr.sin_port);
	}
	~Listener() { if (fd >= 0) close(fd); }
	void stop() { if (fd >= 0) close(fd); fd = -1; }
	int take() const {
		if (fd < 0) return -1;
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, 300) <= 0) return -1;
		return accept(fd, nullptr, nullptr);
	}
};

static int connect_to(const Listener& listener) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(listener.port);
	if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static PgSQL_Backend_Kill_Args* make_args(unsigned int configured_port, int native_fd) {
	PgSQL_Connection_userinfo user;
	user.username = strdup("cancel_test");
	user.password = strdup("cancel_test");
	user.dbname = strdup("cancel_test");
	auto* args = new PgSQL_Backend_Kill_Args(nullptr, &user, "127.0.0.1",
		configured_port, 0, false, PgSQL_Backend_Kill_Args::TYPE::CANCEL_QUERY,
		nullptr, native_fd);
	args->native_mode = true;
	args->backend_pid = 0x11223344;
	args->native_secret_key = 0x55667788;
	return args;
}

static bool exact_packet(int fd) {
	if (fd < 0) return false;
	unsigned char packet[16] {};
	size_t off = 0;
	while (off < sizeof(packet)) {
		ssize_t n = recv(fd, packet + off, sizeof(packet) - off, 0);
		if (n <= 0) { close(fd); return false; }
		off += static_cast<size_t>(n);
	}
	close(fd);
	const unsigned char expected[16] = {
		0, 0, 0, 16, 4, 210, 22, 46,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
	};
	return memcmp(packet, expected, sizeof(expected)) == 0;
}

int main() {
	plan(4);
	if (test_init_minimal() != 0 || test_init_hostgroups() != 0)
		BAIL_OUT("test initialization failed");
	{
		Listener original, configured;
		if (!original.port || !configured.port) BAIL_OUT("listeners failed");
		int source = connect_to(original);
		int accepted_source = original.take();
		if (source < 0 || accepted_source < 0) BAIL_OUT("original connection failed");
		auto* args = make_args(configured.port, source);
		// The detached worker must own the peer address after the source closes.
		close(source);
		close(accepted_source);
		PgSQL_backend_kill_thread(args);
		ok(exact_packet(original.take()), "original peer receives the exact PID and secret");
		int wrong = configured.take();
		ok(wrong < 0, "configured endpoint receives no cancellation packet");
		if (wrong >= 0) close(wrong);
	}
	{
		Listener original, configured;
		if (!original.port || !configured.port) BAIL_OUT("listeners failed");
		int source = connect_to(original);
		int accepted_source = original.take();
		if (source < 0 || accepted_source < 0) BAIL_OUT("original connection failed");
		auto* args = make_args(configured.port, source);
		close(source);
		close(accepted_source);
		original.stop(); // the captured endpoint is now unavailable
		PgSQL_backend_kill_thread(args);
		int wrong = configured.take();
		ok(wrong < 0, "unavailable original endpoint does not redirect to configured endpoint");
		if (wrong >= 0) close(wrong);
	}
	{
		Listener configured;
		if (!configured.port) BAIL_OUT("listener failed");
		PgSQL_backend_kill_thread(make_args(configured.port, -1));
		int wrong = configured.take();
		ok(wrong < 0, "invalid original socket capture does not send to configured endpoint");
		if (wrong >= 0) close(wrong);
	}
	test_cleanup_hostgroups();
	test_cleanup_minimal();
	return exit_status();
}
