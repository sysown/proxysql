#include "mysqlx_thread.h"
#include "mysqlx_session.h"
#include "mysqlx_data_stream.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

static std::atomic<int> sessions_ok{0};
static std::atomic<int> sessions_err{0};

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

static void write_x_frame(int fd, uint8_t msg_type, const uint8_t* payload, size_t payload_len) {
	uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	uint8_t header[5];
	header[0] = size & 0xFF;
	header[1] = (size >> 8) & 0xFF;
	header[2] = (size >> 16) & 0xFF;
	header[3] = (size >> 24) & 0xFF;
	header[4] = msg_type;
	write(fd, header, 5);
	if (payload_len > 0) {
		write(fd, payload, payload_len);
	}
}

static ssize_t read_x_frame(int fd, uint8_t* buf, size_t buf_size) {
	uint8_t header[5];
	ssize_t r = read(fd, header, 5);
	if (r != 5) return -1;
	uint32_t payload_size = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
	uint8_t msg_type = header[4];
	if (5 + payload_size > buf_size) return -1;
	buf[0] = header[0];
	buf[1] = header[1];
	buf[2] = header[2];
	buf[3] = header[3];
	buf[4] = msg_type;
	if (payload_size > 1) {
		r = read(fd, buf + 5, payload_size - 1);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return 4 + payload_size;
}

static void client_thread(int port, int id) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { sessions_err++; return; }

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) { sessions_err++; close(fd); return; }

	write_x_frame(fd, Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);

	uint8_t buf[4096];
	ssize_t r = read_x_frame(fd, buf, sizeof(buf));
	if (r <= 5) { sessions_err++; close(fd); return; }

	if (buf[4] != Mysqlx::ServerMessages_Type_CONN_CAPABILITIES) {
		sessions_err++;
		close(fd);
		return;
	}

	sessions_ok++;
	close(fd);
}

static void test_concurrent_handshakes() {
	diag(">>> %s", __func__);
	int port = find_free_port();

	Mysqlx_Thread thr;
	thr.init(0);
	int rc = thr.add_listener("127.0.0.1", port);
	ok(rc == 0, "listener added on port %d", port);

	diag("starting Mysqlx_Thread on port %d", port);
	bool started = thr.start();
	ok(started, "thread started");
	usleep(100000);

	const int N = 20;
	diag("thread started, spawning %d clients", N);
	std::vector<std::thread> clients;
	sessions_ok = 0;
	sessions_err = 0;

	for (int i = 0; i < N; i++) {
		clients.emplace_back(client_thread, port, i);
	}
	diag("all clients spawned, joining");

	for (auto& t : clients) t.join();
	diag("all clients joined, sleeping 500ms");

	usleep(500000);

	ok(sessions_ok.load() == N,
	   "all %d sessions completed CapabilitiesGet concurrently (ok=%d, err=%d)",
	   N, sessions_ok.load(), sessions_err.load());
	ok(sessions_err.load() == 0, "no sessions failed");

	diag("checking session count");
	ok(thr.get_session_count() == 0,
	   "all sessions cleaned up after disconnect");

	diag("calling thr.stop()");
	thr.stop();
	diag("thr.stop() returned");
	ok(!thr.is_running(), "thread stopped cleanly");
	thr.remove_listeners();
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(6);
	diag("=== mysqlx_concurrent_unit-t starting ===");
	test_concurrent_handshakes();
	return exit_status();
}
