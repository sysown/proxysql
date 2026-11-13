#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "AdminResponseDrain.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;

static void attach_connection(MySQL_Data_Stream& stream) {
	// Frontend stream destruction owns the connection from this handoff onward.
	stream.myconn = std::make_unique<MySQL_Connection>().release();
}
static void attach_connection(PgSQL_Data_Stream&) {
	// PostgreSQL packet staging does not inspect connection compression state.
}

static void require(bool condition) {
	if (!condition) BAIL_OUT("socket fixture failed: errno=%d", errno);
}

static size_t fill_socket(int fd) {
	char data[4096] = {};
	size_t total = 0;
	ssize_t n;
	while ((n = send(fd, data, sizeof(data), 0)) > 0) total += n;
	require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	return total;
}

template<class Stream>
static void check_stream(const char* name) {
	int fds[2];
	require(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	for (int fd : fds) require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
	int size = 1024;
	require(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
	Stream stream;
	stream.init(MYDS_FRONTEND, nullptr, fds[0]);
	attach_connection(stream);
	const size_t filler = fill_socket(fds[0]);
	const std::string payload(stream.queueOUT.size * 3, 'a');
	void* packet = l_alloc(payload.size());
	memcpy(packet, payload.data(), payload.size());
	stream.PSarrayOUT->add(packet, payload.size());
	stream.array2buffer_full();
	ok(stream.queueOUT.partial > 0, "%s: oversized packets require staged refills", name);
	std::atomic<bool> finished{false};
	std::string received;
	std::thread reader([&received, filler, &payload, &fds, &finished] {
		std::this_thread::sleep_for(20ms);
		const auto deadline = std::chrono::steady_clock::now() + 2s;
		char buffer[4096];
		while (received.size() < filler + payload.size() && std::chrono::steady_clock::now() < deadline) {
			const ssize_t n = recv(fds[1], buffer, sizeof(buffer), 0);
			if (n > 0) received.append(buffer, n);
			else if (finished) break;
			else std::this_thread::sleep_for(1ms);
		}
	});
	const bool drained = proxysql_drain_admin_response(stream, 1000);
	finished = true;
	reader.join();
	ok(drained, "%s: a full socket and partial writes drain before shutdown", name);
	ok(received.size() == filler + payload.size() && received.substr(filler) == payload,
		"%s: the peer receives the exact acknowledgement bytes", name);

	fill_socket(fds[0]);
	memcpy(stream.queueOUT.buffer, "ok", 2);
	stream.queueOUT.head = 2;
	stream.queueOUT.tail = 0;
	const auto started = std::chrono::steady_clock::now();
	const bool stalled = proxysql_drain_admin_response(stream, 30);
	ok(!stalled && proxysql_admin_response_pending(stream), "%s: a stalled reader cannot fake a drained reply", name);
	ok(std::chrono::steady_clock::now() - started < 2s, "%s: a stalled reader cannot block teardown indefinitely", name);
	stream.queueOUT.head = stream.queueOUT.tail = 0;
	stream.encrypted = true;
	stream.ssl_write_len = 1;
	ok(proxysql_admin_response_pending(stream), "%s: pending ciphertext counts after plaintext is empty", name);
	stream.ssl_write_len = 0;
	stream.wbio_ssl = BIO_new(BIO_s_mem());
	require(stream.wbio_ssl && BIO_write(stream.wbio_ssl, "x", 1) == 1);
	ok(proxysql_admin_response_pending(stream), "%s: pending TLS BIO data counts as output", name);
	BIO_free(stream.wbio_ssl);
	stream.wbio_ssl = nullptr;
	stream.encrypted = false;
	close(fds[1]);
}

static void transfer(BIO* from, BIO* to) {
	char buffer[4096];
	int n;
	while ((n = BIO_read(from, buffer, sizeof(buffer))) > 0) require(BIO_write(to, buffer, n) == n);
}

template<class Stream>
static void check_tls(const char* name, const std::filesystem::path& fixtures) {
	SSL_CTX* server = SSL_CTX_new(TLS_server_method());
	SSL_CTX* client = SSL_CTX_new(TLS_client_method());
	require(server && client);
	require(SSL_CTX_use_certificate_file(server, (fixtures / "proxysql-cert.pem").c_str(), SSL_FILETYPE_PEM) == 1);
	require(SSL_CTX_use_PrivateKey_file(server, (fixtures / "proxysql-key.pem").c_str(), SSL_FILETYPE_PEM) == 1);
	require(SSL_CTX_set_min_proto_version(server, TLS1_3_VERSION) == 1);
	require(SSL_CTX_set_min_proto_version(client, TLS1_3_VERSION) == 1);
	int fds[2];
	require(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	for (int fd : fds) require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
	int size = 1024;
	require(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
	Stream stream;
	stream.init(MYDS_FRONTEND, nullptr, fds[0]);
	stream.encrypted = true;
	stream.ssl = SSL_new(server);
	stream.rbio_ssl = BIO_new(BIO_s_mem());
	stream.wbio_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(stream.ssl, stream.rbio_ssl, stream.wbio_ssl);
	SSL_set_accept_state(stream.ssl);
	SSL* peer = SSL_new(client);
	BIO* input = BIO_new(BIO_s_mem());
	BIO* output = BIO_new(BIO_s_mem());
	SSL_set_bio(peer, input, output);
	SSL_set_connect_state(peer);
	for (int i = 0; i < 20 && (!SSL_is_init_finished(peer) || !SSL_is_init_finished(stream.ssl)); ++i) {
		SSL_do_handshake(peer);
		transfer(output, stream.rbio_ssl);
		SSL_do_handshake(stream.ssl);
		transfer(stream.wbio_ssl, input);
	}
	require(SSL_is_init_finished(peer) && SSL_is_init_finished(stream.ssl));
	const size_t filler = fill_socket(fds[0]);
	const std::string payload(16000, 't');
	memcpy(stream.queueOUT.buffer, payload.data(), payload.size());
	stream.queueOUT.head = payload.size();
	// Force ciphertext EAGAIN after SSL_write has accepted the plaintext.
	stream.write_to_net();
	ok(stream.queueOUT.head == stream.queueOUT.tail && stream.ssl_write_len > 0,
		"%s: TLS backpressure consumes plaintext once and retains ciphertext", name);
	std::atomic<bool> finished{false};
	std::string received;
	std::thread reader([&fds, filler, input, peer, &received, &finished] {
		std::this_thread::sleep_for(20ms);
		size_t discarded = 0;
		char buffer[4096], plaintext[4096];
		const auto deadline = std::chrono::steady_clock::now() + 2s;
		while (std::chrono::steady_clock::now() < deadline) {
			const ssize_t n = recv(fds[1], buffer, sizeof(buffer), 0);
			if (n > 0) {
				const size_t skip = std::min<size_t>(n, filler - discarded);
				discarded += skip;
				if (static_cast<size_t>(n) > skip) BIO_write(input, buffer + skip, n - skip);
				int count;
				while ((count = SSL_read(peer, plaintext, sizeof(plaintext))) > 0) received.append(plaintext, count);
			} else if (finished) break;
			else std::this_thread::sleep_for(1ms);
		}
	});
	const bool drained = proxysql_drain_admin_response(stream, 1000);
	finished = true;
	reader.join();
	ok(drained, "%s: pending TLS ciphertext drains through partial writes", name);
	ok(received == payload, "%s: TLS peer decrypts the exact plaintext once", name);
	SSL_free(peer);
	SSL_CTX_free(client);
	SSL_CTX_free(server);
	close(fds[1]);
}

int main(int, char** argv) {
	plan(20);
	test_init_minimal();
	check_stream<MySQL_Data_Stream>("MySQL");
	check_stream<PgSQL_Data_Stream>("PostgreSQL");
	auto root = std::filesystem::canonical(argv[0]);
	for (int i = 0; i < 5; ++i) root = root.parent_path();
	const auto fixtures = root / "test/tap/tests/test_cluster_sync_config/test_cluster_sync_nomonitor";
	check_tls<MySQL_Data_Stream>("MySQL", fixtures);
	check_tls<PgSQL_Data_Stream>("PostgreSQL", fixtures);
	test_cleanup_minimal();
	return exit_status();
}
