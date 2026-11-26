/**
 * @file idle_thread_tls_pending_output_unit-t.cpp
 * @brief Regression test for #6679: a worker must not move a TLS frontend session to an idle
 *   thread while encrypted output is still waiting to be written.
 *
 * @details Idle threads poll their sessions for EPOLLIN only and never write, so
 *   Base_Thread::move_session_to_idle_mysql_sessions() refuses to move a session with pending
 *   output (#1939). For TLS frontends, write_to_net() encrypts the whole plaintext queue at once;
 *   when the socket accepts only part of the ciphertext, the rest stays in 'ssl_write_buf' while
 *   the plaintext queues are already empty. The check used to look only at the plaintext queues
 *   ('available_data_out()'), so such a session was moved and the end of its result set was
 *   written only once the client sent something else. A client waiting for that result set sends
 *   nothing and hangs.
 *
 *   For MySQL and PostgreSQL, the test registers a frontend session in a worker object (the thread
 *   is not started) and calls the move check directly from the test thread:
 *   - with no output pending (plaintext and TLS), the session is moved: the fixture reaches the
 *     move, so the refusals below are not caused by the fixture;
 *   - after a real short write over TLS (socketpair with a tiny SO_SNDBUF), with ciphertext left in
 *     'ssl_write_buf' and the plaintext queues empty, the session must stay on the worker;
 *   - with ciphertext still in the write BIO, the session must stay on the worker;
 *   - once the peer has read everything and the ciphertext is flushed, the session is moved.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Thread.h"
#include "PgSQL_Thread.h"

#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

using namespace std::chrono_literals;

namespace {

void require(bool condition, const char* what) {
	if (!condition) BAIL_OUT("fixture failed: %s (errno=%d)", what, errno);
}

void attach_connection(MySQL_Data_Stream& stream) {
	// array2buffer() reads the compression state of the frontend connection, which the frontend
	// data stream destructor owns and deletes.
	stream.myconn = new MySQL_Connection();
}
void attach_connection(PgSQL_Data_Stream&) {
	// PostgreSQL packet staging does not inspect connection state.
}

void set_session_idle_ms(MySQL_Thread*, int ms) { mysql_thread___session_idle_ms = ms; }
void set_session_idle_ms(PgSQL_Thread*, int ms) { pgsql_thread___session_idle_ms = ms; }

void transfer(BIO* from, BIO* to) {
	char buffer[4096];
	int n;
	while ((n = BIO_read(from, buffer, sizeof(buffer))) > 0) require(BIO_write(to, buffer, n) == n, "BIO transfer");
}

size_t fill_socket(int fd) {
	char data[4096] = {};
	size_t total = 0;
	ssize_t n;
	while ((n = send(fd, data, sizeof(data), 0)) > 0) total += n;
	require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "socket filled");
	return total;
}

void drain_socket(int fd) {
	char buffer[65536];
	while (recv(fd, buffer, sizeof(buffer), 0) > 0) {}
}

/**
 * @brief A frontend session and its client data stream, registered on a worker as if accepted
 *   and idle for longer than 'session_idle_ms'. Optionally TLS, with the handshake completed
 *   against an in-memory client.
 */
template<class Thread, class Session, class Stream>
struct Frontend {
	Thread& worker;
	Session* sess = nullptr;
	Stream* myds = nullptr;
	int fds[2] = { -1, -1 };
	SSL_CTX* server_ctx = nullptr;
	SSL_CTX* client_ctx = nullptr;
	SSL* peer = nullptr;
	bool moved = false;

	Frontend(Thread& w, bool tls, const std::filesystem::path& certs) : worker(w) {
		require(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");
		for (int fd : fds) require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "O_NONBLOCK");
		int size = 1024;
		require(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0, "SO_SNDBUF");
		sess = new Session();
		myds = new Stream();
		myds->init(MYDS_FRONTEND, sess, fds[0]);
		attach_connection(*myds);
		sess->client_myds = myds;
		sess->thread = &worker;
		// Not counted as a client connection: the destructor then skips the hostgroup manager
		// counters, which the unit harness does not create. The move check does not look at it.
		sess->connections_handler = true;
		if (tls) start_tls(certs);
		worker.mysql_sessions->add(sess);
		worker.mypolls.add(POLLIN, fds[0], myds, 0);
		// Idle since long before 'curtime': only the pending-output check can keep it on the worker.
		worker.mypolls.last_recv[myds->poll_fds_idx] = 0;
		worker.mypolls.last_sent[myds->poll_fds_idx] = 0;
	}

	void start_tls(const std::filesystem::path& certs) {
		server_ctx = SSL_CTX_new(TLS_server_method());
		client_ctx = SSL_CTX_new(TLS_client_method());
		require(server_ctx && client_ctx, "SSL_CTX_new");
		require(SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION) == 1, "server TLS 1.3 minimum");
		require(SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION) == 1, "client TLS 1.3 minimum");
		require(SSL_CTX_use_certificate_file(server_ctx, (certs / "proxysql-cert.pem").c_str(), SSL_FILETYPE_PEM) == 1, "certificate");
		require(SSL_CTX_use_PrivateKey_file(server_ctx, (certs / "proxysql-key.pem").c_str(), SSL_FILETYPE_PEM) == 1, "private key");
		myds->encrypted = true;
		myds->ssl = SSL_new(server_ctx);
		myds->rbio_ssl = BIO_new(BIO_s_mem());
		myds->wbio_ssl = BIO_new(BIO_s_mem());
		SSL_set_bio(myds->ssl, myds->rbio_ssl, myds->wbio_ssl);
		SSL_set_accept_state(myds->ssl);
		peer = SSL_new(client_ctx);
		BIO* input = BIO_new(BIO_s_mem());
		BIO* output = BIO_new(BIO_s_mem());
		SSL_set_bio(peer, input, output);
		SSL_set_connect_state(peer);
		for (int i = 0; i < 20 && (!SSL_is_init_finished(peer) || !SSL_is_init_finished(myds->ssl)); ++i) {
			SSL_do_handshake(peer);
			transfer(output, myds->rbio_ssl);
			SSL_do_handshake(myds->ssl);
			transfer(myds->wbio_ssl, input);
		}
		require(SSL_is_init_finished(peer) && SSL_is_init_finished(myds->ssl), "TLS handshake");
	}

	/** @brief Queues a response and writes it to a full socket: the ciphertext write is short. */
	void short_write_response() {
		fill_socket(fds[0]);
		const std::string payload(16000, 'r');
		void* packet = l_alloc(payload.size());
		memcpy(packet, payload.data(), payload.size());
		myds->PSarrayOUT->add(packet, payload.size());
		myds->array2buffer_full();
		myds->write_to_net();
	}

	/** @brief The peer reads everything and the worker flushes the remaining ciphertext. */
	void flush_to_peer() {
		for (int i = 0; i < 1000 && myds->ssl_write_len; ++i) {
			drain_socket(fds[1]);
			myds->write_to_net_poll();
			if (myds->ssl_write_len) std::this_thread::sleep_for(1ms);
		}
		drain_socket(fds[1]);
	}

	bool try_move() {
		// A moved session is no longer in the worker's poll array.
		if (moved) return true;
		worker.curtime = monotonic_time();
		moved = worker.template move_session_to_idle_mysql_sessions<Thread, Stream>(myds, myds->poll_fds_idx);
		return moved;
	}

	~Frontend() {
		if (moved) {
			for (unsigned int i = 0; i < worker.idle_mysql_sessions->len; i++) {
				if (worker.idle_mysql_sessions->index(i) == sess) {
					worker.idle_mysql_sessions->remove_index_fast(i);
					break;
				}
			}
		} else {
			worker.mypolls.remove_index_fast(myds->poll_fds_idx);
			myds->mypolls = nullptr;
			for (unsigned int i = 0; i < worker.mysql_sessions->len; i++) {
				if (worker.mysql_sessions->index(i) == sess) {
					worker.mysql_sessions->remove_index_fast(i);
					break;
				}
			}
		}
		// The data stream destructor does not release pending ciphertext.
		free(myds->ssl_write_buf);
		myds->ssl_write_buf = nullptr;
		myds->ssl_write_len = 0;
		sess->thread = nullptr;
		// The session owns its client data stream, as in production: deleting the session deletes
		// the stream, which closes fds[0] and frees the server SSL with its BIOs.
		delete sess;
		myds = nullptr;
		close(fds[1]);
		if (peer) SSL_free(peer);
		if (server_ctx) SSL_CTX_free(server_ctx);
		if (client_ctx) SSL_CTX_free(client_ctx);
	}
};

template<class Thread, class Session, class Stream>
void check_protocol(const char* name, const std::filesystem::path& certs) {
	Thread worker;
	require(worker.init(), "worker init");
	set_session_idle_ms(&worker, 1);
	using F = Frontend<Thread, Session, Stream>;

	{
		F f(worker, false, certs);
		ok(f.try_move(), "%s: an idle plaintext session with no pending output moves to an idle thread", name);
	}
	{
		F f(worker, true, certs);
		ok(f.try_move(), "%s: an idle TLS session with no pending output moves to an idle thread", name);
	}
	{
		F f(worker, true, certs);
		f.short_write_response();
		const bool state = !f.myds->available_data_out() && f.myds->ssl_write_len > 0;
		ok(state, "%s: after a short TLS write the plaintext queues are empty and ciphertext is pending (ssl_write_len=%zu)",
			name, f.myds->ssl_write_len);
		const bool kept = state && !f.try_move();
		ok(kept, "%s: a TLS session with ciphertext pending after a short write stays on the worker", name);
		if (kept) f.flush_to_peer();
		ok(kept && f.myds->ssl_write_len == 0 && f.try_move(),
			"%s: once its ciphertext is flushed the session moves to an idle thread", name);
	}
	{
		F f(worker, true, certs);
		// Ciphertext produced by SSL_write() but not yet read out of the write BIO.
		const char data[] = "pending";
		require(SSL_write(f.myds->ssl, data, sizeof(data)) == (int)sizeof(data), "SSL_write");
		require(BIO_ctrl_pending(f.myds->wbio_ssl) > 0, "ciphertext in write BIO");
		ok(!f.try_move(), "%s: a TLS session with ciphertext in its write BIO stays on the worker", name);
	}
}

} // namespace

int main(int, char** argv) {
	plan(12);
	test_init_minimal();
	GloVars.global.idle_threads = true;
	auto root = std::filesystem::canonical(argv[0]);
	for (int i = 0; i < 5; ++i) root = root.parent_path();
	const auto certs = root / "test/tap/tests/test_cluster_sync_config/test_cluster_sync_nomonitor";
	check_protocol<MySQL_Thread, MySQL_Session, MySQL_Data_Stream>("MySQL", certs);
	check_protocol<PgSQL_Thread, PgSQL_Session, PgSQL_Data_Stream>("PostgreSQL", certs);
	test_cleanup_minimal();
	return exit_status();
}
