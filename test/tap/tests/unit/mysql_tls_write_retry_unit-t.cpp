/**
 * Regression for #6225: SSL_write can accept plaintext even when flushing
 * its ciphertext to a nonblocking socket returns EAGAIN. Retrying must not
 * encrypt the same plaintext twice. Exercise the real stream, TLS and socket
 * implementations, with a full send buffer instead of timing or syscall mocks.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"
#include <algorithm>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static void require(bool condition, const char *what) {
	if (!condition) BAIL_OUT("%s (errno=%d, OpenSSL=%lu)", what, errno, ERR_peek_error());
}

static SSL_CTX *server_context() {
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	EVP_PKEY *key = nullptr;
	require(ctx && key_ctx, "allocate TLS context and key generator");
	require(EVP_PKEY_keygen_init(key_ctx) == 1 &&
		EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) == 1 &&
		EVP_PKEY_keygen(key_ctx, &key) == 1, "generate test key");
	EVP_PKEY_CTX_free(key_ctx);
	X509 *cert = X509_new();
	require(cert != nullptr, "allocate test certificate");
	require(X509_set_version(cert, 2) == 1 &&
		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1 &&
		X509_gmtime_adj(X509_getm_notBefore(cert), -60) &&
		X509_gmtime_adj(X509_getm_notAfter(cert), 3600) &&
		X509_set_pubkey(cert, key) == 1, "initialize test certificate");
	X509_NAME *name = X509_get_subject_name(cert);
	require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		reinterpret_cast<const unsigned char *>("localhost"), -1, -1, 0) == 1 &&
		X509_set_issuer_name(cert, name) == 1 &&
		X509_sign(cert, key, EVP_sha256()) > 0 &&
		SSL_CTX_use_certificate(ctx, cert) == 1 &&
		SSL_CTX_use_PrivateKey(ctx, key) == 1, "install test certificate");
	X509_free(cert);
	EVP_PKEY_free(key);
	return ctx;
}

static void transfer(BIO *from, BIO *to) {
	char buf[4096];
	int n;
	while ((n = BIO_read(from, buf, sizeof(buf))) > 0)
		require(BIO_write(to, buf, n) == n, "transfer handshake bytes");
}

static void handshake(SSL *server, SSL *client) {
	for (int i = 0; i < 100; ++i) {
		for (SSL *ssl : {client, server}) {
			ERR_clear_error();
			int rc = SSL_do_handshake(ssl);
			int error = rc == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, rc);
			require(error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ ||
				error == SSL_ERROR_WANT_WRITE, "complete TLS handshake");
			transfer(SSL_get_wbio(ssl), SSL_get_rbio(ssl == server ? client : server));
		}
		if (SSL_is_init_finished(server) && SSL_is_init_finished(client)) return;
	}
	BAIL_OUT("TLS handshake did not finish");
}

static void receive_plaintext(int fd, SSL *client, std::string &received) {
	char buf[4096];
	ssize_t n;
	while ((n = recv(fd, buf, sizeof(buf), 0)) > 0)
		require(BIO_write(SSL_get_rbio(client), buf, n) == n, "receive ciphertext");
	require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "drain nonblocking socket");
	for (;;) {
		ERR_clear_error();
		int rc = SSL_read(client, buf, sizeof(buf));
		if (rc > 0) {
			received.append(buf, rc);
		} else {
			require(SSL_get_error(client, rc) == SSL_ERROR_WANT_READ, "decrypt complete TLS records");
			break;
		}
	}
}

static void test_retry(SSL_CTX *server_ctx, int version, bool full_socket) {
	diag("TLS %s, %s", version == TLS1_2_VERSION ? "1.2" : "1.3",
		full_socket ? "EAGAIN" : "short socket write");
	int fds[2];
	require(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "create socket pair");
	for (int fd : fds) require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "set nonblocking socket");
	int send_buffer = 1024;
	require(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0,
		"limit socket send buffer");
	MySQL_Data_Stream stream;
	stream.myds_type = MYDS_FRONTEND;
	stream.fd = fds[0];
	stream.encrypted = true;
	stream.ssl = SSL_new(server_ctx);
	SSL_CTX *client_ctx = SSL_CTX_new(TLS_method());
	require(stream.ssl && client_ctx, "allocate TLS endpoints");
	SSL *client = SSL_new(client_ctx);
	require(client != nullptr, "allocate TLS client");
	for (SSL *ssl : {stream.ssl, client}) {
		require(SSL_set_min_proto_version(ssl, version) == 1 &&
			SSL_set_max_proto_version(ssl, version) == 1, "select TLS version");
		BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
		require(in && out, "allocate TLS memory BIOs");
		SSL_set_bio(ssl, in, out);
	}
	SSL_set_accept_state(stream.ssl);
	SSL_set_connect_state(client);
	stream.rbio_ssl = SSL_get_rbio(stream.ssl);
	stream.wbio_ssl = SSL_get_wbio(stream.ssl);
	handshake(stream.ssl, client);

	// Fill the transport before SSL_write, so its first ciphertext flush must
	// return EAGAIN. These filler bytes are discarded before decoding TLS.
	size_t filler = 0;
	char buf[4096] = {};
	if (full_socket) {
		ssize_t n;
		while ((n = send(fds[0], buf, sizeof(buf), 0)) > 0) {
			filler += n;
			require(filler < 16 * 1024 * 1024, "bound send buffer fill");
		}
		require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "fill socket to EAGAIN");
	}
	std::string payload(16384, '\0');
	for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
	require(payload.size() <= stream.queueOUT.size, "payload fits plaintext queue");
	memcpy(stream.queueOUT.buffer, payload.data(), payload.size());
	stream.queueOUT.head = payload.size();
	int rc = stream.write_to_net();
	ok(rc == static_cast<int>(payload.size()), "report plaintext accepted by TLS despite backpressure");
	ok(stream.queueOUT.head == 0 && stream.queueOUT.tail == 0, "consume accepted plaintext exactly once");
	ok(stream.ssl_write_len > 0, "retain ciphertext that the socket could not accept");
	ok(stream.active && !stream.net_failure, "backpressure keeps the stream healthy");
	ok(stream.bytes_info.bytes_sent == payload.size(), "account accepted plaintext once");
	while (filler) {
		ssize_t n = recv(fds[1], buf, std::min(filler, sizeof(buf)), 0);
		require(n > 0, "discard socket filler");
		filler -= n;
	}

	std::string received;
	for (int i = 0; i < 100; ++i) {
		receive_plaintext(fds[1], client, received);
		if (stream.ssl_write_len == 0 && stream.queueOUT.head == stream.queueOUT.tail) break;
		ERR_clear_error();
		stream.write_to_net();
	}
	receive_plaintext(fds[1], client, received);
	ok(stream.ssl_write_len == 0, "retries drain all pending ciphertext");
	ok(received == payload, "TLS peer receives the exact payload with no duplicated or lost bytes (got %zu)", received.size());
	ok(stream.bytes_info.bytes_sent == payload.size(), "retries do not double-count plaintext");
	SSL_free(client);
	SSL_CTX_free(client_ctx);
	close(fds[1]);
	// A failing implementation may leave pending output; the stream destructor
	// does not release this buffer when the test abandons a connection.
	free(stream.ssl_write_buf);
	stream.ssl_write_buf = nullptr;
	stream.ssl_write_len = 0;
}

int main() {
	plan(33);
	ok(test_init_minimal() == 0, "initialize test globals");
	SSL_CTX *ctx = server_context();
	for (int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
		test_retry(ctx, version, true);
		test_retry(ctx, version, false);
	}
	SSL_CTX_free(ctx);
	test_cleanup_minimal();
	return exit_status();
}
