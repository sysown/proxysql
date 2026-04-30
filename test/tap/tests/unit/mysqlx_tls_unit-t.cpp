#include "mysqlx_data_stream.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

static void test_init_ssl_null_ctx() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	ds.init(XDS_FRONTEND, -1);
	ds.init_ssl(nullptr);
	ok(!ds.ssl_init_done(), "init_ssl with null ctx does not init SSL");
	ok(!ds.is_encrypted(), "not encrypted with null ctx");
	ok(!ds.ssl_handshake_complete(), "handshake not complete with null ctx");
}

static void test_non_tls_read_write_unchanged() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxDataStream ds;
	ds.init(XDS_FRONTEND, fds[0]);

	write_x_frame(fds[1], 0x0E, nullptr, 0);

	usleep(5000);
	ssize_t r = ds.read_from_net();
	ok(r > 0, "non-TLS read_from_net reads bytes");
	ok(ds.has_complete_frame(), "non-TLS parse produces complete frame");

	ds.enqueue_frame(0x0E, nullptr, 0);
	r = ds.write_to_net();
	ok(r > 0, "non-TLS write_to_net sends bytes");

	close(fds[0]); close(fds[1]);
}

static SSL_CTX* create_test_ssl_ctx() {
	SSL_CTX* ctx = SSL_CTX_new(TLS_method());
	if (!ctx) return nullptr;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	EVP_PKEY* pkey = EVP_PKEY_new();
	RSA* rsa = RSA_new();
	BIGNUM* bn = BN_new();
	BN_set_word(bn, RSA_F4);
	RSA_generate_key_ex(rsa, 2048, bn, nullptr);
	EVP_PKEY_assign_RSA(pkey, rsa);
	BN_free(bn);

	X509* x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	X509_set_pubkey(x509, pkey);

	X509_NAME* name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(unsigned char*)"test", -1, -1, 0);
	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);
	X509_NAME_free(name);

	X509_sign(x509, pkey, EVP_sha256());

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	return ctx;
}

static void test_ssl_handshake_and_io() {
	diag(">>> %s", __func__);
	SSL_CTX* server_ctx = create_test_ssl_ctx();
	SSL_CTX* client_ctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
	// Test-only: using self-signed test certs, no CA to verify against
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);

	if (!server_ctx || !client_ctx) {
		ok(false, "SSL CTX creation failed");
		for (int i = 0; i < 9; i++) ok(false, "placeholder");
		SSL_CTX_free(server_ctx);
		SSL_CTX_free(client_ctx);
		return;
	}

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxDataStream server_ds;
	server_ds.init(XDS_FRONTEND, fds[0]);
	server_ds.init_ssl(server_ctx);
	ok(server_ds.ssl_init_done(), "server SSL initialized");

	SSL* client_ssl = SSL_new(client_ctx);
	BIO* client_rbio = BIO_new(BIO_s_mem());
	BIO* client_wbio = BIO_new(BIO_s_mem());
	SSL_set_bio(client_ssl, client_rbio, client_wbio);
	SSL_set_connect_state(client_ssl);

	int client_done = 0;
	int server_done = 0;
	char shuttle[16384];

	for (int i = 0; i < 40 && (!client_done || !server_done); i++) {
		if (!server_done) {
			server_ds.read_from_net();
			server_done = server_ds.do_ssl_handshake();
			server_ds.flush_ssl_write_buf();
		}

		int net_r;
		while ((net_r = recv(fds[1], shuttle, sizeof(shuttle), MSG_DONTWAIT)) > 0) {
			BIO_write(client_rbio, shuttle, net_r);
		}

		if (!client_done) {
			int r = SSL_do_handshake(client_ssl);
			if (r == 1) {
				client_done = 1;
			}
			int n;
			while ((n = BIO_read(client_wbio, shuttle, sizeof(shuttle))) > 0) {
				send(fds[1], shuttle, n, 0);
			}
		}

		usleep(5000);
	}

	ok(server_done, "SSL handshake completed on server side");
	ok(server_ds.is_encrypted(), "is_encrypted flag set after handshake");
	ok(client_done, "SSL handshake completed on client side");

	{
		uint8_t x_frame[] = {0x03, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x02};
		SSL_write(client_ssl, x_frame, sizeof(x_frame));
		int n;
		while ((n = BIO_read(client_wbio, shuttle, sizeof(shuttle))) > 0) {
			send(fds[1], shuttle, n, 0);
		}
		usleep(10000);

		ssize_t net_bytes = 0;
		char tmp[65536];
		ssize_t nr = recv(fds[0], tmp, sizeof(tmp), MSG_DONTWAIT);
		if (nr > 0 && server_ds.get_rbio_ssl()) {
			BIO_write(server_ds.get_rbio_ssl(), tmp, nr);
			net_bytes = nr;
		}
		ok(net_bytes > 0, "encrypted bytes received from client");

		if (server_ds.get_ssl()) {
			uint8_t plain[65536];
			int dec = SSL_read(server_ds.get_ssl(), plain, sizeof(plain));
			if (dec > 0) {
				server_ds.feed_bytes(plain, dec);
			}
		}
		ok(server_ds.has_complete_frame(), "encrypted read produces complete frame after SSL_read");
		if (server_ds.has_complete_frame()) {
			const auto& frame = server_ds.front_frame();
			ok(frame[4] == 0x0E, "encrypted frame has correct message type");
		} else {
			ok(false, "encrypted frame has correct message type");
		}
		server_ds.pop_frame();
	}

	{
		server_ds.enqueue_frame(0x0E, nullptr, 0);
		server_ds.write_to_net();

		if (server_ds.has_ssl_pending_write()) {
			server_ds.flush_ssl_write_buf();
		}

		usleep(5000);
		int resp_len = recv(fds[1], shuttle, sizeof(shuttle), MSG_DONTWAIT);
		if (resp_len > 0) {
			BIO_write(client_rbio, shuttle, resp_len);
			char resp[64];
			int r = SSL_read(client_ssl, resp, sizeof(resp));
			ok(r == 5, "client received encrypted response frame (5 bytes)");
			if (r == 5) {
				ok(resp[4] == 0x0E, "encrypted response has correct message type");
			} else {
				ok(false, "encrypted response has correct message type");
			}
		} else {
			ok(false, "client received encrypted response frame");
			ok(false, "encrypted response has correct message type");
		}
	}

	SSL_free(client_ssl);
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);
	close(fds[0]); close(fds[1]);
}

static void test_has_ssl_pending_write() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	ds.init(XDS_FRONTEND, -1);
	ok(!ds.has_ssl_pending_write(), "no pending write without SSL");
}

static void test_ssl_connect_init() {
	diag(">>> %s", __func__);
	SSL_CTX* ctx = create_test_ssl_ctx();
	if (!ctx) {
		ok(false, "init_ssl_connect creates SSL object");
		return;
	}

	MysqlxDataStream ds;
	ds.init(XDS_BACKEND, -1);
	ds.init_ssl_connect(ctx);
	ok(ds.ssl_init_done(), "init_ssl_connect creates SSL object");
	ok(!ds.ssl_handshake_complete(), "handshake not complete initially");

	SSL_CTX_free(ctx);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(18);
	diag("=== mysqlx_tls_unit-t starting ===");

	test_init_ssl_null_ctx();
	test_non_tls_read_write_unchanged();
	test_ssl_handshake_and_io();
	test_has_ssl_pending_write();
	test_ssl_connect_init();

	return exit_status();
}
