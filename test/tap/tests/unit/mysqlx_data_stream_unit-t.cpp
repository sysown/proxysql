#include "mysqlx_data_stream.h"
#include "tap.h"

#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

// Queue application data and close_notify into one socket write, so the
// regression does not depend on how the kernel schedules two peer writes.
static void test_tls_data_before_shutdown(int version, size_t data_size) {
	diag(">>> TLS %x, application bytes %zu", version, data_size);
	SSL_CTX* peer_ctx = SSL_CTX_new(TLS_method());
	SSL_CTX* client_ctx = SSL_CTX_new(TLS_method());
	if (!peer_ctx || !client_ctx) BAIL_OUT("TLS context allocation failed");
	SSL_CTX_set_min_proto_version(peer_ctx, version);
	SSL_CTX_set_max_proto_version(peer_ctx, version);
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, nullptr);
	X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(client_ctx), "localhost", 0);
	EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
	EVP_PKEY* key = nullptr;
	if (!key_ctx || EVP_PKEY_keygen_init(key_ctx) != 1 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_ctx, NID_X9_62_prime256v1) != 1 ||
	    EVP_PKEY_keygen(key_ctx, &key) != 1) BAIL_OUT("TLS key generation failed");
	EVP_PKEY_CTX_free(key_ctx);
	X509* cert = X509_new();
	if (!cert) BAIL_OUT("TLS certificate allocation failed");
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	X509_NAME* name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                          reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
	X509_set_issuer_name(cert, name);
	if (X509_sign(cert, key, EVP_sha256()) <= 0 ||
	    SSL_CTX_use_certificate(peer_ctx, cert) != 1 ||
	    SSL_CTX_use_PrivateKey(peer_ctx, key) != 1) BAIL_OUT("TLS certificate setup failed");
	if (X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx), cert) != 1) {
		BAIL_OUT("TLS test trust store setup failed");
	}
	X509_free(cert);
	EVP_PKEY_free(key);

	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) BAIL_OUT("socketpair failed");
	MysqlxDataStream ds;
	ds.init(XDS_BACKEND, fds[0]);
	ds.init_ssl_connect(client_ctx);
	SSL* peer = SSL_new(peer_ctx);
	if (!ds.get_ssl() || !peer) BAIL_OUT("SSL allocation failed");
	SSL_set_bio(peer, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
	SSL_set_accept_state(peer);
	char bytes[16384];
	auto flush_peer = [peer, &bytes, &fds]() {
		int n;
		while ((n = BIO_read(SSL_get_wbio(peer), bytes, sizeof(bytes))) > 0) {
			if (send(fds[1], bytes, n, 0) != n) BAIL_OUT("TLS peer write failed");
		}
	};
	for (int i = 0; i < 100 &&
	     (!ds.ssl_handshake_complete() || !SSL_is_init_finished(peer)); ++i) {
		ds.do_ssl_handshake();
		ds.flush_ssl_write_buf();
		int n;
		while ((n = recv(fds[1], bytes, sizeof(bytes), MSG_DONTWAIT)) > 0) {
			BIO_write(SSL_get_rbio(peer), bytes, n);
		}
		SSL_do_handshake(peer);
		flush_peer();
		ds.read_from_net();
	}
	if (!ds.ssl_handshake_complete() || !SSL_is_init_finished(peer)) {
		BAIL_OUT("TLS handshake failed");
	}
	const uint8_t frames[] = {1, 0, 0, 0, 17, 1, 0, 0, 0, 17};
	if (data_size && SSL_write(peer, frames, data_size) != static_cast<int>(data_size)) {
		BAIL_OUT("TLS application write failed");
	}
	SSL_shutdown(peer);
	flush_peer();
	const ssize_t received = ds.read_from_net();
	if (data_size == sizeof(frames)) {
		ok(received > 0, "application frames preceding close_notify are reported as data");
		for (int i = 0; i < 2; ++i) {
			ok(ds.read_from_net() > 0, "buffered frame %d remains readable after close_notify", i + 1);
			ok(ds.has_complete_frame() && ds.front_frame() == MysqlxFrame(frames, frames + 5),
			   "final application frame %d is preserved", i + 1);
			ds.pop_frame();
		}
	} else {
		ok(received == 0, "shutdown without a complete frame reports EOF");
	}
	ok(!ds.has_complete_frame(), "no extra application frames remain");
	ok(ds.read_from_net() == 0, "TLS shutdown remains EOF while the peer TCP socket stays open");
	SSL_free(peer);
	close(fds[0]);
	close(fds[1]);
	SSL_CTX_free(peer_ctx);
	SSL_CTX_free(client_ctx);
}

static void test_frame_header_parse() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t frame[] = {
		0x0a, 0x00, 0x00, 0x00,
		0x01,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	};
	ds.feed_bytes(frame, sizeof(frame));
	ok(ds.has_complete_frame(), "complete frame detected");
	if (ds.has_complete_frame()) {
		auto& pkt = ds.front_frame();
		ok(pkt.size() == 14, "frame total size is 14 (4 header + 10 payload)");
		ok(pkt[4] == 0x01, "message type is 1");
	}
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "no more frames after pop");
}

static void test_partial_frame() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t hdr[] = {0x0a, 0x00, 0x00, 0x00, 0x01};
	ds.feed_bytes(hdr, 5);
	ok(!ds.has_complete_frame(), "no complete frame with header only");
	uint8_t body[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	ds.feed_bytes(body, 9);
	ok(ds.has_complete_frame(), "frame complete after body arrives");
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "empty after pop");
}

static void test_multiple_frames() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t f1[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0xAA};
	uint8_t f2[] = {0x02, 0x00, 0x00, 0x00, 0x02, 0xBB};
	uint8_t both[12];
	memcpy(both, f1, 6);
	memcpy(both + 6, f2, 6);
	ds.feed_bytes(both, 12);
	ok(ds.has_complete_frame(), "first frame ready");
	ok(ds.front_frame()[4] == 0x01, "first frame type is 1");
	ds.pop_frame();
	ok(ds.has_complete_frame(), "second frame ready");
	ok(ds.front_frame()[4] == 0x02, "second frame type is 2");
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "empty after both popped");
}

static void test_frame_enqueue_write() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t body[] = {0x01, 0x02, 0x03};
	ds.enqueue_frame(0x0E, body, 3);
	ok(ds.write_buffer_size() == 8, "write buffer has 4 header + 1 msg_type + 3 body = 8 bytes");
	const auto& wb = ds.write_buffer_raw();
	ok(wb[0] == 0x04, "payload_size byte 0 is 4");
	ok(wb[4] == 0x0E, "message type is 0x0E");
}

static void test_parse_error_zero_payload() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t bad[] = {0x00, 0x00, 0x00, 0x00, 0x01};
	ds.feed_bytes(bad, 5);
	ok(ds.has_parse_error(), "zero payload_size sets parse error");
	ok(!ds.has_complete_frame(), "no frame produced after parse error");
}

static void test_parse_error_oversized_payload() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t big[] = {0x01, 0x00, 0x00, 0x01, 0x01};
	ds.feed_bytes(big, 5);
	ok(ds.has_parse_error(), "oversized payload (>16MB) sets parse error");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(0);
	diag("=== mysqlx_data_stream_unit-t starting ===");

	test_frame_header_parse();
	test_partial_frame();
	test_multiple_frames();
	test_frame_enqueue_write();
	test_parse_error_zero_payload();
	test_parse_error_oversized_payload();
	for (int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
		for (size_t data_size : {0u, 3u, 10u}) {
			test_tls_data_before_shutdown(version, data_size);
		}
	}

	return exit_status();
}
