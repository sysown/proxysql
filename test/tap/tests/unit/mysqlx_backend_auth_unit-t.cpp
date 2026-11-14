#include "mysqlx_connection.h"
#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_notice.pb.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

static std::vector<uint8_t> build_x_frame(uint8_t msg_type,
                                         const uint8_t* payload,
                                         size_t payload_len) {
	const uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	std::vector<uint8_t> frame(5 + payload_len);
	frame[0] = size & 0xFF;
	frame[1] = (size >> 8) & 0xFF;
	frame[2] = (size >> 16) & 0xFF;
	frame[3] = (size >> 24) & 0xFF;
	frame[4] = msg_type;
	if (payload_len > 0) {
		memcpy(frame.data() + 5, payload, payload_len);
	}
	return frame;
}

static ssize_t read_x_frame_with_timeout(int fd, uint8_t* buf, size_t buf_size, int timeout_ms) {
	struct pollfd pfd { fd, POLLIN, 0 };
	if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
	uint8_t header[5];
	ssize_t r;
	do {
		r = read(fd, header, sizeof(header));
	} while (r < 0 && errno == EINTR);
	if (r != 5) return -1;
	const uint32_t payload_size = static_cast<uint32_t>(header[0]) |
		(static_cast<uint32_t>(header[1]) << 8) |
		(static_cast<uint32_t>(header[2]) << 16) |
		(static_cast<uint32_t>(header[3]) << 24);
	const size_t total = 4 + payload_size;
	if (total > buf_size) return -1;
	memcpy(buf, header, 5);
	if (payload_size > 1) {
		if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
		do {
			r = read(fd, buf + 5, payload_size - 1);
		} while (r < 0 && errno == EINTR);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return static_cast<ssize_t>(total);
}

static int reject_client_cert_cb(int, X509_STORE_CTX*) {
	return 0;
}

static SSL_CTX* create_test_ssl_ctx() {
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
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
		(const unsigned char*)"test", -1, -1, 0);
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

static int permissive_peer_verify_cb(int, X509_STORE_CTX*) {
	// Mirrors src/proxy_tls.cpp::callback_ssl_verify_peer. The shared core
	// context accepts every certificate; the PLAIN peer check must not rely
	// on this inherited callback.
	return 1;
}

struct TestCa {
	X509* cert = nullptr;
	EVP_PKEY* key = nullptr;
	~TestCa() {
		X509_free(cert);
		EVP_PKEY_free(key);
	}
};

static EVP_PKEY* generate_test_rsa_key() {
	EVP_PKEY* pkey = EVP_PKEY_new();
	RSA* rsa = RSA_new();
	BIGNUM* bn = BN_new();
	if (!pkey || !rsa || !bn ||
	    BN_set_word(bn, RSA_F4) != 1 ||
	    RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
		BN_free(bn);
		RSA_free(rsa);
		EVP_PKEY_free(pkey);
		return nullptr;
	}
	BN_free(bn);
	EVP_PKEY_assign_RSA(pkey, rsa);
	return pkey;
}

static bool add_x509_extension(X509* cert, X509* issuer, int nid, const char* value) {
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
	X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid,
	                                          const_cast<char*>(value));
	if (!ext) return false;
	const int rc = X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return rc == 1;
}

static bool create_test_ca(TestCa& ca) {
	ca.key = generate_test_rsa_key();
	if (!ca.key) return false;
	ca.cert = X509_new();
	if (!ca.cert) return false;
	X509_set_version(ca.cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(ca.cert), 1);
	X509_gmtime_adj(X509_get_notBefore(ca.cert), 0);
	X509_gmtime_adj(X509_get_notAfter(ca.cert), 31536000L);
	X509_set_pubkey(ca.cert, ca.key);
	X509_NAME* name = X509_NAME_new();
	if (!name) return false;
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(const unsigned char*)"ProxySQL MySQLX Test CA", -1, -1, 0);
	X509_set_subject_name(ca.cert, name);
	X509_set_issuer_name(ca.cert, name);
	X509_NAME_free(name);
	if (!add_x509_extension(ca.cert, ca.cert, NID_basic_constraints,
	                        "critical,CA:TRUE")) {
		return false;
	}
	return X509_sign(ca.cert, ca.key, EVP_sha256()) != 0;
}

static SSL_CTX* create_signed_backend_peer_ctx(const TestCa& ca, const char* san) {
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) return nullptr;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	EVP_PKEY* key = generate_test_rsa_key();
	X509* cert = X509_new();
	if (!key || !cert) {
		EVP_PKEY_free(key);
		X509_free(cert);
		SSL_CTX_free(ctx);
		return nullptr;
	}
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
	X509_set_pubkey(cert, key);

	X509_NAME* name = X509_NAME_new();
	if (!name) {
		EVP_PKEY_free(key);
		X509_free(cert);
		SSL_CTX_free(ctx);
		return nullptr;
	}
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(const unsigned char*)"backend.test", -1, -1, 0);
	X509_set_subject_name(cert, name);
	X509_set_issuer_name(cert, X509_get_subject_name(ca.cert));
	X509_NAME_free(name);

	if (!add_x509_extension(cert, ca.cert, NID_basic_constraints,
	                        "critical,CA:FALSE") ||
	    (san != nullptr && *san != '\0' &&
	     !add_x509_extension(cert, ca.cert, NID_subject_alt_name, san)) ||
	    X509_sign(cert, ca.key, EVP_sha256()) == 0) {
		EVP_PKEY_free(key);
		X509_free(cert);
		SSL_CTX_free(ctx);
		return nullptr;
	}

	const bool ok_ctx =
		SSL_CTX_use_certificate(ctx, cert) == 1 &&
		SSL_CTX_use_PrivateKey(ctx, key) == 1 &&
		SSL_CTX_check_private_key(ctx) == 1;
	X509_free(cert);
	EVP_PKEY_free(key);
	if (!ok_ctx) {
		SSL_CTX_free(ctx);
		return nullptr;
	}
	return ctx;
}

static SSL_CTX* create_permissive_shared_ctx(X509* trusted_ca) {
	// Same shape as production: a server-method core SSL_CTX carrying a
	// local certificate, with the permissive core verify callback installed.
	SSL_CTX* ctx = create_test_ssl_ctx();
	if (!ctx) return nullptr;
	if (trusted_ca != nullptr &&
	    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), trusted_ca) != 1) {
		SSL_CTX_free(ctx);
		return nullptr;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
	                   permissive_peer_verify_cb);
	return ctx;
}

static bool enable_anonymous_tls12(SSL_CTX* ctx) {
	if (!ctx) return false;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_security_level(ctx, 0);
	// Server-side ADH suites need group parameters; AECDH suites do not.
	SSL_CTX_set_dh_auto(ctx, 1);
	return SSL_CTX_set_cipher_list(ctx, "aNULL:@SECLEVEL=0") == 1;
}

static SSL_CTX* create_anonymous_backend_peer_ctx() {
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (!enable_anonymous_tls12(ctx)) {
		SSL_CTX_free(ctx);
		return nullptr;
	}
	return ctx;
}

static bool write_all_fd(int fd, const uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
		if (n > 0) { off += static_cast<size_t>(n); continue; }
		if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd { fd, POLLOUT, 0 };
			if (poll(&pfd, 1, 1000) <= 0) return false;
			continue;
		}
		return false;
	}
	return true;
}

static int drain_wbio_to_fd(BIO* wbio, int fd) {
	char buf[16384];
	int n;
	int total = 0;
	while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0) {
		if (!write_all_fd(fd, reinterpret_cast<const uint8_t*>(buf), n)) return -1;
		total += n;
	}
	return total;
}

static void feed_fd_to_rbio(BIO* rbio, int fd,
                            std::vector<uint8_t>* raw_out = nullptr) {
	char buf[16384];
	ssize_t r;
	while ((r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		if (raw_out) raw_out->insert(raw_out->end(), buf, buf + r);
		BIO_write(rbio, buf, static_cast<int>(r));
	}
}

// Drive a real TLS handshake between the connection's backend stream and a
// test-owned server SSL object over a socketpair. Returns true when both
// sides completed.
static bool drive_backend_tls_handshake(MysqlxConnection& conn, int peer_fd,
                                        SSL* server_ssl, BIO* srbio, BIO* swbio,
                                        std::vector<uint8_t>* raw_out = nullptr) {
	bool client_done = false;
	bool server_done = false;
	for (int i = 0; i < 3000 && !(client_done && server_done); ++i) {
		if (conn.step_auth() < 0) break;
		client_done = conn.backend_ds().ssl_handshake_complete();
		feed_fd_to_rbio(srbio, peer_fd, raw_out);
		int r = SSL_do_handshake(server_ssl);
		if (r == 1) server_done = true;
		drain_wbio_to_fd(swbio, peer_fd);
		usleep(300);
	}
	return client_done && server_done;
}

static std::string read_server_plain(SSL* server_ssl, BIO* srbio, int peer_fd,
                                     int timeout_ms,
                                     std::vector<uint8_t>* raw_out = nullptr) {
	std::string out;
	for (int waited = 0; waited < timeout_ms; waited += 2) {
		char net_buf[16384];
		ssize_t nr;
		while ((nr = recv(peer_fd, net_buf, sizeof(net_buf), MSG_DONTWAIT)) > 0) {
			if (raw_out) raw_out->insert(raw_out->end(), net_buf, net_buf + nr);
			BIO_write(srbio, net_buf, static_cast<int>(nr));
		}
		char buf[4096];
		int n;
		while ((n = SSL_read(server_ssl, buf, sizeof(buf))) > 0) {
			out.append(buf, n);
		}
		if (!out.empty()) break;
		usleep(2000);
	}
	return out;
}

static bool server_write_plain(SSL* server_ssl, BIO* swbio, int peer_fd,
                               const uint8_t* data, size_t len) {
	int n = SSL_write(server_ssl, data, static_cast<int>(len));
	if (n != static_cast<int>(len)) return false;
	return drain_wbio_to_fd(swbio, peer_fd) >= 0;
}

struct PlainTlsPeerResult {
	bool cap_exchange_ok = false;
	bool handshake_completed = false;
	// Actual client-side SSL state, independent of the driver's early-break
	// behavior on conn.step_auth() < 0.
	bool client_tls_completed = false;
	bool auth_error = false;
	bool saw_auth_start = false;
	std::string mechanism;
	std::string auth_data;
	std::vector<uint8_t> ciphertext;
};

// Drive the shipped backend auth state machine through CapabilitiesGet/Set
// and a real TLS handshake against a test peer, then capture whether an
// AuthenticateStart(PLAIN) reached the peer. The connection object is the
// production one; only the peer and its certificate are test-owned.
static PlainTlsPeerResult run_plain_tls_peer_case(
	SSL_CTX* shared_ctx,
	SSL_CTX* peer_ctx,
	const char* endpoint,
	const char* secret) {
	PlainTlsPeerResult result;
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return result;

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_address(endpoint);
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("$A$005$not-a-replayable-secret");
	if (secret != nullptr) {
		// "" is a PRESENT empty credential; nullptr means absent.
		conn.set_backend_plain_password(secret);
	}
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);
	conn.set_ssl_ctx(shared_ctx);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	uint8_t buf[4096];
	ssize_t r = -1;
	if (conn.step_auth() != 1) goto done;
	r = read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	if (r < 5 || buf[4] != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET) goto done;

	{
		Mysqlx::Connection::Capabilities caps;
		std::string caps_str;
		caps.SerializeToString(&caps_str);
		write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
			reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());
	}
	if (conn.step_auth() != 1) goto done;
	r = read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	if (r < 5 || buf[4] != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET) goto done;
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	result.cap_exchange_ok = true;

	{
		// Enter BACKEND_AUTH_TLS_HANDSHAKE and emit the first ClientHello.
		conn.step_auth();
		SSL* server_ssl = SSL_new(peer_ctx);
		BIO* srbio = BIO_new(BIO_s_mem());
		BIO* swbio = BIO_new(BIO_s_mem());
		if (!server_ssl || !srbio || !swbio) {
			SSL_free(server_ssl);
			BIO_free(srbio);
			BIO_free(swbio);
			goto done;
		}
		SSL_set_bio(server_ssl, srbio, swbio);
		SSL_set_accept_state(server_ssl);

		result.handshake_completed = drive_backend_tls_handshake(
			conn, fds[1], server_ssl, srbio, swbio, &result.ciphertext);
		// Capture the real client-side handshake state even when the driver
		// broke out early on an auth rejection.
		result.client_tls_completed =
			conn.backend_ds().ssl_handshake_complete();
		result.auth_error =
			conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR;

		const std::string frame = read_server_plain(
			server_ssl, srbio, fds[1], 500, &result.ciphertext);
		if (frame.size() >= 5 &&
		    static_cast<uint8_t>(frame[4]) ==
		        Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START) {
			Mysqlx::Session::AuthenticateStart auth_start;
			if (auth_start.ParseFromArray(
					frame.data() + 5, static_cast<int>(frame.size() - 5))) {
				result.saw_auth_start = true;
				result.mechanism = auth_start.mech_name();
				result.auth_data = auth_start.auth_data();
			}
		}
		SSL_free(server_ssl);
	}

done:
	close(fds[1]);
	// conn owns fds[0] and closes it in its destructor.
	return result;
}

static void expect_plain_tls_rejected(const PlainTlsPeerResult& result,
                                      const char* label) {
	ok(result.cap_exchange_ok,
	   "%s: CapabilitiesGet/Set exchange completed", label);
	ok(!result.client_tls_completed,
	   "%s: client TLS handshake did not complete for the rejected peer", label);
	ok(result.auth_error,
	   "%s: auth state reports BACKEND_AUTH_ERROR", label);
	ok(!result.saw_auth_start,
	   "%s: no AuthenticateStart is sent to the rejected peer", label);
	ok(result.auth_data.find("plain-secret") == std::string::npos,
	   "%s: verified PLAIN secret is not replayed", label);
}

static void test_plain_tls_trusted_dns_positive() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-dns: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-dns: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	ok(SSL_CTX_get_verify_callback(shared_ctx) != nullptr,
	   "plain-tls-dns: inherited permissive verify callback is installed");

	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", "plain-secret");
	ok(result.handshake_completed,
	   "plain-tls-dns: trusted matching DNS peer completes TLS");
	ok(result.saw_auth_start && result.mechanism == "PLAIN",
	   "plain-tls-dns: matching DNS peer receives PLAIN");
	ok(result.auth_data ==
	       std::string("testdb") + std::string("\0", 1) + "plainuser" +
	           std::string("\0", 1) + "plain-secret",
	   "plain-tls-dns: PLAIN data is schema\\0user\\0verified-secret");

	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_trusted_ip_positive() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-ip: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "IP:127.0.0.1");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-ip: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "127.0.0.1", "plain-secret");
	ok(result.handshake_completed,
	   "plain-tls-ip: trusted matching IP peer completes TLS");
	ok(result.saw_auth_start && result.mechanism == "PLAIN",
	   "plain-tls-ip: matching IP SAN peer receives PLAIN");

	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_trusted_ipv6_positive() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-ipv6: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "IP:::1");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-ipv6: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	// Socketpair transport; the endpoint string is only the peer identity.
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "::1", "plain-secret");
	ok(result.handshake_completed,
	   "plain-tls-ipv6: trusted matching IPv6 peer completes TLS");
	ok(result.saw_auth_start && result.mechanism == "PLAIN",
	   "plain-tls-ipv6: IPv6 IP SAN peer receives PLAIN");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_empty_identity() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-empty-identity: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-empty-identity: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	// A trusted chain is not enough without a configured endpoint identity:
	// fail closed rather than falling back to chain-only acceptance.
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "", "plain-secret");
	expect_plain_tls_rejected(result, "plain-tls-empty-identity");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-empty-identity: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_leading_dot_identity() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-leading-dot: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	// OpenSSL's X509 hostname checker treats a leading dot on the checked
	// name as an implicit sub-domain pattern: ".example.com" matches the
	// certificate identity "test.example.com". This identity is injected at
	// the connection layer (the real AF_INET resolver rejects it); the test
	// verifies the TLS configuration guard, not endpoint reachability.
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:test.example.com");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-leading-dot: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, ".example.com", "plain-secret");
	expect_plain_tls_rejected(result, "plain-tls-leading-dot");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-leading-dot: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_untrusted_cert() {
	diag(">>> %s", __func__);
	// Isolate chain verification from hostname verification: the untrusted
	// leaf has the SAME SAN DNS name as the endpoint, but its issuing CA is
	// deliberately absent from the shared trust store. A hostname-only
	// implementation must not pass this test.
	TestCa untrusted_ca;
	SSL_CTX* shared_ctx = create_permissive_shared_ctx(nullptr);
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(untrusted_ca)) {
		ok(false, "plain-tls-untrusted: untrusted CA created");
		SSL_CTX_free(shared_ctx);
		return;
	}
	peer_ctx = create_signed_backend_peer_ctx(
		untrusted_ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-untrusted: contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	ok(SSL_CTX_get_verify_callback(shared_ctx) != nullptr,
	   "plain-tls-untrusted: inherited permissive verify callback is installed");
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", "plain-secret");
	expect_plain_tls_rejected(result, "plain-tls-untrusted");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-untrusted: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_hostname_mismatch() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-host-mismatch: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:other.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-host-mismatch: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", "plain-secret");
	expect_plain_tls_rejected(result, "plain-tls-host-mismatch");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-host-mismatch: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_ip_mismatch() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls-ip-mismatch: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "IP:127.0.0.2");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls-ip-mismatch: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "127.0.0.1", "plain-secret");
	expect_plain_tls_rejected(result, "plain-tls-ip-mismatch");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-ip-mismatch: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_rejects_missing_cert() {
	diag(">>> %s", __func__);
	SSL_CTX* shared_ctx = create_permissive_shared_ctx(nullptr);
	if (!shared_ctx) {
		ok(false, "plain-tls-missing-cert: shared context created");
		return;
	}
	SSL_CTX* peer_ctx = create_anonymous_backend_peer_ctx();
	if (!peer_ctx || !enable_anonymous_tls12(shared_ctx)) {
		// OpenSSL builds without aNULL cannot exercise a genuinely
		// certificate-less TLS 1.2 peer. The defensive "no peer cert"
		// branch still requires the same fail-closed check; label this gap.
		diag("plain-tls-missing-cert: aNULL TLS 1.2 unavailable; skipping");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		skip(6, "anonymous TLS 1.2 cipher unavailable in this OpenSSL build");
		return;
	}
	// Control: the same certificate-less TLS 1.2 contexts must be capable of
	// completing a handshake and sending the historical MYSQL41 mechanism
	// when no frontend-derived PLAIN secret is present. Without this, a "no
	// shared cipher" failure would make the negative test pass trivially.
	const PlainTlsPeerResult control = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", nullptr);
	const bool control_ok =
		control.cap_exchange_ok && control.handshake_completed &&
		control.saw_auth_start && control.mechanism == "MYSQL41";
	ok(control_ok,
	   "plain-tls-missing-cert: control completes anonymous TLS and sends MYSQL41");
	if (!control_ok) {
		ok(false,
		   "plain-tls-missing-cert: fixture cannot exercise certificate-less PLAIN guard");
		skip(4, "anonymous TLS 1.2 fixture did not complete; negative case not exercised");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}

	// Real anonymous TLS 1.2: the peer sends no certificate. The PLAIN path
	// may complete the TLS handshake permissively (historical non-PLAIN
	// semantics), but must fail auth before any AuthenticateStart/replay.
	const PlainTlsPeerResult result = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", "plain-secret");
	ok(result.cap_exchange_ok,
	   "plain-tls-missing-cert: CapabilitiesGet/Set exchange completed");
	ok(result.auth_error,
	   "plain-tls-missing-cert: auth fails closed without a peer certificate");
	ok(!result.saw_auth_start,
	   "plain-tls-missing-cert: no AuthenticateStart is sent");
	ok(result.auth_data.find("plain-secret") == std::string::npos,
	   "plain-tls-missing-cert: verified PLAIN secret is not replayed");
	ok(SSL_CTX_get_verify_callback(shared_ctx) == permissive_peer_verify_cb,
	   "plain-tls-missing-cert: shared permissive callback is unchanged");
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_plain_tls_empty_secret_presence() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-empty-secret: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-empty-secret: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}

	// setter("") is a PRESENT empty credential and must select PLAIN.
	const PlainTlsPeerResult present = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", "");
	ok(present.handshake_completed,
	   "plain-empty-secret: trusted TLS completes");
	ok(present.saw_auth_start && present.mechanism == "PLAIN",
	   "plain-empty-secret: empty present credential selects PLAIN");
	ok(present.auth_data ==
	       std::string("testdb") + std::string("\0", 1) + "plainuser" +
	           std::string("\0", 1),
	   "plain-empty-secret: PLAIN data carries an empty password field");

	// nullptr (or clear) means ABSENT and must keep historical MYSQL41.
	const PlainTlsPeerResult absent = run_plain_tls_peer_case(
		shared_ctx, peer_ctx, "backend.trusted.test", nullptr);
	ok(absent.handshake_completed,
	   "plain-empty-secret: trusted TLS completes for absent credential");
	ok(absent.saw_auth_start && absent.mechanism == "MYSQL41",
	   "plain-empty-secret: absent credential keeps MYSQL41");
	ok(absent.auth_data.find("testdb") == 0,
	   "plain-empty-secret: MYSQL41 carries the schema/user prefix");

	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_backend_auth_tls_fatal_read_with_stale_eagain() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "tls-fatal-eagain: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "tls-fatal-eagain: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_address("backend.trusted.test");
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("$A$005$not-a-replayable-secret");
	conn.set_backend_plain_password("plain-secret");
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);
	conn.set_ssl_ctx(shared_ctx);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	uint8_t buf[4096];
	conn.step_auth();
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	{
		Mysqlx::Connection::Capabilities caps;
		std::string caps_str;
		caps.SerializeToString(&caps_str);
		write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
			reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());
	}
	conn.step_auth();
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	conn.step_auth();

	SSL* server_ssl = SSL_new(peer_ctx);
	BIO* srbio = BIO_new(BIO_s_mem());
	BIO* swbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server_ssl, srbio, swbio);
	SSL_set_accept_state(server_ssl);
	ok(drive_backend_tls_handshake(conn, fds[1], server_ssl, srbio, swbio),
	   "tls-fatal-eagain: trusted TLS handshake completed");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "tls-fatal-eagain: PLAIN AuthenticateStart sent");

	// A complete but corrupt TLS record must be a fatal read. errno is
	// deliberately left at EAGAIN, mimicking the stale errno that a prior
	// nonblocking read can leave behind.
	const uint8_t corrupt_record[] = {
		0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00
	};
	send(fds[1], corrupt_record, sizeof(corrupt_record), MSG_NOSIGNAL);

	int rc = 1;
	for (int i = 0; i < 8 && rc == 1; ++i) {
		errno = EAGAIN;
		rc = conn.step_auth();
		usleep(1000);
	}
	ok(rc == -1,
	   "tls-fatal-eagain: fatal SSL_read fails auth despite stale EAGAIN");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "tls-fatal-eagain: auth state ERROR promptly");

	SSL_free(server_ssl);
	close(fds[1]);
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_backend_auth_tls_notice_ok_then_eof(bool close_notify = false, bool leading_notice = true) {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "tls-notice-ok-eof: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "tls-notice-ok-eof: trusted contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_address("backend.trusted.test");
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("$A$005$not-a-replayable-secret");
	conn.set_backend_plain_password("plain-secret");
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);
	conn.set_ssl_ctx(shared_ctx);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	uint8_t buf[4096];
	conn.step_auth();
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	{
		Mysqlx::Connection::Capabilities caps;
		std::string caps_str;
		caps.SerializeToString(&caps_str);
		write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
			reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());
	}
	conn.step_auth();
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	conn.step_auth();

	SSL* server_ssl = SSL_new(peer_ctx);
	BIO* srbio = BIO_new(BIO_s_mem());
	BIO* swbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server_ssl, srbio, swbio);
	SSL_set_accept_state(server_ssl);
	ok(drive_backend_tls_handshake(conn, fds[1], server_ssl, srbio, swbio),
	   "tls-notice-ok-eof: trusted TLS handshake completed");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "tls-notice-ok-eof: PLAIN AuthenticateStart sent");

	Mysqlx::Notice::Frame notice;
	notice.set_type(Mysqlx::Notice::Frame_Type_SESSION_STATE_CHANGED);
	notice.set_scope(Mysqlx::Notice::Frame_Scope_GLOBAL);
	std::string notice_str;
	notice.SerializeToString(&notice_str);
	const std::vector<uint8_t> notice_frame = build_x_frame(
		Mysqlx::ServerMessages_Type_NOTICE,
		reinterpret_cast<const uint8_t*>(notice_str.data()), notice_str.size());
	Mysqlx::Session::AuthenticateOk auth_ok;
	std::string ok_str;
	auth_ok.SerializeToString(&ok_str);
	const std::vector<uint8_t> ok_frame = build_x_frame(
		Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
		reinterpret_cast<const uint8_t*>(ok_str.data()), ok_str.size());
	const bool sent_notice = !leading_notice || server_write_plain(
		server_ssl, swbio, fds[1], notice_frame.data(), notice_frame.size());
	const bool sent_ok = server_write_plain(
		server_ssl, swbio, fds[1], ok_frame.data(), ok_frame.size());
	ok(sent_notice && sent_ok, "tls-notice-ok-eof: NOTICE and OK queued");
	if (close_notify) {
		SSL_shutdown(server_ssl);
		if (drain_wbio_to_fd(swbio, fds[1]) <= 0) BAIL_OUT("TLS close_notify send failed");
	}
	// The final response and EOF can arrive in one read. Neither graceful
	// nor abrupt closure leaves a usable authenticated connection.
	close(fds[1]);

	int rc = 1;
	for (int i = 0; i < 8 && rc == 1; ++i) {
		rc = conn.step_auth();
		usleep(1000);
	}
	ok(rc == -1,
	   "tls-notice-ok-eof: buffered OK plus EOF fails auth promptly");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "tls-notice-ok-eof: auth state ERROR; peer is already unusable");

	SSL_free(server_ssl);
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

static void test_send_authenticate_start_requires_verified_peer_gate() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("$A$005$not-a-replayable-secret");
	conn.set_backend_plain_password("plain-secret");
	conn.set_tls_active(true);
	conn.init_backend_ds(fds[0]);
	ok(conn.send_authenticate_start() == -1,
	   "plain-gate: tls_active without verified peer fails closed");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "plain-gate: auth state is BACKEND_AUTH_ERROR");
	uint8_t buf[4096];
	const ssize_t r = read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 100);
	ok(r < 5, "plain-gate: no AuthenticateStart is emitted on the unverified path");
	conn.set_fd(-1);
	close(fds[0]);
	close(fds[1]);
}

static void test_start_connect_persists_configured_host() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	// Port 1 is intentionally not a backend. start_connect() must retain the
	// operator-configured identity, not the resolved socket address, before
	// any TLS/PLAIN decision. "localhost" exercises that distinction.
	conn.start_connect("localhost", 1);
	ok(std::string(conn.get_address()) == "localhost",
	   "start_connect persists the configured DNS identity, not the resolved IP");
}

static void test_backend_auth_state_transitions() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.set_backend_schema("testdb");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED,
	   "auth starts at NOT_STARTED");

	int rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 (in progress) after CapGet sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
	   "state is CAPABILITIES_GET_SENT");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read CapabilitiesGet from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET,
		   "sent CapabilitiesGet message type");
	}

	Mysqlx::Connection::Capabilities caps;
	auto* cap = caps.add_capabilities();
	cap->set_name("authentication.mechanisms");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = val->mutable_array();
	auto* v = arr->add_value();
	v->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	// step_auth_capabilities_get_sent skips CapabilitiesSet when no TLS
	// is required — authentication.mechanisms is a read-only capability
	// upstream — and goes straight to AuthenticateStart.
	rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 after AuthStart sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "state is AUTHENTICATE_START_SENT (CapSet step skipped, plaintext path)");

	usleep(10000);
	r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read AuthenticateStart from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		   "sent AuthenticateStart message type");
		Mysqlx::Session::AuthenticateStart auth_start;
		if (auth_start.ParseFromArray(buf + 5, r - 5)) {
			ok(auth_start.mech_name() == "MYSQL41", "auth mechanism is MYSQL41");
		} else {
			ok(false, "parsed AuthenticateStart");
		}
	}

	std::vector<uint8_t> challenge(20, 0xAB);
	std::string challenge_str(challenge.begin(), challenge.end());
	Mysqlx::Session::AuthenticateContinue auth_cont;
	auth_cont.set_auth_data(challenge_str);
	std::string cont_str;
	auth_cont.SerializeToString(&cont_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(cont_str.data()), cont_str.size());

	rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 after AuthContinue sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CONTINUE_SENT,
	   "state is AUTH_CONTINUE_SENT");

	usleep(10000);
	r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read AuthenticateContinue (response) from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		   "sent AuthenticateContinue response type");
		Mysqlx::Session::AuthenticateContinue resp;
		if (resp.ParseFromArray(buf + 5, r - 5)) {
			// MYSQL41 AuthenticateContinue payload to the upstream X
			// server is `schema\0user\0*hex_scramble`. Verify the prefix
			// + the leading '*' of the scramble section so we catch a
			// regression to the old bare `*hex_scramble` form.
			const std::string& ad = resp.auth_data();
			ok(!ad.empty(), "auth response has data");
			const std::string expected_prefix =
				std::string("testdb") + std::string("\0", 1) +
				std::string("testuser") + std::string("\0", 1) +
				std::string("*");
			ok(ad.size() >= expected_prefix.size() &&
			   ad.compare(0, expected_prefix.size(), expected_prefix) == 0,
			   "auth response is schema\\0user\\0*hex_scramble");
		} else {
			ok(false, "parsed auth response");
			ok(false, "auth response is schema\\0user\\0*hex_scramble");
		}
	}

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK, nullptr, 0);

	rc = conn.step_auth();
	ok(rc == 0, "step_auth returns 0 (done) after AuthOk");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_DONE,
	   "state is AUTH_DONE");
	ok(conn.get_state() == MysqlxConnection::IDLE,
	   "connection state is IDLE after auth");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_caps() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on ERROR during CapGet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR");

	close(fds[0]);
	close(fds[1]);
}

// A backend EOF during auth must fail the connection, not look like "no
// frame yet". Before this guard the worker spun on POLLHUP forever.
static void test_backend_auth_eof_fails_auth() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);
	ok(conn.step_auth() == 1, "backend-eof: CapGet sent");
	close(fds[1]);

	ok(conn.step_auth() == -1, "backend-eof: EOF fails auth");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "backend-eof: auth state ERROR (no POLLHUP spin)");

	close(fds[0]);
}

static void test_backend_auth_notice_skip() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	Mysqlx::Notice::Frame notice;
	notice.set_type(Mysqlx::Notice::Frame_Type_WARNING);
	notice.set_scope(Mysqlx::Notice::Frame_Scope_GLOBAL);
	std::string notice_str;
	notice.SerializeToString(&notice_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_NOTICE,
		reinterpret_cast<const uint8_t*>(notice_str.data()), notice_str.size());

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 (continue) when NOTICE received");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
	   "auth state unchanged after NOTICE");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_wrong_caps_response() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on wrong response type during CapGet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR after wrong response");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_set_caps_reject() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on ERROR during CapSet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR after CapSet reject");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode TLS fallback (issue #5693).
// When mysqlx-tls_backend_mode=preferred, the proxy sends
// CapabilitiesSet(tls=true). If the backend rejects with a
// Mysqlx::Error (e.g. it has no TLS configured), the connection
// must silently downgrade to plaintext authentication on the same
// TCP socket -- not fail.
//
// Setup: drive auth to CAPABILITIES_SET_SENT with
// backend_tls_required_=true AND backend_tls_fallback_allowed_=true,
// then inject a Mysqlx::Error on the wire. Expect step_auth to
// continue (rc=1), transition to AUTHENTICATE_START_SENT, and emit
// a SESS_AUTHENTICATE_START frame on the wire.
static void test_backend_auth_preferred_mode_fallback_to_plaintext() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.set_backend_schema("testdb");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	// Mark this connection as preferred-mode: TLS requested with
	// fallback allowed. ssl_ctx is intentionally NOT set: the
	// fallback path must trip BEFORE any TLS handshake is initiated,
	// i.e. when CapabilitiesSet(tls=true) is rejected with Error.
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);

	// CapGet -> CapabilitiesSet(tls=true).
	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));  // drain CapGet from wire
	}

	// Backend returns capabilities with no TLS available, then we
	// send CapabilitiesSet(tls=true), then it rejects with Error.
	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));  // drain CapSet from wire
	}
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_SET_SENT,
	   "preferred-mode: state is CAPABILITIES_SET_SENT after CapSet emitted");

	// Inject the Mysqlx::Error response from the backend.
	Mysqlx::Error err;
	err.set_severity(Mysqlx::Error::ERROR);
	err.set_code(5001);
	err.set_msg("Capability prepare failed: tls");
	err.set_sql_state("HY000");
	std::string err_str;
	err.SerializeToString(&err_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(err_str.data()), err_str.size());

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == 1,
	   "preferred-mode: step_auth returns 1 (in-progress) after Error -> fallback path taken");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "preferred-mode: fallback transitions to AUTHENTICATE_START_SENT");
	ok(!conn.is_backend_tls_required(),
	   "preferred-mode: backend_tls_required_ cleared so subsequent steps don't reattempt TLS");
	ok(!conn.is_tls_active(),
	   "preferred-mode: tls_active stays false after fallback (no handshake performed)");

	// Verify the SESS_AUTHENTICATE_START frame landed on the wire.
	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5 && buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
	   "preferred-mode: AuthenticateStart frame emitted on plaintext socket after fallback");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode + non-TLS error code: must NOT fall back (issue #5710).
//
// Counterpart to test_backend_auth_preferred_mode_fallback_to_plaintext
// (which covers code 5001 = ER_X_CAPABILITIES_PREPARE_FAILED). Here the
// backend rejects CapabilitiesSet(tls=true) with a non-TLS error
// (e.g. ER_X_BAD_MESSAGE = 5000, or a generic permission-denied 1045
// equivalent). Even under `preferred`, fallback must NOT trigger —
// that would let the proxy silently swallow real backend failures.
// The connection must transition to BACKEND_AUTH_ERROR.
static void test_backend_auth_preferred_mode_non_tls_error_no_fallback() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);  // preferred mode

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	// Inject a non-TLS Error code. ER_X_BAD_MESSAGE = 5000, or a
	// MySQL native code like 1045 ("Access denied") — anything but
	// 5001. Use 1045 to model "permission denied at the auth layer".
	Mysqlx::Error err;
	err.set_severity(Mysqlx::Error::ERROR);
	err.set_code(1045);
	err.set_msg("Access denied for user");
	err.set_sql_state("28000");
	std::string err_str;
	err.SerializeToString(&err_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(err_str.data()), err_str.size());

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "preferred-mode + non-TLS error (1045): step_auth returns -1 (no silent fallback)");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "preferred-mode + non-TLS error: auth_state is ERROR");
	ok(!conn.is_tls_active(),
	   "preferred-mode + non-TLS error: tls_active stays false");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode + Error frame with no decodable code: must NOT fall
// back. A code-less or malformed Error body cannot be classified as
// TLS-specific, so the conservative-default is to fail the connect.
static void test_backend_auth_preferred_mode_codeless_error_no_fallback() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);  // preferred mode

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	// Empty Error body — no code field set.
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "preferred-mode + codeless Error: step_auth returns -1 (no fallback on undecodable code)");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "preferred-mode + codeless Error: auth_state is ERROR");

	close(fds[0]);
	close(fds[1]);
}

// required-mode TLS hard-fail (issue #5693).
// Counterpart to the preferred-mode test: same Error injection, but
// fallback_allowed=false (matches mysqlx-tls_backend_mode=required and
// AsClient + frontend-TLS combinations). Expect the connection to
// fail with rc=-1 and BACKEND_AUTH_ERROR — NOT to silently downgrade.
static void test_backend_auth_required_mode_no_fallback_on_error() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "required-mode: step_auth returns -1 on Error when fallback not allowed");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "required-mode: auth_state is ERROR (no silent downgrade)");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_not_started_returns_progress() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_state(MysqlxConnection::AUTHENTICATING);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(-1);

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	conn.set_fd(fds[0]);
	conn.init_backend_ds(fds[0]);

	int rc = conn.step_auth();
	ok(rc == 1, "step_auth on NOT_STARTED sends CapGet and returns 1");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_reset_clears_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_state(MysqlxConnection::IDLE);
	conn.set_backend_plain_password("pooled-secret");
	conn.reset();
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED,
	   "reset clears auth state");
	ok(conn.is_reusable(), "reset marks reusable");
	ok(!conn.has_backend_plain_password_for_test(),
	   "reset wipes the frontend-derived PLAIN secret before pooling");
}

// Helper: drive a connection to the point where AuthenticateStart has
// been emitted, returning the raw frame bytes for inspection. The caller
// is responsible for the earlier CapGet/Capabilities exchange.
static ssize_t read_auth_start_frame(int fd, uint8_t* buf, size_t buf_size,
                                     Mysqlx::Session::AuthenticateStart& out) {
	usleep(5000);
	ssize_t r = read(fd, buf, buf_size);
	if (r < 5) return r;
	return out.ParseFromArray(buf + 5, static_cast<int>(r - 5)) ? r : -1;
}

// Fix #3: a mapped frontend PLAIN login retains the verified secret so a
// TLS-protected backend can authenticate with PLAIN (one-shot
// AuthenticateStart -> AuthenticateOk). This drives a real client-side
// TLS handshake on the connection's backend stream; the test peer sees
// only ciphertext until we decrypt with its SSL object.
static void test_backend_auth_plain_over_tls() {
	diag(">>> %s", __func__);
	// Both contexts use TLS_server_method() like the production shared
	// core context. The shared context carries the same permissive verify
	// callback as src/proxy_tls.cpp; the leaf is signed by a CA that is in
	// the shared context's trust store and matches the configured DNS name.
	// The peer requests an optional client certificate and rejects any
	// presented certificate; the backend client must clear its inherited
	// frontend-server identity and therefore send none.
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "plain-tls: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "plain-tls: test TLS contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	SSL_CTX_set_verify(peer_ctx, SSL_VERIFY_PEER, reject_client_cert_cb);

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_address("backend.trusted.test");
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("$A$005$not-a-replayable-secret");
	conn.set_backend_plain_password("plain-secret");
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);
	conn.set_ssl_ctx(shared_ctx);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	ok(conn.step_auth() == 1, "plain-tls: CapGet sent");
	uint8_t buf[4096];
	ssize_t r = read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	ok(r >= 5 && buf[4] == Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET,
	   "plain-tls: plaintext CapGet observed by backend peer");

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	ok(conn.step_auth() == 1, "plain-tls: CapabilitiesSet(tls=true) sent");
	r = read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	ok(r >= 5 && buf[4] == Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
	   "plain-tls: plaintext CapabilitiesSet observed by backend peer");
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	ok(conn.step_auth() == 1, "plain-tls: backend Ok starts TLS handshake");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_TLS_HANDSHAKE,
	   "plain-tls: state BACKEND_AUTH_TLS_HANDSHAKE");

	SSL* server_ssl = SSL_new(peer_ctx);
	BIO* srbio = BIO_new(BIO_s_mem());
	BIO* swbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server_ssl, srbio, swbio);
	SSL_set_accept_state(server_ssl);
	std::vector<uint8_t> raw_ciphertext;
	ok(drive_backend_tls_handshake(conn, fds[1], server_ssl, srbio, swbio,
	                               &raw_ciphertext),
	   "plain-tls: real encrypted backend TLS handshake completed");
	ok(conn.is_tls_active(), "plain-tls: connection marked TLS-active after handshake");

	for (int i = 0; i < 200 && conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_TLS_HANDSHAKE; ++i) {
		conn.step_auth();
		drive_backend_tls_handshake(conn, fds[1], server_ssl, srbio, swbio);
	}
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "plain-tls: state AUTHENTICATE_START_SENT after TLS");

	const std::string auth_frame =
		read_server_plain(server_ssl, srbio, fds[1], 1000, &raw_ciphertext);
	ok(auth_frame.size() >= 5 && static_cast<uint8_t>(auth_frame[4]) ==
	   Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
	   "plain-tls: encrypted AuthenticateStart decrypted by test peer");
	Mysqlx::Session::AuthenticateStart auth_start;
	const bool parsed = auth_frame.size() >= 5 &&
		auth_start.ParseFromArray(auth_frame.data() + 5,
		                          static_cast<int>(auth_frame.size() - 5));
	ok(parsed && auth_start.mech_name() == "PLAIN",
	   "plain-tls: mechanism is PLAIN inside the encrypted channel");
	const std::string expected = std::string("testdb") + std::string("\0", 1) +
	                             "plainuser" + std::string("\0", 1) + "plain-secret";
	ok(parsed && auth_start.auth_data() == expected,
	   "plain-tls: PLAIN auth_data is schema\\0user\\0verified-secret");
	const uint8_t* secret_begin = reinterpret_cast<const uint8_t*>("plain-secret");
	ok(!raw_ciphertext.empty() &&
	   std::search(raw_ciphertext.begin(), raw_ciphertext.end(),
	               secret_begin, secret_begin + 12) == raw_ciphertext.end(),
	   "plain-tls: raw socket ciphertext does not expose the plaintext secret");

	// PLAIN completes with a direct AuthenticateOk, no Continue round.
	Mysqlx::Session::AuthenticateOk auth_ok;
	std::string ok_str;
	auth_ok.SerializeToString(&ok_str);
	std::vector<uint8_t> ok_frame;
	const uint32_t ok_payload = static_cast<uint32_t>(ok_str.size()) + 1;
	ok_frame.push_back(ok_payload & 0xFF);
	ok_frame.push_back((ok_payload >> 8) & 0xFF);
	ok_frame.push_back((ok_payload >> 16) & 0xFF);
	ok_frame.push_back((ok_payload >> 24) & 0xFF);
	ok_frame.push_back(Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK);
	ok_frame.insert(ok_frame.end(), ok_str.begin(), ok_str.end());
	ok(server_write_plain(server_ssl, swbio, fds[1], ok_frame.data(), ok_frame.size()),
	   "plain-tls: encrypted AuthenticateOk sent by test peer");
	ok(conn.step_auth() == 0, "plain-tls: AuthenticateOk completes auth");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_DONE,
	   "plain-tls: auth state DONE");
	ok(conn.get_state() == MysqlxConnection::IDLE,
	   "plain-tls: connection IDLE after auth");
	ok(!conn.has_backend_plain_password_for_test(),
	   "plain-tls: secret wiped after successful auth");

	SSL_free(server_ssl);
	conn.set_fd(-1);
	close(fds[0]);
	close(fds[1]);
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

// After a real TLS handshake and AuthenticateStart, a peer close (EOF
// or TLS alert) must fail auth promptly instead of spinning on POLLHUP.
static void test_backend_auth_tls_peer_close_fails() {
	diag(">>> %s", __func__);
	TestCa ca;
	SSL_CTX* shared_ctx = nullptr;
	SSL_CTX* peer_ctx = nullptr;
	if (!create_test_ca(ca)) {
		ok(false, "tls-eof: test CA created");
		return;
	}
	shared_ctx = create_permissive_shared_ctx(ca.cert);
	peer_ctx = create_signed_backend_peer_ctx(ca, "DNS:backend.trusted.test");
	if (!shared_ctx || !peer_ctx) {
		ok(false, "tls-eof: contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		return;
	}
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_address("backend.trusted.test");
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_plain_password("plain-secret");
	conn.set_backend_tls_required(true);
	conn.set_ssl_ctx(shared_ctx);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();
	uint8_t buf[4096];
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES, nullptr, 0);
	conn.step_auth();
	read_x_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	conn.step_auth();

	SSL* server_ssl = SSL_new(peer_ctx);
	BIO* srbio = BIO_new(BIO_s_mem());
	BIO* swbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server_ssl, srbio, swbio);
	SSL_set_accept_state(server_ssl);
	ok(drive_backend_tls_handshake(conn, fds[1], server_ssl, srbio, swbio),
	   "tls-eof: handshake completed before peer close");
	close(fds[1]);

	int rc = 1;
	for (int i = 0; i < 200 && rc == 1; ++i) {
		rc = conn.step_auth();
		usleep(1000);
	}
	ok(rc == -1, "tls-eof: peer close fails auth");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "tls-eof: auth state ERROR, no dead-backend spin");

	SSL_free(server_ssl);
	conn.set_fd(-1);
	close(fds[0]);
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
}

// TLS guard: the same retained secret must NOT switch the mechanism to
// PLAIN when the backend leg is still plaintext. Fall back to the
// historical MYSQL41 path and never put the secret on the wire.
static void test_backend_auth_plain_not_used_without_tls() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_password("stored-password");
	conn.set_backend_plain_password("plain-secret");
	conn.set_tls_active(false);
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}
	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();

	uint8_t buf[4096];
	Mysqlx::Session::AuthenticateStart auth_start;
	ssize_t r = read_auth_start_frame(fds[1], buf, sizeof(buf), auth_start);
	ok(r >= 5 && auth_start.mech_name() == "MYSQL41",
	   "plain-no-tls: mechanism stays MYSQL41 on a plaintext backend");
	const std::string plain_secret = "plain-secret";
	ok(std::search(buf, buf + (r > 0 ? r : 0),
	               plain_secret.begin(), plain_secret.end()) == buf + (r > 0 ? r : 0),
	   "plain-no-tls: verified secret never appears on the wire");
	ok(conn.has_backend_plain_password_for_test(),
	   "plain-no-tls: secret is retained until auth completes or fails");

	close(fds[0]);
	close(fds[1]);
}

// Failure cleanup: any auth failure must wipe the retained secret so a
// later pooled checkout cannot accidentally reuse it.
static void test_backend_auth_plain_failure_clears_secret() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("plainuser");
	conn.set_backend_schema("testdb");
	conn.set_backend_plain_password("plain-secret");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}
	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());
	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));  // drain AuthenticateStart
	}

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);
	ok(conn.step_auth() == -1, "plain-failure: backend Error fails auth");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "plain-failure: auth state ERROR");
	ok(!conn.has_backend_plain_password_for_test(),
	   "plain-failure: secret wiped on auth failure");

	close(fds[0]);
	close(fds[1]);
}

// =====================================================================
// Auth-phase NOTICE per-state policy (issue #5695 part 2). Drives
// MysqlxConnection::auth_phase_notice_is_drainable_for_test() with
// synthetic notice bodies. Verifies the per-type decision matrix:
//   WARNING / SESSION_VARIABLE_CHANGED / SESSION_STATE_CHANGED /
//   GROUP_REPLICATION_STATE_CHANGED / SERVER_HELLO -> drainable
//   unknown / malformed / empty -> auth failure (auth_state_=BACKEND_AUTH_ERROR)
// =====================================================================
static std::string build_notice_body_with_type(int type_value) {
	Mysqlx::Notice::Frame f;
	f.set_type(type_value);
	std::string out;
	f.SerializeToString(&out);
	return out;
}

static void test_auth_phase_notice_known_types_drained() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	const int known_types[] = {
		Mysqlx::Notice::Frame_Type_WARNING,
		Mysqlx::Notice::Frame_Type_SESSION_VARIABLE_CHANGED,
		Mysqlx::Notice::Frame_Type_SESSION_STATE_CHANGED,
		Mysqlx::Notice::Frame_Type_GROUP_REPLICATION_STATE_CHANGED,
		Mysqlx::Notice::Frame_Type_SERVER_HELLO,
	};
	for (int t : known_types) {
		// Reset auth state per iteration; the helper sets it to ERROR
		// on the unknown-type branch and we want to assert no leakage.
		conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
		std::string body = build_notice_body_with_type(t);
		bool drainable = conn.auth_phase_notice_is_drainable_for_test(
			reinterpret_cast<const uint8_t*>(body.data()), body.size());
		ok(drainable, "auth-phase NOTICE type=%d is drainable", t);
		ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
		   "auth-phase NOTICE type=%d does not perturb auth_state_", t);
	}
}

static void test_auth_phase_notice_unknown_type_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	// 99 is not in the spec-defined enum range. Auth must fail.
	std::string body = build_notice_body_with_type(99);
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(
		reinterpret_cast<const uint8_t*>(body.data()), body.size());
	ok(!drainable, "auth-phase NOTICE with unknown type=99 is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with unknown type=99 sets BACKEND_AUTH_ERROR");
}

static void test_auth_phase_notice_malformed_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	const uint8_t garbage[] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(
		garbage, sizeof(garbage));
	ok(!drainable, "auth-phase NOTICE with malformed body is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with malformed body sets BACKEND_AUTH_ERROR");
}

static void test_auth_phase_notice_empty_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(nullptr, 0);
	ok(!drainable, "auth-phase NOTICE with empty body is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with empty body sets BACKEND_AUTH_ERROR");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	// Plan derives from ok() count; 4 new auth-phase notice policy tests
	// add 5*2 (known types: drainable + state-preserved) + 2 (unknown
	// type) + 2 (malformed) + 2 (empty) = 16 ok() calls. Switching from
	// hard-coded plan(42) to plan(0) so future additions don't require
	// re-counting.
	plan(0);
	diag("=== mysqlx_backend_auth_unit-t starting ===");

	test_backend_auth_state_transitions();
	test_backend_auth_error_on_caps();
	test_backend_auth_eof_fails_auth();
	test_backend_auth_notice_skip();
	test_backend_auth_error_on_wrong_caps_response();
	test_backend_auth_error_on_set_caps_reject();
	test_backend_auth_preferred_mode_fallback_to_plaintext();
	test_backend_auth_preferred_mode_non_tls_error_no_fallback();
	test_backend_auth_preferred_mode_codeless_error_no_fallback();
	test_backend_auth_required_mode_no_fallback_on_error();
	test_backend_auth_not_started_returns_progress();
	test_backend_reset_clears_auth();

	// Frontend-PLAIN -> backend PLAIN mapped fallback (issue #6553).
	test_backend_auth_plain_over_tls();
	test_backend_auth_tls_peer_close_fails();
	test_backend_auth_plain_not_used_without_tls();
	test_backend_auth_plain_failure_clears_secret();

	// Backend peer identity must be verified before the frontend PLAIN
	// secret is replayed. This is the #6553 P1 regression matrix.
	test_plain_tls_trusted_dns_positive();
	test_plain_tls_trusted_ip_positive();
	test_plain_tls_trusted_ipv6_positive();
	test_plain_tls_rejects_leading_dot_identity();
	test_plain_tls_rejects_untrusted_cert();
	test_plain_tls_rejects_hostname_mismatch();
	test_plain_tls_rejects_ip_mismatch();
	test_plain_tls_rejects_missing_cert();
	test_plain_tls_rejects_empty_identity();
	test_plain_tls_empty_secret_presence();
	test_send_authenticate_start_requires_verified_peer_gate();
	test_backend_auth_tls_fatal_read_with_stale_eagain();
	test_backend_auth_tls_notice_ok_then_eof();
	test_backend_auth_tls_notice_ok_then_eof(true, false);
	test_backend_auth_tls_notice_ok_then_eof(true, true);
	test_start_connect_persists_configured_host();

	// Auth-phase NOTICE per-state policy (#5695 part 2).
	test_auth_phase_notice_known_types_drained();
	test_auth_phase_notice_unknown_type_fails_auth();
	test_auth_phase_notice_malformed_fails_auth();
	test_auth_phase_notice_empty_fails_auth();

	return exit_status();
}
