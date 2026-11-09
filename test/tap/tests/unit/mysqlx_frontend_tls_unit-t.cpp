/**
 * mysqlx_frontend_tls_unit-t.cpp
 *
 * Regression coverage for issue #6553:
 *   - the plaintext CapabilitiesSet(tls=true) Ok must be flushed before
 *     the proxy initializes SSL (otherwise the acknowledgement is
 *     stranded behind the TLS state machine and the client never sends
 *     its ClientHello);
 *   - a fragmented/non-blocking TLS handshake must complete and the
 *     post-TLS X-Protocol PLAIN login must succeed;
 *   - frontend PLAIN must verify caching_sha2_password `$A$` hashes
 *     (including non-default hex rounds) instead of treating the stored
 *     hash as a literal password;
 *   - the verified PLAIN secret is only handed to an implicit mapped
 *     backend, never to an explicit service-account mapping.
 */

#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_config_store.h"
#include "mysqlx_protocol.h"
#include "mysqlx_connection.h"
#include "proxysql.h"

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_sql.pb.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// Exact CapabilitiesSet(tls=true) frame from issue #6553.
static const uint8_t CAPSET_TLS_EXACT[] = {
	0x14, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x11, 0x0a, 0x0f, 0x0a, 0x03,
	't', 'l', 's', 0x12, 0x08, 0x08, 0x01, 0x12, 0x04, 0x08, 0x07,
	0x40, 0x01
};

static bool write_all(int fd, const uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
		if (n > 0) {
			off += static_cast<size_t>(n);
			continue;
		}
		if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd { fd, POLLOUT, 0 };
			if (poll(&pfd, 1, 1000) <= 0) return false;
			continue;
		}
		return false;
	}
	return true;
}

static void write_x_frame(int fd, uint8_t msg_type, const uint8_t* payload, size_t payload_len) {
	uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	uint8_t header[5];
	header[0] = size & 0xFF;
	header[1] = (size >> 8) & 0xFF;
	header[2] = (size >> 16) & 0xFF;
	header[3] = (size >> 24) & 0xFF;
	header[4] = msg_type;
	write_all(fd, header, 5);
	if (payload_len > 0) write_all(fd, payload, payload_len);
}

static ssize_t read_frame_with_timeout(int fd, uint8_t* buf, size_t buf_size, int timeout_ms) {
	struct pollfd pfd { fd, POLLIN, 0 };
	if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
	uint8_t header[5];
	ssize_t r;
	do {
		r = read(fd, header, sizeof(header));
	} while (r < 0 && errno == EINTR);
	if (r != 5) return -1;
	uint32_t payload_size = static_cast<uint32_t>(header[0]) |
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

static int permissive_peer_verify_cb(int, X509_STORE_CTX*) {
	// Mirrors src/proxy_tls.cpp::callback_ssl_verify_peer. The shared core
	// context accepts every certificate; strict backend PLAIN peer checks
	// must override this per SSL object instead of trusting it.
	return 1;
}

static SSL_CTX* create_test_ssl_ctx(const char* san = nullptr) {
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

	if (san != nullptr && *san != '\0') {
		X509V3_CTX v3_ctx;
		X509V3_set_ctx(&v3_ctx, x509, x509, nullptr, nullptr, 0);
		X509_EXTENSION* ext = X509V3_EXT_conf_nid(
			nullptr, &v3_ctx, NID_subject_alt_name,
			const_cast<char*>(san));
		if (ext) {
			X509_add_ext(x509, ext, -1);
			X509_EXTENSION_free(ext);
		}
	}

	X509_sign(x509, pkey, EVP_sha256());

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_use_PrivateKey(ctx, pkey);
	X509_free(x509);
	EVP_PKEY_free(pkey);
	return ctx;
}

// Mirror the production shared core context: permissive verify callback plus
// a trust store containing the intended backend leaf. The leaf is trusted by
// adding its certificate to the same store SSL_CTX_load_verify_locations()
// would populate in production.
static void trust_peer_and_install_permissive_callback(SSL_CTX* shared_ctx,
                                                       SSL_CTX* peer_ctx) {
	if (!shared_ctx || !peer_ctx) return;
	X509* peer_cert = SSL_CTX_get0_certificate(peer_ctx);
	if (peer_cert != nullptr) {
		X509_STORE_add_cert(SSL_CTX_get_cert_store(shared_ctx), peer_cert);
	}
	SSL_CTX_set_verify(shared_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
	                   permissive_peer_verify_cb);
}

static void install_tls_route(MysqlxConfigStore& store) {
	std::unordered_map<std::string, MysqlxRoute> routes;
	MysqlxRoute r {};
	r.name = "tls_route";
	r.destination_hostgroup = 10;
	r.strategy = "first_available";
	routes.emplace(r.name, r);

	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
	MysqlxBackendEndpoint ep {};
	ep.hostname = "127.0.0.1";
	ep.mysql_port = 3306;
	ep.mysqlx_port = 33060;
	endpoints[10].push_back(ep);
	store.install_for_test(std::move(routes), std::move(endpoints));
}

// Pump the session until the client socket becomes readable or the
// deadline expires. handler() is non-blocking; to_process re-enters the
// state machine even when no new poll event has been observed.
static bool pump_until_readable(MysqlxSession& sess, int client_fd, int timeout_ms) {
	for (int waited = 0; waited < timeout_ms; waited += 2) {
		sess.to_process = true;
		sess.handler();
		struct pollfd pfd { client_fd, POLLIN, 0 };
		if (poll(&pfd, 1, 2) > 0 && (pfd.revents & POLLIN)) return true;
		usleep(1000);
	}
	return false;
}

// Push client TLS output to the peer three bytes at a time and let the
// session consume each fragment before the next write. This exercises
// partial TLS records without letting the blocking socketpair fill up.
static bool shuttle_client_tls(SSL* ssl, BIO* wbio, int fd, MysqlxSession& sess) {
	(void)ssl;
	for (int i = 0; i < 8192; ++i) {
		char buf[3];
		int n = BIO_read(wbio, buf, sizeof(buf));
		if (n <= 0) return true;
		size_t off = 0;
		while (off < static_cast<size_t>(n)) {
			ssize_t wr = send(fd, buf + off, static_cast<size_t>(n) - off, MSG_NOSIGNAL);
			if (wr > 0) { off += static_cast<size_t>(wr); continue; }
			if (wr < 0 && errno == EINTR) continue;
			return false;
		}
		sess.to_process = true;
		sess.handler();
	}
	return false;
}

static void feed_client_tls_from_net(SSL* ssl, BIO* rbio, int fd,
                                     std::vector<uint8_t>& plaintext) {
	char net_buf[16384];
	ssize_t r;
	while ((r = recv(fd, net_buf, sizeof(net_buf), MSG_DONTWAIT)) > 0) {
		BIO_write(rbio, net_buf, static_cast<int>(r));
	}
	uint8_t plain_buf[16384];
	int dec;
	while ((dec = SSL_read(ssl, plain_buf, sizeof(plain_buf))) > 0) {
		plaintext.insert(plaintext.end(), plain_buf, plain_buf + dec);
	}
}

static bool take_x_frame(std::vector<uint8_t>& buf, uint8_t* msg_type,
                         std::vector<uint8_t>& payload) {
	if (buf.size() < 5) return false;
	uint32_t payload_size = static_cast<uint32_t>(buf[0]) |
		(static_cast<uint32_t>(buf[1]) << 8) |
		(static_cast<uint32_t>(buf[2]) << 16) |
		(static_cast<uint32_t>(buf[3]) << 24);
	const size_t total = 4 + payload_size;
	if (buf.size() < total) return false;
	*msg_type = buf[4];
	payload.assign(buf.begin() + 5, buf.begin() + total);
	buf.erase(buf.begin(), buf.begin() + total);
	return true;
}

extern "C" char* sha256_crypt_r(const char* key, const char* salt,
                                char* buffer, int buflen);

// Test fixture for credential-presence checks. This uses the same core
// SHA-256 crypt routine as production; it is not an independent algorithm
// oracle. It only supplies a valid $A$ verifier for an empty password.
static std::string make_sha2_hash_for_password(const std::string& password) {
	static const char* salt = "0123456789abcdefghij";
	const std::string setting = std::string("$5$rounds=5000$") + salt;
	char crypt_buf[128];
	char* out = sha256_crypt_r(password.c_str(), setting.c_str(),
	                           crypt_buf, sizeof(crypt_buf));
	if (out == nullptr) return std::string();
	const std::string result(out);
	const size_t digest_pos = result.rfind('$');
	if (digest_pos == std::string::npos) return std::string();
	return std::string("$A$005$") + salt + result.substr(digest_pos + 1);
}

static void send_frontend_plain_start(int fd, const std::string& user,
                                      const std::string& password,
                                      uint8_t msg_type = Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START) {
	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("PLAIN");
	std::string body;
	body.push_back('\0');
	body.append(user);
	body.push_back('\0');
	body.append(password);
	auth.set_auth_data(body);
	std::string serialized;
	auth.SerializeToString(&serialized);
	write_x_frame(fd, msg_type,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
}

static MysqlxResolvedIdentity plain_identity(const std::string& username,
                                             const std::string& stored_password,
                                             const std::string& route = "tls_route") {
	MysqlxResolvedIdentity id {};
	id.username = username;
	id.x_enabled = true;
	id.password = stored_password;
	id.default_route = route;
	id.allowed_auth_methods = "PLAIN";
	return id;
}

// -----------------------------------------------------------------------
// Fix #1: plaintext ACK ordering, fragmented handshake, post-TLS auth.
// -----------------------------------------------------------------------
static void test_tls_ack_then_fragmented_handshake_then_plain_auth() {
	diag(">>> %s", __func__);
	SSL_CTX* server_ctx = create_test_ssl_ctx();
	SSL_CTX* client_ctx = SSL_CTX_new(TLS_method());
	if (client_ctx) {
		SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
		SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);
	}
	if (!server_ctx || !client_ctx) {
		ok(false, "TLS test contexts created");
		SSL_CTX_free(server_ctx);
		SSL_CTX_free(client_ctx);
		return;
	}
	GloVars.global.ssl_ctx = server_ctx;

	MysqlxConfigStore store;
	install_tls_route(store);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], &thr, "tls_route");
	sess.set_identity_lookup([](const std::string& user)
		-> std::optional<MysqlxResolvedIdentity> {
		return plain_identity(user, "testpass");
	});

	// Client sends the exact CapabilitiesSet(tls=true) frame from the
	// issue. The proxy must reply with the plaintext Ok before any TLS
	// bytes and before initializing its SSL object.
	ok(write_all(fds[1], CAPSET_TLS_EXACT, sizeof(CAPSET_TLS_EXACT)),
	   "tls-order: CapabilitiesSet(tls=true) written");
	const bool ack_readable = pump_until_readable(sess, fds[1], 1000);
	ok(ack_readable, "tls-order: client sees the CapabilitiesSet acknowledgement");

	const uint8_t expected_ok[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00};
	uint8_t ack[16];
	ssize_t ack_n = ack_readable
		? read_frame_with_timeout(fds[1], ack, sizeof(ack), 500)
		: -1;
	ok(ack_n == static_cast<ssize_t>(sizeof(expected_ok)) &&
	   memcmp(ack, expected_ok, sizeof(expected_ok)) == 0,
	   "tls-order: first post-CapSet bytes are the exact plaintext Ok (got %zd)", ack_n);
	if (ack_n != static_cast<ssize_t>(sizeof(expected_ok))) {
		ok(false, "tls-order: fragmented handshake skipped after missing Ok");
		ok(false, "tls-order: post-TLS PLAIN authentication succeeds");
		sess.client_ds().init(XDS_FRONTEND, -1);
		close(fds[0]); close(fds[1]);
		SSL_CTX_free(client_ctx);
		GloVars.global.ssl_ctx = nullptr;
		SSL_CTX_free(server_ctx);
		return;
	}
	ok(sess.client_ds().ssl_init_done(),
	   "tls-order: SSL object initialized only after the Ok was drained");

	// Fragmented, non-blocking client handshake. Every client flight is
	// split into <=3-byte writes so the server exercises partial TLS
	// records and EAGAIN reads across multiple handler ticks.
	SSL* client_ssl = SSL_new(client_ctx);
	BIO* crbio = BIO_new(BIO_s_mem());
	BIO* cwbio = BIO_new(BIO_s_mem());
	SSL_set_bio(client_ssl, crbio, cwbio);
	SSL_set_connect_state(client_ssl);

	bool client_done = false;
	bool server_done = false;
	for (int iter = 0; iter < 4000 && !(client_done && server_done); ++iter) {
		if (!client_done) {
			int r = SSL_do_handshake(client_ssl);
			if (r == 1) client_done = true;
		}
		if (!shuttle_client_tls(client_ssl, cwbio, fds[1], sess)) break;
		std::vector<uint8_t> discarded;
		feed_client_tls_from_net(client_ssl, crbio, fds[1], discarded);
		server_done = sess.client_ds().ssl_handshake_complete();
		usleep(500);
	}
	ok(client_done, "tls-handshake: fragmented client handshake completed");
	ok(server_done && sess.client_ds().is_encrypted(),
	   "tls-handshake: fragmented server handshake completed");

	// Post-TLS X-Protocol login: PLAIN AuthenticateStart -> AuthenticateOk.
	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("PLAIN");
	std::string auth_data;
	auth_data.push_back('\0');
	auth_data.append("testuser");
	auth_data.push_back('\0');
	auth_data.append("testpass");
	auth.set_auth_data(auth_data);
	std::string serialized;
	auth.SerializeToString(&serialized);
	std::vector<uint8_t> frame;
	const uint32_t payload_size = static_cast<uint32_t>(serialized.size()) + 1;
	frame.push_back(payload_size & 0xFF);
	frame.push_back((payload_size >> 8) & 0xFF);
	frame.push_back((payload_size >> 16) & 0xFF);
	frame.push_back((payload_size >> 24) & 0xFF);
	frame.push_back(Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START);
	frame.insert(frame.end(), serialized.begin(), serialized.end());
	int wr = SSL_write(client_ssl, frame.data(), static_cast<int>(frame.size()));
	ok(wr == static_cast<int>(frame.size()), "tls-auth: AuthenticateStart written over TLS");

	std::vector<uint8_t> plaintext;
	bool auth_ok = false;
	for (int iter = 0; iter < 4000 && !auth_ok; ++iter) {
		if (!shuttle_client_tls(client_ssl, cwbio, fds[1], sess)) break;
		feed_client_tls_from_net(client_ssl, crbio, fds[1], plaintext);
		uint8_t type = 0;
		std::vector<uint8_t> body;
		while (take_x_frame(plaintext, &type, body)) {
			if (type == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK) {
				auth_ok = true;
			}
		}
		usleep(500);
	}
	ok(auth_ok, "tls-auth: client received AuthenticateOk over TLS");
	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG &&
	   sess.client_ds().is_encrypted(),
	   "tls-auth: session authenticated over proxy-terminated TLS");

	SSL_free(client_ssl);
	// Detach the client fd before the session destructor would close it.
	sess.client_ds().init(XDS_FRONTEND, -1);
	close(fds[0]); close(fds[1]);
	SSL_CTX_free(client_ctx);
	GloVars.global.ssl_ctx = nullptr;
	SSL_CTX_free(server_ctx);
}

// -----------------------------------------------------------------------
// Fix #2: caching_sha2_password `$A$` verification on frontend PLAIN.
// The punctuation/tab-salt fixture is the official MySQL 8.4 gunit
// fixture (sha2_password-t.cc), independent of this verifier.
// -----------------------------------------------------------------------
static const char* SHA2_HASH_5000 =
	"$A$005$0123456789abcdefghijYQhnbWJOqQE7QAs0ikfA6ELpOkWMzxr5meGMQYsjAG3";
static const char* SHA2_HASH_10000 =
	"$A$00A$0123456789abcdefghije98glKu1vSljFgxMpzOD78PDnWrHVUBG2Rii2cEwPO5";
static const char* SHA2_HASH_PASSWORD_256 =
	"$A$005$0123456789abcdefghijxzQVkUVRPJEfZwH1eveTbmmGHhxfp98L8N04fv04Zu2";
static const char* SHA2_HASH_PUNCTUATION =
	"$A$005$AbCd!@#\tEfgH%^&*01@#dNFegEa4OGDrnEu7M4T.nkmm794xI/QoCR3Z.xpLOW6";
static const char* SHA2_PUNCTUATION_PASSWORD = "HahaH0hO1234#$@#%";
static const char* SHA2_HASH_ZERO_ROUNDS =
	"$A$000$0123456789abcdefghijYQhnbWJOqQE7QAs0ikfA6ELpOkWMzxr5meGMQYsjAG3";

static bool attempt_plain_auth(const std::string& attempted_password,
                               const std::string& stored_password,
                               bool encrypted,
                               int* status_out = nullptr,
                               uint8_t* response_type_out = nullptr) {
	MysqlxConfigStore store;
	install_tls_route(store);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], &thr, "tls_route");
	sess.client_ds().set_encrypted(encrypted);
	sess.set_identity_lookup([stored_password](const std::string& user)
		-> std::optional<MysqlxResolvedIdentity> {
		return plain_identity(user, stored_password);
	});

	send_frontend_plain_start(fds[1], "testuser", attempted_password);
	sess.to_process = true;
	sess.handler();

	uint8_t buf[4096];
	const ssize_t r = read_frame_with_timeout(fds[1], buf, sizeof(buf), 500);
	const bool ok_status = sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG;
	if (status_out) *status_out = static_cast<int>(sess.get_status());
	if (response_type_out) *response_type_out = (r >= 5) ? buf[4] : 0;

	sess.client_ds().init(XDS_FRONTEND, -1);
	close(fds[0]); close(fds[1]);
	return ok_status && r >= 5 && buf[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK;
}

static void test_plain_sha2_hash_verification() {
	diag(">>> %s", __func__);
	int status = 0;
	uint8_t type = 0;

	ok(attempt_plain_auth("testpass", SHA2_HASH_5000, true, &status, &type),
	   "plain-sha2: valid $A$ hash authenticates");
	ok(status == static_cast<int>(MysqlxSession::WAITING_CLIENT_XMSG),
	   "plain-sha2: session reaches WAITING_CLIENT_XMSG");
	ok(type == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
	   "plain-sha2: client receives AuthenticateOk");

	ok(!attempt_plain_auth("wrongpass", SHA2_HASH_5000, true, &status, &type),
	   "plain-sha2: wrong password is rejected");
	ok(type == Mysqlx::ServerMessages_Type_ERROR,
	   "plain-sha2: wrong password gets an Error frame");

	// Official MySQL fixture: arbitrary non-NUL/non-$ salt bytes,
	// including punctuation and a tab.
	ok(attempt_plain_auth(SHA2_PUNCTUATION_PASSWORD, SHA2_HASH_PUNCTUATION,
	                      true, &status, &type),
	   "plain-sha2: official punctuation/tab-salt fixture authenticates");

	// Rounds are three uppercase hex digits. 00A == 10 * 1000 rounds and
	// must not be parsed as base-10 (which would silently read 0).
	ok(attempt_plain_auth("testpass", SHA2_HASH_10000, true, &status, &type),
	   "plain-sha2: non-default hex rounds (00A) hash authenticates");

	// MAX_PLAINTEXT_LENGTH boundary and embedded-NUL rejection happen
	// before invoking sha256_crypt_r.
	const std::string password_256(256, 'a');
	const std::string password_257(257, 'a');
	ok(attempt_plain_auth(password_256, SHA2_HASH_PASSWORD_256, true, &status, &type),
	   "plain-sha2: 256-byte password authenticates (inclusive boundary)");
	ok(!attempt_plain_auth(password_257, SHA2_HASH_5000, true, &status, &type),
	   "plain-sha2: 257-byte password rejected before crypt");
	std::string embedded_nul = "testpass";
	embedded_nul.push_back('\0');
	embedded_nul.append("junk");
	ok(!attempt_plain_auth(embedded_nul, SHA2_HASH_5000, true, &status, &type),
	   "plain-sha2: testpass\\0junk rejected despite matching testpass hash");

	std::string bad_hex = SHA2_HASH_5000;
	bad_hex[3] = 'G';
	std::string lower_hex = SHA2_HASH_5000;
	lower_hex[3] = 'a';
	std::string bad_salt = SHA2_HASH_5000;
	bad_salt[7] = '$';
	std::string bad_digest = SHA2_HASH_5000;
	bad_digest[bad_digest.size() - 1] = '!';
	std::string truncated = std::string(SHA2_HASH_5000).substr(0, 69);
	const std::string malformed[] = {
		bad_hex, lower_hex, bad_salt, bad_digest, truncated,
		SHA2_HASH_ZERO_ROUNDS
	};
	for (const auto& hash : malformed) {
		ok(!attempt_plain_auth("testpass", hash, true, &status, &type),
		   "plain-sha2: malformed $A$ hash rejected without throwing");
		ok(type == Mysqlx::ServerMessages_Type_ERROR,
		   "plain-sha2: malformed $A$ hash returns an Error frame");
	}
}

static void test_plain_without_tls_rejected() {
	diag(">>> %s", __func__);
	int status = 0;
	uint8_t type = 0;
	ok(!attempt_plain_auth("testpass", SHA2_HASH_5000, false, &status, &type),
	   "plain-no-tls: PLAIN without TLS is rejected");
	ok(type == Mysqlx::ServerMessages_Type_ERROR,
	   "plain-no-tls: rejection is an X-Protocol Error frame");
}

// -----------------------------------------------------------------------
// Fix #3 (session side): only an implicit mapped identity receives the
// retained frontend PLAIN secret. Explicit service-account / backend
// credentials keep their own material. The mapping decision is observed
// on the real encrypted backend wire, not through a credential accessor.
// -----------------------------------------------------------------------
static bool peer_write_all(int fd, const uint8_t* data, size_t len) {
	return write_all(fd, data, len);
}

static void peer_feed_rbio(BIO* rbio, int fd) {
	char buf[16384];
	ssize_t r;
	while ((r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		BIO_write(rbio, buf, static_cast<int>(r));
	}
}

static int peer_drain_wbio(BIO* wbio, int fd) {
	char buf[16384];
	int n;
	int total = 0;
	while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0) {
		if (!peer_write_all(fd, reinterpret_cast<const uint8_t*>(buf), n)) return -1;
		total += n;
	}
	return total;
}

static bool drive_connection_tls(MysqlxConnection* conn, int peer_fd,
                                 SSL* server_ssl, BIO* srbio, BIO* swbio) {
	bool client_done = false;
	bool server_done = false;
	for (int i = 0; i < 3000 && !(client_done && server_done); ++i) {
		if (conn->step_auth() < 0) break;
		client_done = conn->backend_ds().ssl_handshake_complete();
		peer_feed_rbio(srbio, peer_fd);
		if (SSL_do_handshake(server_ssl) == 1) server_done = true;
		peer_drain_wbio(swbio, peer_fd);
		usleep(300);
	}
	return client_done && server_done;
}

static std::string peer_read_plain(SSL* server_ssl, BIO* srbio, int peer_fd,
                                   int timeout_ms) {
	std::string out;
	for (int waited = 0; waited < timeout_ms; waited += 2) {
		peer_feed_rbio(srbio, peer_fd);
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

static bool observe_backend_auth_start(MysqlxSession& sess,
                                       MysqlxConnection* conn,
                                       int peer_fd,
                                       SSL_CTX* server_ctx,
                                       const std::string& expected_mech,
                                       const std::string& expected_data) {
	// handler_connecting_server() already queued CapGet during the
	// session handler tick that attached this connection.
	uint8_t buf[8192];
	ssize_t r = read_frame_with_timeout(peer_fd, buf, sizeof(buf), 500);
	if (r < 5 || buf[4] != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET) return false;

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(peer_fd, Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn->step_auth();
	r = read_frame_with_timeout(peer_fd, buf, sizeof(buf), 500);
	if (r < 5 || buf[4] != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET) return false;
	write_x_frame(peer_fd, Mysqlx::ServerMessages_Type_OK, nullptr, 0);
	conn->step_auth();

	SSL* server_ssl = SSL_new(server_ctx);
	BIO* srbio = BIO_new(BIO_s_mem());
	BIO* swbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server_ssl, srbio, swbio);
	SSL_set_accept_state(server_ssl);
	const bool tls_ok = drive_connection_tls(conn, peer_fd, server_ssl, srbio, swbio);

	const std::string frame = peer_read_plain(server_ssl, srbio, peer_fd, 1000);
	Mysqlx::Session::AuthenticateStart auth_start;
	const bool parsed = frame.size() >= 5 &&
		auth_start.ParseFromArray(frame.data() + 5,
		                          static_cast<int>(frame.size() - 5));
	const bool match = tls_ok && parsed &&
		auth_start.mech_name() == expected_mech &&
		auth_start.auth_data() == expected_data;

	SSL_free(server_ssl);
	(void)sess;
	return match;
}

static void test_mapped_plain_secret_selection() {
	diag(">>> %s", __func__);
	// Use TLS_server_method() contexts exactly like src/main.cpp /
	// proxy_tls.cpp. The shared worker context carries the core permissive
	// verify callback; the peer leaf has an IP SAN for the socketpair
	// endpoint and is added to the shared trust store. The connection must
	// be able to use the shared context as a client via the per-SSL method
	// switch and still enforce peer identity for PLAIN.
	SSL_CTX* shared_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	SSL_CTX* backend_server_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	if (!shared_ctx || !backend_server_ctx) {
		ok(false, "mapped: TLS contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(backend_server_ctx);
		return;
	}
	trust_peer_and_install_permissive_callback(shared_ctx, backend_server_ctx);
	GloVars.global.ssl_ctx = shared_ctx;

	MysqlxConfigStore store;
	install_tls_route(store);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	int cfds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, cfds);
	MysqlxSession sess;
	sess.init(cfds[0], &thr, "tls_route");
	sess.client_ds().set_encrypted(true);
	sess.set_identity_lookup([](const std::string& user)
		-> std::optional<MysqlxResolvedIdentity> {
		return plain_identity(user, "testpass");
	});
	send_frontend_plain_start(cfds[1], "testuser", "testpass");
	sess.to_process = true;
	sess.handler();
	{
		uint8_t buf[4096];
		read_frame_with_timeout(cfds[1], buf, sizeof(buf), 500);
	}
	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "mapped: frontend PLAIN authenticated");

	// The frontend stream is marked encrypted so the default as_client
	// backend policy negotiates real TLS. No frontend TLS handshake is
	// involved in this mapping-only test.
	auto attach_and_observe = [&](const MysqlxResolvedIdentity& identity,
	                              const std::string& expected_mech,
	                              const std::string& expected_data) {
		sess.inject_identity_for_test(identity);
		int bfds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, bfds);
		MysqlxConnection* conn = new MysqlxConnection();
		conn->set_fd(bfds[0]);
		// Test-only socketpair attachment: production start_connect()
		// persists this identity instead.
		conn->set_address("127.0.0.1");
		conn->set_state(MysqlxConnection::AUTHENTICATING);
		sess.backend_conn() = conn;
		sess.set_status(MysqlxSession::CONNECTING_SERVER);
		sess.to_process = true;
		sess.handler();
		const bool match = observe_backend_auth_start(
			sess, conn, bfds[1], backend_server_ctx, expected_mech, expected_data);
		sess.backend_conn() = nullptr;
		delete conn;
		close(bfds[1]);
		return match;
	};

	MysqlxResolvedIdentity mapped {};
	mapped.username = "testuser";
	mapped.x_enabled = true;
	mapped.default_route = "tls_route";
	mapped.backend_auth_mode = MysqlxBackendAuthMode::mapped;
	ok(attach_and_observe(mapped, "PLAIN",
	                      std::string("\0", 1) + "testuser" + std::string("\0", 1) + "testpass"),
	   "mapped: implicit mapped backend authenticates with PLAIN over TLS");

	MysqlxResolvedIdentity service {};
	service.username = "testuser";
	service.x_enabled = true;
	service.default_route = "tls_route";
	service.backend_auth_mode = MysqlxBackendAuthMode::service_account;
	service.backend_username = "svc_account";
	service.backend_password = "svc_password";
	ok(attach_and_observe(service, "MYSQL41",
	                      std::string("\0", 1) + "svc_account" + std::string("\0", 1)),
	   "mapped: explicit service account keeps MYSQL41 and its own credentials");

	MysqlxResolvedIdentity explicit_mapped {};
	explicit_mapped.username = "testuser";
	explicit_mapped.x_enabled = true;
	explicit_mapped.default_route = "tls_route";
	explicit_mapped.backend_auth_mode = MysqlxBackendAuthMode::mapped;
	explicit_mapped.backend_password = "explicit_backend_password";
	ok(attach_and_observe(explicit_mapped, "MYSQL41",
	                      std::string("\0", 1) + "testuser" + std::string("\0", 1)),
	   "mapped: explicit mapped backend_password suppresses frontend-secret fallback");

	// Session reset must wipe the retained secret: after reset a mapped
	// identity no longer selects PLAIN.
	sess.reset();
	sess.client_ds().set_encrypted(true);
	MysqlxResolvedIdentity after_reset {};
	after_reset.username = "testuser";
	after_reset.x_enabled = true;
	after_reset.password = "testpass";
	after_reset.default_route = "tls_route";
	after_reset.backend_auth_mode = MysqlxBackendAuthMode::mapped;
	ok(attach_and_observe(after_reset, "MYSQL41", std::string("\0\0", 2)),
	   "mapped: session reset wipes the retained PLAIN secret");

	sess.client_ds().init(XDS_FRONTEND, -1);
	close(cfds[0]); close(cfds[1]);
	GloVars.global.ssl_ctx = nullptr;
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(backend_server_ctx);
}

// Session-level credential presence: a valid $A$ verifier for the empty
// password plus an empty frontend PLAIN secret is still a PRESENT credential.
// The mapped backend must therefore select PLAIN with an empty password field,
// not MYSQL41 with the stored verifier.
static void test_mapped_plain_empty_secret_selection() {
	diag(">>> %s", __func__);
	SSL_CTX* shared_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	SSL_CTX* backend_server_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	if (!shared_ctx || !backend_server_ctx) {
		ok(false, "mapped-empty-secret: TLS contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(backend_server_ctx);
		return;
	}
	trust_peer_and_install_permissive_callback(shared_ctx, backend_server_ctx);
	GloVars.global.ssl_ctx = shared_ctx;

	const std::string empty_hash = make_sha2_hash_for_password("");
	if (empty_hash.size() != 70) {
		ok(false, "mapped-empty-secret: empty-password $A$ fixture generated");
		GloVars.global.ssl_ctx = nullptr;
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(backend_server_ctx);
		return;
	}

	MysqlxConfigStore store;
	install_tls_route(store);
	Mysqlx_Thread thr;
	thr.init(0);
	thr.set_config_store(&store);

	int cfds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, cfds);
	MysqlxSession sess;
	sess.init(cfds[0], &thr, "tls_route");
	sess.client_ds().set_encrypted(true);
	sess.set_identity_lookup([empty_hash](const std::string& user)
		-> std::optional<MysqlxResolvedIdentity> {
		return plain_identity(user, empty_hash);
	});
	send_frontend_plain_start(cfds[1], "testuser", "");
	sess.to_process = true;
	sess.handler();
	uint8_t response[4096];
	const ssize_t response_n = read_frame_with_timeout(
		cfds[1], response, sizeof(response), 500);
	ok(response_n >= 5 &&
	   response[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
	   "mapped-empty-secret: frontend empty-password PLAIN authenticates");
	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "mapped-empty-secret: session reaches WAITING_CLIENT_XMSG");

	int bfds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, bfds);
	MysqlxConnection* conn = new MysqlxConnection();
	conn->set_fd(bfds[0]);
	conn->set_address("127.0.0.1");
	conn->set_state(MysqlxConnection::AUTHENTICATING);
	sess.backend_conn() = conn;
	sess.set_status(MysqlxSession::CONNECTING_SERVER);
	sess.to_process = true;
	sess.handler();

	const bool observed = observe_backend_auth_start(
		sess, conn, bfds[1], backend_server_ctx, "PLAIN",
		std::string("\0", 1) + "testuser" + std::string("\0", 1));
	ok(observed,
	   "mapped-empty-secret: present empty verified secret selects backend PLAIN");

	sess.backend_conn() = nullptr;
	delete conn;
	close(bfds[1]);
	sess.client_ds().init(XDS_FRONTEND, -1);
	close(cfds[0]); close(cfds[1]);
	GloVars.global.ssl_ctx = nullptr;
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(backend_server_ctx);
}

// -----------------------------------------------------------------------
// Worker-level progress: after the client sends its first query, the
// worker must drive backend connect/auth/plaintext frames to completion
// without another frontend event. This locks the rebuild_poll_set()
// registration for the pre-XDS_READY backend fds.
// -----------------------------------------------------------------------
struct BackendProbe {
	std::atomic<bool> ok { false };
	std::atomic<bool> saw_execute { false };
	std::string mechanism;
	std::string auth_data;
};

static bool fd_read_exact(int fd, uint8_t* out, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, out + off, len - off);
		if (n > 0) { off += static_cast<size_t>(n); continue; }
		if (n < 0 && errno == EINTR) continue;
		return false;
	}
	return true;
}

static bool fd_read_frame(int fd, uint8_t* type, std::string* payload) {
	uint8_t header[5];
	if (!fd_read_exact(fd, header, sizeof(header))) return false;
	const uint32_t size = static_cast<uint32_t>(header[0]) |
		(static_cast<uint32_t>(header[1]) << 8) |
		(static_cast<uint32_t>(header[2]) << 16) |
		(static_cast<uint32_t>(header[3]) << 24);
	if (size < 1) return false;
	*type = header[4];
	payload->assign(size - 1, '\0');
	return size == 1 || fd_read_exact(fd, reinterpret_cast<uint8_t*>(&(*payload)[0]), size - 1);
}

static bool ssl_read_exact(SSL* ssl, uint8_t* out, size_t len) {
	size_t off = 0;
	int stalls = 0;
	while (off < len) {
		int n = SSL_read(ssl, out + off, static_cast<int>(len - off));
		if (n > 0) { off += static_cast<size_t>(n); stalls = 0; continue; }
		const int err = SSL_get_error(ssl, n);
		if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
		    ++stalls < 100) {
			usleep(1000);
			continue;
		}
		return false;
	}
	return true;
}

static bool ssl_read_frame(SSL* ssl, uint8_t* type, std::string* payload) {
	uint8_t header[5];
	if (!ssl_read_exact(ssl, header, sizeof(header))) return false;
	const uint32_t size = static_cast<uint32_t>(header[0]) |
		(static_cast<uint32_t>(header[1]) << 8) |
		(static_cast<uint32_t>(header[2]) << 16) |
		(static_cast<uint32_t>(header[3]) << 24);
	if (size < 1) return false;
	*type = header[4];
	payload->assign(size - 1, '\0');
	return size == 1 || ssl_read_exact(ssl, reinterpret_cast<uint8_t*>(&(*payload)[0]), size - 1);
}

static bool ssl_write_frame(SSL* ssl, uint8_t type, const std::string& payload) {
	std::vector<uint8_t> frame;
	const uint32_t size = static_cast<uint32_t>(payload.size()) + 1;
	frame.push_back(size & 0xFF);
	frame.push_back((size >> 8) & 0xFF);
	frame.push_back((size >> 16) & 0xFF);
	frame.push_back((size >> 24) & 0xFF);
	frame.push_back(type);
	frame.insert(frame.end(), payload.begin(), payload.end());
	size_t off = 0;
	while (off < frame.size()) {
		int n = SSL_write(ssl, frame.data() + off,
		                  static_cast<int>(frame.size() - off));
		if (n > 0) { off += static_cast<size_t>(n); continue; }
		if (n < 0 && SSL_get_error(ssl, n) == SSL_ERROR_WANT_WRITE) {
			usleep(1000);
			continue;
		}
		return false;
	}
	return true;
}

static void backend_probe_thread(int listen_fd, SSL_CTX* server_ctx, BackendProbe* probe) {
	// Bound the accept wait so a failed frontend/backend-progress run
	// does not leave this helper blocked and force the caller's timeout
	// to be the only failure detector.
	struct pollfd lpfd { listen_fd, POLLIN, 0 };
	if (poll(&lpfd, 1, 5000) <= 0) {
		probe->ok = false;
		return;
	}
	int fd = accept(listen_fd, nullptr, nullptr);
	if (fd < 0) return;
	struct timeval tv { 5, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	uint8_t type = 0;
	std::string payload;
	if (!fd_read_frame(fd, &type, &payload) ||
	    type != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET) {
		close(fd);
		return;
	}
	write_x_frame(fd, Mysqlx::ServerMessages_Type_CONN_CAPABILITIES, nullptr, 0);
	if (!fd_read_frame(fd, &type, &payload) ||
	    type != Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET) {
		close(fd);
		return;
	}
	write_x_frame(fd, Mysqlx::ServerMessages_Type_OK, nullptr, 0);

	SSL* ssl = SSL_new(server_ctx);
	SSL_set_fd(ssl, fd);
	bool ok = SSL_accept(ssl) == 1;

	if (ok) {
		if (ssl_read_frame(ssl, &type, &payload) &&
		    type == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START) {
			Mysqlx::Session::AuthenticateStart auth;
			if (auth.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
				probe->mechanism = auth.mech_name();
				probe->auth_data = auth.auth_data();
			}
			ok = ssl_write_frame(ssl, Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK, "");
		} else {
			ok = false;
		}
	}
	if (ok) {
		if (ssl_read_frame(ssl, &type, &payload) &&
		    type == Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE) {
			probe->saw_execute = true;
			ok = ssl_write_frame(ssl, Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK, "");
		} else {
			ok = false;
		}
	}
	probe->ok = ok;
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(fd);
}

static int pick_free_tcp_port() {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd); return -1;
	}
	socklen_t len = sizeof(addr);
	if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
		close(fd); return -1;
	}
	int port = ntohs(addr.sin_port);
	close(fd);
	return port;
}

static int start_tcp_listener(int* port_out) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	struct sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
	    listen(fd, 8) != 0) {
		close(fd); return -1;
	}
	socklen_t len = sizeof(addr);
	getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
	*port_out = ntohs(addr.sin_port);
	return fd;
}

static void test_worker_progress_without_frontend_wakeups() {
	diag(">>> %s", __func__);
	// The route endpoint is the numeric address 127.0.0.1. The peer leaf
	// carries an IP SAN for it and is in the shared context's trust store,
	// so this positive worker test also proves start_connect() carries the
	// configured endpoint identity into the backend PLAIN peer check
	// without any test-only set_address() call.
	SSL_CTX* shared_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	SSL_CTX* peer_ctx = create_test_ssl_ctx("IP:127.0.0.1");
	trust_peer_and_install_permissive_callback(shared_ctx, peer_ctx);
	SSL_CTX* client_ctx = SSL_CTX_new(TLS_method());
	if (client_ctx) {
		SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
		SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);
	}
	if (!shared_ctx || !peer_ctx || !client_ctx) {
		ok(false, "worker-progress: TLS contexts created");
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		SSL_CTX_free(client_ctx);
		return;
	}
	SSL_CTX_set_verify(peer_ctx, SSL_VERIFY_PEER, reject_client_cert_cb);
	GloVars.global.ssl_ctx = shared_ctx;

	int backend_port = 0;
	int backend_listener = start_tcp_listener(&backend_port);
	int frontend_port = pick_free_tcp_port();
	if (backend_listener < 0 || frontend_port <= 0) {
		ok(false, "worker-progress: listener ports allocated");
		close(backend_listener);
		GloVars.global.ssl_ctx = nullptr;
		SSL_CTX_free(shared_ctx);
		SSL_CTX_free(peer_ctx);
		SSL_CTX_free(client_ctx);
		return;
	}

	BackendProbe probe;
	std::thread backend_thread(backend_probe_thread, backend_listener, peer_ctx, &probe);

	MysqlxConfigStore store;
	std::unordered_map<std::string, MysqlxRoute> routes;
	MysqlxRoute route {};
	route.name = "tls_route";
	route.destination_hostgroup = 10;
	route.strategy = "first_available";
	routes.emplace(route.name, route);
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
	MysqlxBackendEndpoint ep {};
	ep.hostname = "127.0.0.1";
	ep.mysql_port = 3306;
	ep.mysqlx_port = backend_port;
	endpoints[10].push_back(ep);
	store.install_for_test(std::move(routes), std::move(endpoints));
	std::unordered_map<std::string, MysqlxResolvedIdentity> identities;
	MysqlxResolvedIdentity id = plain_identity("testuser", "testpass");
	id.require_tls = true;
	identities.emplace("testuser", id);
	store.install_identities_for_test(std::move(identities));

	Mysqlx_Thread worker;
	worker.init(0);
	worker.set_config_store(&store);
	ok(worker.add_listener("127.0.0.1", frontend_port, "tls_route") == 0,
	   "worker-progress: listener bound");
	ok(worker.start(), "worker-progress: worker thread started");
	usleep(50000);

	int cfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in caddr {};
	caddr.sin_family = AF_INET;
	caddr.sin_port = htons(frontend_port);
	inet_pton(AF_INET, "127.0.0.1", &caddr.sin_addr);
	struct timeval tv { 0, 100000 };
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	ok(connect(cfd, reinterpret_cast<sockaddr*>(&caddr), sizeof(caddr)) == 0,
	   "worker-progress: frontend connected");

	ok(write_all(cfd, CAPSET_TLS_EXACT, sizeof(CAPSET_TLS_EXACT)),
	   "worker-progress: CapabilitiesSet(tls=true) sent");
	uint8_t ack[16];
	ssize_t ack_n = read_frame_with_timeout(cfd, ack, sizeof(ack), 2000);
	ok(ack_n == 7 && ack[4] == Mysqlx::ServerMessages_Type_OK,
	   "worker-progress: plaintext Ok received before TLS");

	SSL* client_ssl = SSL_new(client_ctx);
	SSL_set_fd(client_ssl, cfd);
	int tls_rc = -1;
	for (int i = 0; i < 500; ++i) {
		tls_rc = SSL_connect(client_ssl);
		if (tls_rc == 1) break;
		const int err = SSL_get_error(client_ssl, tls_rc);
		if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;
		usleep(1000);
	}
	ok(tls_rc == 1, "worker-progress: frontend TLS established");

	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("PLAIN");
	std::string auth_data;
	auth_data.push_back('\0');
	auth_data.append("testuser");
	auth_data.push_back('\0');
	auth_data.append("testpass");
	auth.set_auth_data(auth_data);
	std::string serialized;
	auth.SerializeToString(&serialized);
	ok(ssl_write_frame(client_ssl, Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
	                   serialized),
	   "worker-progress: PLAIN AuthenticateStart sent over TLS");

	bool authenticated = false;
	for (int i = 0; i < 1000 && !authenticated; ++i) {
		uint8_t type = 0;
		std::string payload;
		if (!ssl_read_frame(client_ssl, &type, &payload)) break;
		if (type == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK) authenticated = true;
	}
	ok(authenticated, "worker-progress: PLAIN AuthenticateOk received");

	Mysqlx::Sql::StmtExecute stmt;
	stmt.set_stmt("SELECT 1");
	std::string stmt_s;
	stmt.SerializeToString(&stmt_s);
	ok(ssl_write_frame(client_ssl, Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE, stmt_s),
	   "worker-progress: first query sent");

	// The first query must complete without another frontend message
	// driving backend connection, TLS, or authentication progress.
	bool got_result = false;
	for (int i = 0; i < 2000 && !got_result; ++i) {
		uint8_t type = 0;
		std::string payload;
		if (!ssl_read_frame(client_ssl, &type, &payload)) break;
		if (type == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK) got_result = true;
	}
	ok(got_result, "worker-progress: query result arrived without extra frontend events");

	backend_thread.join();
	ok(probe.ok.load() && probe.saw_execute.load(),
	   "worker-progress: backend completed connect/TLS/auth/query");
	ok(probe.mechanism == "PLAIN" &&
	   probe.auth_data == std::string("\0", 1) + "testuser" + std::string("\0", 1) + "testpass",
	   "worker-progress: backend saw mapped PLAIN credentials over TLS");

	SSL_free(client_ssl);
	close(cfd);
	close(backend_listener);
	worker.stop();
	worker.remove_listeners();
	GloVars.global.ssl_ctx = nullptr;
	SSL_CTX_free(shared_ctx);
	SSL_CTX_free(peer_ctx);
	SSL_CTX_free(client_ctx);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(0);
	diag("=== mysqlx_frontend_tls_unit-t starting ===");
	test_init_minimal();

	test_tls_ack_then_fragmented_handshake_then_plain_auth();
	test_plain_sha2_hash_verification();
	test_plain_without_tls_rejected();
	test_mapped_plain_secret_selection();
	test_mapped_plain_empty_secret_selection();
	test_worker_progress_without_frontend_wakeups();

	test_cleanup_minimal();
	return exit_status();
}
