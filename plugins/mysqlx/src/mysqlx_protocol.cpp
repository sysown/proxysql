#include "mysqlx_protocol.h"

#include "mysqlx.pb.h"
#include "mysqlx_session.pb.h"

#include <cerrno>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <unistd.h>

namespace {

// SHA1 helper using EVP API (OpenSSL 3.0+).
bool sha1_digest(const uint8_t* data, size_t len, uint8_t out[20]) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx) return false;
	unsigned int out_len = 0;
	bool ok = EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) == 1
	       && EVP_DigestUpdate(ctx, data, len) == 1
	       && EVP_DigestFinal_ex(ctx, out, &out_len) == 1
	       && out_len == 20;
	EVP_MD_CTX_free(ctx);
	return ok;
}

bool sha1_digest_multi(const uint8_t* d1, size_t l1,
                        const uint8_t* d2, size_t l2,
                        uint8_t out[20]) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx) return false;
	unsigned int out_len = 0;
	bool ok = EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) == 1
	       && EVP_DigestUpdate(ctx, d1, l1) == 1
	       && EVP_DigestUpdate(ctx, d2, l2) == 1
	       && EVP_DigestFinal_ex(ctx, out, &out_len) == 1
	       && out_len == 20;
	EVP_MD_CTX_free(ctx);
	return ok;
}

static constexpr size_t SHA1_LEN = 20;

} // namespace

std::vector<uint8_t> mysqlx_encode_frame_header(const MysqlxFrameHeader& hdr) {
	std::vector<uint8_t> buf(MYSQLX_FRAME_HEADER_SIZE);
	uint32_t ps = hdr.payload_size;
	buf[0] = static_cast<uint8_t>(ps & 0xFF);
	buf[1] = static_cast<uint8_t>((ps >> 8) & 0xFF);
	buf[2] = static_cast<uint8_t>((ps >> 16) & 0xFF);
	buf[3] = static_cast<uint8_t>((ps >> 24) & 0xFF);
	buf[4] = hdr.message_type;
	return buf;
}

std::optional<MysqlxFrameHeader> mysqlx_decode_frame_header(const uint8_t* data, size_t len) {
	if (len < MYSQLX_FRAME_HEADER_SIZE) {
		return std::nullopt;
	}

	MysqlxFrameHeader hdr {};
	hdr.payload_size = static_cast<uint32_t>(data[0])
	                 | (static_cast<uint32_t>(data[1]) << 8)
	                 | (static_cast<uint32_t>(data[2]) << 16)
	                 | (static_cast<uint32_t>(data[3]) << 24);
	hdr.message_type = data[4];
	return hdr;
}

bool mysqlx_is_supported_auth_method(const std::string& method) {
	return method == "MYSQL41" || method == "PLAIN";
}

std::vector<uint8_t> mysqlx_build_frame(uint8_t message_type, const std::string& serialized_payload) {
	// payload_size in the header includes the message_type byte. Reject
	// payloads at the uint32 boundary so the +1 cannot wrap, and clamp at the
	// X Protocol max payload to match the inbound parser (X_MAX_PAYLOAD_SIZE
	// in MysqlxDataStream).
	if (serialized_payload.size() >= MYSQLX_MAX_PAYLOAD_SIZE) {
		return {};
	}
	uint32_t payload_size = static_cast<uint32_t>(serialized_payload.size()) + 1;
	MysqlxFrameHeader hdr { payload_size, message_type };
	std::vector<uint8_t> frame = mysqlx_encode_frame_header(hdr);
	frame.insert(frame.end(), serialized_payload.begin(), serialized_payload.end());
	return frame;
}

bool mysqlx_read_exact(int fd, uint8_t* buf, size_t len) {
	size_t total = 0;
	while (total < len) {
		ssize_t n = read(fd, buf + total, len - total);
		if (n < 0) {
			if (errno == EINTR) continue;
			return false;
		}
		if (n == 0) return false;
		total += static_cast<size_t>(n);
	}
	return true;
}

bool mysqlx_read_frame(int fd, MysqlxFrameHeader& header, std::vector<uint8_t>& payload) {
	uint8_t hdr_buf[MYSQLX_FRAME_HEADER_SIZE];
	if (!mysqlx_read_exact(fd, hdr_buf, MYSQLX_FRAME_HEADER_SIZE)) {
		return false;
	}

	auto opt = mysqlx_decode_frame_header(hdr_buf, MYSQLX_FRAME_HEADER_SIZE);
	if (!opt.has_value()) {
		return false;
	}

	header = opt.value();

	if (header.payload_size > MYSQLX_MAX_PAYLOAD_SIZE) {
		return false;
	}

	// payload_size includes the 1-byte message_type already consumed in header.
	uint32_t body_size = header.payload_size > 0 ? header.payload_size - 1 : 0;
	payload.resize(body_size);
	if (body_size > 0) {
		if (!mysqlx_read_exact(fd, payload.data(), body_size)) {
			return false;
		}
	}

	return true;
}

bool mysqlx_write_all(int fd, const uint8_t* data, size_t len) {
	size_t total = 0;
	while (total < len) {
		ssize_t n = write(fd, data + total, len - total);
		if (n < 0) {
			if (errno == EINTR) continue;
			return false;
		}
		if (n == 0) return false;
		total += static_cast<size_t>(n);
	}
	return true;
}

bool mysqlx_send_error(int fd, uint16_t code, const std::string& msg, const std::string& sql_state) {
	Mysqlx::Error error_msg;
	error_msg.set_severity(Mysqlx::Error::ERROR);
	error_msg.set_code(code);
	error_msg.set_sql_state(sql_state);
	error_msg.set_msg(msg);

	std::string serialized;
	error_msg.SerializeToString(&serialized);

	auto frame = mysqlx_build_frame(
		Mysqlx::ServerMessages_Type_ERROR,
		serialized
	);

	return mysqlx_write_all(fd, frame.data(), frame.size());
}

bool mysqlx_send_ok(int fd, const std::string& msg) {
	Mysqlx::Ok ok_msg;
	if (!msg.empty()) {
		ok_msg.set_msg(msg);
	}

	std::string serialized;
	ok_msg.SerializeToString(&serialized);

	auto frame = mysqlx_build_frame(
		Mysqlx::ServerMessages_Type_OK,
		serialized
	);

	return mysqlx_write_all(fd, frame.data(), frame.size());
}

// ---------------------------------------------------------------------------
// MYSQL41 auth helpers
// ---------------------------------------------------------------------------
// MYSQL41 uses double-SHA1:
//   hash_stage1 = SHA1(password)
//   hash_stage2 = SHA1(hash_stage1)
//   scramble = XOR(hash_stage1, SHA1(challenge + hash_stage2))

std::string mysqlx_hex_encode(const std::vector<uint8_t>& data) {
	static const char hex_chars[] = "0123456789ABCDEF";
	std::string result;
	result.reserve(data.size() * 2);
	for (uint8_t b : data) {
		result += hex_chars[(b >> 4) & 0x0F];
		result += hex_chars[b & 0x0F];
	}
	return result;
}

bool mysqlx_hex_decode(const std::string& hex, std::vector<uint8_t>& out) {
	if (hex.size() % 2 != 0) {
		return false;
	}
	out.clear();
	out.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2) {
		uint8_t hi = 0, lo = 0;
		char c_hi = hex[i], c_lo = hex[i + 1];
		if (c_hi >= '0' && c_hi <= '9') hi = static_cast<uint8_t>(c_hi - '0');
		else if (c_hi >= 'A' && c_hi <= 'F') hi = static_cast<uint8_t>(c_hi - 'A' + 10);
		else if (c_hi >= 'a' && c_hi <= 'f') hi = static_cast<uint8_t>(c_hi - 'a' + 10);
		else return false;
		if (c_lo >= '0' && c_lo <= '9') lo = static_cast<uint8_t>(c_lo - '0');
		else if (c_lo >= 'A' && c_lo <= 'F') lo = static_cast<uint8_t>(c_lo - 'A' + 10);
		else if (c_lo >= 'a' && c_lo <= 'f') lo = static_cast<uint8_t>(c_lo - 'a' + 10);
		else return false;
		out.push_back(static_cast<uint8_t>((hi << 4) | lo));
	}
	return true;
}

std::vector<uint8_t> mysqlx_mysql41_hash(const std::string& password) {
	uint8_t stage1[SHA1_LEN];
	if (!sha1_digest(reinterpret_cast<const uint8_t*>(password.data()), password.size(), stage1)) {
		return {};
	}

	std::vector<uint8_t> stage2(SHA1_LEN);
	if (!sha1_digest(stage1, SHA1_LEN, stage2.data())) {
		return {};
	}
	return stage2;
}

std::vector<uint8_t> mysqlx_mysql41_scramble(const std::vector<uint8_t>& challenge,
                                              const std::string& password) {
	uint8_t stage1[SHA1_LEN];
	if (!sha1_digest(reinterpret_cast<const uint8_t*>(password.data()), password.size(), stage1)) {
		return {};
	}

	uint8_t stage2[SHA1_LEN];
	if (!sha1_digest(stage1, SHA1_LEN, stage2)) {
		return {};
	}

	uint8_t combined[SHA1_LEN];
	if (!sha1_digest_multi(challenge.data(), challenge.size(), stage2, SHA1_LEN, combined)) {
		return {};
	}

	std::vector<uint8_t> result(SHA1_LEN);
	for (size_t i = 0; i < SHA1_LEN; i++) {
		result[i] = stage1[i] ^ combined[i];
	}
	return result;
}

bool mysqlx_mysql41_verify(const std::vector<uint8_t>& challenge,
                            const std::vector<uint8_t>& client_response,
                            const std::string& password) {
	if (client_response.size() != SHA1_LEN) {
		return false;
	}

	auto expected = mysqlx_mysql41_scramble(challenge, password);
	if (expected.size() != SHA1_LEN) {
		return false;
	}
	return CRYPTO_memcmp(expected.data(), client_response.data(), SHA1_LEN) == 0;
}

bool mysqlx_mysql41_verify_hash(const std::vector<uint8_t>& challenge,
                                 const std::vector<uint8_t>& client_response,
                                 const std::vector<uint8_t>& stored_hash) {
	if (client_response.size() != SHA1_LEN || stored_hash.size() != SHA1_LEN) {
		return false;
	}

	uint8_t combined[SHA1_LEN];
	if (!sha1_digest_multi(challenge.data(), challenge.size(),
	                       stored_hash.data(), stored_hash.size(), combined)) {
		return false;
	}

	uint8_t hash_stage1[SHA1_LEN];
	for (size_t i = 0; i < SHA1_LEN; i++) {
		hash_stage1[i] = client_response[i] ^ combined[i];
	}

	uint8_t hash_stage2[SHA1_LEN];
	if (!sha1_digest(hash_stage1, SHA1_LEN, hash_stage2)) {
		return false;
	}

	return CRYPTO_memcmp(hash_stage2, stored_hash.data(), SHA1_LEN) == 0;
}

// =====================================================================
// TLS handshake error classification (issue #5698).
//
// Walks the OpenSSL state to translate "SSL_do_handshake failed" into
// one of the named error classes. Classification logic, in order:
//
//   1. ssl == nullptr       -> NO_SSL_CTX
//   2. SSL_get_verify_result() != X509_V_OK -> a chain-related class
//      (CERT_EXPIRED, HOSTNAME_MISMATCH, UNKNOWN_CA, CERT_VERIFY_FAILED).
//      We check the cert chain first because OpenSSL's error queue
//      sometimes carries both a chain reason and a generic SSL_R_*
//      reason; the chain reason is more actionable for operators.
//   3. ERR_get_error() reasons checked for SSL_R_UNSUPPORTED_PROTOCOL
//      / SSL_R_TLSV1_ALERT_PROTOCOL_VERSION / SSL_R_WRONG_VERSION_NUMBER
//      -> PROTOCOL_MISMATCH.
//   4. Fallback -> HANDSHAKE_FAILED.
//
// peek_err_queue=false skips step 3 (caller may already have drained
// the queue elsewhere or want to preserve it for downstream logging).
// =====================================================================

MysqlxTlsErrorClass mysqlx_classify_tls_error(SSL* ssl, bool peek_err_queue) {
	if (ssl == nullptr) return MysqlxTlsErrorClass::NO_SSL_CTX;

	// Step 1: cert-chain reasons take precedence.
	long verify_rc = SSL_get_verify_result(ssl);
	if (verify_rc != X509_V_OK) {
		switch (verify_rc) {
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CERT_NOT_YET_VALID:
				return MysqlxTlsErrorClass::CERT_EXPIRED;
			case X509_V_ERR_HOSTNAME_MISMATCH:
				return MysqlxTlsErrorClass::HOSTNAME_MISMATCH;
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
				return MysqlxTlsErrorClass::UNKNOWN_CA;
			default:
				// Other cert-chain failures: untrusted root, bad
				// signature, key usage mismatch, etc. Group under
				// CERT_VERIFY_FAILED so operators get the right ballpark.
				return MysqlxTlsErrorClass::CERT_VERIFY_FAILED;
		}
	}

	// Step 2: protocol-mismatch reasons in the OpenSSL error queue.
	if (peek_err_queue) {
		while (true) {
			unsigned long e = ERR_get_error();
			if (e == 0) break;
			int reason = ERR_GET_REASON(e);
			switch (reason) {
				case SSL_R_UNSUPPORTED_PROTOCOL:
				case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
				case SSL_R_WRONG_VERSION_NUMBER:
				case SSL_R_UNKNOWN_PROTOCOL:
					// Drain the rest of the queue then return.
					while (ERR_get_error() != 0) {}
					return MysqlxTlsErrorClass::PROTOCOL_MISMATCH;
				default:
					break;
			}
		}
	}

	// Step 3: fallback. Couldn't classify into a specific class —
	// emit the generic handshake failure.
	return MysqlxTlsErrorClass::HANDSHAKE_FAILED;
}

// Backend-side messages: include enough detail to be operationally
// useful (operator looking at the client's error response can
// immediately see "self-signed CA" vs "expired cert"). Does NOT
// include OpenSSL queue strings — those are appended by the caller in
// the log line, not the wire frame, since exposing chain detail to
// the client is a leak risk if the client is the attacker.
const char* mysqlx_backend_tls_error_message(MysqlxTlsErrorClass cls) {
	switch (cls) {
		case MysqlxTlsErrorClass::CERT_VERIFY_FAILED:
			return "Backend TLS handshake failed: certificate verify failed";
		case MysqlxTlsErrorClass::CERT_EXPIRED:
			return "Backend TLS handshake failed: certificate expired or not yet valid";
		case MysqlxTlsErrorClass::HOSTNAME_MISMATCH:
			return "Backend TLS handshake failed: certificate hostname mismatch";
		case MysqlxTlsErrorClass::PROTOCOL_MISMATCH:
			return "Backend TLS handshake failed: TLS protocol version not supported by backend";
		case MysqlxTlsErrorClass::UNKNOWN_CA:
			return "Backend TLS handshake failed: unknown / untrusted CA in certificate chain";
		case MysqlxTlsErrorClass::NO_SSL_CTX:
			return "Backend TLS handshake failed: SSL context not initialized";
		case MysqlxTlsErrorClass::HANDSHAKE_FAILED:
		case MysqlxTlsErrorClass::UNKNOWN:
		default:
			return "Backend TLS handshake failed";
	}
}

int mysqlx_backend_tls_error_code(MysqlxTlsErrorClass cls) {
	switch (cls) {
		case MysqlxTlsErrorClass::CERT_VERIFY_FAILED:
			return MYSQLX_BACKEND_TLS_ERR_CERT_VERIFY_FAILED;
		case MysqlxTlsErrorClass::CERT_EXPIRED:
			return MYSQLX_BACKEND_TLS_ERR_CERT_EXPIRED;
		case MysqlxTlsErrorClass::HOSTNAME_MISMATCH:
			return MYSQLX_BACKEND_TLS_ERR_HOSTNAME_MISMATCH;
		case MysqlxTlsErrorClass::PROTOCOL_MISMATCH:
			return MYSQLX_BACKEND_TLS_ERR_PROTOCOL_MISMATCH;
		case MysqlxTlsErrorClass::UNKNOWN_CA:
			return MYSQLX_BACKEND_TLS_ERR_UNKNOWN_CA;
		case MysqlxTlsErrorClass::HANDSHAKE_FAILED:
		case MysqlxTlsErrorClass::NO_SSL_CTX:
		case MysqlxTlsErrorClass::UNKNOWN:
		default:
			return MYSQLX_BACKEND_TLS_ERR_HANDSHAKE_FAILED;
	}
}

// Frontend-side messages: deliberately collapse most classes onto
// HANDSHAKE_FAILED. Cert-chain detail in particular can leak
// attacker-supplied cert information through the proxy's response —
// the threat model on the frontend is different from the backend's
// (the frontend client is the potential attacker; the backend is
// trusted infrastructure). PROTOCOL_MISMATCH is operationally useful
// for legitimate clients hitting a too-old/too-new TLS version, so
// it gets its own code; NO_SSL_CTX maps to "TLS not configured".
const char* mysqlx_frontend_tls_error_message(MysqlxTlsErrorClass cls) {
	switch (cls) {
		case MysqlxTlsErrorClass::NO_SSL_CTX:
			return "TLS is not configured on server";
		case MysqlxTlsErrorClass::PROTOCOL_MISMATCH:
			return "TLS protocol version not supported";
		case MysqlxTlsErrorClass::CERT_VERIFY_FAILED:
		case MysqlxTlsErrorClass::CERT_EXPIRED:
		case MysqlxTlsErrorClass::HOSTNAME_MISMATCH:
		case MysqlxTlsErrorClass::UNKNOWN_CA:
		case MysqlxTlsErrorClass::HANDSHAKE_FAILED:
		case MysqlxTlsErrorClass::UNKNOWN:
		default:
			return "TLS handshake failed";
	}
}

int mysqlx_frontend_tls_error_code(MysqlxTlsErrorClass cls) {
	switch (cls) {
		case MysqlxTlsErrorClass::NO_SSL_CTX:
			return MYSQLX_FRONTEND_TLS_ERR_NOT_CONFIGURED;
		case MysqlxTlsErrorClass::PROTOCOL_MISMATCH:
			return MYSQLX_FRONTEND_TLS_ERR_PROTOCOL_MISMATCH;
		case MysqlxTlsErrorClass::CERT_VERIFY_FAILED:
		case MysqlxTlsErrorClass::CERT_EXPIRED:
		case MysqlxTlsErrorClass::HOSTNAME_MISMATCH:
		case MysqlxTlsErrorClass::UNKNOWN_CA:
		case MysqlxTlsErrorClass::HANDSHAKE_FAILED:
		case MysqlxTlsErrorClass::UNKNOWN:
		default:
			return MYSQLX_FRONTEND_TLS_ERR_HANDSHAKE_FAILED;
	}
}
