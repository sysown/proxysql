#include "mysqlx_protocol.h"

#include "mysqlx.pb.h"
#include "mysqlx_session.pb.h"

#include <cerrno>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
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
