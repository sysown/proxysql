/**
 * mysqlx_protocol_unit-t.cpp
 *
 * Unit tests for X Protocol frame encode/decode and auth helpers.
 */

#include "mysqlx_protocol.h"
#include "tap.h"

int main() {
	plan(10);

	// Test 1-3: Frame header encode/decode round-trip.
	{
		MysqlxFrameHeader hdr { 17, 12 };
		auto encoded = mysqlx_encode_frame_header(hdr);
		ok(encoded.size() == 5, "frame header encodes to 5 bytes");

		auto decoded = mysqlx_decode_frame_header(encoded.data(), encoded.size());
		ok(decoded.has_value(), "frame header decodes successfully");
		ok(decoded->payload_size == 17, "payload_size preserved");
	}

	// Test 4: Decode too-short buffer.
	{
		uint8_t short_buf[3] = { 0, 0, 0 };
		auto decoded = mysqlx_decode_frame_header(short_buf, 3);
		ok(!decoded.has_value(), "decode rejects buffer shorter than 5 bytes");
	}

	// Test 5-6: Auth method validation.
	{
		ok(mysqlx_is_supported_auth_method("MYSQL41"), "MYSQL41 is supported");
		ok(!mysqlx_is_supported_auth_method("SHA256_MEMORY"), "SHA256_MEMORY not supported");
	}

	// Test 7: Build frame assembles header + payload correctly.
	{
		std::string payload = "hello";
		auto frame = mysqlx_build_frame(42, payload);
		auto hdr = mysqlx_decode_frame_header(frame.data(), frame.size());
		ok(hdr.has_value() && hdr->payload_size == 6 && hdr->message_type == 42,
		   "build_frame produces correct header");
	}

	// Test 8-10: MYSQL41 hash and verify.
	{
		std::string password = "testpass";
		auto hash = mysqlx_mysql41_hash(password);
		ok(hash.size() == 20, "MYSQL41 hash is 20 bytes (SHA1)");

		std::vector<uint8_t> challenge = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		                                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
		auto scramble = mysqlx_mysql41_scramble(challenge, password);
		ok(scramble.size() == 20, "MYSQL41 scramble is 20 bytes");

		ok(mysqlx_mysql41_verify(challenge, scramble, password),
		   "MYSQL41 verify succeeds with correct scramble");
	}

	return exit_status();
}
