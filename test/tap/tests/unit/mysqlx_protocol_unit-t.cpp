/**
 * mysqlx_protocol_unit-t.cpp
 *
 * Unit tests for X Protocol frame encode/decode and auth helpers.
 */

#include "mysqlx_protocol.h"
#include "tap.h"

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

static void test_frame_header_extra() {
	diag(">>> %s", __func__);
	{
		uint8_t zeros[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
		auto decoded = mysqlx_decode_frame_header(zeros, 5);
		ok(decoded.has_value() && decoded->payload_size == 0 && decoded->message_type == 0,
		   "decode all-zeros header yields payload_size=0, message_type=0");
	}

	{
		MysqlxFrameHeader hdr { 0x12345678, 0x42 };
		auto encoded = mysqlx_encode_frame_header(hdr);
		auto decoded = mysqlx_decode_frame_header(encoded.data(), encoded.size());
		ok(decoded.has_value() && decoded->payload_size == 0x12345678 && decoded->message_type == 0x42,
		   "encode/decode roundtrip preserves payload_size and message_type");
	}

	{
		MysqlxFrameHeader hdr { MYSQLX_MAX_PAYLOAD_SIZE, 1 };
		auto encoded = mysqlx_encode_frame_header(hdr);
		ok(encoded.size() == 5, "encode with MYSQLX_MAX_PAYLOAD_SIZE produces 5 bytes");
	}

	{
		uint8_t buf[6] = { 0x01, 0x00, 0x00, 0x00, 0x05, 0xFF };
		auto decoded = mysqlx_decode_frame_header(buf, 6);
		ok(decoded.has_value() && decoded->payload_size == 1 && decoded->message_type == 5,
		   "decode with 6 bytes succeeds, extra byte ignored");
	}
}

static void test_frame_building() {
	diag(">>> %s", __func__);
	{
		std::string payload = "hello";
		auto frame = mysqlx_build_frame(42, payload);
		bool match = (frame.size() >= 10) &&
		             (memcmp(frame.data() + 5, payload.data(), payload.size()) == 0);
		ok(match, "build_frame payload bytes match input after 5-byte header");
	}

	{
		std::string empty_payload;
		auto frame = mysqlx_build_frame(99, empty_payload);
		auto hdr = mysqlx_decode_frame_header(frame.data(), frame.size());
		ok(frame.size() == 5 && hdr.has_value() && hdr->payload_size == 1,
		   "build_frame with empty payload produces 5 bytes, payload_size=1");
	}

	{
		std::string payload = "test1234";
		auto frame = mysqlx_build_frame(1, payload);
		ok(frame.size() == 5 + payload.size(),
		   "build_frame total size == 5 + payload.size()");
	}
}

static void test_auth_method_extra() {
	diag(">>> %s", __func__);
	ok(mysqlx_is_supported_auth_method("PLAIN"), "PLAIN is supported");
	ok(!mysqlx_is_supported_auth_method(""), "empty auth method not supported");
}

static void test_mysql41_auth_extra() {
	diag(">>> %s", __func__);
	{
		std::vector<uint8_t> challenge(20, 0x01);
		std::string password = "correctpass";
		auto scramble = mysqlx_mysql41_scramble(challenge, password);
		ok(!mysqlx_mysql41_verify(challenge, scramble, "wrongpass"),
		   "MYSQL41 verify fails with wrong password");
	}

	{
		auto hash = mysqlx_mysql41_hash("");
		ok(hash.size() == 20, "MYSQL41 hash of empty string is 20 bytes");
	}

	{
		std::vector<uint8_t> challenge = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
		auto s1 = mysqlx_mysql41_scramble(challenge, "pass");
		auto s2 = mysqlx_mysql41_scramble(challenge, "pass");
		ok(s1 == s2, "MYSQL41 scramble is deterministic");
	}

	{
		std::vector<uint8_t> c1(20, 0x01);
		std::vector<uint8_t> c2(20, 0x02);
		auto s1 = mysqlx_mysql41_scramble(c1, "pass");
		auto s2 = mysqlx_mysql41_scramble(c2, "pass");
		ok(s1 != s2, "different challenges produce different scrambles");
	}

	{
		std::vector<uint8_t> empty_challenge;
		std::vector<uint8_t> empty_response;
		ok(!mysqlx_mysql41_verify(empty_challenge, empty_response, "pass"),
		   "MYSQL41 verify fails with empty response (size != 20)");
	}

	{
		std::vector<uint8_t> challenge(20, 0x01);
		std::vector<uint8_t> truncated(10, 0x00);
		ok(!mysqlx_mysql41_verify(challenge, truncated, "pass"),
		   "MYSQL41 verify fails with truncated response (10 bytes)");
	}
}

static void test_hex_encode_decode() {
	diag(">>> %s", __func__);
	ok(mysqlx_hex_encode({0x00}) == "00", "hex_encode({0x00}) == \"00\"");
	ok(mysqlx_hex_encode({0xFF}) == "FF", "hex_encode({0xFF}) == \"FF\" (uppercase)");
	ok(mysqlx_hex_encode({0xAB, 0xCD}) == "ABCD", "hex_encode({0xAB, 0xCD}) == \"ABCD\"");
	ok(mysqlx_hex_encode({}) == "", "hex_encode({}) == \"\"");

	{
		std::vector<uint8_t> out;
		ok(mysqlx_hex_decode("00", out) && out.size() == 1 && out[0] == 0x00,
		   "hex_decode(\"00\") yields 0x00");
	}
	{
		std::vector<uint8_t> out;
		ok(mysqlx_hex_decode("abcd", out) && out.size() == 2 && out[0] == 0xAB && out[1] == 0xCD,
		   "hex_decode(\"abcd\") yields {0xAB, 0xCD} (case insensitive)");
	}
	{
		std::vector<uint8_t> out;
		ok(mysqlx_hex_decode("", out) && out.empty(),
		   "hex_decode(\"\") yields empty, returns true");
	}
	{
		std::vector<uint8_t> out;
		ok(!mysqlx_hex_decode("ZZZ", out),
		   "hex_decode(\"ZZZ\") returns false (invalid chars)");
	}
	{
		std::vector<uint8_t> out;
		ok(!mysqlx_hex_decode("A", out),
		   "hex_decode(\"A\") returns false (odd length)");
	}
}

static void test_error_ok_frame_building() {
	diag(">>> %s", __func__);
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1045, "Access denied", "28000");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read && hdr.payload_size > 0,
		   "send_error → read_frame succeeds with non-zero payload");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1234, "custom error", "45000");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read, "send_error with custom SQL state → read succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_ok(fds[0]);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read, "send_ok → read_frame succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_ok(fds[0], "test message");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read, "send_ok with message → read succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1000, "", "00000");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read, "send_error with empty message → read succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_ok(fds[0], "");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read, "send_ok with empty string → read succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1045, "err", "28000");
		mysqlx_send_ok(fds[0], "ok msg");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok1 = mysqlx_read_frame(fds[1], hdr, payload);
		bool ok2 = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok1 && ok2, "send error then OK → both reads succeed");
		close(fds[0]);
		close(fds[1]);
	}

	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_ok(fds[0]);
		close(fds[0]);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok1 = mysqlx_read_frame(fds[1], hdr, payload);
		bool ok2 = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok1 && !ok2, "send OK then close sender → second read returns false (EOF)");
		close(fds[1]);
	}
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(42);
	diag("=== mysqlx_protocol_unit-t starting ===");

	signal(SIGPIPE, SIG_IGN);

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

	test_frame_header_extra();
	test_frame_building();
	test_auth_method_extra();
	test_mysql41_auth_extra();
	test_hex_encode_decode();
	test_error_ok_frame_building();

	return exit_status();
}
