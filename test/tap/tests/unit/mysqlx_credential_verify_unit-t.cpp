#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include <cstring>
#include <vector>

// Test-only credential constants (not real credentials)
static const char TEST_PASSWORD_A[] = "testpass";
static const char TEST_PASSWORD_B[] = "correctpass";
static const char TEST_PASSWORD_C[] = "wrongpass";
static const char TEST_PASSWORD_D[] = "password123";
static const char TEST_PASSWORD_E[] = "pass1";
static const char TEST_PASSWORD_F[] = "pass2";

static void test_verify_hash_correct() {
	diag(">>> %s", __func__);
	std::string password = TEST_PASSWORD_A;
	std::vector<uint8_t> hash = mysqlx_mysql41_hash(password);

	std::vector<uint8_t> challenge(20, 0xAB);
	std::vector<uint8_t> scramble = mysqlx_mysql41_scramble(challenge, password);

	ok(mysqlx_mysql41_verify(challenge, scramble, password),
	   "verify returns true for correct password");
	ok(mysqlx_mysql41_verify_hash(challenge, scramble, hash),
	   "verify_hash returns true for correct hash");
}

static void test_verify_hash_wrong_password() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> hash = mysqlx_mysql41_hash(TEST_PASSWORD_B);
	std::vector<uint8_t> challenge(20, 0xCD);
	std::vector<uint8_t> scramble = mysqlx_mysql41_scramble(challenge, TEST_PASSWORD_C);

	ok(!mysqlx_mysql41_verify(challenge, scramble, TEST_PASSWORD_B),
	   "verify returns false for wrong scramble vs password");
	ok(!mysqlx_mysql41_verify_hash(challenge, scramble, hash),
	   "verify_hash returns false for wrong scramble vs hash");
}

static void test_verify_hash_empty_password() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> hash = mysqlx_mysql41_hash("");
	std::vector<uint8_t> challenge(20, 0x11);
	std::vector<uint8_t> scramble = mysqlx_mysql41_scramble(challenge, "");

	ok(mysqlx_mysql41_verify_hash(challenge, scramble, hash),
	   "verify_hash works with empty password");
}

static void test_verify_hash_wrong_size_inputs() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> hash = mysqlx_mysql41_hash(TEST_PASSWORD_A);
	std::vector<uint8_t> short_hash(10, 0xFF);
	std::vector<uint8_t> challenge(20, 0x22);
	std::vector<uint8_t> short_scramble(10, 0x33);

	ok(!mysqlx_mysql41_verify_hash(challenge, short_scramble, hash),
	   "verify_hash rejects short scramble");
	ok(!mysqlx_mysql41_verify_hash(challenge, short_scramble, short_hash),
	   "verify_hash rejects short hash");
	ok(!mysqlx_mysql41_verify(challenge, short_scramble, TEST_PASSWORD_A),
	   "verify rejects short scramble");
}

static void test_hex_encode_decode_roundtrip() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	std::string hex = mysqlx_hex_encode(data);
	ok(hex == "0123456789ABCDEF", "hex encode produces uppercase");

	std::vector<uint8_t> decoded;
	bool ok_flag = mysqlx_hex_decode(hex, decoded);
	ok(ok_flag, "hex decode succeeds");
	ok(decoded == data, "roundtrip matches original");
}

static void test_hex_decode_odd_length() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> decoded;
	bool ok_flag = mysqlx_hex_decode("ABC", decoded);
	ok(!ok_flag, "hex decode rejects odd-length input");
}

static void test_hex_decode_invalid_chars() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> decoded;
	bool ok_flag = mysqlx_hex_decode("GH", decoded);
	ok(!ok_flag, "hex decode rejects invalid characters");
}

static void test_hex_decode_lowercase() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> decoded;
	bool ok_flag = mysqlx_hex_decode("0a1b", decoded);
	ok(ok_flag, "hex decode accepts lowercase");
	if (ok_flag) {
		ok(decoded.size() == 2, "decoded size is 2");
		ok(decoded[0] == 0x0A && decoded[1] == 0x1B, "decoded values correct");
	} else {
		ok(false, "decoded size");
		ok(false, "decoded values");
	}
}

static void test_mysql41_hash_consistency() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> h1 = mysqlx_mysql41_hash(TEST_PASSWORD_D);
	std::vector<uint8_t> h2 = mysqlx_mysql41_hash(TEST_PASSWORD_D);
	ok(h1 == h2, "same password produces same hash");
	ok(h1.size() == 20, "hash is 20 bytes (SHA1)");
}

static void test_mysql41_hash_different_passwords() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> h1 = mysqlx_mysql41_hash(TEST_PASSWORD_E);
	std::vector<uint8_t> h2 = mysqlx_mysql41_hash(TEST_PASSWORD_F);
	ok(h1 != h2, "different passwords produce different hashes");
}

static void test_scramble_deterministic() {
	diag(">>> %s", __func__);
	std::vector<uint8_t> challenge(20, 0x42);
	std::vector<uint8_t> s1 = mysqlx_mysql41_scramble(challenge, "test");
	std::vector<uint8_t> s2 = mysqlx_mysql41_scramble(challenge, "test");
	ok(s1 == s2, "same challenge+password produces same scramble");
	ok(s1.size() == 20, "scramble is 20 bytes");
}

static void test_is_supported_auth() {
	diag(">>> %s", __func__);
	ok(mysqlx_is_supported_auth_method("MYSQL41"), "MYSQL41 is supported");
	ok(!mysqlx_is_supported_auth_method("SHA256_MEMORY"), "SHA256_MEMORY is not supported");
	ok(!mysqlx_is_supported_auth_method("mysql41"), "case-sensitive: lowercase rejected");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(24);
	diag("=== mysqlx_credential_verify_unit-t starting ===");

	test_verify_hash_correct();
	test_verify_hash_wrong_password();
	test_verify_hash_empty_password();
	test_verify_hash_wrong_size_inputs();
	test_hex_encode_decode_roundtrip();
	test_hex_decode_odd_length();
	test_hex_decode_invalid_chars();
	test_hex_decode_lowercase();
	test_mysql41_hash_consistency();
	test_mysql41_hash_different_passwords();
	test_scramble_deterministic();
	test_is_supported_auth();

	return exit_status();
}
