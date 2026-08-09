/**
 * @file protocol_unit-t.cpp
 * @brief Unit tests for protocol encoding/decoding and query digest functions.
 *
 * Tests standalone protocol utility functions in isolation:
 *   - MySQL length-encoded integer encoding and decoding
 *   - mysql_hdr packet header structure
 *   - Query digest functions (MySQL and PostgreSQL)
 *   - String utility functions (escaping, wildcard matching)
 *   - Byte copy helpers (CPY3, CPY8)
 *
 * These functions are pure computation with no global state
 * dependencies, making them ideal for unit testing.
 *
 * @see Phase 2.5 of the Unit Testing Framework (GitHub issue #5477)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Protocol.h"
#include "MySQL_Data_Stream.h"
#include "mysql_connection.h"
#include "MySQL_encode.h"
#include "c_tokenizer.h"
#include "gen_utils.h"

#include <openssl/crypto.h>

#include <cstring>
#include <climits>

mf_unique_ptr<const char> get_masked_pass(const char* pass);

// ============================================================================
// 1. MySQL length-encoded integer decoding
// ============================================================================

/**
 * @brief Test mysql_decode_length() for 1-byte values (0-250).
 */
static void test_decode_length_1byte() {
	unsigned char buf[1];
	uint32_t len = 0;

	buf[0] = 0;
	uint8_t bytes = mysql_decode_length(buf, &len);
	ok(len == 0 && bytes == 1,
		"decode_length: 0 → 1 byte");

	buf[0] = 1;
	bytes = mysql_decode_length(buf, &len);
	ok(len == 1 && bytes == 1,
		"decode_length: 1 → 1 byte");

	buf[0] = 250;
	bytes = mysql_decode_length(buf, &len);
	ok(len == 250 && bytes == 1,
		"decode_length: 250 → 1 byte (max 1-byte value)");
}

/**
 * @brief Test mysql_decode_length() for 2-byte values (0xFC prefix).
 */
static void test_decode_length_2byte() {
	unsigned char buf[3];
	uint32_t len = 0;

	// 0xFC prefix = 2-byte length follows
	buf[0] = 0xFC;
	buf[1] = 0x01;
	buf[2] = 0x00;
	uint8_t bytes = mysql_decode_length(buf, &len);
	ok(len == 1 && bytes == 3,
		"decode_length: 0xFC 0x01 0x00 → 1 (3 bytes total)");

	buf[0] = 0xFC;
	buf[1] = 0xFF;
	buf[2] = 0xFF;
	bytes = mysql_decode_length(buf, &len);
	ok(len == 0xFFFF && bytes == 3,
		"decode_length: 0xFC 0xFF 0xFF → 65535 (3 bytes total)");
}

/**
 * @brief Test mysql_decode_length() for 3-byte values (0xFD prefix).
 */
static void test_decode_length_3byte() {
	// CPY3() reads 4 bytes via uint32_t* cast, so pad buffer to avoid OOB
	unsigned char buf[5];
	uint32_t len = 0;

	buf[0] = 0xFD;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x01;
	buf[4] = 0x00;  // padding for CPY3's 4-byte read from buf+1
	uint8_t bytes = mysql_decode_length(buf, &len);
	ok(len == 0x010000 && bytes == 4,
		"decode_length: 0xFD prefix → 65536 (4 bytes total)");
}

/**
 * @brief Test mysql_decode_length_ll() for 8-byte values (0xFE prefix).
 */
static void test_decode_length_8byte() {
	unsigned char buf[9];
	uint64_t len = 0;

	buf[0] = 0xFE;
	memset(buf + 1, 0, 8);
	buf[1] = 0x01;
	uint8_t bytes = mysql_decode_length_ll(buf, &len);
	ok(len == 1 && bytes == 9,
		"decode_length_ll: 0xFE prefix → 1 (9 bytes total)");

	// Large value
	buf[0] = 0xFE;
	buf[1] = 0xFF;
	buf[2] = 0xFF;
	buf[3] = 0xFF;
	buf[4] = 0xFF;
	buf[5] = 0x00;
	buf[6] = 0x00;
	buf[7] = 0x00;
	buf[8] = 0x00;
	bytes = mysql_decode_length_ll(buf, &len);
	ok(len == 0xFFFFFFFF && bytes == 9,
		"decode_length_ll: 0xFE prefix → 4294967295 (9 bytes total)");
}

// ============================================================================
// 2. MySQL length-encoded integer encoding
// ============================================================================

/**
 * @brief Test mysql_encode_length() and roundtrip with decode.
 */
static void test_encode_length() {
	char hd[9];

	// 1-byte range (0-250): encode returns 1, does NOT write hd
	// (the value itself is the length byte, no prefix needed)
	uint8_t enc_len = mysql_encode_length(0, hd);
	ok(enc_len == 1,
		"encode_length: 0 → 1 byte");

	enc_len = mysql_encode_length(250, hd);
	ok(enc_len == 1,
		"encode_length: 250 → 1 byte");

	// 2-byte range (251-65535)
	enc_len = mysql_encode_length(251, hd);
	ok(enc_len == 3 && (unsigned char)hd[0] == 0xFC,
		"encode_length: 251 → 3 bytes (0xFC prefix)");

	enc_len = mysql_encode_length(65535, hd);
	ok(enc_len == 3 && (unsigned char)hd[0] == 0xFC,
		"encode_length: 65535 → 3 bytes (0xFC prefix)");

	// 3-byte range (65536 - 16777215)
	enc_len = mysql_encode_length(65536, hd);
	ok(enc_len == 4 && (unsigned char)hd[0] == 0xFD,
		"encode_length: 65536 → 4 bytes (0xFD prefix)");

	// 8-byte range (>= 16777216)
	enc_len = mysql_encode_length(16777216, hd);
	ok(enc_len == 9 && (unsigned char)hd[0] == 0xFE,
		"encode_length: 16777216 → 9 bytes (0xFE prefix)");
}

/**
 * @brief Test write_encoded_length + decode roundtrip for various values.
 *
 * write_encoded_length() writes both prefix and value bytes.
 * mysql_decode_length_ll() reads them back.
 */
static void test_encode_decode_roundtrip() {
	unsigned char buf[9];
	char prefix[1];
	uint64_t test_values[] = {0, 1, 250, 251, 1000, 65535, 65536, 16777215, 16777216, 100000000ULL};
	int num_values = sizeof(test_values) / sizeof(test_values[0]);

	int pass_count = 0;
	for (int i = 0; i < num_values; i++) {
		memset(buf, 0, sizeof(buf));
		prefix[0] = 0;  // Initialize to avoid UB for 1-byte values
		uint8_t enc_len = mysql_encode_length(test_values[i], prefix);
		write_encoded_length(buf, test_values[i], enc_len, prefix[0]);

		uint64_t decoded = 0;
		mysql_decode_length_ll(buf, &decoded);
		if (decoded == test_values[i]) pass_count++;
	}
	ok(pass_count == num_values,
		"encode/decode roundtrip: all %d values survive roundtrip", num_values);
}

// ============================================================================
// 3. mysql_hdr packet header structure
// ============================================================================

/**
 * @brief Test mysql_hdr structure layout (24-bit length + 8-bit id).
 */
static void test_mysql_hdr() {
	mysql_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));

	ok(sizeof(mysql_hdr) == 4,
		"mysql_hdr: sizeof is 4 bytes");

	hdr.pkt_length = 100;
	hdr.pkt_id = 1;
	ok(hdr.pkt_length == 100 && hdr.pkt_id == 1,
		"mysql_hdr: pkt_length and pkt_id set correctly");

	// Max 24-bit value
	hdr.pkt_length = 0xFFFFFF;
	ok(hdr.pkt_length == 0xFFFFFF,
		"mysql_hdr: max pkt_length (16MB-1)");
}

#ifdef PROXYSQL31
static void test_auth_more_data_packet() {
	MySQL_Data_Stream stream;
	stream.PSarrayOUT = new PtrSizeArray();
	stream.pkt_sid = 7;
	MySQL_Data_Stream *stream_pointer = &stream;
	MySQL_Protocol protocol;
	protocol.myds = &stream_pointer;
	const unsigned char public_key[] = "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n";
	const size_t public_key_length = sizeof(public_key) - 1;

	ok(protocol.generate_auth_more_data(public_key, public_key_length),
		"AuthMoreData reports successful packet construction");

	ok(stream.PSarrayOUT->len == 1,
		"AuthMoreData queues exactly one packet");
	const PtrSize_t packet = stream.PSarrayOUT->pdata[0];
	const mysql_hdr *header = static_cast<const mysql_hdr *>(packet.ptr);
	ok(packet.size == sizeof(mysql_hdr) + 1 + public_key_length &&
		header->pkt_length == 1 + public_key_length && header->pkt_id == 8,
		"AuthMoreData header accounts for marker and exact data length");
	const unsigned char *payload = static_cast<const unsigned char *>(packet.ptr) + sizeof(mysql_hdr);
	ok(payload[0] == 0x01,
		"AuthMoreData payload starts with the 0x01 protocol marker");
	ok(memcmp(payload + 1, public_key, public_key_length) == 0 &&
		packet.size == sizeof(mysql_hdr) + 1 + public_key_length,
		"AuthMoreData carries public PEM bytes without a terminating NUL");

	l_free(packet.size, packet.ptr);
	stream.PSarrayOUT->len = 0;
}

static void test_caching_sha2_stage5_payload_validation() {
	auto run_stage5 = [](
		bool encrypted,
		unsigned char *payload,
		size_t payload_length,
		std::string* recovered = nullptr,
		bool* pass_is_sensitive = nullptr
	) {
		MySQL_Data_Stream stream;
		stream.myds_type = MYDS_FRONTEND;
		stream.myconn = new MySQL_Connection();
		stream.myconn->userinfo->username = strdup("rsa-stage5-user");
		stream.switching_auth_stage = 5;
		stream.switching_auth_type = AUTH_MYSQL_CACHING_SHA2_PASSWORD;
		stream.encrypted = encrypted;
		MySQL_Data_Stream *stream_pointer = &stream;
		MySQL_Protocol protocol;
		protocol.myds = &stream_pointer;
		MyProt_tmp_auth_vars vars;
		bool authenticated = true;
		const int result = protocol.PPHR_1(
			payload, static_cast<unsigned int>(sizeof(mysql_hdr) + payload_length),
			authenticated, vars
		);
		if (recovered != nullptr && vars.pass != nullptr) {
			recovered->assign(reinterpret_cast<const char *>(vars.pass), vars.pass_len);
		}
		if (pass_is_sensitive != nullptr) {
			*pass_is_sensitive = vars.pass_is_sensitive;
		}
		if (vars.pass != nullptr) {
			OPENSSL_cleanse(vars.pass, vars.pass_len + 1);
		}
		free(vars.pass);
		return result;
	};

	unsigned char raw_cleartext[] = { 's', 'e', 'c', 'r', 'e', 't', '\0' };
	ok(run_stage5(false, raw_cleartext, sizeof(raw_cleartext)) == 1,
		"non-TLS caching_sha2 stage 5 rejects raw cleartext instead of bypassing RSA");

	// A NUL exists just beyond the declared payload. An unbounded strlen()
	// incorrectly accepts this packet by reading outside its protocol length.
	unsigned char unterminated_storage[] = { 'n', 'o', '\0' };
	ok(run_stage5(true, unterminated_storage, 2) == 1,
		"caching_sha2 stage 5 rejects a payload without an in-bounds trailing NUL");

	unsigned char tls_cleartext[] = { 's', 'e', 'c', 'r', 'e', 't', '\0' };
	std::string recovered;
	bool pass_is_sensitive = false;
	ok(run_stage5(
		true, tls_cleartext, sizeof(tls_cleartext), &recovered, &pass_is_sensitive
	) == 2 && recovered == "secret",
		"TLS caching_sha2 stage 5 accepts exactly one trailing-NUL cleartext payload");
	ok(pass_is_sensitive,
		"TLS caching_sha2 stage 5 marks copied cleartext for cleansing");
}

static void test_internal_session_redacts_password() {
	MySQL_Data_Stream stream;
	stream.myds_type = MYDS_FRONTEND;
	stream.myconn = new MySQL_Connection();
	stream.myconn->userinfo->username = strdup("rsa-dump-user");
	stream.myconn->userinfo->password = strdup("recovered-rsa-secret");
	nlohmann::json internal_session;
	stream.get_client_myds_info_json(internal_session);
	const std::string serialized = internal_session.dump();
	ok(serialized.find("recovered-rsa-secret") == std::string::npos,
		"internal-session JSON never exposes a frontend password");
}
#endif

// ============================================================================
// 4. CPY3 and CPY8 byte copy helpers
// ============================================================================

/**
 * @brief Test CPY3() — copies 3 bytes as little-endian unsigned int.
 */
static void test_cpy3() {
	// CPY3() reads 4 bytes via uint32_t* cast, so use 4-byte buffers
	unsigned char buf[4] = {0x01, 0x02, 0x03, 0x00};
	unsigned int val = CPY3(buf);
	ok(val == 0x030201,
		"CPY3: little-endian 3-byte copy correct");

	unsigned char zero[4] = {0, 0, 0, 0};
	ok(CPY3(zero) == 0, "CPY3: zero bytes → 0");
}

/**
 * @brief Test CPY8() — copies 8 bytes as little-endian uint64.
 */
static void test_cpy8() {
	unsigned char buf[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint64_t val = CPY8(buf);
	ok(val == 1, "CPY8: little-endian 8-byte copy correct");

	unsigned char max[8];
	memset(max, 0xFF, 8);
	uint64_t maxval = CPY8(max);
	ok(maxval == UINT64_MAX, "CPY8: all 0xFF → UINT64_MAX");
}

// ============================================================================
// 5. Query digest functions
// ============================================================================

/**
 * @brief Test MySQL query digest normalization (two-stage pipeline).
 *
 * first_stage normalizes whitespace/structure, second_stage replaces
 * literals with '?'. The combined _2 function does both.
 */
static void test_mysql_query_digest() {
	char buf[QUERY_DIGEST_BUF];
	char *first_comment = nullptr;

	// Digest normalizes the query (whitespace, literals)
	char *digest = mysql_query_digest_and_first_comment_2(
		"SELECT  *  FROM  users  WHERE  id = 1", 37,
		&first_comment, buf);
	ok(digest != nullptr,
		"mysql digest: SELECT produces non-null digest");
	if (digest != nullptr) {
		// Verify whitespace is normalized (collapsed to single space)
		ok(strstr(digest, "  ") == nullptr,
			"mysql digest: extra whitespace normalized");
	} else {
		ok(0, "mysql digest: whitespace normalized (skipped)");
	}

	// Query with comment — first_comment should capture it
	if (first_comment) { free(first_comment); first_comment = nullptr; }
	digest = mysql_query_digest_and_first_comment_2(
		"/* my_comment */ SELECT 1", 25,
		&first_comment, buf);
	ok(digest != nullptr,
		"mysql digest: query with comment produces non-null digest");

	// Empty query
	if (first_comment) { free(first_comment); first_comment = nullptr; }
	digest = mysql_query_digest_and_first_comment_2(
		"", 0, &first_comment, buf);
	ok(digest != nullptr,
		"mysql digest: empty query produces non-null digest");
	if (first_comment) { free(first_comment); first_comment = nullptr; }
}

/**
 * @brief Test PgSQL query digest normalization.
 */
static void test_pgsql_query_digest() {
	char buf[QUERY_DIGEST_BUF];
	char *first_comment = nullptr;

	const char *pgsql_q = "SELECT  *  FROM  orders  WHERE  total > 0";
	char *digest = pgsql_query_digest_and_first_comment_2(
		pgsql_q, strlen(pgsql_q),
		&first_comment, buf);
	ok(digest != nullptr,
		"pgsql digest: SELECT produces non-null digest");
	if (digest != nullptr) {
		// Verify whitespace is normalized
		ok(strstr(digest, "  ") == nullptr,
			"pgsql digest: extra whitespace normalized");
	} else {
		ok(0, "pgsql digest: whitespace normalized (skipped)");
	}
	if (first_comment) { free(first_comment); first_comment = nullptr; }
}

// ============================================================================
// 6. String utility functions
// ============================================================================

/**
 * @brief Test escape_string_single_quotes().
 */
static void test_escape_single_quotes() {
	// No quotes — returns the original pointer (not a copy)
	char *input1 = strdup("hello world");
	char *escaped1 = escape_string_single_quotes(input1, true);
	ok(escaped1 != nullptr && strcmp(escaped1, "hello world") == 0,
		"escape: string without quotes unchanged");
	free(escaped1);

	// With single quotes — should double them
	char *input2 = strdup("it's a test");
	char *escaped2 = escape_string_single_quotes(input2, true);
	ok(escaped2 != nullptr && strcmp(escaped2, "it''s a test") == 0,
		"escape: single quote doubled");
	free(escaped2);

	// Multiple quotes
	char *input3 = strdup("a'b'c");
	char *escaped3 = escape_string_single_quotes(input3, true);
	ok(escaped3 != nullptr && strcmp(escaped3, "a''b''c") == 0,
		"escape: multiple single quotes doubled");
	free(escaped3);
}

static void test_password_log_redaction() {
	auto short_password = get_masked_pass("xy");
	auto long_password = get_masked_pass("a-much-longer-secret");

	ok(strcmp(short_password.get(), "(redacted)") == 0,
		"password logging fully redacts short credentials");
	ok(strcmp(long_password.get(), "(redacted)") == 0,
		"password logging fully redacts long credentials");
}

/**
 * @brief Test mywildcmp() — wildcard pattern matching with % and _.
 */
static void test_wildcard_matching() {
	// Exact match
	ok(mywildcmp("hello", "hello") == true,
		"wildcard: exact match");

	// % matches any sequence
	ok(mywildcmp("hel%", "hello") == true,
		"wildcard: %% suffix matches");
	ok(mywildcmp("%llo", "hello") == true,
		"wildcard: %% prefix matches");
	ok(mywildcmp("%ll%", "hello") == true,
		"wildcard: %% on both sides matches");
	ok(mywildcmp("%", "anything") == true,
		"wildcard: lone %% matches anything");

	// _ matches single character
	ok(mywildcmp("h_llo", "hello") == true,
		"wildcard: _ matches single char");
	ok(mywildcmp("h_llo", "hallo") == true,
		"wildcard: _ matches any single char");

	// Non-match
	ok(mywildcmp("hello", "world") == false,
		"wildcard: no match on different strings");
	ok(mywildcmp("hel%", "world") == false,
		"wildcard: %% prefix doesn't match unrelated");
	ok(mywildcmp("h_llo", "hllo") == false,
		"wildcard: _ requires exactly one char");

	// Empty cases
	ok(mywildcmp("", "") == true,
		"wildcard: empty pattern matches empty string");
	ok(mywildcmp("%", "") == true,
		"wildcard: %% matches empty string");
}

// ============================================================================
// Main
// ============================================================================

int main() {
#ifdef PROXYSQL31
	plan(55);
#else
	plan(45);
#endif

	test_init_minimal();

	// MySQL length-encoded integers
	test_decode_length_1byte();              // 3 tests
	test_decode_length_2byte();              // 2 tests
	test_decode_length_3byte();              // 1 test
	test_decode_length_8byte();              // 2 tests
	test_encode_length();                    // 6 tests
	test_encode_decode_roundtrip();          // 1 test

	// Packet header
	test_mysql_hdr();                        // 3 tests
#ifdef PROXYSQL31
	test_auth_more_data_packet();            // 5 tests
	test_caching_sha2_stage5_payload_validation(); // 4 tests
	test_internal_session_redacts_password(); // 1 test
#endif

	// Byte copy helpers
	test_cpy3();                             // 2 tests
	test_cpy8();                             // 2 tests

	// Query digest
	test_mysql_query_digest();               // 4 tests
	test_pgsql_query_digest();               // 2 tests

	// String utilities
	test_escape_single_quotes();             // 3 tests
	test_password_log_redaction();            // 2 tests
	test_wildcard_matching();                // 12 tests
	// Total on the stable tier: 3+2+1+2+6+1+3+2+2+4+2+3+2+12 = 45

	test_cleanup_minimal();

	return exit_status();
}
