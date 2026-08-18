/**
 * @file ffto_protocol_unit-t.cpp
 * @brief Comprehensive unit tests for FFTO protocol parsing utilities.
 *
 * Tests both MySQL and PgSQL protocol parsing functions used by FFTO:
 *   - MySQL: read_lenenc_int, packet building, OK packet parsing
 *   - PgSQL: CommandComplete tag parsing
 *   - Both: fragmented data reassembly simulation, large payloads
 *
 * @see FFTO unit testing (GitHub issue #5499)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "MySQLProtocolUtils.h"
#include "PgSQLCommandComplete.h"
#include "PgSQLErrorFields.h"

#include <cstring>
#include <vector>

// ============================================================================
// 1. MySQL: read_lenenc_int
// ============================================================================

static void test_mysql_lenenc_1byte() {
	unsigned char buf[] = {0};
	const unsigned char *p = buf; size_t len = 1;
	ok(mysql_read_lenenc_int(p, len) == 0, "lenenc: 0x00 → 0");
	ok(len == 0 && p == buf + 1, "lenenc: consumed 1 byte");

	unsigned char buf2[] = {250};
	p = buf2; len = 1;
	ok(mysql_read_lenenc_int(p, len) == 250, "lenenc: 0xFA → 250 (max 1-byte)");
}

static void test_mysql_lenenc_2byte() {
	unsigned char buf[] = {0xFC, 0x01, 0x00};
	const unsigned char *p = buf; size_t len = 3;
	ok(mysql_read_lenenc_int(p, len) == 1, "lenenc 2-byte: 0xFC 01 00 → 1");
	ok(len == 0, "lenenc 2-byte: consumed 3 bytes");

	unsigned char buf2[] = {0xFC, 0xFF, 0xFF};
	p = buf2; len = 3;
	ok(mysql_read_lenenc_int(p, len) == 65535, "lenenc 2-byte: max → 65535");
}

static void test_mysql_lenenc_3byte() {
	unsigned char buf[] = {0xFD, 0x00, 0x00, 0x01, 0x00};  // padded for CPY safety
	const unsigned char *p = buf; size_t len = 4;
	ok(mysql_read_lenenc_int(p, len) == 65536, "lenenc 3-byte: → 65536");
}

static void test_mysql_lenenc_8byte() {
	unsigned char buf[9] = {0xFE, 0x01, 0, 0, 0, 0, 0, 0, 0};
	const unsigned char *p = buf; size_t len = 9;
	ok(mysql_read_lenenc_int(p, len) == 1, "lenenc 8-byte: → 1");

	unsigned char buf2[9] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0};
	p = buf2; len = 9;
	ok(mysql_read_lenenc_int(p, len) == 0xFFFFFFFF, "lenenc 8-byte: → 4294967295");
}

static void test_mysql_lenenc_truncated() {
	// 2-byte prefix but only 1 byte of data
	unsigned char buf[] = {0xFC, 0x01};
	const unsigned char *p = buf; size_t len = 2;
	ok(mysql_read_lenenc_int(p, len) == 0, "lenenc truncated: 0xFC with 1 byte → 0");

	// Empty buffer
	const unsigned char *p2 = nullptr; size_t len2 = 0;
	ok(mysql_read_lenenc_int(p2, len2) == 0, "lenenc empty: → 0");
}

// ============================================================================
// 2. MySQL: packet building
// ============================================================================

static void test_mysql_build_packet() {
	unsigned char payload[] = {0x03, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
	unsigned char out[13];
	size_t total = mysql_build_packet(payload, 9, 0, out);
	ok(total == 13, "build packet: total size 13");
	ok(out[0] == 9 && out[1] == 0 && out[2] == 0, "build packet: length = 9");
	ok(out[3] == 0, "build packet: seq_id = 0");
	ok(memcmp(out + 4, payload, 9) == 0, "build packet: payload intact");
}

static void test_mysql_build_large_packet() {
	// Build a packet with 1000-byte payload
	std::vector<unsigned char> payload(1000, 'X');
	std::vector<unsigned char> out(1004);
	size_t total = mysql_build_packet(payload.data(), 1000, 5, out.data());
	ok(total == 1004, "large packet: total size 1004");
	ok(out[0] == 0xE8 && out[1] == 0x03 && out[2] == 0x00,
		"large packet: length = 1000 (little-endian)");
	ok(out[3] == 5, "large packet: seq_id = 5");
}

static void test_mysql_build_empty_packet() {
	unsigned char out[4];
	size_t total = mysql_build_packet(nullptr, 0, 1, out);
	ok(total == 4, "empty packet: header only");
	ok(out[0] == 0 && out[1] == 0 && out[2] == 0, "empty packet: length = 0");
}

// ============================================================================
// 3. MySQL: OK packet affected_rows extraction
// ============================================================================

static void test_mysql_ok_affected_rows() {
	// Build an OK packet: 0x00 + affected_rows(lenenc) + last_insert_id(lenenc)
	// affected_rows = 42
	unsigned char ok_payload[] = {0x00, 42, 0};  // OK, affected=42, last_insert=0
	unsigned char pkt[7];
	mysql_build_packet(ok_payload, 3, 1, pkt);

	// Parse affected_rows from the OK packet payload
	const unsigned char *pos = ok_payload + 1;
	size_t rem = 2;
	uint64_t affected = mysql_read_lenenc_int(pos, rem);
	ok(affected == 42, "OK packet: affected_rows = 42");
}

static void test_mysql_ok_large_affected_rows() {
	// affected_rows = 300 (needs 0xFC prefix)
	unsigned char ok_payload[] = {0x00, 0xFC, 0x2C, 0x01, 0};
	const unsigned char *pos = ok_payload + 1;
	size_t rem = 4;
	uint64_t affected = mysql_read_lenenc_int(pos, rem);
	ok(affected == 300, "OK packet: affected_rows = 300 (2-byte lenenc)");
}

// ============================================================================
// 4. PgSQL: CommandComplete — extended tests
// ============================================================================

static void test_pgsql_insert_with_oid() {
	// "INSERT oid count" format — the count is always the last token
	auto r = parse_pgsql_command_complete(
		(const unsigned char *)"INSERT 12345 50", 15);
	ok(r.rows == 50 && r.is_select == false,
		"PgSQL INSERT with OID: rows=50 (last token)");
}

static void test_pgsql_large_row_count() {
	auto r = parse_pgsql_command_complete(
		(const unsigned char *)"SELECT 1000000", 14);
	ok(r.rows == 1000000 && r.is_select == true,
		"PgSQL large SELECT: rows=1000000");
}

static void test_pgsql_zero_rows() {
	auto r = parse_pgsql_command_complete(
		(const unsigned char *)"UPDATE 0", 8);
	ok(r.rows == 0 && r.is_select == false, "PgSQL UPDATE 0: rows=0");

	auto r2 = parse_pgsql_command_complete(
		(const unsigned char *)"SELECT 0", 8);
	ok(r2.rows == 0 && r2.is_select == true, "PgSQL SELECT 0: rows=0");
}

static void test_pgsql_all_command_types() {
	struct { const char *tag; uint64_t expected; bool is_sel; } cases[] = {
		{"INSERT 0 1", 1, false},
		{"UPDATE 5", 5, false},
		{"DELETE 3", 3, false},
		{"SELECT 10", 10, true},
		{"FETCH 7", 7, true},
		{"MOVE 2", 2, true},
		{"COPY 100", 100, false},
		{"MERGE 8", 8, false},
	};
	int pass = 0;
	for (auto &c : cases) {
		auto r = parse_pgsql_command_complete(
			(const unsigned char *)c.tag, strlen(c.tag));
		if (r.rows == c.expected && r.is_select == c.is_sel) pass++;
	}
	ok(pass == 8, "PgSQL all 8 command types parse correctly");
}

static void test_pgsql_ddl_commands() {
	const char *ddls[] = {
		"CREATE TABLE", "ALTER TABLE", "DROP TABLE",
		"CREATE INDEX", "DROP INDEX", "VACUUM",
		"TRUNCATE TABLE", "GRANT", "REVOKE",
	};
	int pass = 0;
	for (auto &ddl : ddls) {
		auto r = parse_pgsql_command_complete(
			(const unsigned char *)ddl, strlen(ddl));
		if (r.rows == 0) pass++;
	}
	ok(pass == 9, "PgSQL DDL commands all return rows=0");
}

static void test_pgsql_null_terminated_payload() {
	// Payload with null terminator (common in real wire format)
	unsigned char payload[] = {'S', 'E', 'L', 'E', 'C', 'T', ' ', '5', '\0'};
	auto r = parse_pgsql_command_complete(payload, 9);
	ok(r.rows == 5, "PgSQL null-terminated: SELECT 5 → rows=5");
}

// ============================================================================
// 5. Fragmented data simulation
// ============================================================================

static void test_mysql_fragmented_lenenc() {
	// Simulate reading a lenenc int where data arrives in chunks
	// Build a 3-byte lenenc (0xFD prefix + 3 bytes)
	unsigned char full[] = {0xFD, 0x40, 0x42, 0x0F};  // = 999,999 + 1 (not quite, but valid)

	// First chunk: just the prefix
	const unsigned char *p = full; size_t len = 1;
	uint64_t val = mysql_read_lenenc_int(p, len);
	// With only 1 byte, the 0xFD prefix is consumed but there aren't 3 bytes after → returns 0
	ok(val == 0, "fragmented: 0xFD with no data bytes → 0 (truncated)");

	// Full data
	p = full; len = 4;
	val = mysql_read_lenenc_int(p, len);
	ok(val > 0, "fragmented: full 3-byte lenenc decoded successfully");
}

static void test_mysql_multi_packet_build() {
	// Build 3 packets sequentially (simulating a multi-packet stream)
	unsigned char stream[64];
	size_t offset = 0;

	unsigned char p1[] = {0x03, 'S', 'E', 'L'};
	offset += mysql_build_packet(p1, 4, 0, stream + offset);

	unsigned char p2[] = {0x01, 0x02, 0x03};
	offset += mysql_build_packet(p2, 3, 1, stream + offset);

	unsigned char p3[] = {0xFE, 0x00, 0x00, 0x00, 0x00};
	offset += mysql_build_packet(p3, 5, 2, stream + offset);

	ok(offset == 4+4 + 3+4 + 5+4, "multi-packet: total stream size correct");

	// Verify each packet header
	ok(stream[0] == 4 && stream[3] == 0, "multi-packet: pkt 0 header ok");
	ok(stream[8] == 3 && stream[11] == 1, "multi-packet: pkt 1 header ok");
	ok(stream[15] == 5 && stream[18] == 2, "multi-packet: pkt 2 header ok");
}

// ============================================================================
// 6. MySQL: ERR packet parsing
// ============================================================================

static void test_mysql_err_packet_basic() {
    unsigned char payload[] = {
        0xFF,
        0x15, 0x04,
        '#',
        '2','8','0','0','0',
        'A','c','c','e','s','s',' ','d','e','n','i','e','d'
    };
    uint16_t err_no = 0;
    const char* errmsg = nullptr;
    size_t errmsg_len = 0;
    bool ok_parse = mysql_parse_err_packet(payload, sizeof(payload), &err_no, &errmsg, &errmsg_len);
    ok(ok_parse == true, "ERR parse: basic packet parsed successfully");
    ok(err_no == 1045, "ERR parse: errno = 1045");
    ok(errmsg_len == 13 && memcmp(errmsg, "Access denied", 13) == 0,
       "ERR parse: message = 'Access denied'");
}

static void test_mysql_err_packet_no_sqlstate() {
    unsigned char payload[] = {
        0xFF,
        0x01, 0x00,
        'S','o','m','e',' ','e','r','r','o','r'
    };
    uint16_t err_no = 0;
    const char* errmsg = nullptr;
    size_t errmsg_len = 0;
    bool ok_parse = mysql_parse_err_packet(payload, sizeof(payload), &err_no, &errmsg, &errmsg_len);
    ok(ok_parse == true, "ERR parse no-sqlstate: parsed");
    ok(err_no == 1, "ERR parse no-sqlstate: errno = 1");
    ok(errmsg_len == 10 && memcmp(errmsg, "Some error", 10) == 0,
       "ERR parse no-sqlstate: message correct");
}

static void test_mysql_err_packet_truncated() {
    unsigned char payload[] = {0xFF};
    uint16_t err_no = 0;
    const char* errmsg = nullptr;
    size_t errmsg_len = 0;
    bool ok_parse = mysql_parse_err_packet(payload, 1, &err_no, &errmsg, &errmsg_len);
    ok(ok_parse == false, "ERR parse truncated: returns false");
}

static void test_mysql_err_packet_empty_message() {
    unsigned char payload[] = {
        0xFF,
        0x00, 0x04,
        '#',
        '4','2','0','0','0'
    };
    uint16_t err_no = 0;
    const char* errmsg = nullptr;
    size_t errmsg_len = 0;
    bool ok_parse = mysql_parse_err_packet(payload, sizeof(payload), &err_no, &errmsg, &errmsg_len);
    ok(ok_parse == true, "ERR parse empty msg: parsed");
    ok(err_no == 1024, "ERR parse empty msg: errno = 1024");
    ok(errmsg_len == 0, "ERR parse empty msg: empty message");
}

// ============================================================================
// 7. PgSQL: ErrorResponse field parsing
// ============================================================================

static void test_pgsql_error_fields_basic() {
    unsigned char payload[] = {
        'S','E','R','R','O','R','\0',
        'C','4','2','6','0','1','\0',
        'M','s','y','n','t','a','x',' ','e','r','r','o','r','\0',
        '\0'
    };
    PgSQLErrorResult r = pgsql_parse_error_response(payload, sizeof(payload));
    ok(r.parsed == true, "PgSQL error parse: basic parsed");
    ok(strcmp(r.sqlstate, "42601") == 0, "PgSQL error parse: sqlstate = 42601");
    ok(r.message != nullptr && strncmp(r.message, "syntax error", 12) == 0,
       "PgSQL error parse: message starts with 'syntax error'");
}

static void test_pgsql_error_fields_missing_code() {
    unsigned char payload[] = {
        'S','E','R','R','O','R','\0',
        'M','s','o','m','e',' ','e','r','r','\0',
        '\0'
    };
    PgSQLErrorResult r = pgsql_parse_error_response(payload, sizeof(payload));
    ok(r.parsed == true, "PgSQL error no-code: parsed");
    ok(strlen(r.sqlstate) == 0, "PgSQL error no-code: empty sqlstate");
    ok(r.message != nullptr && strncmp(r.message, "some err", 8) == 0,
       "PgSQL error no-code: message correct");
}

static void test_pgsql_error_fields_empty() {
    unsigned char payload[] = {'\0'};
    PgSQLErrorResult r = pgsql_parse_error_response(payload, 1);
    ok(r.parsed == true, "PgSQL error empty: parsed (no fields)");
    ok(strlen(r.sqlstate) == 0, "PgSQL error empty: empty sqlstate");
    ok(r.message == nullptr, "PgSQL error empty: null message");
}

static void test_pgsql_error_fields_zero_length() {
    PgSQLErrorResult r = pgsql_parse_error_response(nullptr, 0);
    ok(r.parsed == false, "PgSQL error null: returns false");
}

// ============================================================================
// 8. MySQL: OK/EOF payload helpers
// ============================================================================

#ifndef SERVER_MORE_RESULTS_EXIST
#define SERVER_MORE_RESULTS_EXIST 8
#endif

static void test_mysql_is_eof_payload() {
	unsigned char eof5[] = {0xFE, 0x00, 0x00, 0x02, 0x00}; // warnings=0, status=AUTOCOMMIT
	ok(mysql_is_eof_payload(eof5, sizeof(eof5)) == true, "EOF: 5-byte classic EOF");
	unsigned char not_eof[] = {0xFE, 0x01, 0, 0, 0, 0, 0, 0, 0}; // lenenc 8-byte style length
	ok(mysql_is_eof_payload(not_eof, sizeof(not_eof)) == false, "EOF: 0xFE with len>=9 is not EOF");
	unsigned char okpkt[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
	ok(mysql_is_eof_payload(okpkt, sizeof(okpkt)) == false, "EOF: OK is not EOF");
}

static void test_mysql_parse_ok_payload() {
	// OK: header 0x00, affected=1, last_insert=0, status=0x0002, warnings=0
	unsigned char okp[] = {0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00};
	MySQLOkFields f{};
	ok(mysql_parse_ok_payload(okp, sizeof(okp), &f) == true, "OK parse: success");
	ok(f.affected_rows == 1, "OK parse: affected_rows=1");
	ok(f.status_flags == 0x0002, "OK parse: status AUTOCOMMIT");
	ok((f.status_flags & SERVER_MORE_RESULTS_EXIST) == 0, "OK parse: no MORE_RESULTS");
}

static void test_mysql_parse_ok_more_results() {
	// status = SERVER_MORE_RESULTS_EXIST (8) | AUTOCOMMIT (2) = 10
	unsigned char okp[] = {0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00};
	MySQLOkFields f{};
	ok(mysql_parse_ok_payload(okp, sizeof(okp), &f) == true, "OK more: parse ok");
	ok((f.status_flags & SERVER_MORE_RESULTS_EXIST) != 0, "OK more: MORE_RESULTS set");
}

static void test_mysql_eof_status_flags() {
	unsigned char eof5[] = {0xFE, 0x00, 0x00, 0x0A, 0x00}; // warnings=0, status=0x000A
	uint16_t st = 0, wr = 0;
	ok(mysql_parse_eof_payload(eof5, sizeof(eof5), &wr, &st) == true, "EOF parse: ok");
	ok(st == 0x000A, "EOF parse: status has MORE_RESULTS|AUTOCOMMIT");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(67);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	// MySQL lenenc
	test_mysql_lenenc_1byte();         // 3
	test_mysql_lenenc_2byte();         // 3
	test_mysql_lenenc_3byte();         // 1
	test_mysql_lenenc_8byte();         // 2
	test_mysql_lenenc_truncated();     // 2

	// MySQL packet building
	test_mysql_build_packet();         // 4
	test_mysql_build_large_packet();   // 3
	test_mysql_build_empty_packet();   // 2

	// MySQL OK packet parsing
	test_mysql_ok_affected_rows();     // 1
	test_mysql_ok_large_affected_rows(); // 1

	// PgSQL extended
	test_pgsql_insert_with_oid();      // 1
	test_pgsql_large_row_count();      // 1
	test_pgsql_zero_rows();            // 2
	test_pgsql_all_command_types();    // 1
	test_pgsql_ddl_commands();         // 1
	test_pgsql_null_terminated_payload(); // 1

	// Fragmentation
	test_mysql_fragmented_lenenc();    // 2
	test_mysql_multi_packet_build();   // 4
	// Total: 1+3+3+1+2+2+4+3+2+1+1+1+1+2+1+1+1+2+4 = 36... recount
	// 1 (init) + 3+3+1+2+2 (lenenc=11) + 4+3+2 (build=9) + 1+1 (ok=2) +
	// 1+1+2+1+1+1 (pgsql=7) + 2+4 (frag=6) = 1+11+9+2+7+6 = 36

	// MySQL ERR packet parsing
	test_mysql_err_packet_basic();          // 3
	test_mysql_err_packet_no_sqlstate();    // 3
	test_mysql_err_packet_truncated();      // 1
	test_mysql_err_packet_empty_message();  // 3

	// PgSQL ErrorResponse parsing
	test_pgsql_error_fields_basic();        // 3
	test_pgsql_error_fields_missing_code(); // 3
	test_pgsql_error_fields_empty();        // 3
	test_pgsql_error_fields_zero_length();  // 1

	// MySQL OK/EOF payload helpers
	test_mysql_is_eof_payload();            // 3
	test_mysql_parse_ok_payload();          // 4
	test_mysql_parse_ok_more_results();     // 2
	test_mysql_eof_status_flags();          // 2

	test_cleanup_minimal();
	return exit_status();
}
