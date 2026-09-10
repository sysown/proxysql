/**
 * @file pgsql_stmt_meta_cache-t.cpp
 * @brief Unit tests for the statement-level Describe metadata cache on
 *        PgSQL_STMT_Global_info (Task E).
 *
 * Exercises the set-once cache contract that backs the "serve Describe from
 * cache" fast path in handle_post_sync_describe_message (both backend modes):
 *
 *   - a fresh global statement has no describe cache;
 *   - publish_describe_cache() is set-once: the first candidate wins and is
 *     installed; a later candidate LOSES and is freed by publish() (ownership
 *     transfer on both branches — verified here as a no-double-free / no-leak
 *     contract, and caught concretely under ASAN);
 *   - payload fidelity: the stored bytes (including embedded NULs) are returned
 *     verbatim, so a later serve is byte-identical to the capture;
 *   - the NoData variant is preserved.
 *
 * These are the pure-data-structure guarantees; end-to-end byte-parity of the
 * served wire messages vs a real backend round-trip is covered by the
 * differential TAP test pgsql-native_prepared-t (kind EXT_DESCRIBE_CACHED).
 */

#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Session.h"            // Parse_Param_Types
#include "PgSQL_PreparedStatement.h"  // PgSQL_STMT_Global_info, PgSQL_Describe_Cache
#include "tap.h"

#include <cstring>
#include <string>
#include <memory>

// Build a minimal global statement info. h=0 → the ctor computes the hash
// (SpookyHash, linked from libproxysql.a). No GloPgStmt dependency.
static std::unique_ptr<PgSQL_STMT_Global_info> make_gi(const char* query) {
	Parse_Param_Types ppt; // empty is fine for these tests
	return std::unique_ptr<PgSQL_STMT_Global_info>(
		new PgSQL_STMT_Global_info(1, "u", "db", query, (unsigned int)strlen(query),
			std::move(ppt), nullptr, /*_h=*/0));
}

static void test_fresh_is_empty() {
	auto gi = make_gi("SELECT $1::int");
	ok(gi->get_describe_cache() == nullptr,
		"fresh global statement has no describe cache");
}

static void test_set_once() {
	auto gi = make_gi("SELECT $1::int, $2::text");

	// Body of ParameterDescription 't': uint16 count=1 + uint32 OID=23 (int4).
	const std::string param("\x00\x01\x00\x00\x00\x17", 6);
	// Body of RowDescription 'T' — arbitrary bytes incl. an embedded NUL to prove
	// binary-safe storage (field-name "id\0" then per-column fixed fields).
	const std::string row("\x00\x01id\x00\x00\x00\x00\x2a\x00\x01\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00", 22);

	auto* a = new PgSQL_Describe_Cache();
	a->param_desc_payload = param;
	a->row_desc_payload = row;
	a->no_data = false;

	bool won_a = gi->publish_describe_cache(a);
	ok(won_a, "first publish wins the set-once race");
	ok(gi->get_describe_cache() == a, "cache slot holds the first-published candidate");

	// Second publish must LOSE and free its own candidate (do NOT delete b here —
	// publish() owns it on the losing branch; a double-free would trip ASAN).
	auto* b = new PgSQL_Describe_Cache();
	b->param_desc_payload = "different";
	b->no_data = true;
	bool won_b = gi->publish_describe_cache(b);
	ok(!won_b, "second publish loses (set-once: first writer wins)");
	ok(gi->get_describe_cache() == a, "cache slot still holds the first candidate after a losing publish");

	// Payload fidelity: the served bytes must match the captured bytes verbatim.
	const PgSQL_Describe_Cache* dc = gi->get_describe_cache();
	ok(dc->param_desc_payload.size() == param.size(), "param_desc payload length preserved");
	ok(dc->param_desc_payload == param, "param_desc payload bytes preserved verbatim");
	ok(dc->row_desc_payload.size() == row.size(), "row_desc payload length preserved (incl. embedded NUL)");
	ok(dc->row_desc_payload == row, "row_desc payload bytes preserved verbatim");
	ok(dc->no_data == false, "no_data flag preserved (false for a row-returning statement)");
	// gi's destructor frees 'a'; 'b' was freed by the losing publish().
}

static void test_no_data_variant() {
	auto gi = make_gi("INSERT INTO t VALUES ($1)");
	const std::string param("\x00\x01\x00\x00\x00\x17", 6);

	auto* c = new PgSQL_Describe_Cache();
	c->param_desc_payload = param;
	c->no_data = true; // statement returns no columns → NoData 'n'

	ok(gi->publish_describe_cache(c), "publish of a NoData describe cache wins");
	const PgSQL_Describe_Cache* dc = gi->get_describe_cache();
	ok(dc->no_data == true, "no_data flag preserved (true for a no-result statement)");
	ok(dc->row_desc_payload.empty(), "row_desc payload empty for the NoData variant");
	// gi's destructor frees 'c'.
}

int main() {
	plan(1 /*init*/ + 1 /*fresh*/ + 9 /*set_once*/ + 3 /*no_data*/);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_fresh_is_empty();   // 1
	test_set_once();         // 9
	test_no_data_variant();  // 3

	test_cleanup_minimal();
	return exit_status();
}
