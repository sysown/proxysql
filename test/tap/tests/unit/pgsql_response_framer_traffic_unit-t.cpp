/**
 * @file pgsql_response_framer_traffic_unit-t.cpp
 * @brief Synthetic PostgreSQL backend message traffic against PgSQLResponseFramer.
 */
#ifdef PROXYSQLFFTO

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQLResponseFramer.h"

#include <cstring>
#include <string>

static void test_multi_c_then_z_simple() {
	// Simple-query path: multiple CommandComplete, finalize only meaningful at FFTO
	// on Z when response_seen. Framer must set response_seen on first C and keep it.
	PgSQLResponseFramer f;
	f.on_query_activated(true); // finalize_on_sync
	auto e = f.on_message('C', (const unsigned char*)"SELECT 1", 8);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 1 && e.is_select,
		"multi C: first SELECT 1");
	ok(f.response_seen(), "multi C: response_seen after first C");
	e = f.on_message('C', (const unsigned char*)"INSERT 0 2", 10);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 2 && !e.is_select,
		"multi C: INSERT 0 2");
	ok(f.response_seen(), "multi C: response_seen still set");
	e = f.on_message('Z', (const unsigned char*)"I", 1);
	ok(e.kind == PgSQLRSEventKind::ReadyForQuery, "multi C: Z event");
	ok(f.response_seen(), "multi C: Z does not clear response_seen (FFTO finalizes)");
}

static void test_extended_c_then_stale_z() {
	// Extended: finalize_on_sync=false. After C, FFTO would finalize and activate next.
	// Simulate activate clearing response_seen before stale Z arrives.
	PgSQLResponseFramer f;
	f.on_query_activated(false);
	auto e = f.on_message('C', (const unsigned char*)"SELECT 5", 8);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 5, "ext: C SELECT 5");
	ok(f.response_seen(), "ext: seen after C");
	// Next query activated (as FFTO would after extended finalize)
	f.on_query_activated(false);
	ok(!f.response_seen(), "ext: next query cleared response_seen");
	e = f.on_message('Z', (const unsigned char*)"I", 1);
	ok(e.kind == PgSQLRSEventKind::ReadyForQuery, "ext: stale Z");
	ok(!f.response_seen(), "ext: stale Z must NOT set response_seen (no false finalize)");
}

static void test_empty_then_execute_cycle() {
	PgSQLResponseFramer f;
	f.on_query_activated(false);
	auto e = f.on_message('I', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::EmptyQuery && f.response_seen(), "I: empty + seen");
	f.on_query_activated(false);
	ok(!f.response_seen(), "I: next query clear");
	e = f.on_message('C', (const unsigned char*)"SELECT 0", 8);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 0 && e.is_select,
		"I→C: SELECT 0");
	ok(f.response_seen(), "I→C: seen");
}

static void test_portal_suspended_cycle() {
	PgSQLResponseFramer f;
	f.on_query_activated(false);
	auto e = f.on_message('s', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::PortalSuspended && f.response_seen(), "s: suspended + seen");
	f.on_query_activated(false);
	e = f.on_message('C', (const unsigned char*)"SELECT 10", 9);
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 10, "s→C: later complete");
}

static void test_error_mid_batch() {
	PgSQLResponseFramer f;
	f.on_query_activated(true);
	f.on_message('C', (const unsigned char*)"SELECT 1", 8);
	ok(f.response_seen(), "E batch: seen before error");
	auto e = f.on_message('E', (const unsigned char*)"S", 1);
	ok(e.kind == PgSQLRSEventKind::Error, "E batch: Error kind");
	// Framer does not clear response_seen on E — FFTO resets whole framer
	ok(f.response_seen(), "E batch: framer leaves response_seen (FFTO m_rs.reset())");
	f.reset();
	ok(!f.response_seen() && !f.finalize_on_sync(), "E batch: reset clears all");
}

static void test_ignored_message_types() {
	PgSQLResponseFramer f;
	f.on_query_activated(true);
	// RowDescription, DataRow, Notice — should be None, no response_seen
	auto e = f.on_message('T', (const unsigned char*)"x", 1);
	ok(e.kind == PgSQLRSEventKind::None && !f.response_seen(), "ignore RowDescription T");
	e = f.on_message('D', (const unsigned char*)"x", 1);
	ok(e.kind == PgSQLRSEventKind::None && !f.response_seen(), "ignore DataRow D");
	e = f.on_message('N', (const unsigned char*)"x", 1);
	ok(e.kind == PgSQLRSEventKind::None && !f.response_seen(), "ignore Notice N");
	// BindComplete etc.
	e = f.on_message('2', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::None, "ignore BindComplete 2");
}

static void test_command_tags_matrix() {
	PgSQLResponseFramer f;
	struct {
		const char* tag;
		uint64_t rows;
		bool is_sel;
	} cases[] = {
		{"SELECT 42", 42, true},
		{"FETCH 7", 7, true},
		{"MOVE 3", 3, true},
		{"UPDATE 11", 11, false},
		{"DELETE 0", 0, false},
		{"COPY 100", 100, false},
		{"MERGE 4", 4, false},
		{"CREATE TABLE", 0, false},
		{"INSERT 12345 9", 9, false},
	};
	int pass = 0;
	for (auto& c : cases) {
		f.on_query_activated(false);
		auto e = f.on_message('C', (const unsigned char*)c.tag, strlen(c.tag));
		if (e.kind == PgSQLRSEventKind::CommandComplete && e.rows == c.rows && e.is_select == c.is_sel)
			pass++;
	}
	ok(pass == 9, "command tag matrix: all 9 tags parse");
}

static void test_z_without_prior_c() {
	// Query activated, only Z (should not look "seen")
	PgSQLResponseFramer f;
	f.on_query_activated(true);
	auto e = f.on_message('Z', (const unsigned char*)"T", 1);
	ok(e.kind == PgSQLRSEventKind::ReadyForQuery && !f.response_seen(),
		"Z alone after activate: not seen");
}

static void test_set_finalize_on_sync() {
	PgSQLResponseFramer f;
	f.on_query_activated(false);
	ok(!f.finalize_on_sync(), "default false from activate");
	f.set_finalize_on_sync(true);
	ok(f.finalize_on_sync(), "set_finalize_on_sync true");
	f.set_finalize_on_sync(false);
	ok(!f.finalize_on_sync(), "set_finalize_on_sync false");
}

int main() {
	// init 1
	// multi C/Z: 6
	// ext stale Z: 5
	// empty cycle: 4
	// portal: 2
	// error batch: 4
	// ignored: 4
	// tags: 1
	// z alone: 1
	// set finalize: 3
	// total 1+6+5+4+2+4+4+1+1+3 = 31
	plan(31);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");

	test_multi_c_then_z_simple();
	test_extended_c_then_stale_z();
	test_empty_then_execute_cycle();
	test_portal_suspended_cycle();
	test_error_mid_batch();
	test_ignored_message_types();
	test_command_tags_matrix();
	test_z_without_prior_c();
	test_set_finalize_on_sync();

	test_cleanup_minimal();
	return exit_status();
}

#else

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

int main() {
	plan(1);
	ok(1, "pgsql traffic framer tests skipped (PROXYSQLFFTO not enabled)");
	return exit_status();
}

#endif
