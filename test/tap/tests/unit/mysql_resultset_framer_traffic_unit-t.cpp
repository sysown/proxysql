/**
 * @file mysql_resultset_framer_traffic_unit-t.cpp
 * @brief Synthetic MySQL wire traffic against MySQLResultsetFramer.
 *
 * Feeds crafted packet payloads (including odd shapes) and asserts event
 * sequences. No server, no session — pure framer behavior.
 */
#ifdef PROXYSQLFFTO

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"

#include <cstring>
#include <vector>

#ifndef SERVER_MORE_RESULTS_EXIST
#define SERVER_MORE_RESULTS_EXIST 8
#endif

static std::vector<unsigned char> colcount(uint8_t n) { return {n}; }
static std::vector<unsigned char> dummy_coldef() {
	return {3, 'd', 'e', 'f', 0, 0, 0, 0, 0, 0x0c, 0x3f, 0x00, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0, 0};
}
static std::vector<unsigned char> eof_pkt(uint16_t status = 0x0002) {
	return {0xFE, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8)};
}
static std::vector<unsigned char> ok_term(uint16_t status = 0x0002, uint64_t affected = 0) {
	// Minimal OK: 0x00 + affected(1-byte lenenc if <0xFB) + last_insert 0 + status + warnings
	std::vector<unsigned char> p;
	p.push_back(0x00);
	if (affected < 0xFB) {
		p.push_back((uint8_t)affected);
	} else {
		p.push_back(0xFC);
		p.push_back((uint8_t)(affected & 0xFF));
		p.push_back((uint8_t)((affected >> 8) & 0xFF));
	}
	p.push_back(0x00); // last_insert_id
	p.push_back((uint8_t)(status & 0xFF));
	p.push_back((uint8_t)(status >> 8));
	p.push_back(0x00);
	p.push_back(0x00);
	return p;
}
static std::vector<unsigned char> err_pkt(uint16_t code = 1045) {
	return {0xFF, (uint8_t)(code & 0xFF), (uint8_t)(code >> 8), '#', 'H', 'Y', '0', '0', '0', 'x'};
}
static std::vector<unsigned char> text_row_one() { return {0x01, '1'}; }

static void feed_cols(MySQLResultsetFramer& f, uint8_t n, bool deprecate_eof) {
	f.on_first_payload(colcount(n).data(), 1);
	for (uint8_t i = 0; i < n; i++) {
		f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	}
	if (!deprecate_eof) {
		f.on_payload(eof_pkt().data(), eof_pkt().size());
	}
}

// --- multi-result: DML OK then SELECT ---
static void test_multi_dml_then_select() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	auto ok_more = ok_term(0x0002 | SERVER_MORE_RESULTS_EXIST, 3);
	auto e = f.on_first_payload(ok_more.data(), ok_more.size());
	ok(e.kind == MySQLRSEventKind::OKNoResultset && e.more_results && e.affected_rows == 3,
		"multi DML→SELECT: first OK more=1 affected=3");
	ok(f.active(), "multi DML→SELECT: still active");
	feed_cols(f, 1, true);
	f.on_payload(text_row_one().data(), text_row_one().size());
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && !e.more_results && e.rows_sent_total == 1,
		"multi DML→SELECT: second RS completes rows=1");
	ok(!f.active(), "multi DML→SELECT: idle");
}

// --- multi-result: SELECT then DML OK ---
static void test_multi_select_then_dml() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	feed_cols(f, 1, true);
	f.on_payload(text_row_one().data(), text_row_one().size());
	auto e = f.on_payload(ok_term(0x0002 | SERVER_MORE_RESULTS_EXIST).data(), 7);
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.more_results && e.rows_sent_total == 1,
		"multi SELECT→DML: first RS more=1");
	auto ok_dml = ok_term(0x0002, 9);
	e = f.on_payload(ok_dml.data(), ok_dml.size());
	ok(e.kind == MySQLRSEventKind::OKNoResultset && !e.more_results && e.affected_rows == 9,
		"multi SELECT→DML: trailing OK affected=9");
	ok(!f.active(), "multi SELECT→DML: idle");
}

// --- classic EOF with MORE_RESULTS ---
static void test_classic_eof_more_results() {
	MySQLResultsetFramer f;
	f.begin(false, false);
	feed_cols(f, 1, false);
	f.on_payload(text_row_one().data(), text_row_one().size());
	auto e = f.on_payload(eof_pkt(0x0002 | SERVER_MORE_RESULTS_EXIST).data(), 5);
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.more_results && e.rows_sent_total == 1,
		"classic EOF MORE_RESULTS on final EOF");
	ok(f.active(), "classic EOF MORE_RESULTS: awaits next RS");
	// second RS: single-row then plain EOF
	feed_cols(f, 1, false);
	f.on_payload(text_row_one().data(), text_row_one().size());
	e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && !e.more_results && e.rows_sent_total == 1,
		"classic EOF MORE_RESULTS: second RS done");
}

// --- binary multi-col all-null ---
static void test_binary_multicol_all_null() {
	MySQLResultsetFramer f;
	f.begin(true, true);
	feed_cols(f, 3, true);
	// null_bitmap len = (3+9)/8 = 1.5 → 1? (3+9)/8 = 1 in integer div... (3+9)=12/8=1
	// Actually (cols+7+2)/8 = (cols+9)/8. cols=3 → 12/8 = 1.
	// All nulls: set bits 2.. for columns (offset +2 in MySQL binary protocol)
	// For test: 0x00 + 1-byte bitmap 0xFF is enough for "row-like"
	unsigned char brow[] = {0x00, 0xFF};
	auto e = f.on_payload(brow, sizeof(brow));
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1,
		"binary 3-col all-null bitmap is Row");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 1,
		"binary 3-col: OK ends");
}

// --- text NULL field 0xFB ---
static void test_text_null_field() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	feed_cols(f, 2, true);
	// NULL + "x"
	unsigned char row[] = {0xFB, 0x01, 'x'};
	auto e = f.on_payload(row, sizeof(row));
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "text: 0xFB NULL field is Row");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete, "text NULL: OK ends");
}

// --- ERR after column count (before any coldef) ---
static void test_err_after_colcount() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	f.on_first_payload(colcount(2).data(), 1);
	auto err = err_pkt(1064);
	auto e = f.on_payload(err.data(), err.size());
	ok(e.kind == MySQLRSEventKind::Error && e.error_code == 1064, "ERR after colcount");
	ok(!f.active(), "ERR after colcount: idle");
}

// --- ERR mid column defs ---
static void test_err_mid_columns() {
	MySQLResultsetFramer f;
	f.begin(false, false);
	f.on_first_payload(colcount(3).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	auto err = err_pkt(2013);
	auto e = f.on_payload(err.data(), err.size());
	ok(e.kind == MySQLRSEventKind::Error && e.error_code == 2013, "ERR mid-columns");
	ok(!f.active(), "ERR mid-columns: idle");
}

// --- ERR on first payload (before any resultset) ---
static void test_err_first_payload() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	auto err = err_pkt(1146);
	auto e = f.on_first_payload(err.data(), err.size());
	ok(e.kind == MySQLRSEventKind::Error && e.error_code == 1146, "ERR as first payload");
	ok(!f.active(), "ERR first: idle");
}

// --- empty / null inputs do not crash ---
static void test_empty_and_null_payloads() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	auto e = f.on_first_payload(nullptr, 0);
	ok(e.kind == MySQLRSEventKind::None && f.active(), "null first payload: still awaiting");
	e = f.on_payload(nullptr, 5);
	ok(e.kind == MySQLRSEventKind::None, "null on_payload ignored");
	unsigned char empty = 0;
	e = f.on_payload(&empty, 0);
	ok(e.kind == MySQLRSEventKind::None, "zero-len on_payload ignored");
	// complete with DML OK so we leave clean
	auto okp = ok_term(0x0002, 0);
	e = f.on_first_payload(okp.data(), okp.size());
	ok(e.kind == MySQLRSEventKind::OKNoResultset, "recover with OK after empties");
}

// --- idle framer ignores traffic ---
static void test_idle_ignores() {
	MySQLResultsetFramer f;
	auto e = f.on_payload(text_row_one().data(), text_row_one().size());
	ok(e.kind == MySQLRSEventKind::None && !f.active(), "idle ignores row payload");
	e = f.on_first_payload(colcount(1).data(), 1);
	ok(e.kind == MySQLRSEventKind::None && !f.active(), "idle ignores first_payload without begin");
}

// --- many rows then complete ---
static void test_many_rows() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	feed_cols(f, 1, true);
	MySQLRSEvent e{};
	for (int i = 0; i < 50; i++) {
		e = f.on_payload(text_row_one().data(), text_row_one().size());
	}
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 50, "50 text rows counted");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 50, "50-row RS complete");
}

// --- binary two rows then OK ---
static void test_binary_two_rows() {
	MySQLResultsetFramer f;
	f.begin(true, true);
	feed_cols(f, 1, true);
	unsigned char r1[] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00}; // int 1
	unsigned char r2[] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00}; // int 2
	auto e = f.on_payload(r1, sizeof(r1));
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "binary row1");
	e = f.on_payload(r2, sizeof(r2));
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 2, "binary row2");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 2, "binary 2-row complete");
}

// --- begin() resets prior in-flight ---
static void test_begin_resets_inflight() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	feed_cols(f, 1, true);
	f.on_payload(text_row_one().data(), text_row_one().size());
	ok(f.active(), "precondition: active mid-RS");
	f.begin(false, false);
	ok(f.active(), "begin again: AwaitingFirst active");
	// classic path fresh
	feed_cols(f, 1, false);
	auto e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 0,
		"begin reset: 0-row classic complete (no leftover row count)");
}

// --- truncated OK as first payload ---
static void test_truncated_ok_first() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	unsigned char trunc[] = {0x00, 0x01}; // incomplete OK
	auto e = f.on_first_payload(trunc, sizeof(trunc));
	ok(e.kind == MySQLRSEventKind::None, "truncated OK: None event");
	ok(!f.active(), "truncated OK: framer idle (gave up)");
}

// --- three-result multi SELECT ---
static void test_three_resultsets() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	uint64_t total_from_events = 0;
	for (int rs = 0; rs < 3; rs++) {
		const bool last = (rs == 2);
		feed_cols(f, 1, true);
		f.on_payload(text_row_one().data(), text_row_one().size());
		f.on_payload(text_row_one().data(), text_row_one().size());
		uint16_t st = last ? 0x0002 : (uint16_t)(0x0002 | SERVER_MORE_RESULTS_EXIST);
		auto e = f.on_payload(ok_term(st).data(), 7);
		ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 2 &&
			e.more_results == !last,
			last ? "3RS: last complete more=0" : "3RS: intermediate complete more=1");
		total_from_events += e.rows_sent_total;
		if (!last) ok(f.active(), "3RS: still active between");
	}
	ok(total_from_events == 6, "3RS: cumulative rows across events = 6");
	ok(!f.active(), "3RS: idle at end");
}

int main() {
	// init(1) + 4+3+3+2+2+2+2+2+4+2+2+3+3+2+7 = 44
	plan(44);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");

	test_multi_dml_then_select();
	test_multi_select_then_dml();
	test_classic_eof_more_results();
	test_binary_multicol_all_null();
	test_text_null_field();
	test_err_after_colcount();
	test_err_mid_columns();
	test_err_first_payload();
	test_empty_and_null_payloads();
	test_idle_ignores();
	test_many_rows();
	test_binary_two_rows();
	test_begin_resets_inflight();
	test_truncated_ok_first();
	test_three_resultsets();

	test_cleanup_minimal();
	return exit_status();
}

#else

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

int main() {
	plan(1);
	ok(1, "mysql traffic framer tests skipped (PROXYSQLFFTO not enabled)");
	return exit_status();
}

#endif
