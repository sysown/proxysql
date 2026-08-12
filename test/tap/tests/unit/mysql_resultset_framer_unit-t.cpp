#ifdef PROXYSQLFFTO

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <vector>
#include <cstring>

#ifndef SERVER_MORE_RESULTS_EXIST
#define SERVER_MORE_RESULTS_EXIST 8
#endif

static std::vector<unsigned char> colcount(uint8_t n) { return { n }; }
static std::vector<unsigned char> dummy_coldef() {
	return { 3,'d','e','f', 0, 0, 0, 0, 0, 0x0c, 0x3f,0x00, 0,0,0,0, 0xfd, 0,0,0,0,0,0 };
}
static std::vector<unsigned char> eof_pkt(uint16_t status = 0x0002) {
	return { 0xFE, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8) };
}
static std::vector<unsigned char> ok_term(uint16_t status = 0x0002) {
	return { 0x00, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8), 0x00, 0x00 };
}
static std::vector<unsigned char> text_row_one() {
	return { 0x01, '1' };
}

static void test_text_select_classic_eof() {
	MySQLResultsetFramer f;
	f.begin(false, false);
	auto e = f.on_first_payload(colcount(1).data(), 1);
	ok(e.kind == MySQLRSEventKind::None && f.active(), "classic: after colcount still active");
	e = f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	ok(e.kind == MySQLRSEventKind::None, "classic: coldef");
	e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::None, "classic: intermediate EOF → rows");
	e = f.on_payload(text_row_one().data(), text_row_one().size());
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "classic: row counted");
	e = f.on_payload(eof_pkt().data(), eof_pkt().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 1 && !e.more_results,
		"classic: final EOF completes");
	ok(!f.active(), "classic: idle after complete");
}

static void test_text_select_deprecate_eof() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	auto e = f.on_payload(text_row_one().data(), text_row_one().size());
	ok(e.kind == MySQLRSEventKind::Row && e.rows_sent_total == 1, "dep_eof: row without intermediate EOF");
	e = f.on_payload(ok_term().data(), ok_term().size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.rows_sent_total == 1, "dep_eof: OK terminates");
}

static void test_ok_dml() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	unsigned char okp[] = {0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00};
	auto e = f.on_first_payload(okp, sizeof(okp));
	ok(e.kind == MySQLRSEventKind::OKNoResultset && e.affected_rows == 5, "DML OK affected=5");
	ok(!f.active(), "DML: idle");
}

static void test_multi_result_two_selects_dep_eof() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	// RS1
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	f.on_payload(text_row_one().data(), text_row_one().size());
	auto ok1 = ok_term(0x0002 | SERVER_MORE_RESULTS_EXIST);
	auto e = f.on_payload(ok1.data(), ok1.size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && e.more_results && e.rows_sent_total == 1,
		"multi: first RS complete more=1");
	ok(f.active(), "multi: still active for next RS");
	// RS2 via on_payload (AwaitingFirst)
	f.on_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	f.on_payload(text_row_one().data(), text_row_one().size());
	auto ok2 = ok_term(0x0002);
	e = f.on_payload(ok2.data(), ok2.size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete && !e.more_results && e.rows_sent_total == 1,
		"multi: second RS complete more=0");
}

static void test_binary_row_not_ok() {
	MySQLResultsetFramer f;
	f.begin(true, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	// binary row: 0x00 + null_bitmap (1 byte for 1 col) + int32 value 7
	// 7 bytes so a naive OK parse succeeds (affected=0, last_insert=7, status/warn=0)
	// and binary discrimination is required to keep it a Row.
	unsigned char brow[] = { 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00 };
	auto e = f.on_payload(brow, sizeof(brow));
	ok(e.kind == MySQLRSEventKind::Row, "binary: row not mistaken for OK");
	auto ot = ok_term();
	e = f.on_payload(ot.data(), ot.size());
	ok(e.kind == MySQLRSEventKind::ResultsetComplete, "binary: OK ends RS");
}

static void test_err_mid_rows() {
	MySQLResultsetFramer f;
	f.begin(false, true);
	f.on_first_payload(colcount(1).data(), 1);
	f.on_payload(dummy_coldef().data(), dummy_coldef().size());
	unsigned char err[] = { 0xFF, 0x15, 0x04, '#', 'H','Y','0','0','0', 'x' };
	auto e = f.on_payload(err, sizeof(err));
	ok(e.kind == MySQLRSEventKind::Error && e.error_code == 1045, "ERR mid-rows");
	ok(!f.active(), "idle after ERR");
}

int main() {
	plan(18);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");
	test_text_select_classic_eof();
	test_text_select_deprecate_eof();
	test_ok_dml();
	test_multi_result_two_selects_dep_eof();
	test_binary_row_not_ok();
	test_err_mid_rows();
	test_cleanup_minimal();
	return exit_status();
}

#else

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

int main() {
	plan(1);
	ok(1, "MySQLResultsetFramer tests skipped (PROXYSQLFFTO not enabled)");
	return exit_status();
}

#endif
