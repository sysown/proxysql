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

int main() {
	plan(11);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");
	test_text_select_classic_eof();
	test_text_select_deprecate_eof();
	test_ok_dml();
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
