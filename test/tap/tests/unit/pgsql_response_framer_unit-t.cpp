#ifdef PROXYSQLFFTO

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQLResponseFramer.h"
#include <cstring>

static void test_command_complete_select() {
	PgSQLResponseFramer f;
	const char* tag = "SELECT 3";
	auto e = f.on_message('C', (const unsigned char*)tag, strlen(tag));
	ok(e.kind == PgSQLRSEventKind::CommandComplete && e.rows == 3 && e.is_select,
		"CommandComplete SELECT 3 → rows=3 is_select");
	ok(f.response_seen(), "CommandComplete sets response_seen");
}

static void test_portal_suspended() {
	PgSQLResponseFramer f;
	auto e = f.on_message('s', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::PortalSuspended, "PortalSuspended kind");
	ok(f.response_seen(), "PortalSuspended sets response_seen");
}

static void test_ready_for_query_alone() {
	PgSQLResponseFramer f;
	auto e = f.on_message('Z', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::ReadyForQuery, "ReadyForQuery kind");
	ok(!f.response_seen(), "ReadyForQuery alone does NOT set response_seen");
}

static void test_empty_query() {
	PgSQLResponseFramer f;
	auto e = f.on_message('I', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::EmptyQuery, "EmptyQuery kind");
	ok(f.response_seen(), "EmptyQuery sets response_seen");
}

static void test_error_event() {
	PgSQLResponseFramer f;
	auto e = f.on_message('E', nullptr, 0);
	ok(e.kind == PgSQLRSEventKind::Error, "Error event kind");
}

static void test_on_query_activated_clears() {
	PgSQLResponseFramer f;
	const char* tag = "SELECT 1";
	f.on_message('C', (const unsigned char*)tag, strlen(tag));
	ok(f.response_seen(), "precondition: response_seen after CC");
	f.on_query_activated(true);
	ok(!f.response_seen(), "on_query_activated clears response_seen");
	ok(f.finalize_on_sync(), "on_query_activated sets finalize_on_sync");
}

int main() {
	plan(13);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal");
	test_command_complete_select();
	test_portal_suspended();
	test_ready_for_query_alone();
	test_empty_query();
	test_error_event();
	test_on_query_activated_clears();
	test_cleanup_minimal();
	return exit_status();
}

#else

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

int main() {
	plan(1);
	ok(1, "PgSQLResponseFramer tests skipped (PROXYSQLFFTO not enabled)");
	return exit_status();
}

#endif
