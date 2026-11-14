/**
 * @file pgsql_native_startup_params_reset_unit-t.cpp
 * @brief A native connection must still know its startup settings after a reset.
 *
 * ProxySQL sends five settings in the startup packet and records what it sent, so it
 * later knows how that connection is configured. DISCARD ALL puts the backend back to
 * exactly those values, so reset() restores the record from them. The native path
 * skipped that restore and came back claiming nothing was set, while the backend still
 * had all five -- so the pool could never score it as a match, and the next client
 * re-sent a SET for each one. Driving that for real needs a backend; here it is offline.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

#include <cstring>

// The settings that travel in the startup packet, one per slot and in the same order as
// pgsql_tracked_variables[]. A missing entry leaves a null that opened() below copies, and crashes.
static const char* CRITICAL[PGSQL_NAME_LAST_LOW_WM] = {
	"UTF8",             // client_encoding
	"ISO, MDY",         // DateStyle
	"postgres",         // IntervalStyle
	"on",               // standard_conforming_strings
	"UTC",              // TimeZone
	"\"$user\", public",  // search_path
};

// A hash per slot. Only equality is ever tested, so any non-zero value will do.
static uint32_t hash_for(int i) { return 0x1000u + (uint32_t)i; }

// A connection configured the way a live one is, with its startup packet recorded.
// copy_pgsql_variables_to_startup_parameters() is the same call native_send_startup()
// reaches through build_and_record_startup_session_params().
static PgSQL_Connection* opened(bool native) {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = native;
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		c->variables[i].value = strdup(CRITICAL[i]);
		c->var_hash[i] = hash_for(i);
	}
	c->copy_pgsql_variables_to_startup_parameters(true);
	return c;
}

int main(int, char**) {
	plan(3);

	PgSQL_Connection* c = opened(true);
	c->reset();   // what the session does once DISCARD ALL has come back

	int restored = 0;
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		if (c->var_hash[i] == hash_for(i)) restored++;
	}
	ok(restored == PGSQL_NAME_LAST_LOW_WM,
	   "a reset native connection still knows its %d startup settings (%d restored)%s",
	   PGSQL_NAME_LAST_LOW_WM, restored,
	   restored ? "" : "  <-- reset left it claiming nothing is set");

	int same = 0;
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		if (c->variables[i].value && strcmp(c->variables[i].value, CRITICAL[i]) == 0) same++;
	}
	ok(same == PGSQL_NAME_LAST_LOW_WM,
	   "and the values are the ones it was opened with (%d/%d)", same, PGSQL_NAME_LAST_LOW_WM);

	// The consequence the pool cares about: a client wanting exactly these settings has
	// to see a perfect match, which is what lets get_random_MyConn_inner_search() stop
	// looking instead of scanning the rest of the list.
	PgSQL_Connection* client = opened(false);
	unsigned int not_match = 0;
	unsigned int cnt = c->number_of_matching_session_variables(client, not_match);
	ok(cnt == (unsigned int)PGSQL_NAME_LAST_LOW_WM && not_match == 0,
	   "and the pool scores it a perfect match (%u matching, %u not)%s",
	   cnt, not_match, not_match ? "  <-- never reaches connection_quality_level 3" : "");

	delete client;
	delete c;
	return exit_status();
}
