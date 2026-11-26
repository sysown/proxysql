/**
 * @file pgsql_init_connect_unit-t.cpp
 * @brief The state ProxySQL keeps for PostgreSQL init_connect, checked offline.
 *
 * handler_again___verify_init_connect() strdup()s the init_connect it sends into
 * options.init_connect and sets options.init_connect_sent, so each backend
 * connection runs it once. PgSQL_Connection::reset() (after DISCARD ALL) must
 * free that copy and re-arm the flag, otherwise a reset connection keeps the
 * backend state init_connect set up gone while ProxySQL believes it is there.
 *
 * pgsql-init_connect is read through get_variable_string(), which must return
 * NULL for an empty value: verify_init_connect() sends anything non-NULL.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Thread.h"

#include <cstring>

extern PgSQL_Threads_Handler* GloPTH;

// reset() restores the startup settings it recorded; an unrecorded slot is a
// null it copies and crashes on. Same values as pgsql_native_startup_params_reset_unit-t.
static const char* CRITICAL[PGSQL_NAME_LAST_LOW_WM] = {
	"UTF8", "ISO, MDY", "postgres", "on", "UTC", "\"$user\", public",
};

static PgSQL_Connection* opened() {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;   // no libpq handle offline
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		c->variables[i].value = strdup(CRITICAL[i]);
		c->var_hash[i] = 0x1000u + (uint32_t)i;
	}
	c->copy_pgsql_variables_to_startup_parameters(true);
	return c;
}

static void set_init_connect(const char* value) {
	GloPTH->wrlock();
	GloPTH->set_variable((char*)"init_connect", value);
	GloPTH->commit();
	GloPTH->wrunlock();
}

int main(int, char**) {
	plan(4);
	test_init_minimal();
	test_init_query_processor();

	PgSQL_Connection* c = opened();
	c->options.init_connect = strdup("SET ic.marker TO 'x'");
	c->options.init_connect_sent = true;
	c->reset();
	ok(c->options.init_connect == NULL, "reset() frees init_connect");
	ok(c->options.init_connect_sent == false, "reset() re-arms init_connect_sent");
	delete c;

	set_init_connect("");
	char* empty = GloPTH->get_variable_string((char*)"init_connect");
	ok(empty == NULL, "empty pgsql-init_connect reads back as NULL (got '%s')", empty ? empty : "NULL");
	free(empty);

	set_init_connect("SET ic.marker TO 'x'");
	char* value = GloPTH->get_variable_string((char*)"init_connect");
	ok(value != NULL && strcmp(value, "SET ic.marker TO 'x'") == 0,
	   "non-empty pgsql-init_connect round-trips (got '%s')", value ? value : "NULL");
	free(value);
	set_init_connect("");

	return exit_status();
}
