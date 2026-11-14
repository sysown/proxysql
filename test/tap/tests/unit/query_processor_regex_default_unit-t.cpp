/**
 * @file query_processor_regex_default_unit-t.cpp
 * @brief Per-tier default and range of '*-query_processor_regex' (issue #6411).
 *
 * Maintainer decision on #6411:
 *   - v3.0 (Stable): PCRE (engine 1) only; PCRE2 (engine 3) cannot be selected.
 *   - v3.1 (PROXYSQL31): default 1, engine 3 is opt-in.
 *   - v4.0 (PROXYSQL40): default 3.
 * Checked on the real MySQL and PgSQL threads handlers.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"

#include <cstdlib>
#include <string>

extern MySQL_Threads_Handler* GloMTH;
extern PgSQL_Threads_Handler* GloPTH;

namespace {

#if defined(PROXYSQL40)
constexpr const char* kDefault = "3";
#else
constexpr const char* kDefault = "1";
#endif

template <typename Handler>
std::string get_regex(Handler* handler) {
	char* value = handler->get_variable((char*)"query_processor_regex");
	const std::string result = value != nullptr ? value : "";
	free(value);
	return result;
}

template <typename Handler>
void check(Handler* handler, const char* module) {
	ok(get_regex(handler) == kDefault, "%s-query_processor_regex defaults to %s on this tier", module, kDefault);

	const bool set3 = handler->set_variable((char*)"query_processor_regex", (char*)"3");
#ifdef PROXYSQL31
	ok(set3 && get_regex(handler) == "3", "%s-query_processor_regex accepts 3 (PCRE2) on v3.1/v4.0", module);
#else
	ok(!set3 && get_regex(handler) == "1", "%s-query_processor_regex rejects 3 (PCRE2) on v3.0", module);
#endif
	ok(handler->set_variable((char*)"query_processor_regex", (char*)"1") && get_regex(handler) == "1",
		"%s-query_processor_regex accepts 1 (PCRE)", module);
	ok(!handler->set_variable((char*)"query_processor_regex", (char*)"4") && get_regex(handler) == "1",
		"%s-query_processor_regex rejects 4", module);
}

} // namespace

int main() {
	plan(8);
	test_init_minimal();
	test_init_query_processor();
	check(GloMTH, "mysql");
	check(GloPTH, "pgsql");
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
