/**
 * @file log_filename_variables_unit-t.cpp
 * @brief Preserve empty log filenames and filename validation in both protocol handlers (#6595).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"

#include <cstdlib>
#include <cstring>
#include <memory>

/** @brief Read back the actual handler value and release the returned string. */
template<class Handler>
static bool has_filename(Handler& handler, char* name, const char* expected) {
	const std::unique_ptr<char, decltype(&free)> value(handler.get_variable(name), &free);
	return value && strcmp(value.get(), expected) == 0;
}

/** @brief Empty filenames disable logging; rejected values must preserve the previously accepted filename. */
template<class Handler>
static void test_filenames(Handler& handler, const char* protocol) {
	char names[][24] = {"auditlog_filename", "eventslog_filename"};
	for (auto& name : names) {
		ok(handler.set_variable(name, "proxysql-test.log") && has_filename(handler, name, "proxysql-test.log"),
			"%s %s accepts a relative filename", protocol, name);
		ok(!handler.set_variable(name, "/tmp/") && has_filename(handler, name, "proxysql-test.log"),
			"%s %s rejects a trailing slash and retains its filename", protocol, name);
		ok(handler.set_variable(name, "") && has_filename(handler, name, ""),
			"%s %s accepts an empty filename to disable logging", protocol, name);
		ok(!handler.set_variable(name, nullptr) && has_filename(handler, name, ""),
			"%s %s rejects null and preserves disabled logging", protocol, name);
	}
}

/** @brief Exercise real MySQL and PostgreSQL setters with the standard unit-test harness. */
int main() {
	plan(16);
	if (test_init_minimal() != 0) return EXIT_FAILURE;
	{
		MySQL_Threads_Handler handler;
		test_filenames(handler, "mysql");
	}
	{
		PgSQL_Threads_Handler handler;
		test_filenames(handler, "pgsql");
	}
	test_cleanup_minimal();
	return exit_status();
}
