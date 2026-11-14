/** Verify native mode is unavailable in Stable and configurable in later tiers. */
#include <cstdlib>
#include <cstring>
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"

int main() {
	plan(17);
	if (test_init_minimal() != 0) BAIL_OUT("test initialization failed");
	PgSQL_Threads_Handler handler;
	char name[] = "use_native_backend_protocol";
	char** names = handler.get_variables_list();
	bool listed = false;
	for (char** p = names; p && *p; ++p) {
		listed |= strcmp(*p, name) == 0;
		free(*p);
	}
	free(names);
#ifdef PROXYSQL31
	const bool native_supported = true;
#else
	const bool native_supported = false;
#endif
	ok(listed == native_supported, "native setting is advertised only in v3.1/v4.0");
	char* initial = handler.get_variable(name);
	ok(native_supported ? initial && strcmp(initial, "true") == 0 : initial == nullptr,
	   "native defaults on when supported, and is absent in Stable");
	free(initial);
	for (const char* value : {"false", "0", "FALSE", "true", "1", "TRUE"}) {
		ok(handler.set_variable(name, value) == native_supported,
		   "setting %s succeeds only in v3.1/v4.0", value);
		char* current = handler.get_variable(name);
		const bool enabled = strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0 || strcmp(value, "1") == 0;
		ok(native_supported ? current && strcmp(current, enabled ? "true" : "false") == 0 : current == nullptr,
		   "runtime value matches the accepted setting or remains absent");
		free(current);
	}
	ok(!handler.set_variable(name, "invalid"), "invalid boolean is rejected");
	ok(!handler.set_variable(name, nullptr), "null value is rejected");
	char uppercase[] = "USE_NATIVE_BACKEND_PROTOCOL";
	ok(handler.set_variable(uppercase, "true") == native_supported, "case does not bypass the tier restriction");
	return exit_status();
}
