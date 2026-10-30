#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql_glovars.hpp"

#include <cstddef>

namespace {
// Keep existing global-field offsets stable for plugins built before the
// startup permissions were added. New permissions belong at the class tail.
struct LegacyGlobalPrefix {
	unsigned long long start_time;
	bool gdbg;
	bool nostart;
	bool my_monitor;
	bool pg_monitor;
	bool version_check;
#ifdef SO_REUSEPORT
	bool reuseport;
#endif
#ifdef IDLE_THREADS
	bool idle_threads;
#endif
	pthread_mutex_t start_mutex;
};
}

int main() {
	plan(1);
	test_init_minimal();
	ok(offsetof(decltype(ProxySQL_GlobalVariables::global), start_mutex) ==
		offsetof(LegacyGlobalPrefix, start_mutex),
		"startup permissions preserve the legacy global-field prefix");
	test_cleanup_minimal();
	return exit_status();
}
