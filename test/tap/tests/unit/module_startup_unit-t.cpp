#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "private_daemon_probe.h"

int main(int argc, char** argv) {
	plan(1);
#ifndef __linux__
	skip(1, "private daemon startup probes require Linux");
#else
	test_init_minimal();
	const int result = run_private_daemon_probe(argv[0], argc > 1 ? argv[1] : nullptr, "test_module_startup.py");
	if (result == 77) {
		skip(1, "private daemon startup probes require python3, mysql and psql");
	} else {
		ok(result == 0, "private daemons preserve startup permissions and saved worker counts");
	}
	test_cleanup_minimal();
#endif
	return exit_status();
}
