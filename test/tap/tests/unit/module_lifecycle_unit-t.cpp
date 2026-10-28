#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "private_daemon_probe.h"

int main(int argc, char** argv) {
	plan(1);
	test_init_minimal();
	ok(run_private_daemon_probe(argv[0], argc > 1 ? argv[1] : nullptr, "test_module_lifecycle.py"),
		"private daemons preserve STOP/START responses, stopped-state safety, and explicit SAVE errors");
	test_cleanup_minimal();
	return exit_status();
}
