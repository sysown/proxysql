#include "tap.h"

#include "../cacert_duration_parser.h"

int main() {
	plan(6);

	const auto duration { parse_proxysqltest_duration_ms("result: Took 123ms complete") };
	ok(duration && *duration == 123, "parses a complete ProxySQLTEST duration");
	ok(!parse_proxysqltest_duration_ms("result unavailable"),
		"rejects a response without duration markers");
	ok(!parse_proxysqltest_duration_ms("ms Took 123"),
		"rejects reversed duration markers");
	ok(!parse_proxysqltest_duration_ms("Took -123ms "),
		"rejects a negative duration");
	ok(!parse_proxysqltest_duration_ms("Took 123junkms "),
		"rejects trailing duration junk");
	ok(!parse_proxysqltest_duration_ms("Took 18446744073709551616ms "),
		"rejects an overflowing duration");

	return exit_status();
}
