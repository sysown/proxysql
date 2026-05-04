#include "tap.h"

#include <cstring>

#include "MySQL_Resolution.h"

// NOTE: This unit test covers the helper functions for mysql-resolution_family.
// The actual DNS resolution path in MySQL_Monitor.cpp uses these helpers, but
// only when the DNS cache is enabled. On DNS cache miss, the hostname is passed
// directly to mysql_real_connect() which uses hardcoded AF_UNSPEC via the
// MariaDB client library. This limitation is documented in the PR description.
// A future enhancement may address this by patching the client library.

int main() {
	plan(12);

	ok(mysql_resolution_family_is_valid("system"), "system is accepted");
	ok(mysql_resolution_family_is_valid("ipv4"), "ipv4 is accepted");
	ok(mysql_resolution_family_is_valid("ipv6"), "ipv6 is accepted");
	ok(!mysql_resolution_family_is_valid("invalid"), "invalid value is rejected");

	ok(strcmp(mysql_resolution_family_normalize("IPv4"), "ipv4") == 0, "ipv4 values are normalized");
	ok(strcmp(mysql_resolution_family_normalize("IPv6"), "ipv6") == 0, "ipv6 values are normalized");
	ok(strcmp(mysql_resolution_family_normalize("SYSTEM"), "system") == 0, "system values are normalized");
	ok(strcmp(mysql_resolution_family_normalize("invalid"), "system") == 0, "invalid values normalize to system");

	ok(mysql_resolution_family_to_ai_family("ipv4") == AF_INET, "ipv4 maps to AF_INET");
	ok(mysql_resolution_family_to_ai_family("ipv6") == AF_INET6, "ipv6 maps to AF_INET6");
	ok(mysql_resolution_family_to_ai_family("system") == AF_UNSPEC, "system maps to AF_UNSPEC");
	ok(mysql_resolution_family_to_ai_family("invalid") == AF_UNSPEC, "invalid values fall back to AF_UNSPEC");

	return exit_status();
}
