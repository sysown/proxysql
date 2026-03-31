#include "tap.h"

#include <cstring>

#include "MySQL_Resolution.h"

int main() {
	plan(9);

	ok(mysql_resolution_family_is_valid("system"), "system is accepted");
	ok(mysql_resolution_family_is_valid("ipv4"), "ipv4 is accepted");
	ok(mysql_resolution_family_is_valid("ipv6"), "ipv6 is accepted");
	ok(!mysql_resolution_family_is_valid("invalid"), "invalid value is rejected");

	ok(strcmp(mysql_resolution_family_normalize("IPv4"), "ipv4") == 0, "ipv4 values are normalized");
	ok(strcmp(mysql_resolution_family_normalize("IPv6"), "ipv6") == 0, "ipv6 values are normalized");
	ok(strcmp(mysql_resolution_family_normalize("SYSTEM"), "system") == 0, "system values are normalized");

	ok(mysql_resolution_family_to_ai_family("ipv4") == AF_INET, "ipv4 maps to AF_INET");
	ok(mysql_resolution_family_to_ai_family("invalid") == AF_UNSPEC, "invalid values fall back to AF_UNSPEC");

	return exit_status();
}
