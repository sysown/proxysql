#include <string>

#include "tap.h"
#include "proxysql_listen_validator.h"

int main() {
	plan(7);

	std::string error {};

	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "MySQL", "0.0.0.0:6033" },
				{ "PostgreSQL", "0.0.0.0:6033" },
			},
			error
		) == false &&
		error.find("MySQL") != std::string::npos &&
		error.find("PostgreSQL") != std::string::npos &&
		error.find("0.0.0.0:6033") != std::string::npos,
		"detects identical TCP listeners across modules"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "MySQL", "0.0.0.0:6033" },
				{ "PostgreSQL", "127.0.0.1:6033" },
			},
			error
		) == false &&
		error.find("127.0.0.1:6033") != std::string::npos,
		"detects wildcard and specific IPv4 listener conflicts"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "Admin", "/tmp/proxysql.sock" },
				{ "MySQL", "/tmp/proxysql.sock" },
			},
			error
		) == false &&
		error.find("/tmp/proxysql.sock") != std::string::npos,
		"detects duplicate unix socket listeners across modules"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "MySQL", "0.0.0.0:6033" },
				{ "PostgreSQL", "0.0.0.0:6133" },
			},
			error
		),
		"allows listeners on different ports"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "MySQL", "0.0.0.0:6033" },
				{ "PostgreSQL", "[::1]:6033" },
			},
			error
		),
		"allows separate IPv4 and IPv6 listeners on the same port"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "MySQL", "127.0.0.1:" },
				{ "PostgreSQL", "127.0.0.1:" },
			},
			error
		),
		"ignores malformed TCP listeners instead of misclassifying them as conflicting UNIX sockets"
	);

	error.clear();
	ok(
		proxysql_listen_validator::validate_module_listener_conflicts(
			{
				{ "Admin Telnet", "(null)" },
				{ "Admin Stats Telnet", "(null)" },
			},
			error
		),
		"ignores '(null)' listeners"
	);

	return exit_status();
}
