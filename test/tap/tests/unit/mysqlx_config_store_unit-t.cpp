#include "mysqlx_config_store.h"
#include "tap.h"

int main() {
	plan(5);

	MysqlxResolvedIdentity identity {};
	identity.username = "canonical_user";
	identity.default_hostgroup = 42;
	identity.x_enabled = true;

	ok(identity.username == "canonical_user",
	   "MysqlxResolvedIdentity keeps canonical username");
	ok(identity.default_hostgroup == 42,
	   "MysqlxResolvedIdentity keeps canonical default_hostgroup");
	ok(identity.x_enabled,
	   "MysqlxResolvedIdentity can enable mysqlx access");
	ok(identity.backend_auth_mode == MysqlxBackendAuthMode::mapped,
	   "MysqlxResolvedIdentity defaults backend_auth_mode to mapped");
	ok(mysqlx_backend_auth_mode_from_string("pass_through") ==
	   MysqlxBackendAuthMode::pass_through,
	   "backend auth mode parser accepts pass_through");

	return exit_status();
}
