#include "mysqlx_admin_schema.h"

namespace {

const char kMysqlxUsersTable[] = "mysqlx_users";
const char kMysqlxUsersTableDef[] =
	"CREATE TABLE mysqlx_users ("
	" username VARCHAR NOT NULL PRIMARY KEY,"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" require_tls INT CHECK (require_tls IN (0,1)) NOT NULL DEFAULT 0,"
	" allowed_auth_methods VARCHAR NOT NULL DEFAULT '',"
	" default_route VARCHAR,"
	" policy_profile VARCHAR,"
	" backend_auth_mode VARCHAR NOT NULL DEFAULT 'mapped',"
	" backend_username VARCHAR,"
	" backend_password VARCHAR,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

} // namespace

bool mysqlx_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr) {
		return false;
	}

	ProxySQL_PluginTableDef admin_def {
		ProxySQL_PluginDBKind::admin_db,
		kMysqlxUsersTable,
		kMysqlxUsersTableDef
	};
	ProxySQL_PluginTableDef config_def {
		ProxySQL_PluginDBKind::config_db,
		kMysqlxUsersTable,
		kMysqlxUsersTableDef
	};

	services.register_table(admin_def);
	services.register_table(config_def);
	return true;
}
