#include "mysqlx_admin_schema.h"

namespace {

const char kMysqlxUsersTable[] = "mysqlx_users";
const char kMysqlxUsersTableDef[] =
	"CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)";

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
