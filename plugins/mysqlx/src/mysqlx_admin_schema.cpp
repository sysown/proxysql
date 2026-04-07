#include "mysqlx_plugin.h"

namespace {

const char kMysqlxUsersTable[] = "mysqlx_users";
const char kMysqlxUsersTableDef[] =
	"CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)";

} // namespace

void mysqlx_register_admin_schema() {
	MysqlxPluginContext& ctx = mysqlx_context();
	if (ctx.services == nullptr || ctx.services->register_table == nullptr) {
		return;
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

	ctx.services->register_table(admin_def);
	ctx.services->register_table(config_def);
}
