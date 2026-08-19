#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"

#include <dlfcn.h>
#include <string>
#include <vector>

namespace {

class Module final : public ProxySQL_ServerModuleHooks {
public:
	Module(ProxySQL_ServerProtocol protocol,
		std::vector<ProxySQL_ServerModuleTable> tables)
		: ProxySQL_ServerModuleHooks(protocol, std::move(tables)) {}
};

void destroy_module(ProxySQL_ServerModuleHooks* module) { delete module; }

} // namespace

int main() {
	plan(9);
	ProxySQL_PluginManager manager;
	void* handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	ProxySQL_ServerModuleTable mysql_a {
		ProxySQL_ServerProtocol::mysql,
		"mysql_aws_plugin_aurora_hostgroups",
		"runtime_mysql_aws_plugin_aurora_hostgroups",
		"writer_hostgroup,reader_hostgroup",
	};
	ProxySQL_ServerModuleTable mysql_b {
		ProxySQL_ServerProtocol::mysql,
		"mysql_aws_plugin_rds_hostgroups",
		"runtime_mysql_aws_plugin_rds_hostgroups",
		"writer_hostgroup,reader_hostgroup",
	};
	ProxySQL_ServerModuleTable pgsql_a {
		ProxySQL_ServerProtocol::pgsql,
		"pgsql_aws_plugin_aurora_hostgroups",
		"runtime_pgsql_aws_plugin_aurora_hostgroups",
		"writer_hostgroup,reader_hostgroup",
	};

	ok(manager.server_module_tables(ProxySQL_ServerProtocol::mysql).empty(),
		"schemas remain absent with no MySQL module");
	ok(manager.server_module_tables(ProxySQL_ServerProtocol::pgsql).empty(),
		"schemas remain absent with no PGSQL module");
	auto* mysql_module = new Module(ProxySQL_ServerProtocol::mysql, {mysql_b, mysql_a});
	ok(manager.register_server_module(mysql_module, destroy_module, handle), "registers MySQL module tables");
	ok(manager.register_server_module(new Module(ProxySQL_ServerProtocol::pgsql,
		{pgsql_a}), destroy_module, dlopen(nullptr, RTLD_NOW | RTLD_LOCAL)),
		"registers PGSQL module tables");
	const auto mysql_tables = manager.server_module_tables(ProxySQL_ServerProtocol::mysql);
	const auto pgsql_tables = manager.server_module_tables(ProxySQL_ServerProtocol::pgsql);
	ok(mysql_tables.size() == 2 && mysql_tables[0].table_name == mysql_a.table_name &&
		mysql_tables[1].table_name == mysql_b.table_name,
		"MySQL table order is lexical and stable");
	ok(pgsql_tables.size() == 1 && pgsql_tables[0].table_name == pgsql_a.table_name &&
		mysql_tables[0].table_name != pgsql_tables[0].table_name,
		"MySQL and PGSQL table affiliations remain isolated");
	mysql_module->tables[0].table_name = "mutated_after_registration";
	ok(manager.server_module_tables(ProxySQL_ServerProtocol::mysql)[0].table_name == mysql_a.table_name,
		"registry owns deep table metadata copies");
	ProxySQL_ServerModuleTable malformed = mysql_a;
	malformed.runtime_table_name.clear();
	ProxySQL_PluginManager malformed_manager;
	void* malformed_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto* malformed_module = new Module(ProxySQL_ServerProtocol::mysql, {malformed});
	ok(!malformed_manager.register_server_module(malformed_module, destroy_module, malformed_handle),
		"malformed registration fails schema phase");
	delete malformed_module;
	dlclose(malformed_handle);
	ProxySQL_PluginManager duplicate_manager;
	void* duplicate_handle = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
	auto* duplicate_module = new Module(ProxySQL_ServerProtocol::mysql, {mysql_a, mysql_a});
	ok(!duplicate_manager.register_server_module(duplicate_module, destroy_module, duplicate_handle),
		"duplicate registration fails schema phase");
	delete duplicate_module;
	dlclose(duplicate_handle);
	return exit_status();
}
