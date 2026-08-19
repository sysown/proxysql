// Frozen ABI-8 plugin declarations.  This fixture deliberately must not
// include ProxySQL_Plugin.h: its service layout is the ABI-8 contract a
// separately compiled provider would have shipped before ABI-9 existed.
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <string>

class SQLite3DB;
class SQLite3_result;
class AwsIamTokenSource;
class AwsMetadataProvider;
namespace prometheus { class Registry; }

namespace frozen_abi8 {

enum class ProxySQL_PluginDBKind : uint8_t {
	admin_db = 0,
	config_db = 1,
	stats_db = 2
};

struct ProxySQL_PluginTableDef {
	ProxySQL_PluginDBKind db_kind;
	const char *table_name;
	const char *table_def;
};

struct ProxySQL_PluginCommandContext {
	SQLite3DB *admindb;
	SQLite3DB *configdb;
	SQLite3DB *statsdb;
};

struct ProxySQL_PluginCommandResult {
	int error_code;
	uint64_t rows_affected;
	std::string message;
};

using proxysql_plugin_admin_command_cb =
	ProxySQL_PluginCommandResult (*)(const ProxySQL_PluginCommandContext &, const char *);
using proxysql_plugin_register_table_cb = void (*)(const ProxySQL_PluginTableDef &);
using proxysql_plugin_register_command_cb = void (*)(const char *, proxysql_plugin_admin_command_cb);
using proxysql_plugin_snapshot_cb = SQLite3_result *(*)();
using proxysql_plugin_db_handle_cb = SQLite3DB *(*)();
using proxysql_plugin_log_message_cb = void (*)(int, const char *);

enum class ProxySQL_PluginProtocol : uint8_t { mysql = 0, pgsql = 1 };
struct ProxySQL_PluginQueryHookPayload {
	const char *user;
	const char *client_ip;
	const char *schema;
	const char *query_text;
	uint32_t query_len;
};
enum class ProxySQL_PluginQueryHookAction : uint8_t { allow = 0, deny = 1 };
struct ProxySQL_PluginQueryHookResult {
	ProxySQL_PluginQueryHookAction action;
	std::string message;
};
using proxysql_plugin_query_hook_cb =
	ProxySQL_PluginQueryHookResult (*)(const ProxySQL_PluginQueryHookPayload &);
using proxysql_plugin_register_query_hook_cb =
	bool (*)(ProxySQL_PluginProtocol, proxysql_plugin_query_hook_cb);
using proxysql_plugin_get_prometheus_registry_cb = prometheus::Registry *(*)();
using proxysql_plugin_register_command_alias_cb = void (*)(const char *, const char *);

struct ProxySQL_PluginRuntimeView {
	const char *table_name;
	void (*refresh)(SQLite3DB *db, void *opaque);
	void *opaque;
	ProxySQL_PluginDBKind db_kind;
};
using proxysql_plugin_register_runtime_view_cb = bool (*)(const ProxySQL_PluginRuntimeView &);
using proxysql_plugin_install_aws_iam_token_source_cb =
	bool (*)(AwsIamTokenSource *, void (*)(AwsIamTokenSource *), void *module_handle);
using uninstall_aws_iam_token_source_cb = bool (*)(AwsIamTokenSource *);
using proxysql_plugin_get_aws_iam_limits_cb = void (*)(size_t *, size_t *);
using proxysql_plugin_install_aws_metadata_provider_cb =
	bool (*)(AwsMetadataProvider *, void (*)(AwsMetadataProvider *), void *module_handle);
using proxysql_plugin_refresh_mysql_aws_locality_stats_cb = void (*)(SQLite3DB *);

// The nine chassis-base callbacks, followed by ABI 2 through ABI 8.  These
// are the frozen, exact pre-ABI-9 declarations; no current plugin header is
// included, so an ABI-9 tail insertion cannot accidentally mask layout skew.
struct ProxySQL_PluginServices {
	proxysql_plugin_register_table_cb register_table;
	proxysql_plugin_register_command_cb register_command;
	proxysql_plugin_snapshot_cb get_mysql_users_snapshot;
	proxysql_plugin_snapshot_cb get_mysql_servers_snapshot;
	proxysql_plugin_snapshot_cb get_mysql_group_replication_hostgroups_snapshot;
	proxysql_plugin_log_message_cb log_message;
	proxysql_plugin_db_handle_cb get_admindb;
	proxysql_plugin_db_handle_cb get_configdb;
	proxysql_plugin_db_handle_cb get_statsdb;
	proxysql_plugin_register_query_hook_cb register_query_hook;
	proxysql_plugin_get_prometheus_registry_cb get_prometheus_registry;
	proxysql_plugin_register_command_alias_cb register_command_alias;
	proxysql_plugin_register_runtime_view_cb register_runtime_view;
	proxysql_plugin_install_aws_iam_token_source_cb install_aws_iam_token_source;
	proxysql_plugin_get_aws_iam_limits_cb get_aws_iam_limits;
	proxysql_plugin_install_aws_metadata_provider_cb install_aws_metadata_provider;
	proxysql_plugin_refresh_mysql_aws_locality_stats_cb refresh_mysql_aws_locality_stats;
	uninstall_aws_iam_token_source_cb uninstall_aws_iam_token_source;
};

using proxysql_plugin_init_cb = bool (*)(ProxySQL_PluginServices *);
using proxysql_plugin_start_cb = bool (*)();
using proxysql_plugin_stop_cb = bool (*)();
using proxysql_plugin_status_json_cb = const char *(*)();
using proxysql_plugin_register_schemas_cb = bool (*)(ProxySQL_PluginServices *);

struct ProxySQL_PluginDescriptor {
	const char *name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
	proxysql_plugin_register_schemas_cb register_schemas;
};

bool abi8_tail_called = false;

bool init(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->uninstall_aws_iam_token_source == nullptr) return false;
	// Calling the frozen ABI-8 tail through the real loader/init service table
	// proves that ABI-9 appended its fields without shifting this callback.
	abi8_tail_called = !services->uninstall_aws_iam_token_source(nullptr);
	return abi8_tail_called;
}
bool start() { return true; }
bool stop() { return true; }
const char *status_json() { return "{\"name\":\"fake_plugin_abi8\"}"; }

const ProxySQL_PluginDescriptor descriptor {
	"fake_plugin_abi8", 8u, &init, &start, &stop, &status_json, nullptr
};

const ProxySQL_PluginDescriptor unsupported_descriptor {
	"fake_plugin_abi10", 10u, &init, &start, &stop, &status_json, nullptr
};

} // namespace frozen_abi8

extern "C" const frozen_abi8::ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI8_FORCE_ABI10") != nullptr) {
		return &frozen_abi8::unsupported_descriptor;
	}
	return &frozen_abi8::descriptor;
}

extern "C" bool proxysql_fake_plugin_abi8_tail_called() {
	return frozen_abi8::abi8_tail_called;
}
