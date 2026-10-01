// Frozen ABI-10 plugin declarations.  This fixture deliberately must not
// include ProxySQL_Plugin.h: its service layout is the ABI-10 contract a
// separately compiled provider (e.g. the AWS IAM/locality plugin) would have
// shipped before the ABI-11 server-discovery tail existed.  Tail callbacks the
// fixture never calls are declared with layout-equivalent opaque function
// pointer types; only their position and size matter here.
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <string>

class SQLite3DB;
class SQLite3_result;
class AwsIamTokenSource;
class AwsMetadataProvider;
namespace prometheus { class Registry; }

namespace frozen_abi10 {

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
	void *admin_mutex_context;
	void (*release_admin_mutex)(void *);
	void (*acquire_admin_mutex)(void *);
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

using opaque_tail_cb = void (*)();

// The nine chassis-base callbacks, followed by ABI 2 through ABI 10.  These
// are the frozen, exact pre-ABI-11 declarations; no current plugin header is
// included, so an ABI-11 tail insertion cannot accidentally mask layout skew.
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
	// ABI 7: put_secret, get_secret, erase_secret.
	opaque_tail_cb put_secret;
	opaque_tail_cb get_secret;
	opaque_tail_cb erase_secret;
	// ABI 8: set_listener_gate, apply_mysql_config.  ABI 9: apply_mysql_config_v2.
	opaque_tail_cb set_listener_gate;
	opaque_tail_cb apply_mysql_config;
	opaque_tail_cb apply_mysql_config_v2;
	// ABI 10: AWS integration tail.
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
	// ABI 6: register_cli_options, early_action.  ABI 8: runtime_ready.
	opaque_tail_cb register_cli_options;
	opaque_tail_cb early_action;
	opaque_tail_cb runtime_ready;
};

// The loader requires the DEBUG tag to match the core exactly.
#ifdef DEBUG
constexpr uint32_t frozen_debug_bit = 0x40000000u;
#else
constexpr uint32_t frozen_debug_bit = 0u;
#endif

bool abi10_tail_called = false;

bool init(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->uninstall_aws_iam_token_source == nullptr) return false;
	// Calling the frozen ABI-10 tail through the real loader/init service table
	// proves that ABI-11 appended its fields without shifting this callback.
	abi10_tail_called = !services->uninstall_aws_iam_token_source(nullptr);
	return abi10_tail_called;
}
bool start() { return true; }
bool stop() { return true; }
const char *status_json() { return "{\"name\":\"fake_plugin_abi10\"}"; }

const ProxySQL_PluginDescriptor descriptor {
	"fake_plugin_abi10", 10u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr
};

const ProxySQL_PluginDescriptor unsupported_descriptor {
	"fake_plugin_abi13", 13u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr
};

} // namespace frozen_abi10

extern "C" const frozen_abi10::ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI10_FORCE_ABI13") != nullptr) {
		return &frozen_abi10::unsupported_descriptor;
	}
	return &frozen_abi10::descriptor;
}

extern "C" bool proxysql_fake_plugin_abi10_tail_called() {
	return frozen_abi10::abi10_tail_called;
}
