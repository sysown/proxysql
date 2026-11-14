// Frozen ABI-13 plugin declarations, plus an independently sized ABI-16
// descriptor used only for compatibility coverage.  This fixture deliberately
// must not include ProxySQL_Plugin.h: its service layout is the ABI-13
// contract a separately compiled provider (e.g. the AWS IAM/locality plugin)
// would have shipped before the ABI-14 server-discovery tail existed.  Tail
// callbacks the fixture never calls are declared with layout-equivalent opaque
// function pointer types; only their position and size matter here.
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <string>

class SQLite3DB;
class SQLite3_result;
class AwsIamTokenSource;
class AwsMetadataProvider;
namespace prometheus { class Registry; }

namespace frozen_abi13 {

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

// The nine chassis-base callbacks, followed by ABI 2 through ABI 13.  These
// are the frozen, exact pre-ABI-14 declarations; no current plugin header is
// included, so an ABI-14 tail insertion cannot accidentally mask layout skew.
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
	// ABI 10: shared Admin connection transaction serialization.
	bool (*with_admin_db_lock)(bool (*body)(void *), void *);
	// ABI 13: AWS integration tail.
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

// Independently frozen ABI-16 descriptor: the complete ABI-13 prefix above
// plus the ABI-15 managed-configuration accessor.  The ABI-16 fixture must use
// this object, not a frozen ABI-13 descriptor merely relabelled as 16: the
// loader reads the accessor for layout >= 15, so the shorter object would be
// an out-of-bounds read.  Return type compatibility does not matter here; only
// the accessor's position and pointer size do.
using proxysql_plugin_managed_configuration_accessor_cb = const void *(*)();

struct ProxySQL_PluginDescriptorAbi16 {
	const char *name;
	uint32_t abi_version;
	proxysql_plugin_init_cb init;
	proxysql_plugin_start_cb start;
	proxysql_plugin_stop_cb stop;
	proxysql_plugin_status_json_cb status_json;
	proxysql_plugin_register_schemas_cb register_schemas;
	opaque_tail_cb register_cli_options;
	opaque_tail_cb early_action;
	opaque_tail_cb runtime_ready;
	proxysql_plugin_managed_configuration_accessor_cb managed_configuration_service;
};

static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, name) ==
	offsetof(ProxySQL_PluginDescriptor, name), "frozen ABI-16 name slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, abi_version) ==
	offsetof(ProxySQL_PluginDescriptor, abi_version), "frozen ABI-16 abi_version slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, register_schemas) ==
	offsetof(ProxySQL_PluginDescriptor, register_schemas), "frozen ABI-16 register_schemas slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, register_cli_options) ==
	offsetof(ProxySQL_PluginDescriptor, register_cli_options),
	"frozen ABI-16 register_cli_options slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, early_action) ==
	offsetof(ProxySQL_PluginDescriptor, early_action), "frozen ABI-16 early_action slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, runtime_ready) ==
	offsetof(ProxySQL_PluginDescriptor, runtime_ready), "frozen ABI-16 runtime_ready slot moved");
static_assert(offsetof(ProxySQL_PluginDescriptorAbi16, managed_configuration_service) ==
	sizeof(ProxySQL_PluginDescriptor),
	"frozen ABI-16 managed accessor must follow the complete ABI-13 descriptor prefix");

// Independently frozen ABI-17 service table: the complete ABI-13 prefix plus
// the ABI-14 discovery tail, six ABI-15 managed-runtime callbacks, and the
// ABI-17 listener validator.  ABI-18 appends its raw-backend getter after the
// validator, so an old ABI-17 plugin must keep loading and calling this tail.
struct ProxySQL_PluginServicesAbi17 {
	ProxySQL_PluginServices abi13;
	opaque_tail_cb register_server_module;
	opaque_tail_cb install_server_discovery_controller;
	opaque_tail_cb uninstall_server_discovery_controller;
	opaque_tail_cb post_server_desired_set;
	opaque_tail_cb lock_configuration;
	opaque_tail_cb unlock_configuration;
	opaque_tail_cb configdb_locked;
	opaque_tail_cb prepare_managed_runtime_locked;
	opaque_tail_cb activate_managed_runtime_locked;
	opaque_tail_cb destroy_managed_prepared_runtime;
	bool (*validate_listener_interfaces)(const char*, const char*, std::string&);
};

using validate_listener_interfaces_cb =
	bool (*)(const char*, const char*, std::string&);
static_assert(sizeof(ProxySQL_PluginServicesAbi17::validate_listener_interfaces) ==
	sizeof(validate_listener_interfaces_cb),
	"frozen ABI-17 listener validation slot must stay one function pointer");

// The loader requires the DEBUG tag to match the core exactly.
#ifdef DEBUG
constexpr uint32_t frozen_debug_bit = 0x40000000u;
#else
constexpr uint32_t frozen_debug_bit = 0u;
#endif

bool abi13_tail_called = false;

bool init(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->uninstall_aws_iam_token_source == nullptr) return false;
	// Calling the frozen ABI-13 tail through the real loader/init service table
	// proves that ABI-14 appended its fields without shifting this callback.
	abi13_tail_called = !services->uninstall_aws_iam_token_source(nullptr);
	return abi13_tail_called;
}
bool start() { return true; }
bool stop() { return true; }
const char *status_json() { return "{\"name\":\"fake_plugin_abi13\"}"; }

bool abi17_tail_called = false;

bool init17(ProxySQL_PluginServices *services) {
	auto *frozen17 = reinterpret_cast<ProxySQL_PluginServicesAbi17 *>(services);
	if (frozen17 == nullptr || frozen17->validate_listener_interfaces == nullptr) return false;
	std::string error = "stale";
	// Empty interface list is always a valid zero-listener request; a live
	// ABI-18 core still serves this old ABI-17 tail without reading past it.
	abi17_tail_called = frozen17->validate_listener_interfaces(
		"fake_plugin_abi17", "", error) && error.empty();
	return abi17_tail_called;
}

const ProxySQL_PluginDescriptor descriptor {
	"fake_plugin_abi13", 13u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr
};

// ABI-17 descriptor is full sized: the loader reads the ABI-15 managed
// configuration accessor by offset after checking layout >= 15.  Relabelling a
// truncated frozen ABI-13 descriptor would make that read run past the object.
const ProxySQL_PluginDescriptorAbi16 compatible_abi17_descriptor {
	"fake_plugin_abi17", 17u | frozen_debug_bit, &init17, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr, nullptr
};

const ProxySQL_PluginDescriptor unsupported_descriptor {
	"fake_plugin_abi19", 19u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr
};

// ABI 16 remains a compatible prefix even though ABI 17 appends a service
// tail.  It is a complete, correctly sized ABI-16 descriptor with a null
// managed-configuration accessor: provider lookup must treat it as "no
// provider" without reading past the object.
const ProxySQL_PluginDescriptorAbi16 compatible_abi16_descriptor {
	"fake_plugin_abi16", 16u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr,
	nullptr, nullptr, nullptr, nullptr
};

const ProxySQL_PluginDescriptor legacy_aws_descriptors[] = {
	{"aws", 10u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"aws", 11u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"aws", 12u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"aws", 13u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr}
};

const ProxySQL_PluginDescriptor reserved_descriptors[] = {
	{"reserved_layout", 11u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"reserved_layout", 12u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"incompatible_discovery_layout", 14u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr},
	{"incompatible_discovery_layout", 15u | frozen_debug_bit, &init, &start, &stop, &status_json, nullptr, nullptr, nullptr, nullptr}
};

} // namespace frozen_abi13

extern "C" const frozen_abi13::ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI13_FORCE_ABI16") != nullptr) {
		// The loader reads the ABI-15 tail only after checking the layout
		// version; both frozen structs share the complete prefix, and the
		// ABI-16 object really owns that tail.
		return reinterpret_cast<const frozen_abi13::ProxySQL_PluginDescriptor *>(
			&frozen_abi13::compatible_abi16_descriptor);
	}
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI13_FORCE_ABI17") != nullptr) {
		return reinterpret_cast<const frozen_abi13::ProxySQL_PluginDescriptor *>(
			&frozen_abi13::compatible_abi17_descriptor);
	}
	if (std::getenv("PROXYSQL_FAKE_PLUGIN_ABI13_FORCE_ABI19") != nullptr) {
		return &frozen_abi13::unsupported_descriptor;
	}
	const char *legacy = std::getenv("PROXYSQL_FAKE_PLUGIN_LEGACY_AWS_ABI");
	if (legacy != nullptr) {
		const int version = std::atoi(legacy);
		if (version >= 10 && version <= 13) return &frozen_abi13::legacy_aws_descriptors[version - 10];
	}
	const char *reserved = std::getenv("PROXYSQL_FAKE_PLUGIN_RESERVED_ABI");
	if (reserved != nullptr) {
		const int version = std::atoi(reserved);
		if (version == 11 || version == 12)
			return &frozen_abi13::reserved_descriptors[version - 11];
		if (version == 14 || version == 15)
			return &frozen_abi13::reserved_descriptors[version - 12];
	}
	return &frozen_abi13::descriptor;
}

extern "C" bool proxysql_fake_plugin_abi13_tail_called() {
	return frozen_abi13::abi13_tail_called;
}

extern "C" bool proxysql_fake_plugin_abi17_tail_called() {
	return frozen_abi13::abi17_tail_called;
}
