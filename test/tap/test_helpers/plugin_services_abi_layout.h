#ifndef PROXYSQL_PLUGIN_SERVICES_ABI_LAYOUT_TEST_H
#define PROXYSQL_PLUGIN_SERVICES_ABI_LAYOUT_TEST_H

#include "ProxySQL_Plugin.h"
#include <cstddef>
#include <type_traits>

// Freeze the published upstream ABI-10 slot order independently of the current
// services struct. Types follow the public declarations, but field placement
// must not change when AWS or future plugin services are appended.
namespace plugin_services_abi_layout_test {
struct UpstreamAbi10 {
	decltype(ProxySQL_PluginServices::register_table) register_table;
	decltype(ProxySQL_PluginServices::register_command) register_command;
	decltype(ProxySQL_PluginServices::get_mysql_users_snapshot) get_mysql_users_snapshot;
	decltype(ProxySQL_PluginServices::get_mysql_servers_snapshot) get_mysql_servers_snapshot;
	decltype(ProxySQL_PluginServices::get_mysql_group_replication_hostgroups_snapshot) get_mysql_group_replication_hostgroups_snapshot;
	decltype(ProxySQL_PluginServices::log_message) log_message;
	decltype(ProxySQL_PluginServices::get_admindb) get_admindb;
	decltype(ProxySQL_PluginServices::get_configdb) get_configdb;
	decltype(ProxySQL_PluginServices::get_statsdb) get_statsdb;
	decltype(ProxySQL_PluginServices::register_query_hook) register_query_hook;
	decltype(ProxySQL_PluginServices::get_prometheus_registry) get_prometheus_registry;
	decltype(ProxySQL_PluginServices::register_command_alias) register_command_alias;
	decltype(ProxySQL_PluginServices::register_runtime_view) register_runtime_view;
	decltype(ProxySQL_PluginServices::put_secret) put_secret;
	decltype(ProxySQL_PluginServices::get_secret) get_secret;
	decltype(ProxySQL_PluginServices::erase_secret) erase_secret;
	decltype(ProxySQL_PluginServices::set_listener_gate) set_listener_gate;
	decltype(ProxySQL_PluginServices::apply_mysql_config) apply_mysql_config;
	decltype(ProxySQL_PluginServices::apply_mysql_config_v2) apply_mysql_config_v2;
	decltype(ProxySQL_PluginServices::with_admin_db_lock) with_admin_db_lock;
};

static_assert(offsetof(ProxySQL_PluginServices, register_table) ==
	offsetof(UpstreamAbi10, register_table), "upstream ABI-10 register_table slot moved");
static_assert(offsetof(ProxySQL_PluginServices, register_command) ==
	offsetof(UpstreamAbi10, register_command), "upstream ABI-10 register_command slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_mysql_users_snapshot) ==
	offsetof(UpstreamAbi10, get_mysql_users_snapshot), "upstream ABI-10 get_mysql_users_snapshot slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_mysql_servers_snapshot) ==
	offsetof(UpstreamAbi10, get_mysql_servers_snapshot), "upstream ABI-10 get_mysql_servers_snapshot slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_mysql_group_replication_hostgroups_snapshot) ==
	offsetof(UpstreamAbi10, get_mysql_group_replication_hostgroups_snapshot), "upstream ABI-10 get_mysql_group_replication_hostgroups_snapshot slot moved");
static_assert(offsetof(ProxySQL_PluginServices, log_message) ==
	offsetof(UpstreamAbi10, log_message), "upstream ABI-10 log_message slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_admindb) ==
	offsetof(UpstreamAbi10, get_admindb), "upstream ABI-10 get_admindb slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_configdb) ==
	offsetof(UpstreamAbi10, get_configdb), "upstream ABI-10 get_configdb slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_statsdb) ==
	offsetof(UpstreamAbi10, get_statsdb), "upstream ABI-10 get_statsdb slot moved");
static_assert(offsetof(ProxySQL_PluginServices, register_query_hook) ==
	offsetof(UpstreamAbi10, register_query_hook), "upstream ABI-10 register_query_hook slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_prometheus_registry) ==
	offsetof(UpstreamAbi10, get_prometheus_registry), "upstream ABI-10 get_prometheus_registry slot moved");
static_assert(offsetof(ProxySQL_PluginServices, register_command_alias) ==
	offsetof(UpstreamAbi10, register_command_alias), "upstream ABI-10 register_command_alias slot moved");
static_assert(offsetof(ProxySQL_PluginServices, register_runtime_view) ==
	offsetof(UpstreamAbi10, register_runtime_view), "upstream ABI-10 register_runtime_view slot moved");
static_assert(offsetof(ProxySQL_PluginServices, put_secret) ==
	offsetof(UpstreamAbi10, put_secret), "upstream ABI-10 put_secret slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_secret) ==
	offsetof(UpstreamAbi10, get_secret), "upstream ABI-10 get_secret slot moved");
static_assert(offsetof(ProxySQL_PluginServices, erase_secret) ==
	offsetof(UpstreamAbi10, erase_secret), "upstream ABI-10 erase_secret slot moved");
static_assert(offsetof(ProxySQL_PluginServices, set_listener_gate) ==
	offsetof(UpstreamAbi10, set_listener_gate), "upstream ABI-10 set_listener_gate slot moved");
static_assert(offsetof(ProxySQL_PluginServices, apply_mysql_config) ==
	offsetof(UpstreamAbi10, apply_mysql_config), "upstream ABI-10 apply_mysql_config slot moved");
static_assert(offsetof(ProxySQL_PluginServices, apply_mysql_config_v2) ==
	offsetof(UpstreamAbi10, apply_mysql_config_v2), "upstream ABI-10 apply_mysql_config_v2 slot moved");
static_assert(offsetof(ProxySQL_PluginServices, with_admin_db_lock) ==
	offsetof(UpstreamAbi10, with_admin_db_lock), "upstream ABI-10 with_admin_db_lock slot moved");

struct AwsAbi13 {
	UpstreamAbi10 upstream;
	decltype(ProxySQL_PluginServices::install_aws_iam_token_source) install_aws_iam_token_source;
	decltype(ProxySQL_PluginServices::get_aws_iam_limits) get_aws_iam_limits;
	decltype(ProxySQL_PluginServices::install_aws_metadata_provider) install_aws_metadata_provider;
	decltype(ProxySQL_PluginServices::refresh_mysql_aws_locality_stats) refresh_mysql_aws_locality_stats;
	decltype(ProxySQL_PluginServices::uninstall_aws_iam_token_source) uninstall_aws_iam_token_source;
};

static_assert(offsetof(ProxySQL_PluginServices, install_aws_iam_token_source) ==
	offsetof(AwsAbi13, install_aws_iam_token_source), "AWS ABI-13 install_aws_iam_token_source slot moved");
static_assert(offsetof(ProxySQL_PluginServices, get_aws_iam_limits) ==
	offsetof(AwsAbi13, get_aws_iam_limits), "AWS ABI-13 get_aws_iam_limits slot moved");
static_assert(offsetof(ProxySQL_PluginServices, install_aws_metadata_provider) ==
	offsetof(AwsAbi13, install_aws_metadata_provider), "AWS ABI-13 install_aws_metadata_provider slot moved");
static_assert(offsetof(ProxySQL_PluginServices, refresh_mysql_aws_locality_stats) ==
	offsetof(AwsAbi13, refresh_mysql_aws_locality_stats), "AWS ABI-13 refresh_mysql_aws_locality_stats slot moved");
static_assert(offsetof(ProxySQL_PluginServices, uninstall_aws_iam_token_source) ==
	offsetof(AwsAbi13, uninstall_aws_iam_token_source), "AWS ABI-13 uninstall_aws_iam_token_source slot moved");
static_assert(offsetof(ProxySQL_PluginServices, register_server_module) == sizeof(AwsAbi13),
	"discovery ABI-14 must follow the complete AWS ABI-13 prefix");

// register_server_module is a reserved slot (server modules are no longer
// supported) but must keep its place so later slots keep their offsets.
struct DiscoveryAbi14 {
	AwsAbi13 aws;
	decltype(ProxySQL_PluginServices::register_server_module) register_server_module;
	decltype(ProxySQL_PluginServices::install_server_discovery_controller) install_server_discovery_controller;
	decltype(ProxySQL_PluginServices::uninstall_server_discovery_controller) uninstall_server_discovery_controller;
	decltype(ProxySQL_PluginServices::post_server_desired_set) post_server_desired_set;
};

static_assert(sizeof(ProxySQL_PluginServices::register_server_module) == sizeof(void (*)()),
	"reserved ABI-14 register_server_module slot must stay one function pointer");
static_assert(offsetof(ProxySQL_PluginServices, register_server_module) ==
	offsetof(DiscoveryAbi14, register_server_module), "reserved ABI-14 register_server_module slot moved");
static_assert(offsetof(ProxySQL_PluginServices, install_server_discovery_controller) ==
	offsetof(DiscoveryAbi14, install_server_discovery_controller), "ABI-14 install_server_discovery_controller slot moved");
static_assert(offsetof(ProxySQL_PluginServices, uninstall_server_discovery_controller) ==
	offsetof(DiscoveryAbi14, uninstall_server_discovery_controller), "ABI-14 uninstall_server_discovery_controller slot moved");
static_assert(offsetof(ProxySQL_PluginServices, post_server_desired_set) ==
	offsetof(DiscoveryAbi14, post_server_desired_set), "ABI-14 post_server_desired_set slot moved");
static_assert(offsetof(ProxySQL_PluginServices, lock_configuration) == sizeof(DiscoveryAbi14),
	"managed-configuration ABI-15 must follow the complete ABI-14 prefix");

// Complete frozen ABI-16 service prefix: the ABI-14 discovery tail plus the
// six ABI-15 caller-held-mutex/managed-runtime callbacks.  ABI-17 appends its
// listener-validation service strictly after this prefix.  Keeping the six
// callbacks explicit here detects an earlier field being moved or resized;
// comparing only the current struct's final-field end cannot.
struct ManagedConfigurationAbi16 {
	DiscoveryAbi14 discovery;
	decltype(ProxySQL_PluginServices::lock_configuration) lock_configuration;
	decltype(ProxySQL_PluginServices::unlock_configuration) unlock_configuration;
	decltype(ProxySQL_PluginServices::configdb_locked) configdb_locked;
	decltype(ProxySQL_PluginServices::prepare_managed_runtime_locked) prepare_managed_runtime_locked;
	decltype(ProxySQL_PluginServices::activate_managed_runtime_locked) activate_managed_runtime_locked;
	decltype(ProxySQL_PluginServices::destroy_managed_prepared_runtime) destroy_managed_prepared_runtime;
};

static_assert(sizeof(ManagedConfigurationAbi16::lock_configuration) == sizeof(void (*)()),
	"ABI-16 lock_configuration slot must stay one function pointer");
static_assert(offsetof(ProxySQL_PluginServices, lock_configuration) ==
	offsetof(ManagedConfigurationAbi16, lock_configuration), "ABI-16 lock_configuration slot moved");
static_assert(offsetof(ProxySQL_PluginServices, unlock_configuration) ==
	offsetof(ManagedConfigurationAbi16, unlock_configuration), "ABI-16 unlock_configuration slot moved");
static_assert(offsetof(ProxySQL_PluginServices, configdb_locked) ==
	offsetof(ManagedConfigurationAbi16, configdb_locked), "ABI-16 configdb_locked slot moved");
static_assert(offsetof(ProxySQL_PluginServices, prepare_managed_runtime_locked) ==
	offsetof(ManagedConfigurationAbi16, prepare_managed_runtime_locked),
	"ABI-16 prepare_managed_runtime_locked slot moved");
static_assert(offsetof(ProxySQL_PluginServices, activate_managed_runtime_locked) ==
	offsetof(ManagedConfigurationAbi16, activate_managed_runtime_locked),
	"ABI-16 activate_managed_runtime_locked slot moved");
static_assert(offsetof(ProxySQL_PluginServices, destroy_managed_prepared_runtime) ==
	offsetof(ManagedConfigurationAbi16, destroy_managed_prepared_runtime),
	"ABI-16 destroy_managed_prepared_runtime slot moved");
static_assert(offsetof(ProxySQL_PluginServices, validate_listener_interfaces) ==
	sizeof(ManagedConfigurationAbi16),
	"ABI-17 listener validation must follow the complete frozen ABI-16 prefix");

// Complete frozen ABI-17 service prefix: the whole frozen ABI-16 prefix plus
// the listener-validation callback.  ABI-18 appends its raw-backend getter
// strictly after this object, so an earlier field resize/move is detected
// without relying only on the current struct's final-member end.
struct ListenerValidationAbi17 {
	ManagedConfigurationAbi16 managed_configuration;
	decltype(ProxySQL_PluginServices::validate_listener_interfaces) validate_listener_interfaces;
};

static_assert(sizeof(ListenerValidationAbi17::validate_listener_interfaces) ==
	sizeof(bool (*)(const char*, const char*, std::string&)),
	"ABI-17 listener validation slot must stay one function pointer");
static_assert(offsetof(ProxySQL_PluginServices, validate_listener_interfaces) ==
	offsetof(ListenerValidationAbi17, validate_listener_interfaces),
	"ABI-17 listener validation slot moved inside the frozen prefix");
static_assert(offsetof(ProxySQL_PluginServices, get_raw_backend_service) ==
	sizeof(ListenerValidationAbi17),
	"ABI-18 raw backend getter must follow the complete frozen ABI-17 prefix");
static_assert(offsetof(ProxySQL_PluginServices, get_raw_backend_service) ==
	offsetof(ProxySQL_PluginServices, validate_listener_interfaces) +
		sizeof(ProxySQL_PluginServices::validate_listener_interfaces),
	"ABI-18 raw backend getter must be the single pointer immediately after listener validation");
static_assert(std::is_same<decltype(ProxySQL_RawBackendServiceV2::destroy),
	bool (*)(ProxySQL_RawBackend*) noexcept>::value,
	"V2 destroy must return the final HARD bool from its noexcept callback");
static_assert(std::is_same<decltype(ProxySQL_RawBackendServiceV2::version), uint32_t>::value,
	"V2 service version must remain a uint32_t");
static_assert(std::is_same<decltype(ProxySQL_PluginServices::get_raw_backend_service),
	const ProxySQL_RawBackendServiceV2* (*)()>::value,
	"ABI-18 raw backend getter must return the frozen V2 service pointer");
} // namespace plugin_services_abi_layout_test
#endif
