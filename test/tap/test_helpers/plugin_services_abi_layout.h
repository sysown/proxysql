#ifndef PROXYSQL_PLUGIN_SERVICES_ABI_LAYOUT_TEST_H
#define PROXYSQL_PLUGIN_SERVICES_ABI_LAYOUT_TEST_H

#include "ProxySQL_Plugin.h"
#include <cstddef>

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
} // namespace plugin_services_abi_layout_test
#endif
