#include "mysql_router_plugin.h"

#include <json.hpp>

const char* mysql_router_status_json() {
	MysqlRouterContext& context = mysql_router_context();
	thread_local std::string serialized;
	std::lock_guard<std::mutex> guard(context.status_mutex);
	serialized = nlohmann::json {
		{"plugin", "mysql_router"},
		{"state", context.status.state},
		{"topology_type", context.status.topology_type},
		{"topology_uuid", context.status.topology_uuid},
		{"metadata_version", context.status.metadata_version},
		{"advertised_contract", context.status.advertised_contract},
		{"router_id", context.status.router_id},
		{"router_label", context.status.router_label},
		{"managed_hostgroups", context.status.managed_hostgroups},
		{"metadata_available", context.status.metadata_available},
		{"registration_exists", context.status.registration_exists},
		{"gates_ready", context.status.gates_ready},
		{"unsupported_router_options", context.status.unsupported_router_options},
		{"topology_generation", context.status.topology_generation},
		{"user_generation", context.status.user_generation},
		{"topology_last_success", context.status.topology_last_success},
		{"user_last_success", context.status.user_last_success},
		{"metadata_last_success", context.status.metadata_last_success},
		{"stale_seconds", context.status.stale_seconds},
		{"user_collisions", context.status.user_collisions},
		{"unsupported_auth_plugins", context.status.unsupported_auth_plugins},
		{"last_error", context.status.last_error},
	}.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
	return serialized.c_str();
}
