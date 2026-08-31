#include "mysql_router_plugin.h"

#include <cstdio>

const char* mysql_router_status_json() {
	MysqlRouterContext& context = mysql_router_context();
	thread_local char json[512];
	std::lock_guard<std::mutex> guard(context.status_mutex);
	std::snprintf(json, sizeof(json),
		"{\"plugin\":\"mysql_router\",\"state\":\"%s\","
		"\"topology_generation\":%llu,\"user_generation\":%llu}",
		context.status.state.c_str(),
		static_cast<unsigned long long>(context.status.topology_generation),
		static_cast<unsigned long long>(context.status.user_generation));
	return json;
}
