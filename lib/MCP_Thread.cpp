#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "Config_Tool_Handler.h"
#include "Query_Tool_Handler.h"
#include "Admin_Tool_Handler.h"
#include "Cache_Tool_Handler.h"
#include "Observe_Tool_Handler.h"
#include "proxysql_debug.h"
#include "ProxySQL_MCP_Server.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>

// Define the array of variable names for the MCP module
static const char* mcp_thread_variables_names[] = {
	"enabled",
	"port",
	"config_endpoint_auth",
	"observe_endpoint_auth",
	"query_endpoint_auth",
	"admin_endpoint_auth",
	"cache_endpoint_auth",
	"timeout_ms",
	// MySQL Tool Handler configuration
	"mysql_hosts",
	"mysql_ports",
	"mysql_user",
	"mysql_password",
	"mysql_schema",
	"catalog_path",
	NULL
};

MCP_Threads_Handler::MCP_Threads_Handler() {
	shutdown_ = 0;

	// Initialize the rwlock
	pthread_rwlock_init(&rwlock, NULL);

	// Initialize variables with default values
	variables.mcp_enabled = false;
	variables.mcp_port = 6071;
	variables.mcp_config_endpoint_auth = strdup("");
	variables.mcp_observe_endpoint_auth = strdup("");
	variables.mcp_query_endpoint_auth = strdup("");
	variables.mcp_admin_endpoint_auth = strdup("");
	variables.mcp_cache_endpoint_auth = strdup("");
	variables.mcp_timeout_ms = 30000;
	// MySQL Tool Handler default values
	variables.mcp_mysql_hosts = strdup("127.0.0.1");
	variables.mcp_mysql_ports = strdup("3306");
	variables.mcp_mysql_user = strdup("");
	variables.mcp_mysql_password = strdup("");
	variables.mcp_mysql_schema = strdup("");
	variables.mcp_catalog_path = strdup("mcp_catalog.db");

	status_variables.total_requests = 0;
	status_variables.failed_requests = 0;
	status_variables.active_connections = 0;

	mcp_server = NULL;
	mysql_tool_handler = NULL;

	// Initialize new tool handlers
	config_tool_handler = NULL;
	query_tool_handler = NULL;
	admin_tool_handler = NULL;
	cache_tool_handler = NULL;
	observe_tool_handler = NULL;
}

MCP_Threads_Handler::~MCP_Threads_Handler() {
	if (variables.mcp_config_endpoint_auth)
		free(variables.mcp_config_endpoint_auth);
	if (variables.mcp_observe_endpoint_auth)
		free(variables.mcp_observe_endpoint_auth);
	if (variables.mcp_query_endpoint_auth)
		free(variables.mcp_query_endpoint_auth);
	if (variables.mcp_admin_endpoint_auth)
		free(variables.mcp_admin_endpoint_auth);
	if (variables.mcp_cache_endpoint_auth)
		free(variables.mcp_cache_endpoint_auth);
	// Free MySQL Tool Handler variables
	if (variables.mcp_mysql_hosts)
		free(variables.mcp_mysql_hosts);
	if (variables.mcp_mysql_ports)
		free(variables.mcp_mysql_ports);
	if (variables.mcp_mysql_user)
		free(variables.mcp_mysql_user);
	if (variables.mcp_mysql_password)
		free(variables.mcp_mysql_password);
	if (variables.mcp_mysql_schema)
		free(variables.mcp_mysql_schema);
	if (variables.mcp_catalog_path)
		free(variables.mcp_catalog_path);

	if (mcp_server) {
		delete mcp_server;
		mcp_server = NULL;
	}

	if (mysql_tool_handler) {
		delete mysql_tool_handler;
		mysql_tool_handler = NULL;
	}

	// Clean up new tool handlers
	if (config_tool_handler) {
		delete config_tool_handler;
		config_tool_handler = NULL;
	}
	if (query_tool_handler) {
		delete query_tool_handler;
		query_tool_handler = NULL;
	}
	if (admin_tool_handler) {
		delete admin_tool_handler;
		admin_tool_handler = NULL;
	}
	if (cache_tool_handler) {
		delete cache_tool_handler;
		cache_tool_handler = NULL;
	}
	if (observe_tool_handler) {
		delete observe_tool_handler;
		observe_tool_handler = NULL;
	}

	// Destroy the rwlock
	pthread_rwlock_destroy(&rwlock);
}

void MCP_Threads_Handler::init() {
	proxy_info("Initializing MCP Threads Handler\n");
	// For now, this is a simple initialization
	// The HTTPS server will be started when mcp_enabled is set to true
	// and will be managed through ProxySQL_Admin
	print_version();
}

void MCP_Threads_Handler::shutdown() {
	proxy_info("Shutting down MCP Threads Handler\n");
	shutdown_ = 1;

	// Stop the HTTPS server if it's running
	if (mcp_server) {
		delete mcp_server;
		mcp_server = NULL;
	}
}

void MCP_Threads_Handler::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void MCP_Threads_Handler::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

int MCP_Threads_Handler::get_variable(const char* name, char* val) {
	if (!name || !val)
		return -1;

	if (!strcmp(name, "enabled")) {
		sprintf(val, "%s", variables.mcp_enabled ? "true" : "false");
		return 0;
	}
	if (!strcmp(name, "port")) {
		sprintf(val, "%d", variables.mcp_port);
		return 0;
	}
	if (!strcmp(name, "config_endpoint_auth")) {
		sprintf(val, "%s", variables.mcp_config_endpoint_auth ? variables.mcp_config_endpoint_auth : "");
		return 0;
	}
	if (!strcmp(name, "observe_endpoint_auth")) {
		sprintf(val, "%s", variables.mcp_observe_endpoint_auth ? variables.mcp_observe_endpoint_auth : "");
		return 0;
	}
	if (!strcmp(name, "query_endpoint_auth")) {
		sprintf(val, "%s", variables.mcp_query_endpoint_auth ? variables.mcp_query_endpoint_auth : "");
		return 0;
	}
	if (!strcmp(name, "admin_endpoint_auth")) {
		sprintf(val, "%s", variables.mcp_admin_endpoint_auth ? variables.mcp_admin_endpoint_auth : "");
		return 0;
	}
	if (!strcmp(name, "cache_endpoint_auth")) {
		sprintf(val, "%s", variables.mcp_cache_endpoint_auth ? variables.mcp_cache_endpoint_auth : "");
		return 0;
	}
	if (!strcmp(name, "timeout_ms")) {
		sprintf(val, "%d", variables.mcp_timeout_ms);
		return 0;
	}
	// MySQL Tool Handler configuration
	if (!strcmp(name, "mysql_hosts")) {
		sprintf(val, "%s", variables.mcp_mysql_hosts ? variables.mcp_mysql_hosts : "");
		return 0;
	}
	if (!strcmp(name, "mysql_ports")) {
		sprintf(val, "%s", variables.mcp_mysql_ports ? variables.mcp_mysql_ports : "");
		return 0;
	}
	if (!strcmp(name, "mysql_user")) {
		sprintf(val, "%s", variables.mcp_mysql_user ? variables.mcp_mysql_user : "");
		return 0;
	}
	if (!strcmp(name, "mysql_password")) {
		sprintf(val, "%s", variables.mcp_mysql_password ? variables.mcp_mysql_password : "");
		return 0;
	}
	if (!strcmp(name, "mysql_schema")) {
		sprintf(val, "%s", variables.mcp_mysql_schema ? variables.mcp_mysql_schema : "");
		return 0;
	}
	if (!strcmp(name, "catalog_path")) {
		sprintf(val, "%s", variables.mcp_catalog_path ? variables.mcp_catalog_path : "");
		return 0;
	}

	return -1;
}

int MCP_Threads_Handler::set_variable(const char* name, const char* value) {
	if (!name || !value)
		return -1;

	if (!strcmp(name, "enabled")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.mcp_enabled = true;
			return 0;
		}
		if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.mcp_enabled = false;
			return 0;
		}
		return -1;
	}
	if (!strcmp(name, "port")) {
		int port = atoi(value);
		if (port > 0 && port < 65536) {
			variables.mcp_port = port;
			return 0;
		}
		return -1;
	}
	if (!strcmp(name, "config_endpoint_auth")) {
		if (variables.mcp_config_endpoint_auth)
			free(variables.mcp_config_endpoint_auth);
		variables.mcp_config_endpoint_auth = strdup(value);
		return 0;
	}
	if (!strcmp(name, "observe_endpoint_auth")) {
		if (variables.mcp_observe_endpoint_auth)
			free(variables.mcp_observe_endpoint_auth);
		variables.mcp_observe_endpoint_auth = strdup(value);
		return 0;
	}
	if (!strcmp(name, "query_endpoint_auth")) {
		if (variables.mcp_query_endpoint_auth)
			free(variables.mcp_query_endpoint_auth);
		variables.mcp_query_endpoint_auth = strdup(value);
		return 0;
	}
	if (!strcmp(name, "admin_endpoint_auth")) {
		if (variables.mcp_admin_endpoint_auth)
			free(variables.mcp_admin_endpoint_auth);
		variables.mcp_admin_endpoint_auth = strdup(value);
		return 0;
	}
	if (!strcmp(name, "cache_endpoint_auth")) {
		if (variables.mcp_cache_endpoint_auth)
			free(variables.mcp_cache_endpoint_auth);
		variables.mcp_cache_endpoint_auth = strdup(value);
		return 0;
	}
	if (!strcmp(name, "timeout_ms")) {
		int timeout = atoi(value);
		if (timeout >= 0) {
			variables.mcp_timeout_ms = timeout;
			return 0;
		}
		return -1;
	}
	// MySQL Tool Handler configuration
	if (!strcmp(name, "mysql_hosts")) {
		if (variables.mcp_mysql_hosts)
			free(variables.mcp_mysql_hosts);
		variables.mcp_mysql_hosts = strdup(value);
		return 0;
	}
	if (!strcmp(name, "mysql_ports")) {
		if (variables.mcp_mysql_ports)
			free(variables.mcp_mysql_ports);
		variables.mcp_mysql_ports = strdup(value);
		return 0;
	}
	if (!strcmp(name, "mysql_user")) {
		if (variables.mcp_mysql_user)
			free(variables.mcp_mysql_user);
		variables.mcp_mysql_user = strdup(value);
		return 0;
	}
	if (!strcmp(name, "mysql_password")) {
		if (variables.mcp_mysql_password)
			free(variables.mcp_mysql_password);
		variables.mcp_mysql_password = strdup(value);
		return 0;
	}
	if (!strcmp(name, "mysql_schema")) {
		if (variables.mcp_mysql_schema)
			free(variables.mcp_mysql_schema);
		variables.mcp_mysql_schema = strdup(value);
		return 0;
	}
	if (!strcmp(name, "catalog_path")) {
		if (variables.mcp_catalog_path)
			free(variables.mcp_catalog_path);
		variables.mcp_catalog_path = strdup(value);
		return 0;
	}

	return -1;
}

bool MCP_Threads_Handler::has_variable(const char* name) {
	if (!name)
		return false;

	for (int i = 0; mcp_thread_variables_names[i]; i++) {
		if (!strcmp(name, mcp_thread_variables_names[i])) {
			return true;
		}
	}
	return false;
}

char** MCP_Threads_Handler::get_variables_list() {
	// Count variables
	int count = 0;
	while (mcp_thread_variables_names[count]) {
		count++;
	}

	// Allocate array
	char** list = (char**)malloc(sizeof(char*) * (count + 1));
	if (!list)
		return NULL;

	// Fill array
	for (int i = 0; i < count; i++) {
		list[i] = strdup(mcp_thread_variables_names[i]);
	}
	list[count] = NULL;

	return list;
}

void MCP_Threads_Handler::print_version() {
	fprintf(stderr, "MCP Threads Handler rev. %s -- %s -- %s\n", MCP_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}
