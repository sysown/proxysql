#include "MCP_Thread.h"
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

	status_variables.total_requests = 0;
	status_variables.failed_requests = 0;
	status_variables.active_connections = 0;

	mcp_server = NULL;
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

	if (mcp_server) {
		delete mcp_server;
		mcp_server = NULL;
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

	return -1;
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
