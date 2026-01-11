#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "ProxySQL_MCP_Server.hpp"
#include "MCP_Endpoint.h"
#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "proxysql_utils.h"

using namespace httpserver;

extern ProxySQL_Admin *GloAdmin;

/**
 * @brief Thread function for the MCP server
 *
 * This function runs in a dedicated thread and starts the webserver.
 *
 * @param arg Pointer to the webserver instance
 * @return NULL
 */
static void *mcp_server_thread(void *arg) {
	set_thread_name("MCP_Server", GloVars.set_thread_name);
	httpserver::webserver * ws = (httpserver::webserver *)arg;
	ws->start(true);
	return NULL;
}

ProxySQL_MCP_Server::ProxySQL_MCP_Server(int p, MCP_Threads_Handler* h)
	: port(p), handler(h), thread_id(0)
{
	proxy_info("Creating ProxySQL MCP Server on port %d\n", port);

	// Get SSL certificates from ProxySQL
	char* ssl_key = NULL;
	char* ssl_cert = NULL;
	GloVars.get_SSL_pem_mem(&ssl_key, &ssl_cert);

	// Check if SSL certificates are available
	if (!ssl_key || !ssl_cert) {
		proxy_error("Cannot start MCP server: SSL certificates not loaded. Please configure ssl_key_fp and ssl_cert_fp.\n");
		return;
	}

	// Create HTTPS webserver using existing ProxySQL TLS certificates
	// Use raw_https_mem_key/raw_https_mem_cert to pass in-memory PEM buffers
	ws = std::unique_ptr<httpserver::webserver>(new webserver(
		create_webserver(port)
			.use_ssl()
			.raw_https_mem_key(std::string(ssl_key))
			.raw_https_mem_cert(std::string(ssl_cert))
			.no_post_process()
	));

	// Register MCP endpoints
	// Each endpoint is a distinct MCP server with its own authentication
	std::unique_ptr<httpserver::http_resource> config_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, "config"));
	ws->register_resource("/mcp/config", config_resource.get(), true);
	_endpoints.push_back({"/mcp/config", std::move(config_resource)});

	std::unique_ptr<httpserver::http_resource> observe_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, "observe"));
	ws->register_resource("/mcp/observe", observe_resource.get(), true);
	_endpoints.push_back({"/mcp/observe", std::move(observe_resource)});

	std::unique_ptr<httpserver::http_resource> query_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, "query"));
	ws->register_resource("/mcp/query", query_resource.get(), true);
	_endpoints.push_back({"/mcp/query", std::move(query_resource)});

	std::unique_ptr<httpserver::http_resource> admin_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, "admin"));
	ws->register_resource("/mcp/admin", admin_resource.get(), true);
	_endpoints.push_back({"/mcp/admin", std::move(admin_resource)});

	std::unique_ptr<httpserver::http_resource> cache_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, "cache"));
	ws->register_resource("/mcp/cache", cache_resource.get(), true);
	_endpoints.push_back({"/mcp/cache", std::move(cache_resource)});

	proxy_info("Registered 5 MCP endpoints: /mcp/config, /mcp/observe, /mcp/query, /mcp/admin, /mcp/cache\n");

	// Initialize MySQL Tool Handler with the configuration from MCP variables
	if (!handler->mysql_tool_handler) {
		proxy_info("Initializing MySQL Tool Handler...\n");
		handler->mysql_tool_handler = new MySQL_Tool_Handler(
			handler->variables.mcp_mysql_hosts ? handler->variables.mcp_mysql_hosts : "",
			handler->variables.mcp_mysql_ports ? handler->variables.mcp_mysql_ports : "",
			handler->variables.mcp_mysql_user ? handler->variables.mcp_mysql_user : "",
			handler->variables.mcp_mysql_password ? handler->variables.mcp_mysql_password : "",
			handler->variables.mcp_mysql_schema ? handler->variables.mcp_mysql_schema : "",
			handler->variables.mcp_catalog_path ? handler->variables.mcp_catalog_path : ""
		);

		// Initialize the tool handler
		if (handler->mysql_tool_handler->init() != 0) {
			proxy_error("Failed to initialize MySQL Tool Handler\n");
			delete handler->mysql_tool_handler;
			handler->mysql_tool_handler = NULL;
		} else {
			proxy_info("MySQL Tool Handler initialized successfully\n");
		}
	}
}

ProxySQL_MCP_Server::~ProxySQL_MCP_Server() {
	stop();

	// Clean up MySQL Tool Handler
	if (handler && handler->mysql_tool_handler) {
		proxy_info("Cleaning up MySQL Tool Handler...\n");
		delete handler->mysql_tool_handler;
		handler->mysql_tool_handler = NULL;
	}
}

void ProxySQL_MCP_Server::start() {
	if (!ws) {
		proxy_error("Cannot start MCP server: webserver not initialized\n");
		return;
	}

	proxy_info("Starting MCP HTTPS server on port %d\n", port);

	// Start the server in a dedicated thread
	if (pthread_create(&thread_id, NULL, mcp_server_thread, ws.get()) != 0) {
		proxy_error("Failed to create MCP server thread: %s\n", strerror(errno));
		return;
	}

	proxy_info("MCP HTTPS server started successfully\n");
}

void ProxySQL_MCP_Server::stop() {
	if (ws) {
		proxy_info("Stopping MCP HTTPS server\n");
		ws->stop();

		if (thread_id) {
			pthread_join(thread_id, NULL);
			thread_id = 0;
		}

		proxy_info("MCP HTTPS server stopped\n");
	}
}
