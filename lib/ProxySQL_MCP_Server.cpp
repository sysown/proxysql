#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "ProxySQL_MCP_Server.hpp"
#include "MCP_Endpoint.h"
#include "MCP_Thread.h"
#include "MySQL_Tool_Handler.h"
#include "MCP_Tool_Handler.h"
#include "Config_Tool_Handler.h"
#include "Query_Tool_Handler.h"
#include "Admin_Tool_Handler.h"
#include "Cache_Tool_Handler.h"
#include "Observe_Tool_Handler.h"
#include "AI_Tool_Handler.h"
#include "AI_Features_Manager.h"
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

	// Initialize tool handlers for each endpoint
	proxy_info("Initializing MCP tool handlers...\n");

	// 1. Config Tool Handler
	handler->config_tool_handler = new Config_Tool_Handler(handler);
	if (handler->config_tool_handler->init() == 0) {
		proxy_info("Config Tool Handler initialized\n");
	} else {
		proxy_error("Failed to initialize Config Tool Handler\n");
		delete handler->config_tool_handler;
		handler->config_tool_handler = NULL;
	}

	// 2. Query Tool Handler (uses Discovery_Schema directly for two-phase discovery)
	proxy_info("Initializing Query Tool Handler...\n");
	handler->query_tool_handler = new Query_Tool_Handler(
		handler->variables.mcp_mysql_hosts ? handler->variables.mcp_mysql_hosts : "",
		handler->variables.mcp_mysql_ports ? handler->variables.mcp_mysql_ports : "",
		handler->variables.mcp_mysql_user ? handler->variables.mcp_mysql_user : "",
		handler->variables.mcp_mysql_password ? handler->variables.mcp_mysql_password : "",
		handler->variables.mcp_mysql_schema ? handler->variables.mcp_mysql_schema : "",
		handler->variables.mcp_catalog_path ? handler->variables.mcp_catalog_path : "/var/lib/proxysql/discovery_catalog.db"
	);
	if (handler->query_tool_handler->init() == 0) {
		proxy_info("Query Tool Handler initialized successfully\n");
	} else {
		proxy_error("Failed to initialize Query Tool Handler\n");
		delete handler->query_tool_handler;
		handler->query_tool_handler = NULL;
	}

	// 3. Admin Tool Handler
	handler->admin_tool_handler = new Admin_Tool_Handler(handler);
	if (handler->admin_tool_handler->init() == 0) {
		proxy_info("Admin Tool Handler initialized\n");
	}

	// 4. Cache Tool Handler
	handler->cache_tool_handler = new Cache_Tool_Handler(handler);
	if (handler->cache_tool_handler->init() == 0) {
		proxy_info("Cache Tool Handler initialized\n");
	}

	// 5. Observe Tool Handler
	handler->observe_tool_handler = new Observe_Tool_Handler(handler);
	if (handler->observe_tool_handler->init() == 0) {
		proxy_info("Observe Tool Handler initialized\n");
	}

	// 6. AI Tool Handler (for LLM and other AI features)
	extern AI_Features_Manager *GloAI;
	if (GloAI) {
		handler->ai_tool_handler = new AI_Tool_Handler(GloAI->get_llm_bridge(), GloAI->get_anomaly_detector());
		if (handler->ai_tool_handler->init() == 0) {
			proxy_info("AI Tool Handler initialized\n");
		} else {
			proxy_error("Failed to initialize AI Tool Handler\n");
			delete handler->ai_tool_handler;
			handler->ai_tool_handler = NULL;
		}
	} else {
		proxy_warning("AI_Features_Manager not available, AI Tool Handler not initialized\n");
		handler->ai_tool_handler = NULL;
	}

	// Register MCP endpoints
	// Each endpoint gets its own dedicated tool handler
	std::unique_ptr<httpserver::http_resource> config_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->config_tool_handler, "config"));
	ws->register_resource("/mcp/config", config_resource.get(), true);
	_endpoints.push_back({"/mcp/config", std::move(config_resource)});

	std::unique_ptr<httpserver::http_resource> observe_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->observe_tool_handler, "observe"));
	ws->register_resource("/mcp/observe", observe_resource.get(), true);
	_endpoints.push_back({"/mcp/observe", std::move(observe_resource)});

	std::unique_ptr<httpserver::http_resource> query_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->query_tool_handler, "query"));
	ws->register_resource("/mcp/query", query_resource.get(), true);
	_endpoints.push_back({"/mcp/query", std::move(query_resource)});

	std::unique_ptr<httpserver::http_resource> admin_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->admin_tool_handler, "admin"));
	ws->register_resource("/mcp/admin", admin_resource.get(), true);
	_endpoints.push_back({"/mcp/admin", std::move(admin_resource)});

	std::unique_ptr<httpserver::http_resource> cache_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->cache_tool_handler, "cache"));
	ws->register_resource("/mcp/cache", cache_resource.get(), true);
	_endpoints.push_back({"/mcp/cache", std::move(cache_resource)});

	// 6. AI endpoint (for LLM and other AI features)
	if (handler->ai_tool_handler) {
		std::unique_ptr<httpserver::http_resource> ai_resource =
			std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->ai_tool_handler, "ai"));
		ws->register_resource("/mcp/ai", ai_resource.get(), true);
		_endpoints.push_back({"/mcp/ai", std::move(ai_resource)});
	}

	proxy_info("Registered %d MCP endpoints with dedicated tool handlers: /mcp/config, /mcp/observe, /mcp/query, /mcp/admin, /mcp/cache%s/mcp/ai\n",
	          handler->ai_tool_handler ? 6 : 5,
	          handler->ai_tool_handler ? ", " : "");
}

ProxySQL_MCP_Server::~ProxySQL_MCP_Server() {
	stop();

	// Clean up tool handlers
	if (handler) {
		// Clean up AI Tool Handler (uses shared components, don't delete them)
		if (handler->ai_tool_handler) {
			proxy_info("Cleaning up AI Tool Handler...\n");
			delete handler->ai_tool_handler;
			handler->ai_tool_handler = NULL;
		}
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
