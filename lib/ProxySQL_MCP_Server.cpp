#ifdef PROXYSQLGENAI

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
#include "Stats_Tool_Handler.h"
#include "AI_Tool_Handler.h"
#include "RAG_Tool_Handler.h"
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
	: port(p), handler(h), thread_id(0), use_ssl(h->variables.mcp_use_ssl)
{
	proxy_info("Creating ProxySQL MCP Server on port %d (SSL: %s)\n",
		port, use_ssl ? "enabled" : "disabled");

	// Create webserver - conditionally use SSL
	if (handler->variables.mcp_use_ssl) {
		// HTTPS mode: Get SSL certificates from ProxySQL
		char* ssl_key = NULL;
		char* ssl_cert = NULL;
		GloVars.get_SSL_pem_mem(&ssl_key, &ssl_cert);

		// Check if SSL certificates are available
		if (!ssl_key || !ssl_cert) {
			proxy_error("Cannot start MCP server in SSL mode: SSL certificates not loaded. "
				"Please configure ssl_key_fp and ssl_cert_fp, or set mcp_use_ssl=false.\n");
			return;
		}

		// Create HTTPS webserver using ProxySQL TLS certificates
		ws = std::unique_ptr<httpserver::webserver>(new webserver(
			create_webserver(port)
				.use_ssl()
				.raw_https_mem_key(std::string(ssl_key))
				.raw_https_mem_cert(std::string(ssl_cert))
				.no_post_process()
		));
		proxy_info("MCP server configured for HTTPS\n");
	} else {
		// HTTP mode: No SSL certificates required
		ws = std::unique_ptr<httpserver::webserver>(new webserver(
			create_webserver(port)
				.no_ssl()  // Explicitly disable SSL
				.no_post_process()
		));
		proxy_info("MCP server configured for HTTP (unencrypted)\n");
	}

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

	// Hardcode catalog path to datadir/mcp_catalog.db for stability
	std::string catalog_path = std::string(GloVars.datadir) + "/mcp_catalog.db";

	handler->query_tool_handler = new Query_Tool_Handler(
		catalog_path.c_str()
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

	// 5. Stats Tool Handler
	handler->stats_tool_handler = new Stats_Tool_Handler(handler);
	if (handler->stats_tool_handler->init() == 0) {
		proxy_info("Stats Tool Handler initialized\n");
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

	std::unique_ptr<httpserver::http_resource> stats_resource =
		std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->stats_tool_handler, "stats"));
	ws->register_resource("/mcp/stats", stats_resource.get(), true);
	_endpoints.push_back({"/mcp/stats", std::move(stats_resource)});

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

	// 7. RAG endpoint (for Retrieval-Augmented Generation)
	extern AI_Features_Manager *GloAI;
	if (GloAI) {
		// Use same catalog path as query_tool_handler for logging
		std::string catalog_path = std::string(GloVars.datadir) + "/mcp_catalog.db";
		handler->rag_tool_handler = new RAG_Tool_Handler(GloAI, catalog_path);
		if (handler->rag_tool_handler->init() == 0) {
			std::unique_ptr<httpserver::http_resource> rag_resource =
				std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(handler, handler->rag_tool_handler, "rag"));
			ws->register_resource("/mcp/rag", rag_resource.get(), true);
			_endpoints.push_back({"/mcp/rag", std::move(rag_resource)});
			proxy_info("RAG Tool Handler initialized\n");
		} else {
			proxy_error("Failed to initialize RAG Tool Handler\n");
			delete handler->rag_tool_handler;
			handler->rag_tool_handler = NULL;
		}
	} else {
		proxy_warning("AI_Features_Manager not available, RAG Tool Handler not initialized\n");
		handler->rag_tool_handler = NULL;
	}

	int endpoint_count = (handler->ai_tool_handler ? 1 : 0) + (handler->rag_tool_handler ? 1 : 0) + 5;
	std::string endpoints_list = "/mcp/config, /mcp/stats, /mcp/query, /mcp/admin, /mcp/cache";
	if (handler->ai_tool_handler) {
		endpoints_list += ", /mcp/ai";
	}
	if (handler->rag_tool_handler) {
		endpoints_list += ", /mcp/rag";
	}
	proxy_info("Registered %d MCP endpoints with dedicated tool handlers: %s\n",
	          endpoint_count, endpoints_list.c_str());
}

ProxySQL_MCP_Server::~ProxySQL_MCP_Server() {
	stop();

	// Clean up all tool handlers stored in the handler object
	if (handler) {

		// Clean up MySQL Tool Handler
		if (handler->mysql_tool_handler) {
			proxy_info("Cleaning up MySQL Tool Handler...\n");
			delete handler->mysql_tool_handler;
			handler->mysql_tool_handler = NULL;
		}

		// Clean up Config Tool Handler
		if (handler->config_tool_handler) {
			proxy_info("Cleaning up Config Tool Handler...\n");
			delete handler->config_tool_handler;
			handler->config_tool_handler = NULL;
		}

		// Clean up Query Tool Handler
		if (handler->query_tool_handler) {
			proxy_info("Cleaning up Query Tool Handler...\n");
			delete handler->query_tool_handler;
			handler->query_tool_handler = NULL;
		}

		// Clean up Admin Tool Handler
		if (handler->admin_tool_handler) {
			proxy_info("Cleaning up Admin Tool Handler...\n");
			delete handler->admin_tool_handler;
			handler->admin_tool_handler = NULL;
		}

		// Clean up Cache Tool Handler
		if (handler->cache_tool_handler) {
			proxy_info("Cleaning up Cache Tool Handler...\n");
			delete handler->cache_tool_handler;
			handler->cache_tool_handler = NULL;
		}

		// Clean up Stats Tool Handler
		if (handler->stats_tool_handler) {
			proxy_info("Cleaning up Stats Tool Handler...\n");
			delete handler->stats_tool_handler;
			handler->stats_tool_handler = NULL;
		}

		// Clean up AI Tool Handler (uses shared components, don't delete them)
		if (handler->ai_tool_handler) {
			proxy_info("Cleaning up AI Tool Handler...\n");
			delete handler->ai_tool_handler;
			handler->ai_tool_handler = NULL;
		}

		// Clean up RAG Tool Handler
		if (handler->rag_tool_handler) {
			proxy_info("Cleaning up RAG Tool Handler...\n");
			delete handler->rag_tool_handler;
			handler->rag_tool_handler = NULL;
		}
	}
}

void ProxySQL_MCP_Server::start() {
	if (!ws) {
		proxy_error("Cannot start MCP server: webserver not initialized\n");
		return;
	}

	const char* mode = handler->variables.mcp_use_ssl ? "HTTPS" : "HTTP";
	proxy_info("Starting MCP %s server on port %d\n", mode, port);

	// Start the server in a dedicated thread
	if (pthread_create(&thread_id, NULL, mcp_server_thread, ws.get()) != 0) {
		proxy_error("Failed to create MCP server thread: %s\n", strerror(errno));
		return;
	}

	proxy_info("MCP %s server started successfully\n", mode);
}

void ProxySQL_MCP_Server::stop() {
	if (ws) {
		const char* mode = handler->variables.mcp_use_ssl ? "HTTPS" : "HTTP";
		proxy_info("Stopping MCP %s server\n", mode);
		ws->stop();

		if (thread_id) {
			pthread_join(thread_id, NULL);
			thread_id = 0;
		}

		proxy_info("MCP %s server stopped\n", mode);
	}
}

#endif /* PROXYSQLGENAI */
