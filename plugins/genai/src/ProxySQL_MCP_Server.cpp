#ifdef PROXYSQL40

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
// AI_Tool_Handler / RAG_Tool_Handler are now plugin-side (Step 5).
// Their endpoint registrations re-enabled below.
#include "AI_Tool_Handler.h"
#include "RAG_Tool_Handler.h"
#include "AI_Features_Manager.h"
#include "genai_plugin.h"
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
	: port(p), use_ssl(h->variables.mcp_use_ssl), thread_id(0), handler(h)
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
	} else {
		proxy_error("Failed to initialize Admin Tool Handler\n");
		delete handler->admin_tool_handler;
		handler->admin_tool_handler = NULL;
	}

	// 4. Cache Tool Handler
	handler->cache_tool_handler = new Cache_Tool_Handler(handler);
	if (handler->cache_tool_handler->init() == 0) {
		proxy_info("Cache Tool Handler initialized\n");
	} else {
		proxy_error("Failed to initialize Cache Tool Handler\n");
		delete handler->cache_tool_handler;
		handler->cache_tool_handler = NULL;
	}

	// 5. Stats Tool Handler
	handler->stats_tool_handler = new Stats_Tool_Handler(handler);
	if (handler->stats_tool_handler->init() == 0) {
		proxy_info("Stats Tool Handler initialized\n");
	} else {
		proxy_error("Failed to initialize Stats Tool Handler\n");
		delete handler->stats_tool_handler;
		handler->stats_tool_handler = NULL;
	}

	// 6. AI Tool Handler (for LLM and other AI features).  After
	// Step 5 the AI_Tool_Handler class lives in the plugin alongside
	// AI_Features_Manager / LLM_Bridge, so this construction is
	// once again the plugin's responsibility.
	extern AI_Features_Manager *GloAI;
	if (GloAI) {
		handler->ai_tool_handler = new AI_Tool_Handler(GloAI->get_llm_bridge());
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
	auto register_endpoint = [&](const std::string& uri, MCP_Tool_Handler* tool, const std::string& name) {
		if (!tool) {
			proxy_warning("Skipping MCP endpoint %s: %s Tool Handler not initialized\n", uri.c_str(), name.c_str());
			return;
		}
		std::unique_ptr<httpserver::http_resource> resource(
			new MCP_JSONRPC_Resource(handler, tool, name)
		);
		ws->register_resource(uri, resource.get(), true);
		_endpoints.push_back({uri, std::move(resource)});
	};

	register_endpoint("/mcp/config", handler->config_tool_handler, "config");
	register_endpoint("/mcp/stats", handler->stats_tool_handler, "stats");
	register_endpoint("/mcp/query", handler->query_tool_handler, "query");
	register_endpoint("/mcp/admin", handler->admin_tool_handler, "admin");
	register_endpoint("/mcp/cache", handler->cache_tool_handler, "cache");

	// 6. AI endpoint (for LLM and other AI features).
	if (handler->ai_tool_handler) {
		std::unique_ptr<httpserver::http_resource> ai_resource =
			std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(
				handler, handler->ai_tool_handler, "ai",
				&genai_context().runtime_dependencies_mutex));
		ws->register_resource("/mcp/ai", ai_resource.get(), true);
		_endpoints.push_back({"/mcp/ai", std::move(ai_resource)});
	}

	// 7. RAG endpoint (Retrieval-Augmented Generation).  Step 5
	// pulled RAG_Tool_Handler in alongside AI_Features_Manager (it
	// shares LLM_Bridge), so this construction is now plugin-owned.
	if (GloAI) {
		std::string catalog_path = std::string(GloVars.datadir) + "/mcp_catalog.db";
		handler->rag_tool_handler = new RAG_Tool_Handler(GloAI, catalog_path);
		if (handler->rag_tool_handler->init() == 0) {
			std::unique_ptr<httpserver::http_resource> rag_resource =
				std::unique_ptr<httpserver::http_resource>(new MCP_JSONRPC_Resource(
					handler, handler->rag_tool_handler, "rag",
					&genai_context().runtime_dependencies_mutex));
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

	std::string endpoints_list;
	for (size_t i = 0; i < _endpoints.size(); i++) {
		if (i > 0) {
			endpoints_list += ", ";
		}
		endpoints_list += _endpoints[i].first;
	}
	proxy_info("Registered %zu MCP endpoints with dedicated tool handlers: %s\n",
		_endpoints.size(), endpoints_list.empty() ? "(none)" : endpoints_list.c_str());
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

bool ProxySQL_MCP_Server::start() {
	if (!ws) {
		proxy_error("Cannot start MCP server: webserver not initialized\n");
		return false;
	}

	const char* mode = handler->variables.mcp_use_ssl ? "HTTPS" : "HTTP";
	proxy_info("Starting MCP %s server on port %d\n", mode, port);

	// Start the server in a dedicated thread
	if (pthread_create(&thread_id, NULL, mcp_server_thread, ws.get()) != 0) {
		proxy_error("Failed to create MCP server thread: %s\n", strerror(errno));
		return false;
	}

	proxy_info("MCP %s server started successfully\n", mode);
	return true;
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

#endif /* PROXYSQL40 */
