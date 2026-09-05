#ifndef CLASS_PROXYSQL_MCP_SERVER_H
#define CLASS_PROXYSQL_MCP_SERVER_H

#ifdef PROXYSQL40

#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <memory>
#include <functional>
#include <vector>

// Forward declaration
class MCP_Threads_Handler;

// Include httpserver after proxysql.h
#include "httpserver.hpp"

/**
 * @brief ProxySQL MCP Server class
 *
 * This class wraps an HTTP/HTTPS server using libhttpserver to provide
 * MCP (Model Context Protocol) endpoints. Supports both HTTP and HTTPS
 * modes based on mcp_use_ssl configuration. It supports multiple
 * MCP server endpoints with their own authentication.
 */
class ProxySQL_MCP_Server {
private:
	std::unique_ptr<httpserver::webserver> ws;
	int port;
	bool use_ssl;  // SSL mode the server was started with
	pthread_t thread_id;

	// Endpoint resources
	std::vector<std::pair<std::string, std::unique_ptr<httpserver::http_resource>>> _endpoints;

	MCP_Threads_Handler* handler;

public:
	/**
	 * @brief Constructor for ProxySQL_MCP_Server
	 *
	 * Creates a new HTTP/HTTPS server instance on the specified port.
	 * Uses HTTPS if mcp_use_ssl is true, otherwise uses HTTP.
	 *
	 * @param p The port number to listen on
	 * @param h Pointer to the MCP_Threads_Handler instance
	 */
	ProxySQL_MCP_Server(int p, MCP_Threads_Handler* h);

	/**
	 * @brief Destructor for ProxySQL_MCP_Server
	 *
	 * Stops the webserver and cleans up resources.
	 */
	~ProxySQL_MCP_Server();

	/**
	 * @brief Start the HTTP/HTTPS server
	 *
	 * Starts the webserver in a dedicated thread.
	 *
	 * @return true if the server thread was created, false otherwise
	 */
	bool start();

	/**
	 * @brief Stop the HTTP/HTTPS server
	 *
	 * Stops the webserver and waits for the thread to complete.
	 */
	void stop();

	/**
	 * @brief Get the port the server is listening on
	 *
	 * @return int The port number
	 */
	int get_port() const { return port; }

	/**
	 * @brief Check if the server is using SSL/TLS
	 *
	 * @return true if server is using HTTPS, false if using HTTP
	 */
	bool is_using_ssl() const { return use_ssl; }
};

#endif /* PROXYSQL40 */

#endif /* CLASS_PROXYSQL_MCP_SERVER_H */
