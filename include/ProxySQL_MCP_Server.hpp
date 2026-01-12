#ifndef CLASS_PROXYSQL_MCP_SERVER_H
#define CLASS_PROXYSQL_MCP_SERVER_H

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
 * This class wraps an HTTPS server using libhttpserver to provide
 * MCP (Model Context Protocol) endpoints. It supports multiple
 * MCP server endpoints with their own authentication.
 */
class ProxySQL_MCP_Server {
private:
	std::unique_ptr<httpserver::webserver> ws;
	int port;
	pthread_t thread_id;

	// Endpoint resources
	std::vector<std::pair<std::string, std::unique_ptr<httpserver::http_resource>>> _endpoints;

	MCP_Threads_Handler* handler;

public:
	/**
	 * @brief Constructor for ProxySQL_MCP_Server
	 *
	 * Creates a new HTTPS server instance on the specified port.
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
	 * @brief Start the HTTPS server
	 *
	 * Starts the webserver in a dedicated thread.
	 */
	void start();

	/**
	 * @brief Stop the HTTPS server
	 *
	 * Stops the webserver and waits for the thread to complete.
	 */
	void stop();
};

#endif /* CLASS_PROXYSQL_MCP_SERVER_H */
