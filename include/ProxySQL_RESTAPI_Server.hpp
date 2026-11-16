#ifndef CLASS_PROXYSQL_RESTAPI_SERVER_H
#define CLASS_PROXYSQL_RESTAPI_SERVER_H
#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <memory>
#include <functional>
#include <sys/socket.h>
#include <sys/types.h>

#include "httpserver.hpp"

/**
 * @brief Runtime configuration for the REST API / Prometheus listener.
 *
 * The PEM strings are read only during listener construction; libhttpserver
 * copies them into its own configuration and the server does not retain this
 * structure. They are copied from ProxySQL's global TLS material at
 * (re)configuration time; the caller must free any temporary buffers returned
 * by GloVars.get_SSL_pem_mem().
 */
struct ProxySQL_RESTAPI_Config {
	int port { 6070 };
	/**
	 * @brief Empty = bind all interfaces (historical behavior). Otherwise an
	 * IPv4/IPv6 numeric address, or an absolute Unix socket path (optionally
	 * prefixed with "unix:"). Unix socket parents must be owned by root or the
	 * effective user and must restrict group/other writes unless sticky.
	 */
	std::string interface_name {};
	bool use_ssl { false };
	bool verify_client { false };
	std::string ssl_key_pem {};
	std::string ssl_cert_pem {};
	std::string ssl_ca_pem {};
};

/**
 * @brief Parse an admin-restapi_interface value into a bind address.
 *
 * Unix parsing checks the supplied pathname length without inspecting the
 * filesystem. Startup also checks the canonical path and, on Linux, the
 * effective /proc/self/fd/<dirfd>/<leaf> length after opening the parent FD.
 * A path accepted here can therefore still fail listener startup.
 *
 * @param interface_name Value of admin-restapi_interface.
 * @param port TCP port (0..65535) for the IPv4/IPv6 sockaddr (ignored for Unix).
 * @param has_bind_address Set true when addr/addr_len must be passed to
 *        libhttpserver; false for the historical "all interfaces" default.
 * @param addr Filled for IPv4/IPv6 addresses.
 * @param addr_len Filled with the sockaddr length.
 * @param unix_socket_path Filled for Unix socket paths.
 * @param error Human-readable error on failure.
 * @return true on success, false for malformed/invalid input.
 */
bool ProxySQL_RESTAPI_parse_bind_address(
	const std::string& interface_name,
	int port,
	bool& has_bind_address,
	struct sockaddr_storage& addr,
	socklen_t& addr_len,
	std::string& unix_socket_path,
	std::string& error
);

class ProxySQL_RESTAPI_Server {
	private:
	std::unique_ptr<httpserver::webserver> ws;
	int port;
	struct sockaddr_storage bind_addr {};
	socklen_t bind_addr_len { 0 };
	bool has_bind_address { false };
	/**
	 * @brief Canonical Unix socket path and pinned parent directory.
	 *
	 * Unix listeners require the immediate parent to be owned by root or the
	 * effective UID and non-writable by group/other unless sticky.
	 * The parent FD is opened once, before startup, so validation and cleanup
	 * cannot be redirected by renaming or replacing the parent path. On Linux
	 * that ancestor protection applies only after the parent has been opened
	 * and pinned: canonical resolution and opening of the immediate parent
	 * occur before it starts. The listener then binds through
	 * /proc/self/fd/<dir_fd>/<leaf>, so socket creation stays in the pinned
	 * directory and shared ancestors remain supported. On other platforms every
	 * canonical ancestor must meet the same ownership/write policy before
	 * canonical binding; untrusted UIDs cannot replace a validated ancestor,
	 * but trusted root/effective-user filesystem changes remain outside this
	 * threat model. Post-bind ownership verification still applies on every
	 * platform.
	 */
	std::string unix_socket_path {};
	std::string unix_socket_leaf {};
	int unix_socket_dir_fd { -1 };
	bool unix_socket_path_owned { false };
	dev_t unix_socket_dev { 0 };
	ino_t unix_socket_ino { 0 };
	void prepare_unix_socket();
	bool capture_unix_socket_ownership();
	std::unique_ptr<httpserver::http_resource> endpoint;
	std::unique_ptr<httpserver::http_resource> tsdb_endpoint;
	std::unique_ptr<httpserver::http_resource> tsdb_dashboard_endpoint;
	std::unique_ptr<httpserver::http_resource> tsdb_chart_js_endpoint;
	std::vector<std::pair<std::string, std::unique_ptr<httpserver::http_resource>>> _endpoints {};
	void cleanup_unix_socket();
	public:
	ProxySQL_RESTAPI_Server(
		int p,
		std::vector<
			std::pair<
				std::string,
				std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>
		> endpoints =
			std::vector<
				std::pair<
					std::string,
					std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>> {}
	);
	/**
	 * @brief Construct a listener from an explicit REST API configuration.
	 *
	 * Validates bind-address, TLS material and fail-closed combinations before
	 * creating any listener artifact. The configuration is consumed only for
	 * construction; libhttpserver copies the PEM strings it needs.
	 *
	 * @param config Listener port, interface, TLS and client-verification settings.
	 * @param endpoints Custom GET routes to register before the listener starts.
	 */
	ProxySQL_RESTAPI_Server(
		const ProxySQL_RESTAPI_Config& config,
		std::vector<
			std::pair<
				std::string,
				std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>
		> endpoints =
			std::vector<
				std::pair<
					std::string,
					std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>>> {}
	);
	~ProxySQL_RESTAPI_Server();
	void init();
	void print_version();
	/**
	 * @brief Report whether the listener was successfully started.
	 *
	 * @return true when the underlying webserver exists and reports running.
	 */
	bool is_running() const;
};
#endif /* CLASS_PROXYSQL_RESTAPI_SERVER */
