/**
 * @file restapi_tls_config_unit-t.cpp
 * @brief Unit coverage for admin-restapi_interface bind-address parsing (#6552).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "ProxySQL_RESTAPI_Server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

static bool parse(
	const std::string& value,
	bool& has_bind,
	sockaddr_storage& addr,
	socklen_t& addr_len,
	std::string& socket_path,
	std::string& error
) {
	return ProxySQL_RESTAPI_parse_bind_address(
		value, 6070, has_bind, addr, addr_len, socket_path, error);
}

static bool is_ipv4(const sockaddr_storage& addr, const char* expected) {
	if (addr.ss_family != AF_INET) return false;
	const auto* a = reinterpret_cast<const sockaddr_in*>(&addr);
	char buf[INET_ADDRSTRLEN] {};
	return inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf)) != nullptr &&
		std::string(buf) == expected;
}

static bool is_ipv6(const sockaddr_storage& addr, const char* expected) {
	if (addr.ss_family != AF_INET6) return false;
	const auto* a = reinterpret_cast<const sockaddr_in6*>(&addr);
	char buf[INET6_ADDRSTRLEN] {};
	return inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf)) != nullptr &&
		std::string(buf) == expected;
}

static int find_free_ipv6_port() {
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in6 addr {};
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_loopback;
	addr.sin6_port = 0;
	if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	socklen_t len = sizeof(addr);
	if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
		close(fd);
		return -1;
	}
	const int port = ntohs(addr.sin6_port);
	close(fd);
	return port;
}

static bool ipv6_http_get_ok(int port) {
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) return false;
	struct timeval timeout {};
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_in6 addr {};
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_loopback;
	addr.sin6_port = htons(static_cast<uint16_t>(port));
	if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return false;
	}
	const char request[] = "GET /ping HTTP/1.0\r\nHost: [::1]\r\n\r\n";
	if (send(fd, request, sizeof(request) - 1, 0) != static_cast<ssize_t>(sizeof(request) - 1)) {
		close(fd);
		return false;
	}
	char buffer[512] {};
	const ssize_t received = recv(fd, buffer, sizeof(buffer) - 1, 0);
	close(fd);
	if (received <= 0) return false;
	return strstr(buffer, "200") != nullptr;
}

using restapi_endpoints = std::vector<std::pair<
	std::string,
	std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>
>>;

static restapi_endpoints ping_endpoints() {
	restapi_endpoints endpoints;
	endpoints.push_back({
		"/ping",
		[](const httpserver::http_request&) {
			return std::shared_ptr<httpserver::http_response>(
				new httpserver::string_response("pong", httpserver::http::http_utils::http_ok));
		}
	});
	return endpoints;
}

static std::string read_text_file(const std::string& path) {
	std::ifstream input(path);
	std::ostringstream content;
	content << input.rdbuf();
	return content.str();
}

static bool run_openssl(const std::string& command) {
	return std::system((command + " >/dev/null 2>&1").c_str()) == 0;
}

static bool write_text_file(const std::string& path, const std::string& content) {
	std::ofstream output(path);
	output << content;
	return output.good();
}

// Generate an isolated CA plus server and client identities. The listener
// tests below need real PEM material because the production constructor hands
// it to GnuTLS; hard-coded fixtures would hide key/certificate mismatches.
static bool generate_tls_material(
	const std::string& dir,
	std::string& ca_pem,
	std::string& server_cert,
	std::string& server_key,
	std::string& client_cert,
	std::string& client_key
) {
	const std::string ca_key = dir + "/ca.key";
	ca_pem = dir + "/ca.pem";
	const std::string server_csr = dir + "/server.csr";
	server_cert = dir + "/server.pem";
	server_key = dir + "/server.key";
	const std::string server_ext = dir + "/server.ext";
	const std::string client_csr = dir + "/client.csr";
	client_cert = dir + "/client.pem";
	client_key = dir + "/client.key";
	const std::string client_ext = dir + "/client.ext";

	if (!run_openssl(
			"openssl req -x509 -newkey rsa:2048 -nodes -days 2 "
			"-subj /CN=ProxySQL-6552-Unit-CA "
			"-addext 'basicConstraints=critical,CA:TRUE' "
			"-addext 'keyUsage=critical,keyCertSign,cRLSign' "
			"-keyout '" + ca_key + "' -out '" + ca_pem + "'")) {
		return false;
	}
	if (!write_text_file(server_ext,
			"subjectAltName=DNS:localhost\n"
			"extendedKeyUsage=serverAuth\n") ||
		!write_text_file(client_ext, "extendedKeyUsage=clientAuth\n")) {
		return false;
	}
	if (!run_openssl(
			"openssl req -new -newkey rsa:2048 -nodes "
			"-subj /CN=localhost -keyout '" + server_key + "' -out '" + server_csr + "'") ||
		!run_openssl(
			"openssl x509 -req -in '" + server_csr + "' -CA '" + ca_pem + "' "
			"-CAkey '" + ca_key + "' -CAcreateserial -days 2 "
			"-extfile '" + server_ext + "' -out '" + server_cert + "'")) {
		return false;
	}
	if (!run_openssl(
			"openssl req -new -newkey rsa:2048 -nodes "
			"-subj /CN=ProxySQL-6552-Unit-Client "
			"-keyout '" + client_key + "' -out '" + client_csr + "'") ||
		!run_openssl(
			"openssl x509 -req -in '" + client_csr + "' -CA '" + ca_pem + "' "
			"-CAkey '" + ca_key + "' -CAcreateserial -days 2 "
			"-extfile '" + client_ext + "' -out '" + client_cert + "'")) {
		return false;
	}
	return true;
}

static int curl_unix_https_code(
	const std::string& socket_path,
	const std::string& ca_pem,
	const std::string& client_cert,
	const std::string& client_key
) {
	char command[2048];
	snprintf(
		command, sizeof(command),
		"curl -s -o /dev/null -w '%%{http_code}' --max-time 4 "
		"--unix-socket '%s' --cacert '%s' --cert '%s' --key '%s' "
		"https://localhost/ping 2>/dev/null",
		socket_path.c_str(), ca_pem.c_str(), client_cert.c_str(), client_key.c_str());
	FILE* pipe = popen(command, "r");
	if (pipe == nullptr) return 0;
	char buffer[16] {};
	if (fgets(buffer, sizeof(buffer), pipe) == nullptr) {
		pclose(pipe);
		return 0;
	}
	pclose(pipe);
	return atoi(buffer);
}

/**
 * A listener whose TLS material is rejected by GnuTLS must fail before MHD
 * binds its Unix path. MHD closes the bound fd on its own TLS-init failure but
 * does not unlink the pathname; ProxySQL cannot know it owned that inode
 * because ownership is recorded only after a successful start. The path must
 * therefore be reusable by a corrected configuration, and a pre-existing path
 * must never be removed.
 */
static void test_unix_socket_tls_failure_cleanup() {
	char directory_template[] = "/tmp/proxysql-restapi-6552-XXXXXX";
	char* directory = mkdtemp(directory_template);
	if (directory == nullptr) {
		diag("Cannot create temporary directory for TLS fixture: %s", strerror(errno));
		ok(0, "created temporary directory for TLS fixture");
		skip(18, "TLS fixture directory unavailable");
		return;
	}
	const std::string dir(directory);

	std::string ca_pem;
	std::string server_cert;
	std::string server_key;
	std::string client_cert;
	std::string client_key;
	const bool have_material = generate_tls_material(
		dir, ca_pem, server_cert, server_key, client_cert, client_key);
	if (!have_material) {
		diag("openssl is unavailable or failed to create the TLS fixture");
		std::filesystem::remove_all(dir);
		ok(0, "created local CA, server and client TLS material");
		skip(18, "TLS fixture material unavailable");
		return;
	}
	ok(1, "created local CA, server and client TLS material");

	const std::string server_key_pem = read_text_file(server_key);
	const std::string server_cert_pem = read_text_file(server_cert);
	const std::string ca_pem_text = read_text_file(ca_pem);

	const std::string socket_path = dir + "/restapi.sock";
	unlink(socket_path.c_str());

	ProxySQL_RESTAPI_Config malformed_ca {};
	malformed_ca.interface_name = socket_path;
	malformed_ca.use_ssl = true;
	malformed_ca.verify_client = true;
	malformed_ca.ssl_key_pem = server_key_pem;
	malformed_ca.ssl_cert_pem = server_cert_pem;
	malformed_ca.ssl_ca_pem =
		"-----BEGIN CERTIFICATE-----\n"
		"this is not a certificate\n"
		"-----END CERTIFICATE-----\n";

	{
		ProxySQL_RESTAPI_Server server(malformed_ca, ping_endpoints());
		ok(!server.is_running(),
			"malformed client trust rejects the listener before it starts");
	}

	struct stat socket_stat {};
	ok(lstat(socket_path.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"failed TLS startup leaves no Unix socket path behind");

	// A syntactically harmless trust value that imports zero anchors must
	// also fail before binding instead of starting an mTLS listener whose
	// trust store cannot authenticate any client.
	const std::string zero_anchor_socket = dir + "/zero-anchor.sock";
	unlink(zero_anchor_socket.c_str());
	ProxySQL_RESTAPI_Config zero_anchor = malformed_ca;
	zero_anchor.interface_name = zero_anchor_socket;
	zero_anchor.ssl_ca_pem = "no trusted certificates here\n";
	{
		ProxySQL_RESTAPI_Server server(zero_anchor, ping_endpoints());
		ok(!server.is_running(),
			"trust material with zero anchors rejects the TLS listener");
	}
	ok(lstat(zero_anchor_socket.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"zero-anchor trust leaves no Unix socket path behind");

	// A corrected trust store must be able to reuse the exact same path and
	// serve HTTPS with a client certificate.
	ProxySQL_RESTAPI_Config corrected = malformed_ca;
	corrected.ssl_ca_pem = ca_pem_text;
	{
		ProxySQL_RESTAPI_Server reused(corrected, ping_endpoints());
		ok(reused.is_running(),
			"corrected trust reuses the same Unix socket path");
		ok(curl_unix_https_code(socket_path, ca_pem, client_cert, client_key) == 200,
			"corrected listener serves HTTPS over the reused Unix socket");
	}
	ok(lstat(socket_path.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"destroying the corrected listener removes its owned Unix socket");

	// Missing TLS material must fail before creating a Unix artifact.
	const std::string missing_key_socket = dir + "/missing-key.sock";
	unlink(missing_key_socket.c_str());
	ProxySQL_RESTAPI_Config missing_key = corrected;
	missing_key.interface_name = missing_key_socket;
	missing_key.ssl_key_pem.clear();
	{
		ProxySQL_RESTAPI_Server server(missing_key, ping_endpoints());
		ok(!server.is_running(),
			"HTTPS without a key rejects the listener");
	}
	ok(lstat(missing_key_socket.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"missing key leaves no Unix socket path behind");

	const std::string missing_cert_socket = dir + "/missing-cert.sock";
	unlink(missing_cert_socket.c_str());
	ProxySQL_RESTAPI_Config missing_cert = corrected;
	missing_cert.interface_name = missing_cert_socket;
	missing_cert.ssl_cert_pem.clear();
	{
		ProxySQL_RESTAPI_Server server(missing_cert, ping_endpoints());
		ok(!server.is_running(),
			"HTTPS without a certificate rejects the listener");
	}
	ok(lstat(missing_cert_socket.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"missing certificate leaves no Unix socket path behind");

	const std::string missing_ca_socket = dir + "/missing-ca.sock";
	unlink(missing_ca_socket.c_str());
	ProxySQL_RESTAPI_Config missing_ca = corrected;
	missing_ca.interface_name = missing_ca_socket;
	missing_ca.ssl_ca_pem.clear();
	{
		ProxySQL_RESTAPI_Server server(missing_ca, ping_endpoints());
		ok(!server.is_running(),
			"client verification without a CA rejects the listener");
	}
	ok(lstat(missing_ca_socket.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"missing required CA leaves no Unix socket path behind");

	// The existing refusal to replace anything already at the path must be
	// preserved, and cleanup must not unlink a path this server never owned.
	const std::string existing_path = dir + "/existing.sock";
	ok(write_text_file(existing_path, "not a socket"), "created a pre-existing path");
	ProxySQL_RESTAPI_Config preexisting {};
	preexisting.interface_name = existing_path;
	preexisting.use_ssl = false;
	{
		ProxySQL_RESTAPI_Server server(preexisting, ping_endpoints());
		ok(!server.is_running(),
			"a pre-existing path is still refused instead of replaced");
	}
	ok(lstat(existing_path.c_str(), &socket_stat) == 0 && S_ISREG(socket_stat.st_mode),
		"cleanup preserves the pre-existing path");

	const std::string bad_key_socket = dir + "/badkey.sock";
	unlink(bad_key_socket.c_str());
	ProxySQL_RESTAPI_Config malformed_key {};
	malformed_key.interface_name = bad_key_socket;
	malformed_key.use_ssl = true;
	malformed_key.ssl_key_pem = "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n";
	malformed_key.ssl_cert_pem = server_cert_pem;
	{
		ProxySQL_RESTAPI_Server server(malformed_key, ping_endpoints());
		ok(!server.is_running(),
			"malformed key material rejects the TLS listener");
	}
	ok(lstat(bad_key_socket.c_str(), &socket_stat) != 0 && errno == ENOENT,
		"failed key validation leaves no Unix socket path behind");

	std::filesystem::remove_all(dir);
}

int main() {
	plan(37);
	if (test_init_minimal() != 0) {
		ok(0, "test_init_minimal() succeeds");
		return exit_status();
	}
	ok(1, "test_init_minimal() succeeds");

	bool has_bind = true;
	sockaddr_storage addr {};
	socklen_t addr_len = 123;
	std::string socket_path;
	std::string error;

	// Empty value preserves the historical all-interfaces bind.
	ok(parse("", has_bind, addr, addr_len, socket_path, error) &&
		!has_bind && socket_path.empty() && error.empty(),
		"empty interface keeps all-interfaces behavior");

	ok(parse("   ", has_bind, addr, addr_len, socket_path, error) &&
		!has_bind && socket_path.empty(),
		"whitespace-only interface keeps all-interfaces behavior");

	ok(parse("127.0.0.1", has_bind, addr, addr_len, socket_path, error) &&
		has_bind && is_ipv4(addr, "127.0.0.1") &&
		addr_len == sizeof(sockaddr_in),
		"IPv4 loopback parses to AF_INET");

	ok(parse("0.0.0.0", has_bind, addr, addr_len, socket_path, error) &&
		has_bind && is_ipv4(addr, "0.0.0.0"),
		"IPv4 wildcard parses explicitly");

	ok(parse("::1", has_bind, addr, addr_len, socket_path, error) &&
		has_bind && is_ipv6(addr, "::1") &&
		addr_len == sizeof(sockaddr_in6),
		"IPv6 loopback parses to AF_INET6");

	ok(parse("[2001:db8::5]", has_bind, addr, addr_len, socket_path, error) &&
		has_bind && is_ipv6(addr, "2001:db8::5"),
		"bracketed IPv6 literal is accepted");

	ok(parse("2001:db8::6", has_bind, addr, addr_len, socket_path, error) &&
		has_bind && is_ipv6(addr, "2001:db8::6"),
		"unbracketed IPv6 literal is accepted");

	{
		struct sockaddr_in* a4 = reinterpret_cast<struct sockaddr_in*>(&addr);
		parse("192.0.2.10", has_bind, addr, addr_len, socket_path, error);
		ok(a4->sin_port == htons(6070), "IPv4 sockaddr carries configured port");
	}

	ok(parse("/var/lib/proxysql/restapi.sock", has_bind, addr, addr_len,
			socket_path, error) &&
		has_bind && addr.ss_family == AF_UNIX &&
		socket_path == "/var/lib/proxysql/restapi.sock",
		"absolute path is a Unix socket with a bind sockaddr");

	ok(parse("unix:/var/lib/proxysql/restapi2.sock", has_bind, addr, addr_len,
			socket_path, error) &&
		has_bind && addr.ss_family == AF_UNIX &&
		socket_path == "/var/lib/proxysql/restapi2.sock",
		"unix: prefix is accepted");

	ok(!parse("unix:relative.sock", has_bind, addr, addr_len, socket_path, error) &&
		!error.empty(),
		"unix: prefix requires an absolute path");

	ok(!parse("localhost", has_bind, addr, addr_len, socket_path, error) &&
		!error.empty(),
		"hostnames are rejected instead of silently binding all interfaces");

	ok(!parse("999.1.1.1", has_bind, addr, addr_len, socket_path, error) &&
		!error.empty(),
		"malformed IPv4 is rejected");

	std::string too_long = "/tmp/" + std::string(200, 'x') + ".sock";
	ok(!parse(too_long, has_bind, addr, addr_len, socket_path, error) &&
		!error.empty(),
		"overlong Unix socket path is rejected");

	// Live IPv6 bind: this exercises the real libhttpserver -> MHD
	// MHD_OPTION_SOCK_ADDR_LEN path and the explicit use_ipv6() flag, not just
	// the parser. The TAP runner always has an IPv6 loopback in its namespace.
	const int ipv6_port = find_free_ipv6_port();
	if (ipv6_port > 0) {
		ok(ipv6_port > 0, "found free IPv6 loopback port");
		ProxySQL_RESTAPI_Config config {};
		config.port = ipv6_port;
		config.interface_name = "::1";
		config.use_ssl = false;
		config.verify_client = false;
		std::vector<std::pair<
			std::string,
			std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)>
		>> endpoints;
		endpoints.push_back({
			"/ping",
			[](const httpserver::http_request&) {
				return std::shared_ptr<httpserver::http_response>(
					new httpserver::string_response("pong", httpserver::http::http_utils::http_ok));
			}
		});
		ProxySQL_RESTAPI_Server server(config, std::move(endpoints));
		ok(server.is_running(), "REST listener reports running on ::1");
		ok(ipv6_http_get_ok(ipv6_port), "live HTTP 200 over IPv6 loopback");
	} else {
		skip(3, "IPv6 loopback is unavailable in this environment");
	}

	test_unix_socket_tls_failure_cleanup();

	test_cleanup_minimal();
	return exit_status();
}
