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
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
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

int main() {
	plan(18);
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

	test_cleanup_minimal();
	return exit_status();
}
