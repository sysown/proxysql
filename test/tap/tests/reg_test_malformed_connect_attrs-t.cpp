/**
 * @file reg_test_malformed_connect_attrs-t.cpp
 * @brief Ensure malformed frontend connection attributes are rejected safely.
 */

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

namespace {

constexpr unsigned char MYSQL_ERR_PACKET = 0xFF;
constexpr unsigned char LENGTH_ENCODED_8_BYTE_MARKER = 0xFE;
constexpr uint32_t MYSQL_MAX_PACKET_SIZE = 0x00FFFFFF;
constexpr uint8_t MYSQL_DEFAULT_CHARSET = 33;
constexpr int SOCKET_TIMEOUT_SEC = 3;

enum class malformed_result_t : uint8_t {
	connection_closed,
	error_packet,
	unexpected_response,
	send_failed,
};

int connect_raw_socket(const CommandLine& cl) {
	struct addrinfo hints {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* result = nullptr;
	const std::string port_str = std::to_string(cl.port);
	const int gai_rc = getaddrinfo(cl.host, port_str.c_str(), &hints, &result);
	if (gai_rc != 0) {
		diag("Failed to resolve host '%s': %s", cl.host, gai_strerror(gai_rc));
		return -1;
	}

	int sock = -1;
	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) {
			continue;
		}

		timeval timeout {};
		timeout.tv_sec = SOCKET_TIMEOUT_SEC;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(result);
	return sock;
}

bool send_all(int sock, const unsigned char* data, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		const ssize_t rc = send(sock, data + sent, len - sent, 0);
		if (rc <= 0) {
			return false;
		}
		sent += rc;
	}
	return true;
}

std::vector<unsigned char> build_overflowing_connect_attrs_handshake(const CommandLine& cl) {
	std::vector<unsigned char> payload {};
	const uint32_t client_capabilities =
		CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS;

	payload.push_back(client_capabilities & 0xFF);
	payload.push_back((client_capabilities >> 8) & 0xFF);
	payload.push_back((client_capabilities >> 16) & 0xFF);
	payload.push_back((client_capabilities >> 24) & 0xFF);
	payload.push_back(MYSQL_MAX_PACKET_SIZE & 0xFF);
	payload.push_back((MYSQL_MAX_PACKET_SIZE >> 8) & 0xFF);
	payload.push_back((MYSQL_MAX_PACKET_SIZE >> 16) & 0xFF);
	payload.push_back((MYSQL_MAX_PACKET_SIZE >> 24) & 0xFF);
	payload.push_back(MYSQL_DEFAULT_CHARSET);
	payload.insert(payload.end(), 23, 0);
	payload.insert(payload.end(), cl.username, cl.username + strlen(cl.username));
	payload.push_back(0);
	payload.push_back(0);  // Empty CLIENT_SECURE_CONNECTION auth response.

	static constexpr char auth_plugin[] = "mysql_native_password";
	payload.insert(payload.end(), auth_plugin, auth_plugin + sizeof(auth_plugin));

	payload.push_back(10);  // Attribute block: 9-byte key length plus one byte.
	payload.push_back(LENGTH_ENCODED_8_BYTE_MARKER);
	payload.insert(payload.end(), 8, 0xFF);  // UINT64_MAX key length.
	payload.push_back(0);

	std::vector<unsigned char> packet {};
	const size_t payload_len = payload.size();
	packet.reserve(payload_len + 4);
	packet.push_back(payload_len & 0xFF);
	packet.push_back((payload_len >> 8) & 0xFF);
	packet.push_back((payload_len >> 16) & 0xFF);
	packet.push_back(1);
	packet.insert(packet.end(), payload.begin(), payload.end());

	return packet;
}

const char* malformed_result_str(malformed_result_t result) {
	switch (result) {
		case malformed_result_t::connection_closed:
			return "connection_closed";
		case malformed_result_t::error_packet:
			return "error_packet";
		case malformed_result_t::unexpected_response:
			return "unexpected_response";
		case malformed_result_t::send_failed:
			return "send_failed";
	}

	return "unknown";
}

malformed_result_t send_overflowing_connect_attrs_handshake(const CommandLine& cl, bool& greeting_received) {
	greeting_received = false;
	const int sock = connect_raw_socket(cl);
	if (sock < 0) {
		return malformed_result_t::send_failed;
	}

	unsigned char greeting[512] {};
	const ssize_t greeting_len = recv(sock, greeting, sizeof(greeting), 0);
	if (greeting_len > 0) {
		greeting_received = true;
	} else {
		close(sock);
		return malformed_result_t::send_failed;
	}

	const std::vector<unsigned char> packet = build_overflowing_connect_attrs_handshake(cl);
	if (!send_all(sock, packet.data(), packet.size())) {
		close(sock);
		return malformed_result_t::send_failed;
	}

	unsigned char response[256] {};
	const ssize_t received = recv(sock, response, sizeof(response), 0);
	close(sock);

	if (received == 0) {
		return malformed_result_t::connection_closed;
	}
	if (received < 0) {
		diag("recv() after malformed handshake failed: errno=%d (%s)", errno, strerror(errno));
		return malformed_result_t::unexpected_response;
	}
	if (received >= 5 && response[4] == MYSQL_ERR_PACKET) {
		return malformed_result_t::error_packet;
	}

	return malformed_result_t::unexpected_response;
}

bool connect_client(MYSQL* conn, const CommandLine& cl) {
	return mysql_real_connect(conn, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0) != nullptr;
}

}  // namespace

int main() {
	plan(4);

	CommandLine cl {};
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	bool greeting_received = false;
	const malformed_result_t malformed_result = send_overflowing_connect_attrs_handshake(cl, greeting_received);
	ok(greeting_received, "Received frontend greeting before malformed connection attributes");
	ok(
		malformed_result == malformed_result_t::connection_closed || malformed_result == malformed_result_t::error_packet,
		"Overflowing connection attributes are rejected   result='%s'",
		malformed_result_str(malformed_result)
	);

	MYSQL* probe = mysql_init(nullptr);
	ok(probe != nullptr, "Created probe connection handle after malformed connection attributes");

	const bool proxysql_alive = probe != nullptr && connect_client(probe, cl);
	ok(proxysql_alive, "ProxySQL remains available after malformed connection attributes");

	if (probe) {
		mysql_close(probe);
	}

	return exit_status();
}
