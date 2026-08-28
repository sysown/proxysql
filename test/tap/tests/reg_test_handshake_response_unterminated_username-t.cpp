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
constexpr uint32_t MALFORMED_USERNAME_LEN = 32;
constexpr uint32_t MYSQL_MAX_PACKET_SIZE = 0x00ffffff;
constexpr uint8_t MYSQL_DEFAULT_CHARSET = 33;
constexpr int SOCKET_TIMEOUT_SEC = 3;

enum class malformed_result_t {
	connection_closed,
	error_packet,
	unexpected_response,
	send_failed,
};

bool connect_client(MYSQL* conn, const CommandLine& cl, const char* label) {
	if (mysql_real_connect(conn, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		return true;
	}

	diag(
		"Failed to connect %s   host='%s' port=%d user='%s' error='%s'",
		label, cl.host, cl.port, cl.username, mysql_error(conn)
	);
	return false;
}

bool run_select_one(MYSQL* conn) {
	if (mysql_query(conn, "SELECT 1")) {
		return false;
	}

	MYSQL_RES* result = mysql_store_result(conn);
	if (result == nullptr) {
		return false;
	}

	bool ok_result = false;
	if (mysql_num_rows(result) == 1) {
		MYSQL_ROW row = mysql_fetch_row(result);
		ok_result = (row != nullptr && row[0] != nullptr && strcmp(row[0], "1") == 0);
	}

	mysql_free_result(result);
	return ok_result;
}

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

std::vector<unsigned char> build_unterminated_username_handshake_response() {
	std::vector<unsigned char> payload {};
	const uint32_t client_capabilities = CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH;

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
	payload.insert(payload.end(), MALFORMED_USERNAME_LEN, 0xFF);

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

malformed_result_t send_malformed_handshake_response(const CommandLine& cl, bool& greeting_received) {
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

	const std::vector<unsigned char> packet = build_unterminated_username_handshake_response();
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

} // namespace

int main() {
	plan(4);

	CommandLine cl {};
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	bool greeting_received = false;
	const malformed_result_t malformed_result = send_malformed_handshake_response(cl, greeting_received);
	ok(greeting_received, "Received frontend greeting before sending malformed HandshakeResponse41");
	ok(
		malformed_result == malformed_result_t::connection_closed ||
		malformed_result == malformed_result_t::error_packet,
		"Malformed HandshakeResponse41 without username terminator is rejected   result='%s'",
		malformed_result_str(malformed_result)
	);

	MYSQL* probe = mysql_init(nullptr);
	ok(probe != nullptr, "Created probe connection handle after malformed handshake");

	bool proxysql_alive = false;
	if (probe != nullptr && connect_client(probe, cl, "after malformed HandshakeResponse41")) {
		proxysql_alive = run_select_one(probe);
	}

	ok(proxysql_alive, "ProxySQL remains usable after malformed HandshakeResponse41");

	if (probe) {
		mysql_close(probe);
	}

	return exit_status();
}
