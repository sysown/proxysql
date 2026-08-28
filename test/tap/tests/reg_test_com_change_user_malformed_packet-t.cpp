#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

namespace {

constexpr unsigned char MYSQL_COM_CHANGE_USER = 0x11;
constexpr unsigned char MYSQL_ERR_PACKET = 0xFF;
constexpr unsigned char MALFORMED_PASS_LEN = 200;
constexpr uint16_t MYSQL_DEFAULT_CHARSET = 33;
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

bool send_all(my_socket sock, const unsigned char* data, size_t len) {
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

std::vector<unsigned char> build_malformed_change_user_packet(const CommandLine& cl) {
	std::vector<unsigned char> payload {};
	payload.push_back(MYSQL_COM_CHANGE_USER);

	payload.insert(payload.end(), cl.username, cl.username + strlen(cl.username));
	payload.push_back(0);

	payload.push_back(MALFORMED_PASS_LEN);
	payload.insert(payload.end(), MALFORMED_PASS_LEN, 'A');

	payload.push_back(0); // empty default schema
	payload.push_back(MYSQL_DEFAULT_CHARSET & 0xFF);
	payload.push_back((MYSQL_DEFAULT_CHARSET >> 8) & 0xFF);

	static constexpr char auth_plugin[] = "mysql_native_password";
	payload.insert(payload.end(), auth_plugin, auth_plugin + sizeof(auth_plugin));

	std::vector<unsigned char> packet {};
	const size_t payload_len = payload.size();

	packet.reserve(payload_len + 4);
	packet.push_back(payload_len & 0xFF);
	packet.push_back((payload_len >> 8) & 0xFF);
	packet.push_back((payload_len >> 16) & 0xFF);
	packet.push_back(0); // every command starts at sequence id 0
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

malformed_result_t send_malformed_change_user(MYSQL* conn, const CommandLine& cl) {
	my_socket sock = mysql_get_socket(conn);
	if (sock < 0) {
		return malformed_result_t::send_failed;
	}

	timeval timeout {};
	timeout.tv_sec = SOCKET_TIMEOUT_SEC;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	const std::vector<unsigned char> packet = build_malformed_change_user_packet(cl);
	if (!send_all(sock, packet.data(), packet.size())) {
		return malformed_result_t::send_failed;
	}

	unsigned char buf[256] {};
	const ssize_t received = recv(sock, buf, sizeof(buf), 0);

	if (received == 0) {
		return malformed_result_t::connection_closed;
	}
	if (received < 0) {
		return malformed_result_t::unexpected_response;
	}
	if (received >= 5 && buf[4] == MYSQL_ERR_PACKET) {
		return malformed_result_t::error_packet;
	}

	return malformed_result_t::unexpected_response;
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

} // namespace

int main() {
	plan(4);

	CommandLine cl {};
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* victim = mysql_init(nullptr);
	ok(victim != nullptr, "Created client handle for malformed COM_CHANGE_USER test");
	if (victim == nullptr) {
		return exit_status();
	}

	const bool initial_connect = connect_client(victim, cl, "for malformed COM_CHANGE_USER");
	ok(initial_connect, "Connected client session used to send malformed COM_CHANGE_USER");
	if (!initial_connect) {
		mysql_close(victim);
		return exit_status();
	}

	const malformed_result_t malformed_result = send_malformed_change_user(victim, cl);
	ok(
		malformed_result == malformed_result_t::connection_closed ||
		malformed_result == malformed_result_t::error_packet,
		"Malformed COM_CHANGE_USER is rejected without crashing ProxySQL   result='%s'",
		malformed_result_str(malformed_result)
	);
	mysql_close(victim);

	MYSQL* probe = mysql_init(nullptr);
	bool proxysql_alive = false;
	if (probe != nullptr && connect_client(probe, cl, "after malformed COM_CHANGE_USER")) {
		proxysql_alive = run_select_one(probe);
	}

	ok(proxysql_alive, "ProxySQL remains usable after malformed COM_CHANGE_USER");

	if (probe) {
		mysql_close(probe);
	}

	return exit_status();
}
