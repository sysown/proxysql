#include "mcp_client.h"
#include "tap.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

class OneShotHttpServer {
public:
	OneShotHttpServer(int status, std::string body, int timeout_ms = 2000)
		: listen_fd_(socket(AF_INET, SOCK_STREAM, 0)), status_(status),
		  body_(std::move(body)), timeout_ms_(timeout_ms) {
		if (listen_fd_ < 0) throw std::runtime_error(std::strerror(errno));

		int reuse = 1;
		setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
		sockaddr_in address {};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address.sin_port = 0;
		if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
			listen(listen_fd_, 1) != 0) {
			const std::string error = std::strerror(errno);
			close(listen_fd_);
			throw std::runtime_error(error);
		}
		const timeval timeout {
			timeout_ms_ / 1000,
			(timeout_ms_ % 1000) * 1000
		};
		if (setsockopt(listen_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
			const std::string error = std::strerror(errno);
			close(listen_fd_);
			throw std::runtime_error(error);
		}

		socklen_t address_size = sizeof(address);
		if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
			const std::string error = std::strerror(errno);
			close(listen_fd_);
			throw std::runtime_error(error);
		}
		port_ = ntohs(address.sin_port);
		worker_ = std::thread(&OneShotHttpServer::serve, this);
	}

	~OneShotHttpServer() {
		if (worker_.joinable()) worker_.join();
		if (listen_fd_ >= 0) close(listen_fd_);
	}

	int port() const { return port_; }

	const std::string& request() {
		if (worker_.joinable()) worker_.join();
		return request_;
	}

private:
	void serve() {
		const int client = accept(listen_fd_, nullptr, nullptr);
		if (client < 0) return;
		const timeval timeout {
			timeout_ms_ / 1000,
			(timeout_ms_ % 1000) * 1000
		};
		if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
			close(client);
			return;
		}

		char buffer[2048];
		while (request_.find("\r\n\r\n") == std::string::npos) {
			const ssize_t bytes = recv(client, buffer, sizeof(buffer), 0);
			if (bytes <= 0) break;
			request_.append(buffer, static_cast<size_t>(bytes));
		}

		const char* reason = status_ == 200 ? "OK" : "Unauthorized";
		const std::string response =
			"HTTP/1.1 " + std::to_string(status_) + " " + reason + "\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: " + std::to_string(body_.size()) + "\r\n"
			"Connection: close\r\n\r\n" + body_;
		size_t sent = 0;
		while (sent < response.size()) {
			const ssize_t bytes = send(
				client, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
			if (bytes <= 0) break;
			sent += static_cast<size_t>(bytes);
		}
		close(client);
	}

	int listen_fd_ {-1};
	int port_ {0};
	int status_;
	std::string body_;
	std::string request_;
	std::thread worker_;
	int timeout_ms_;
};

} // namespace

int main() {
	plan(10);

	const auto idle_server_started = std::chrono::steady_clock::now();
	{
		OneShotHttpServer idle_server(200, R"({})", 100);
	}
	const auto idle_server_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - idle_server_started);
	ok(idle_server_elapsed.count() < 1000,
	   "idle one-shot server teardown is bounded (took %lld ms)",
	   static_cast<long long>(idle_server_elapsed.count()));

	OneShotHttpServer authenticated_server(
		200, R"({"jsonrpc":"2.0","result":{},"id":1})");
	MCPClient authenticated_client("127.0.0.1", authenticated_server.port(), 2000);
	authenticated_client.set_auth_token("tap-token");
	ok(authenticated_client.check_server(),
	   "authenticated HTTP 200 JSON-RPC ping is ready");
	const std::string authenticated_request = authenticated_server.request();
	ok(authenticated_request.find("Authorization: Bearer tap-token\r\n") != std::string::npos,
	   "readiness request sends configured bearer token");
	ok(authenticated_request.find("POST /mcp/config HTTP/") != std::string::npos,
	   "readiness request targets the config endpoint");

	OneShotHttpServer unauthorized_server(
		401, R"({"jsonrpc":"2.0","result":{},"id":1})");
	MCPClient unauthorized_client("127.0.0.1", unauthorized_server.port(), 2000);
	unauthorized_client.set_auth_token("wrong-token");
	ok(!unauthorized_client.check_server(),
	   "HTTP 401 is not accepted even when its body contains a result");
	ok(unauthorized_client.get_last_error().find("401") != std::string::npos,
	   "HTTP readiness failure preserves the response status");
	unauthorized_server.request();

	OneShotHttpServer malformed_server(200, R"(not JSON, but contains "result")");
	MCPClient malformed_client("127.0.0.1", malformed_server.port(), 2000);
	ok(!malformed_client.check_server(),
	   "HTTP 200 body containing result text is rejected when it is not JSON");
	malformed_server.request();

	OneShotHttpServer wrong_id_server(
		200, R"({"jsonrpc":"2.0","result":{},"id":99})");
	MCPClient wrong_id_client("127.0.0.1", wrong_id_server.port(), 2000);
	ok(!wrong_id_client.check_server(),
	   "JSON-RPC response with a mismatched id is rejected");
	wrong_id_server.request();

	OneShotHttpServer anonymous_server(
		200, R"({"jsonrpc":"2.0","result":{},"id":1})");
	MCPClient anonymous_client("127.0.0.1", anonymous_server.port(), 2000);
	ok(anonymous_client.check_server(),
	   "readiness still supports an endpoint configured without authentication");
	const std::string anonymous_request = anonymous_server.request();
	ok(anonymous_request.find("Authorization:") == std::string::npos,
	   "readiness omits Authorization when no token is configured");

	return exit_status();
}
