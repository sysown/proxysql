#include "mysqlx_backend_session.h"
#include "mysqlx_protocol.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

MysqlxBackendSession::MysqlxBackendSession() = default;

MysqlxBackendSession::~MysqlxBackendSession() {
	if (backend_fd_ >= 0) {
		close(backend_fd_);
		backend_fd_ = -1;
	}
}

bool MysqlxBackendSession::connect(const MysqlxResolvedIdentity& identity,
                                    const MysqlxBackendEndpoint& endpoint,
                                    std::string& err) {
	if (identity.backend_auth_mode == MysqlxBackendAuthMode::pass_through) {
		err = "pass_through backend auth mode not supported in Phase 1";
		return false;
	}

	if (endpoint.hostname.empty() || endpoint.mysqlx_port <= 0) {
		err = "no valid backend endpoint";
		return false;
	}

	// TCP connect to backend X port.
	backend_fd_ = socket(AF_INET, SOCK_STREAM, 0);
	if (backend_fd_ < 0) {
		err = "socket() failed: ";
		err += strerror(errno);
		return false;
	}

	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(endpoint.mysqlx_port));

	if (inet_pton(AF_INET, endpoint.hostname.c_str(), &addr.sin_addr) != 1) {
		err = "invalid backend hostname: " + endpoint.hostname;
		close(backend_fd_);
		backend_fd_ = -1;
		return false;
	}

	// Set socket timeouts to prevent indefinite blocking.
	struct timeval tv { 10, 0 }; // 10 second timeout for reads and writes
	setsockopt(backend_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(backend_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (::connect(backend_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
		err = "connect() to " + endpoint.hostname + ":" +
		      std::to_string(endpoint.mysqlx_port) + " failed: " + strerror(errno);
		close(backend_fd_);
		backend_fd_ = -1;
		return false;
	}

	// Authenticate to the backend MySQL X server.
	std::string backend_user = identity.backend_username;
	std::string backend_pass = identity.backend_password;

	return authenticate_backend(backend_user, backend_pass, err);
}

bool MysqlxBackendSession::authenticate_backend(const std::string& username,
                                                 const std::string& password,
                                                 std::string& err) {
	// Step 1: Send CapabilitiesGet to learn what the backend supports.
	{
		Mysqlx::Connection::CapabilitiesGet cap_get;
		std::string serialized;
		cap_get.SerializeToString(&serialized);
		auto frame = mysqlx_build_frame(
			Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET,
			serialized
		);
		if (!mysqlx_write_all(backend_fd_, frame.data(), frame.size())) {
			err = "failed to send CapabilitiesGet to backend";
			return false;
		}
	}

	// Step 2: Read Capabilities response.
	{
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};
		if (!mysqlx_read_frame(backend_fd_, header, payload)) {
			err = "failed to read Capabilities from backend";
			return false;
		}
		if (header.message_type != Mysqlx::ServerMessages_Type_CONN_CAPABILITIES) {
			err = "unexpected response to CapabilitiesGet from backend";
			return false;
		}
		// We don't inspect capabilities in Phase 1 — just proceed with auth.
	}

	// Step 3: Send AuthenticateStart with MYSQL41.
	{
		Mysqlx::Session::AuthenticateStart auth_start;
		auth_start.set_mech_name("MYSQL41");
		// auth_data: schema\0username\0
		std::string auth_data;
		auth_data += '\0'; // empty schema
		auth_data += username;
		auth_data += '\0';
		auth_start.set_auth_data(auth_data);

		std::string serialized;
		auth_start.SerializeToString(&serialized);
		auto frame = mysqlx_build_frame(
			Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
			serialized
		);
		if (!mysqlx_write_all(backend_fd_, frame.data(), frame.size())) {
			err = "failed to send AuthenticateStart to backend";
			return false;
		}
	}

	// Step 4: Read AuthenticateContinue with challenge from backend.
	std::vector<uint8_t> challenge {};
	{
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};
		if (!mysqlx_read_frame(backend_fd_, header, payload)) {
			err = "failed to read auth challenge from backend";
			return false;
		}

		if (header.message_type == Mysqlx::ServerMessages_Type_ERROR) {
			Mysqlx::Error error_msg;
			error_msg.ParseFromArray(payload.data(), static_cast<int>(payload.size()));
			err = "backend auth error: " + error_msg.msg();
			return false;
		}

		if (header.message_type != Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
			err = "unexpected message type during backend auth";
			return false;
		}

		Mysqlx::Session::AuthenticateContinue auth_continue;
		if (!auth_continue.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
			err = "failed to parse backend AuthenticateContinue";
			return false;
		}

		const std::string& ch = auth_continue.auth_data();
		challenge.assign(ch.begin(), ch.end());
	}

	// Step 5: Compute MYSQL41 scramble and send AuthenticateContinue.
	{
		auto scramble = mysqlx_mysql41_scramble(challenge, password);

		Mysqlx::Session::AuthenticateContinue auth_continue;
		auth_continue.set_auth_data(std::string(scramble.begin(), scramble.end()));

		std::string serialized;
		auth_continue.SerializeToString(&serialized);
		auto frame = mysqlx_build_frame(
			Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
			serialized
		);
		if (!mysqlx_write_all(backend_fd_, frame.data(), frame.size())) {
			err = "failed to send auth response to backend";
			return false;
		}
	}

	// Step 6: Read AuthenticateOk (or Error).
	{
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};
		if (!mysqlx_read_frame(backend_fd_, header, payload)) {
			err = "failed to read auth result from backend";
			return false;
		}

		if (header.message_type == Mysqlx::ServerMessages_Type_ERROR) {
			Mysqlx::Error error_msg;
			error_msg.ParseFromArray(payload.data(), static_cast<int>(payload.size()));
			err = "backend auth failed: " + error_msg.msg();
			return false;
		}

		// Accept both AuthenticateOk and Notice (some servers send notices first).
		while (header.message_type == Mysqlx::ServerMessages_Type_NOTICE) {
			if (!mysqlx_read_frame(backend_fd_, header, payload)) {
				err = "failed to read post-notice frame from backend";
				return false;
			}
		}

		if (header.message_type != Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK) {
			err = "unexpected message type after backend auth";
			return false;
		}
	}

	return true;
}

bool MysqlxBackendSession::relay(int frontend_fd) {
	// Byte-level bidirectional relay between frontend and backend.
	uint8_t buf[65536];

	struct pollfd pfds[2];
	pfds[0].fd = frontend_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = backend_fd_;
	pfds[1].events = POLLIN;

	while (true) {
		pfds[0].revents = 0;
		pfds[1].revents = 0;

		int ready = poll(pfds, 2, 30000 /*ms*/);
		if (ready < 0) {
			return false;
		}
		if (ready == 0) {
			return false; // idle timeout
		}

		// Check for errors/hangups.
		if ((pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
		    (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
			return false;
		}

		// Frontend → Backend
		if (pfds[0].revents & POLLIN) {
			ssize_t n = read(frontend_fd, buf, sizeof(buf));
			if (n <= 0) {
				return n == 0;
			}
			if (!mysqlx_write_all(backend_fd_, buf, static_cast<size_t>(n))) {
				return false;
			}
		}

		// Backend → Frontend
		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(backend_fd_, buf, sizeof(buf));
			if (n <= 0) {
				return n == 0;
			}
			if (!mysqlx_write_all(frontend_fd, buf, static_cast<size_t>(n))) {
				return false;
			}
		}
	}
}
