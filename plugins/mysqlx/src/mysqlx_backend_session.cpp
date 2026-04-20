#include "mysqlx_backend_session.h"
#include "mysqlx_protocol.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
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

	std::string port_str = std::to_string(endpoint.mysqlx_port);
	struct addrinfo hints {}, *result = nullptr;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	int gai_rc = getaddrinfo(endpoint.hostname.c_str(), port_str.c_str(), &hints, &result);
	if (gai_rc != 0) {
		err = "mysqlx backend: cannot resolve '";
		err += endpoint.hostname;
		err += "': ";
		err += gai_strerror(gai_rc);
		return false;
	}

	int fd = -1;
	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;

		int flag = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

		struct timeval tv { 10, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(result);

	if (fd < 0) {
		err = "mysqlx backend: connect failed to ";
		err += endpoint.hostname + ":" + std::to_string(endpoint.mysqlx_port);
		return false;
	}
	backend_fd_ = fd;

	// Authenticate to the backend MySQL X server.
	std::string backend_user = identity.backend_username;
	std::string backend_pass = identity.backend_password;

	if (!authenticate_backend(backend_user, backend_pass, err)) {
		// Auth failure: close the socket we just opened so a later retry
		// on this MysqlxBackendSession doesn't overwrite backend_fd_ and
		// leak the previous fd.
		close(backend_fd_);
		backend_fd_ = -1;
		return false;
	}
	return true;
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

	// Step 2: Read Capabilities response (skip any preceding Notice frames).
	{
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};
		if (!mysqlx_read_frame(backend_fd_, header, payload)) {
			err = "failed to read Capabilities from backend";
			return false;
		}
		while (header.message_type == Mysqlx::ServerMessages_Type_NOTICE) {
			if (!mysqlx_read_frame(backend_fd_, header, payload)) {
				err = "failed to read frame after notice during capabilities";
				return false;
			}
		}
		if (header.message_type != Mysqlx::ServerMessages_Type_CONN_CAPABILITIES) {
			err = "unexpected response to CapabilitiesGet from backend";
			return false;
		}
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

	// Step 4: Read AuthenticateContinue with challenge (skip Notice frames).
	std::vector<uint8_t> challenge {};
	{
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};
		if (!mysqlx_read_frame(backend_fd_, header, payload)) {
			err = "failed to read auth challenge from backend";
			return false;
		}

		// Skip any intervening Notice frames.
		while (header.message_type == Mysqlx::ServerMessages_Type_NOTICE) {
			if (!mysqlx_read_frame(backend_fd_, header, payload)) {
				err = "failed to read frame after notice during auth challenge";
				return false;
			}
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
	// Wire format: \0username\0*UPPERCASE_HEX(scramble)
	{
		auto scramble = mysqlx_mysql41_scramble(challenge, password);
		std::string hex_scramble = mysqlx_hex_encode(scramble);

		std::string auth_data;
		auth_data += '\0'; // empty schema
		auth_data += username;
		auth_data += '\0';
		auth_data += '*';
		auth_data += hex_scramble;

		Mysqlx::Session::AuthenticateContinue auth_continue;
		auth_continue.set_auth_data(auth_data);

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
