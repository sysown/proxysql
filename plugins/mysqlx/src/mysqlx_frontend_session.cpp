#include "mysqlx_frontend_session.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_notice.pb.h"

#include <cstdlib>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr size_t CHALLENGE_LENGTH = 20;

// Parse "schema\0user\0" from auth_data (MYSQL41 initial message).
// Returns false if parsing fails.
bool parse_mysql41_auth_data(const std::string& auth_data,
                              std::string& schema,
                              std::string& username) {
	// Format: \0-terminated schema, then \0-terminated username, then scramble.
	// For AuthenticateStart, auth_data is just schema + \0 + user + \0.
	size_t first_nul = auth_data.find('\0');
	if (first_nul == std::string::npos) {
		return false;
	}

	schema = auth_data.substr(0, first_nul);

	size_t rest_start = first_nul + 1;
	size_t second_nul = auth_data.find('\0', rest_start);
	if (second_nul == std::string::npos) {
		// No second NUL — everything after first NUL is username.
		username = auth_data.substr(rest_start);
	} else {
		username = auth_data.substr(rest_start, second_nul - rest_start);
	}

	return !username.empty();
}

// Parse PLAIN auth data: \0username\0password
bool parse_plain_auth_data(const std::string& auth_data,
                            std::string& username,
                            std::string& password) {
	// Format: \0user\0password
	if (auth_data.empty() || auth_data[0] != '\0') {
		return false;
	}

	size_t second_nul = auth_data.find('\0', 1);
	if (second_nul == std::string::npos) {
		return false;
	}

	username = auth_data.substr(1, second_nul - 1);
	password = auth_data.substr(second_nul + 1);
	return !username.empty();
}

// Check if the auth method is allowed for this user.
// Empty allowed_auth_methods means all supported methods are allowed.
bool is_auth_method_allowed(const std::string& method, const std::string& allowed) {
	if (allowed.empty()) {
		return true;
	}
	// allowed_auth_methods is comma-separated, e.g. "MYSQL41,PLAIN"
	size_t pos = 0;
	while (pos < allowed.size()) {
		size_t comma = allowed.find(',', pos);
		if (comma == std::string::npos) comma = allowed.size();
		std::string token = allowed.substr(pos, comma - pos);
		// Trim whitespace.
		while (!token.empty() && token.front() == ' ') token.erase(0, 1);
		while (!token.empty() && token.back() == ' ') token.pop_back();
		if (token == method) return true;
		pos = comma + 1;
	}
	return false;
}

} // namespace

MysqlxFrontendSession::MysqlxFrontendSession(int client_fd)
	: client_fd_(client_fd) {
	// Set socket timeouts to prevent slow-client DoS.
	struct timeval tv { 30, 0 }; // 30 second timeout
	setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	// Generate random challenge for MYSQL41.
	auth_challenge_.resize(CHALLENGE_LENGTH);
	RAND_bytes(auth_challenge_.data(), CHALLENGE_LENGTH);
}

MysqlxFrontendSession::~MysqlxFrontendSession() = default;

bool MysqlxFrontendSession::run_handshake_and_auth(MysqlxConfigStore& config_store) {
	// X Protocol handshake loop:
	// 1. Wait for CapabilitiesGet or AuthenticateStart.
	// 2. If CapabilitiesGet → reply with Capabilities, then wait for next.
	// 3. If CapabilitiesSet → handle TLS etc, reply Ok, wait for next.
	// 4. If AuthenticateStart → run auth flow.

	while (true) {
		MysqlxFrameHeader header {};
		std::vector<uint8_t> payload {};

		if (!mysqlx_read_frame(client_fd_, header, payload)) {
			return false;
		}

		switch (header.message_type) {
			case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET:
				if (!handle_capabilities_get()) {
					return false;
				}
				break;

			case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET:
				if (!handle_capabilities_set(payload)) {
					return false;
				}
				break;

			case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START: {
				// Parse AuthenticateStart.
				Mysqlx::Session::AuthenticateStart auth_start;
				if (!auth_start.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
					mysqlx_send_error(client_fd_, 1045, "Invalid AuthenticateStart message");
					return false;
				}

				auth_method_ = auth_start.mech_name();

				if (!mysqlx_is_supported_auth_method(auth_method_)) {
					mysqlx_send_error(client_fd_, 1251,
						"Authentication method '" + auth_method_ + "' not supported");
					return false;
				}

				if (auth_method_ == "PLAIN") {
					// PLAIN: auth_data contains \0user\0password in one shot.
					std::string username {};
					std::string password {};
					if (!parse_plain_auth_data(auth_start.auth_data(), username, password)) {
						mysqlx_send_error(client_fd_, 1045, "Invalid PLAIN auth data");
						return false;
					}

					auto resolved = config_store.resolve_identity(username);
					if (!resolved.has_value()) {
						mysqlx_send_error(client_fd_, 1045,
							"Access denied for user '" + username + "'");
						return false;
					}

					identity_ = resolved.value();

					if (!identity_.x_enabled) {
						mysqlx_send_error(client_fd_, 1045,
							"X Protocol access not enabled for user '" + username + "'");
						return false;
					}

					if (identity_.require_tls) {
						mysqlx_send_error(client_fd_, 1045,
							"User '" + username + "' requires TLS for X Protocol access");
						return false;
					}

					if (!is_auth_method_allowed("PLAIN", identity_.allowed_auth_methods)) {
						mysqlx_send_error(client_fd_, 1251,
							"Authentication method 'PLAIN' not allowed for user '" + username + "'");
						return false;
					}

					if (identity_.backend_auth_mode == MysqlxBackendAuthMode::pass_through) {
						mysqlx_send_error(client_fd_, 1045,
							"pass_through backend auth mode not supported in Phase 1");
						return false;
					}

					// For PLAIN, verify password against backend_password using
					// constant-time comparison to prevent timing side-channels.
					if (password.size() != identity_.backend_password.size() ||
					    CRYPTO_memcmp(password.data(), identity_.backend_password.data(),
					                  password.size()) != 0) {
						mysqlx_send_error(client_fd_, 1045,
							"Access denied for user '" + username + "'");
						return false;
					}

					// Send AuthenticateOk.
					Mysqlx::Session::AuthenticateOk auth_ok;
					std::string serialized;
					auth_ok.SerializeToString(&serialized);
					auto frame = mysqlx_build_frame(
						Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
						serialized
					);
					if (!mysqlx_write_all(client_fd_, frame.data(), frame.size())) {
						return false;
					}
					return true;
				}

				if (auth_method_ == "MYSQL41") {
					// MYSQL41 phase 1: parse schema+user, send challenge.
					std::string schema {};
					std::string username {};
					if (!parse_mysql41_auth_data(auth_start.auth_data(), schema, username)) {
						mysqlx_send_error(client_fd_, 1045, "Invalid MYSQL41 auth data");
						return false;
					}

					auto resolved = config_store.resolve_identity(username);
					if (!resolved.has_value()) {
						mysqlx_send_error(client_fd_, 1045,
							"Access denied for user '" + username + "'");
						return false;
					}

					identity_ = resolved.value();

					if (!identity_.x_enabled) {
						mysqlx_send_error(client_fd_, 1045,
							"X Protocol access not enabled for user '" + username + "'");
						return false;
					}

					if (identity_.require_tls) {
						mysqlx_send_error(client_fd_, 1045,
							"User '" + username + "' requires TLS for X Protocol access");
						return false;
					}

					if (!is_auth_method_allowed("MYSQL41", identity_.allowed_auth_methods)) {
						mysqlx_send_error(client_fd_, 1251,
							"Authentication method 'MYSQL41' not allowed for user '" + username + "'");
						return false;
					}

					if (identity_.backend_auth_mode == MysqlxBackendAuthMode::pass_through) {
						mysqlx_send_error(client_fd_, 1045,
							"pass_through backend auth mode not supported in Phase 1");
						return false;
					}

					// Send AuthenticateContinue with challenge.
					if (!send_auth_continue_challenge()) {
						return false;
					}

					// Wait for AuthenticateContinue from client with scrambled response.
					return handle_authenticate(config_store);
				}

				mysqlx_send_error(client_fd_, 1251, "Unsupported auth method");
				return false;
			}

			case Mysqlx::ClientMessages_Type_CON_CLOSE:
				return false;

			default:
				mysqlx_send_error(client_fd_, 5000,
					"Unexpected message during handshake");
				return false;
		}
	}
}

bool MysqlxFrontendSession::handle_capabilities_get() {
	return send_capabilities();
}

bool MysqlxFrontendSession::handle_capabilities_set(const std::vector<uint8_t>& payload) {
	Mysqlx::Connection::CapabilitiesSet cap_set;
	if (!cap_set.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
		mysqlx_send_error(client_fd_, 5001, "Invalid CapabilitiesSet message");
		return false;
	}

	// Phase 1: reject TLS requests explicitly since we don't implement it yet.
	if (cap_set.has_capabilities()) {
		for (const auto& cap : cap_set.capabilities().capabilities()) {
			if (cap.name() == "tls") {
				mysqlx_send_error(client_fd_, 5001,
					"TLS capability not supported by mysqlx plugin in Phase 1");
				return false;
			}
		}
	}

	return mysqlx_send_ok(client_fd_);
}

bool MysqlxFrontendSession::send_capabilities() {
	Mysqlx::Connection::Capabilities caps;

	// Advertise supported auth methods.
	auto* cap_auth = caps.add_capabilities();
	cap_auth->set_name("authentication.mechanisms");
	auto* auth_array = cap_auth->mutable_value()->mutable_array();

	auto* mysql41 = auth_array->add_value();
	mysql41->set_type(Mysqlx::Datatypes::Any::SCALAR);
	mysql41->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	mysql41->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");

	auto* plain = auth_array->add_value();
	plain->set_type(Mysqlx::Datatypes::Any::SCALAR);
	plain->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	plain->mutable_scalar()->mutable_v_string()->set_value("PLAIN");

	std::string serialized;
	caps.SerializeToString(&serialized);

	auto frame = mysqlx_build_frame(
		Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		serialized
	);

	return mysqlx_write_all(client_fd_, frame.data(), frame.size());
}

bool MysqlxFrontendSession::send_auth_continue_challenge() {
	Mysqlx::Session::AuthenticateContinue auth_continue;
	auth_continue.set_auth_data(
		std::string(auth_challenge_.begin(), auth_challenge_.end())
	);

	std::string serialized;
	auth_continue.SerializeToString(&serialized);

	auto frame = mysqlx_build_frame(
		Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		serialized
	);

	return mysqlx_write_all(client_fd_, frame.data(), frame.size());
}

bool MysqlxFrontendSession::handle_authenticate(MysqlxConfigStore& /* config_store */) {
	// Read AuthenticateContinue from client.
	MysqlxFrameHeader header {};
	std::vector<uint8_t> payload {};

	if (!mysqlx_read_frame(client_fd_, header, payload)) {
		return false;
	}

	if (header.message_type != Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
		mysqlx_send_error(client_fd_, 1045, "Expected AuthenticateContinue");
		return false;
	}

	Mysqlx::Session::AuthenticateContinue auth_continue;
	if (!auth_continue.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
		mysqlx_send_error(client_fd_, 1045, "Invalid AuthenticateContinue");
		return false;
	}

	// Client response is the scrambled auth data.
	const std::string& response_str = auth_continue.auth_data();
	std::vector<uint8_t> client_response(response_str.begin(), response_str.end());

	// Verify MYSQL41 scramble against the stored password.
	if (!mysqlx_mysql41_verify(auth_challenge_, client_response, identity_.backend_password)) {
		mysqlx_send_error(client_fd_, 1045,
			"Access denied for user '" + identity_.username + "'");
		return false;
	}

	// Authentication succeeded — send AuthenticateOk.
	Mysqlx::Session::AuthenticateOk auth_ok;
	std::string serialized;
	auth_ok.SerializeToString(&serialized);

	auto frame = mysqlx_build_frame(
		Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
		serialized
	);

	return mysqlx_write_all(client_fd_, frame.data(), frame.size());
}
