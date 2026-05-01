#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_protocol.h"
#include "mysqlx_stats.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <zstd.h>
#include <lz4.h>

namespace {

constexpr size_t CHALLENGE_LENGTH = 20;

// Hard cap on the amount of bytes a single Compression message is allowed to
// produce after decompression. The X Protocol spec leaves this open-ended;
// without a cap a malicious client could send a tiny compressed payload that
// inflates to multiple gigabytes (zip-bomb / billion-laughs equivalent). We
// pick the same 16 MiB ceiling that MysqlxDataStream already enforces for
// the on-the-wire payload size, so a Compression message can never exceed
// what the rest of the data plane is willing to handle anyway.
constexpr size_t COMPRESSION_MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024;

// Outbound Phase 3: only compress frames whose body is at least this many
// bytes. Below this size, the per-Compression-message overhead (protobuf
// envelope, framing header, fixed compressor block prefix) dwarfs any
// savings, so we send the body verbatim. 50 bytes is the same cutoff the
// upstream MySQL X plugin uses by default.
constexpr size_t COMPRESSION_MIN_OUTPUT_BYTES = 50;
// When max_combine_messages is unset by the client (zero), default to a
// modest cap so we never let the outbound batch grow unboundedly while
// waiting for more frames.
constexpr uint32_t COMPRESSION_DEFAULT_MAX_COMBINE = 64;

// Push a uint32 little-endian payload size + 1-byte msg type + body into a
// flat buffer in the same wire layout MysqlxDataStream::enqueue_frame()
// produces. Used to re-frame a decompressed single message before feeding
// it back through MysqlxDataStream::feed_bytes() so the frame parser can
// pick it up as if it had arrived directly from the network.
void append_x_frame(std::vector<uint8_t>& out, uint8_t msg_type,
                    const uint8_t* body, size_t body_len) {
	uint32_t payload_size = static_cast<uint32_t>(body_len) + 1;
	out.push_back(static_cast<uint8_t>(payload_size & 0xFF));
	out.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF));
	out.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF));
	out.push_back(msg_type);
	if (body_len > 0 && body) {
		out.insert(out.end(), body, body + body_len);
	}
}

uint64_t monotonic_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

// Derive the 20-byte mysql_native_password hash from the stored form.
// Accepts either the "*HEX40" mysql_native_password format or a cleartext
// password. Returns false on any failure; in that case `out` is cleared.
bool derive_stored_hash(const std::string& stored, std::vector<uint8_t>& out) {
	out.clear();
	if (stored.empty()) return false;
	if (stored[0] == '*') {
		if (!mysqlx_hex_decode(stored.substr(1), out) || out.size() != 20) {
			out.clear();
			return false;
		}
		return true;
	}
	auto hash = mysqlx_mysql41_hash(stored);
	if (hash.size() != 20) return false;
	out.assign(hash.begin(), hash.end());
	return true;
}

}

MysqlxSession::MysqlxSession()
	: backend_conn_(nullptr)
	, thread_ptr_(nullptr)
	, to_process(false)
	, status_(NONE)
	, healthy(true)
	, target_hostgroup_(0)
	, target_port_(0)
	, target_use_ssl_(false)
	, start_time_(0)
	, last_active_time_(0)
	, response_state_(RESP_IDLE)
	, tls_mode_(TLS_OFF)
	, compression_algo_(MYSQLX_COMPR_NONE)
	, compression_combine_mixed_messages_(false)
	, compression_max_combine_messages_(0)
	, zstd_dctx_(nullptr)
	, zstd_cctx_(nullptr)
	, compress_batch_count_(0)
	, pre_auth_cap_msgs_(0) {
}

MysqlxSession::~MysqlxSession() {
	if (backend_conn_) {
		return_backend_to_pool();
	}
	if (client_ds_.get_fd() >= 0) {
		close(client_ds_.get_fd());
	}
	reset_compression_state();
}

void MysqlxSession::reset_compression_state() {
	if (zstd_dctx_) {
		ZSTD_freeDCtx(zstd_dctx_);
		zstd_dctx_ = nullptr;
	}
	if (zstd_cctx_) {
		ZSTD_freeCCtx(zstd_cctx_);
		zstd_cctx_ = nullptr;
	}
	compress_batch_framed_.clear();
	compress_batch_count_ = 0;
}

void MysqlxSession::init(int fd, Mysqlx_Thread* thread_ptr) {
	client_ds_.init(XDS_FRONTEND, fd);
	client_ds_.set_nonblocking();
	status_ = CONNECTING_CLIENT;
	healthy = true;
	to_process = false;
	thread_ptr_ = thread_ptr;
	backend_conn_ = nullptr;
	target_hostgroup_ = 0;
	target_address_.clear();
	target_port_ = 0;
	target_use_ssl_ = false;
	identity_.reset();
	start_time_ = monotonic_time_ms();
	last_active_time_ = start_time_;
	compression_algo_ = MYSQLX_COMPR_NONE;
	compression_combine_mixed_messages_ = false;
	compression_max_combine_messages_ = 0;
	reset_compression_state();
}

void MysqlxSession::reset() {
	status_ = NONE;
	healthy = true;
	to_process = false;
	username_.clear();
	schema_.clear();
	auth_method_.clear();
	auth_challenge_.clear();
	backend_conn_ = nullptr;
	target_hostgroup_ = 0;
	target_address_.clear();
	target_port_ = 0;
	target_use_ssl_ = false;
	identity_.reset();
	compression_algo_ = MYSQLX_COMPR_NONE;
	compression_combine_mixed_messages_ = false;
	compression_max_combine_messages_ = 0;
	reset_compression_state();
	pre_auth_cap_msgs_ = 0;
}

int MysqlxSession::handler() {
	if (!to_process) return 0;
	to_process = false;

	ssize_t r = client_ds_.read_from_net();
	if (client_ds_.has_parse_error()) {
		healthy = false; return -1;
	}
	if (r == 0) { healthy = false; return -1; }
	if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		healthy = false; return -1;
	}

handler_again:
	switch (status_) {
		case CONNECTING_CLIENT:      handler_connecting_client(); break;
		case X_CAPABILITIES_GET:     handler_capabilities_get(); break;
		case X_CAPABILITIES_SET:     handler_capabilities_set(); break;
		case X_AUTH_START:           handler_auth_start(); break;
		case X_AUTH_CHALLENGE_SENT:  handler_auth_challenge_response(); break;
		case WAITING_CLIENT_XMSG:    handler_waiting_client_msg(); break;
		case CONNECTING_SERVER:      handler_connecting_server(); break;
		case WAITING_SERVER_XMSG:    handler_waiting_server_msg(); break;
		case X_TLS_ACCEPT_INIT:      handler_tls_accept_init(); break;
		case X_SESSION_RESET_WAITING: handler_session_reset_waiting(); break;
		case X_SESSION_CLOSING:      handler_session_closing(); break;
		default: break;
	}

	if (to_process) {
		to_process = false;
		goto handler_again;
	}

	ssize_t wr = client_ds_.write_to_net();
	if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		healthy = false;
		return -1;
	}
	return 0;
}

uint8_t MysqlxSession::extract_msg_type_from_frame(const MysqlxFrame& frame) {
	if (frame.size() < 5) return 0;
	return frame[4];
}

void MysqlxSession::forward_frame_to_client(uint8_t msg_type, const MysqlxFrame& frame) {
	// Phase 3: route data-plane server frames through the compressor.
	// send_to_client_compressed() is a no-op pass-through when
	// compression isn't negotiated or the body is below the threshold.
	if (frame.size() > 5) {
		send_to_client_compressed(msg_type, frame.data() + 5, frame.size() - 5);
	} else {
		send_to_client_compressed(msg_type, nullptr, 0);
	}
}

void MysqlxSession::handler_connecting_client() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	switch (msg_type) {
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET:
			status_ = X_CAPABILITIES_GET;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET:
			status_ = X_CAPABILITIES_SET;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START:
			status_ = X_AUTH_START;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_CON_CLOSE:
			client_ds_.pop_frame();
			healthy = false;
			break;

		default:
			client_ds_.pop_frame();
			send_error(5000, "Unexpected message during handshake");
			healthy = false;
			break;
	}
}

void MysqlxSession::handler_capabilities_get() {
	if (!client_ds_.has_complete_frame()) return;

	// Bound how many pre-auth capability messages a client can ship per
	// session. Each one runs through frame parsing + send_capabilities()
	// allocations; without a cap, an idle hostile client can pin a
	// worker on the cap-replay path forever. The counter applies only
	// while still pre-auth; post-auth callers (dispatch_client_message
	// → CON_CAPABILITIES_GET) routinely query capabilities and should
	// not trip the bound. status_ == WAITING_CLIENT_XMSG indicates auth
	// completed.
	if (status_ != WAITING_CLIENT_XMSG &&
	    ++pre_auth_cap_msgs_ > MAX_PRE_AUTH_CAP_MSGS) {
		client_ds_.pop_frame();
		send_error(5008, "Too many pre-auth capability messages", true);
		healthy = false;
		return;
	}

	client_ds_.pop_frame();
	send_capabilities();
	status_ = CONNECTING_CLIENT;
}

// Walk the OBJECT-typed `compression` capability the client sent in
// CapabilitiesSet, picking out the algorithm string and the two coalescing
// hints. Returns true if the message was structurally valid AND the requested
// algorithm is one we support; populates *out_algo / *out_combine /
// *out_max_combine in that case. Returns false on any structural issue or
// unsupported algorithm so the caller can emit a 5052 error frame.
//
// Object schema (per X Protocol):
//   compression {
//     algorithm: "zstd_stream" | "lz4_message" | "deflate_stream"
//     server_combine_mixed_messages?: bool   // server -> client coalescing
//     server_max_combine_messages?: uint     // server -> client batch cap
//   }
// We accept the same `combine_mixed_messages` / `max_combine_messages`
// short-form keys that some clients send (mysql-connector-python in
// particular). The MySQL server tolerates both spellings.
static bool parse_compression_capability(
	const Mysqlx::Connection::Capability& cap,
	MysqlxCompressionAlgo* out_algo,
	bool* out_combine,
	uint32_t* out_max_combine)
{
	*out_algo = MYSQLX_COMPR_NONE;
	*out_combine = false;
	*out_max_combine = 0;

	const auto& any = cap.value();
	if (any.type() != Mysqlx::Datatypes::Any::OBJECT) return false;
	const auto& obj = any.obj();

	std::string algo_str;
	bool have_algo = false;
	for (const auto& fld : obj.fld()) {
		const std::string& key = fld.key();
		const auto& val = fld.value();
		if (key == "algorithm") {
			if (val.type() != Mysqlx::Datatypes::Any::SCALAR) return false;
			const auto& sc = val.scalar();
			if (sc.type() != Mysqlx::Datatypes::Scalar::V_STRING) return false;
			algo_str = sc.v_string().value();
			have_algo = true;
		} else if (key == "server_combine_mixed_messages" ||
		           key == "combine_mixed_messages") {
			if (val.type() != Mysqlx::Datatypes::Any::SCALAR) return false;
			const auto& sc = val.scalar();
			if (sc.type() == Mysqlx::Datatypes::Scalar::V_BOOL) {
				*out_combine = sc.v_bool();
			} else {
				return false;
			}
		} else if (key == "server_max_combine_messages" ||
		           key == "max_combine_messages") {
			if (val.type() != Mysqlx::Datatypes::Any::SCALAR) return false;
			const auto& sc = val.scalar();
			if (sc.type() == Mysqlx::Datatypes::Scalar::V_UINT) {
				*out_max_combine = static_cast<uint32_t>(sc.v_unsigned_int());
			} else {
				return false;
			}
		}
		// Unknown sub-keys are silently ignored: forward-compat with future
		// fields the spec may add.
	}

	if (!have_algo) return false;

	if (algo_str == "zstd_stream") {
		*out_algo = MYSQLX_COMPR_ZSTD_STREAM;
		return true;
	}
	if (algo_str == "lz4_message") {
		*out_algo = MYSQLX_COMPR_LZ4_MESSAGE;
		return true;
	}
	// deflate_stream is part of the spec but not implemented here; treat
	// like any other unsupported algorithm.
	return false;
}

void MysqlxSession::handler_capabilities_set() {
	if (!client_ds_.has_complete_frame()) return;

	// Same per-session bound as handler_capabilities_get(); see comment
	// there. Counter only applies pre-auth.
	if (status_ != WAITING_CLIENT_XMSG &&
	    ++pre_auth_cap_msgs_ > MAX_PRE_AUTH_CAP_MSGS) {
		client_ds_.pop_frame();
		send_error(5008, "Too many pre-auth capability messages", true);
		healthy = false;
		return;
	}

	const auto& frame = client_ds_.front_frame();
	if (frame.size() > 5) {
		Mysqlx::Connection::CapabilitiesSet cap_set;
		if (!cap_set.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
			// Malformed CapabilitiesSet body: do NOT fall through to send_ok().
			// A buggy or hostile client that ships unparseable capability
			// payloads must not be told the negotiation succeeded — that
			// would leave the server believing capabilities are in a state
			// the client never actually selected. 5051 is the X Protocol
			// convention for an unrecognized/unparseable capability message.
			client_ds_.pop_frame();
			send_error(5051, "Invalid CapabilitiesSet payload");
			status_ = CONNECTING_CLIENT;
			return;
		}

		// First pass: detect the `compression` capability before TLS so
		// a single CapabilitiesSet message that combines both does not
		// silently drop the compression negotiation. We process TLS
		// in its own pass to preserve the existing handshake-flow
		// invariant (TLS terminates capability negotiation).
		MysqlxCompressionAlgo new_algo = MYSQLX_COMPR_NONE;
		bool new_combine = false;
		uint32_t new_max_combine = 0;
		bool saw_compression = false;
		for (const auto& cap : cap_set.capabilities().capabilities()) {
			if (cap.name() == "compression") {
				saw_compression = true;
				if (!parse_compression_capability(cap, &new_algo,
				                                 &new_combine,
				                                 &new_max_combine)) {
					client_ds_.pop_frame();
					// 5052: Capability prepare failed for ... — the
					// X Protocol convention for an unsupported or
					// malformed capability value.
					send_error(5052, "Capability 'compression' value not supported");
					status_ = CONNECTING_CLIENT;
					return;
				}
				break;
			}
		}

		for (const auto& cap : cap_set.capabilities().capabilities()) {
			if (cap.name() == "tls") {
				client_ds_.pop_frame();
				// Reject TLS upgrade post-auth or on an already-encrypted
				// channel. The X Protocol forbids TLS negotiation after
				// AuthenticateOk, and a second tls=true on an already-TLS
				// channel would desync the state machine (the server
				// expects a fresh handshake; the client expects to keep
				// the existing TLS session). Either case is a hostile or
				// confused client; respond with 5052 and drop the
				// session before driving SSL_do_handshake.
				if (client_ds_.is_encrypted()) {
					send_error(5052, "TLS already negotiated on this session", true);
					healthy = false;
					return;
				}
				if (status_ != CONNECTING_CLIENT &&
				    status_ != X_CAPABILITIES_GET &&
				    status_ != X_CAPABILITIES_SET) {
					send_error(5052, "TLS negotiation not allowed after authentication", true);
					healthy = false;
					return;
				}
				SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
				if (!ctx) {
					send_error(3150, "TLS is not configured on server");
					healthy = false;
					return;
				}
				send_ok();
				status_ = X_TLS_ACCEPT_INIT;
				to_process = true;
				return;
			}
		}

		if (saw_compression) {
			compression_algo_ = new_algo;
			compression_combine_mixed_messages_ = new_combine;
			compression_max_combine_messages_ = new_max_combine;
		}
	}

	client_ds_.pop_frame();
	send_ok();
	status_ = CONNECTING_CLIENT;
}

bool MysqlxSession::enforce_identity_policy() {
	if (!identity_) {
		return true;  // nothing to enforce
	}

	// require_tls: per-user "MYSQL41 / PLAIN must run over TLS".
	// PLAIN already has a hardcoded TLS gate at handle_auth_plain entry;
	// this is the per-user knob that also covers MYSQL41 — operators set
	// require_tls=1 on a row to forbid the (otherwise legal) "MYSQL41
	// over plaintext" path.
	if (identity_->require_tls && !client_ds_.is_encrypted()) {
		send_error(1045, "User requires a TLS connection");
		return false;
	}

	// allowed_auth_methods: per-user whitelist of mechanism names.
	// Empty string preserves the historical "any wired method" default
	// so existing rows don't require a backfill. Non-empty: comma-
	// separated, case-insensitive match against auth_method_.
	if (!identity_->allowed_auth_methods.empty()) {
		const std::string& list = identity_->allowed_auth_methods;
		bool matched = false;
		size_t pos = 0;
		while (pos < list.size()) {
			size_t comma = list.find(',', pos);
			if (comma == std::string::npos) comma = list.size();
			std::string token = list.substr(pos, comma - pos);
			// Trim leading/trailing whitespace.
			while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(token.begin());
			while (!token.empty() && (token.back()  == ' ' || token.back()  == '\t')) token.pop_back();
			if (!token.empty() && strcasecmp(token.c_str(), auth_method_.c_str()) == 0) {
				matched = true;
				break;
			}
			pos = comma + 1;
		}
		if (!matched) {
			send_error(1045, "Authentication mechanism not allowed for user");
			return false;
		}
	}

	return true;
}

void MysqlxSession::handle_auth_mysql41(const std::string& auth_data) {
	size_t first_nul = auth_data.find('\0');
	if (first_nul != std::string::npos) {
		size_t second_nul = auth_data.find('\0', first_nul + 1);
		if (second_nul != std::string::npos) {
			schema_ = auth_data.substr(first_nul + 1, second_nul - first_nul - 1);
			size_t third_nul = auth_data.find('\0', second_nul + 1);
			if (third_nul != std::string::npos) {
				username_ = auth_data.substr(second_nul + 1, third_nul - second_nul - 1);
			} else {
				username_ = auth_data.substr(second_nul + 1);
			}
		}
	}

	auth_challenge_.resize(CHALLENGE_LENGTH);
	RAND_bytes(auth_challenge_.data(), CHALLENGE_LENGTH);

	std::string challenge_str(auth_challenge_.begin(), auth_challenge_.end());
	send_auth_continue(challenge_str);
	status_ = X_AUTH_CHALLENGE_SENT;
}

void MysqlxSession::handle_auth_plain(const std::string& auth_data) {
	if (!client_ds_.is_encrypted()) {
		send_error(1045, "PLAIN authentication requires TLS");
		healthy = false;
		return;
	}

	if (auth_data.empty() || auth_data[0] != '\0') {
		send_error(1045, "Invalid PLAIN auth data");
		healthy = false;
		return;
	}

	size_t second_nul = auth_data.find('\0', 1);
	if (second_nul == std::string::npos) {
		send_error(1045, "Invalid PLAIN auth data format");
		healthy = false;
		return;
	}

	username_ = auth_data.substr(1, second_nul - 1);
	std::string password = auth_data.substr(second_nul + 1);

	if (!identity_lookup_) {
		// No identity source wired — refuse auth rather than falling through
		// to resolve_backend_target() and surfacing a misleading 4002. An
		// unconfigured plugin must not become an open proxy.
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}
	identity_ = identity_lookup_(username_);
	if (!identity_ || !identity_->x_enabled) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	if (!enforce_identity_policy()) {
		healthy = false;
		return;
	}

	std::vector<uint8_t> stored_hash;
	if (!derive_stored_hash(identity_->password, stored_hash)) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	std::vector<uint8_t> input_hash_vec = mysqlx_mysql41_hash(password);
	if (input_hash_vec.size() != 20 ||
	    CRYPTO_memcmp(input_hash_vec.data(), stored_hash.data(), 20) != 0) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	// Resolve the user's default_route to a concrete backend target
	// BEFORE sending the X-Protocol Ok frame. If this is skipped or
	// deferred until after Ok, the client would see a successful
	// authentication response and then the session would attempt to
	// connect to an empty host on port 0 (or some other broken state).
	// A routing failure here surfaces as an X-Protocol Error frame and
	// transitions the session to X_SESSION_CLOSING; the client never
	// reaches a "logged in" state against an unresolvable backend.
	if (resolve_backend_target() != 0) {
		status_ = X_SESSION_CLOSING;
		return;
	}

	last_active_time_ = monotonic_time_ms();
	send_auth_ok();
	status_ = WAITING_CLIENT_XMSG;
}

void MysqlxSession::handler_auth_start() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	if (msg_type != Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START) {
		send_error(1045, "Expected AuthenticateStart");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	if (frame.size() <= 5) {
		send_error(1045, "Empty AuthenticateStart payload");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	Mysqlx::Session::AuthenticateStart auth_start;
	if (!auth_start.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		send_error(1045, "Invalid AuthenticateStart message");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	client_ds_.pop_frame();
	auth_method_ = auth_start.mech_name();

	if (auth_method_ == "MYSQL41") {
		handle_auth_mysql41(auth_start.auth_data());
	} else if (auth_method_ == "PLAIN") {
		handle_auth_plain(auth_start.auth_data());
	} else {
		send_error(1251, "Unsupported authentication method");
		healthy = false;
	}
}

void MysqlxSession::handler_auth_challenge_response() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	if (msg_type != Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
		send_error(1045, "Expected AuthenticateContinue");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	if (frame.size() <= 5) {
		send_error(1045, "Empty auth response");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	Mysqlx::Session::AuthenticateContinue auth_cont;
	if (!auth_cont.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		send_error(1045, "Invalid auth response");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	client_ds_.pop_frame();

	const std::string& auth_data = auth_cont.auth_data();
	if (auth_data.size() > 1 && auth_data[0] == '*') {
		std::string hex_scramble = auth_data.substr(1);
		std::vector<uint8_t> scramble;
		if (!mysqlx_hex_decode(hex_scramble, scramble) || scramble.size() != 20) {
			send_error(1045, "Invalid scramble format", true);
			healthy = false;
			return;
		}

		if (!identity_lookup_) {
			// See handle_auth_plain — refuse auth when no identity source is
			// configured rather than skipping credential verification.
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}
		identity_ = identity_lookup_(username_);
		if (!identity_ || !identity_->x_enabled) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}

		if (!enforce_identity_policy()) {
			healthy = false;
			return;
		}

		std::vector<uint8_t> stored_hash;
		if (!derive_stored_hash(identity_->password, stored_hash)) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}

		if (!mysqlx_mysql41_verify_hash(auth_challenge_, scramble, stored_hash)) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}
	} else {
		// Malformed AuthenticateContinue: data missing the "*hex" marker.
		// Reject as FATAL rather than falling through to
		// resolve_backend_target() and surfacing a misleading 4002.
		send_error(1045, "Access denied for user", true);
		healthy = false;
		return;
	}

	// Resolve the user's default_route to a concrete backend target
	// BEFORE sending the X-Protocol Ok frame. See handle_auth_plain for
	// the full rationale; the same invariant holds on the MYSQL41 path.
	// to_process is kept true on the failure branch so the session state
	// machine drives itself to X_SESSION_CLOSED on the next handler tick.
	if (resolve_backend_target() != 0) {
		status_ = X_SESSION_CLOSING;
		to_process = true;
		return;
	}

	// Defense in depth: clear the verified challenge so a stale value
	// cannot be re-used by a misbehaving client. Combined with the
	// re-auth rejection in dispatch_client_message, this leaves no
	// path for AuthenticateContinue to be replayed against the same
	// challenge after AuthenticateOk.
	auth_challenge_.clear();

	last_active_time_ = monotonic_time_ms();
	send_auth_ok();
	status_ = WAITING_CLIENT_XMSG;
	to_process = true;
}

int MysqlxSession::dispatch_client_message(uint8_t msg_type) {
	// Re-authentication on an established session is not supported. The
	// X Protocol uses Mysqlx::Session::Reset for that purpose; a direct
	// AUTHENTICATE_START/CONTINUE after the session is already in
	// WAITING_CLIENT_XMSG would otherwise overwrite username_,
	// identity_, target_hostgroup_, target_address_, target_port_ —
	// without tearing down backend_conn_, so the next StmtExecute would
	// be forwarded over the previous user's pooled backend connection.
	// That is an identity-coherence / audit hazard (the proxy bills the
	// query as user B while the backend executes it as user A's role).
	// Reject explicitly with a fatal error and drop the session.
	if ((msg_type == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START ||
	     msg_type == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE) &&
	    status_ == WAITING_CLIENT_XMSG) {
		client_ds_.pop_frame();
		send_error(1845, "Re-authentication is not supported on an active session; "
		                 "use Mysqlx::Session::Reset to start a new session", true);
		status_ = X_SESSION_CLOSING;
		healthy = false;
		return -1;
	}
	switch (msg_type) {
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET:
			handler_capabilities_get(); return 0;
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET:
			handler_capabilities_set(); return 0;
		case Mysqlx::ClientMessages_Type_CON_CLOSE:
		case Mysqlx::ClientMessages_Type_SESS_CLOSE:
			client_ds_.pop_frame();
			status_ = X_SESSION_CLOSING; healthy = false;
			to_process = true; return 0;
		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START:
			handler_auth_start(); return 0;
		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE:
			handler_auth_challenge_response(); return 0;
		case Mysqlx::ClientMessages_Type_SESS_RESET:
			response_state_ = RESP_WAITING_SESS_RESET;
			forward_to_backend();
			status_ = X_SESSION_RESET_WAITING;
			to_process = true;
			return 0;
		case Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE:
			response_state_ = RESP_WAITING_STMT_EXECUTE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CRUD_FIND:
		case Mysqlx::ClientMessages_Type_CRUD_INSERT:
		case Mysqlx::ClientMessages_Type_CRUD_UPDATE:
		case Mysqlx::ClientMessages_Type_CRUD_DELETE:
		case Mysqlx::ClientMessages_Type_CRUD_CREATE_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_MODIFY_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_DROP_VIEW:
			response_state_ = RESP_WAITING_CRUD;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_PREPARE:
			if (backend_conn_) backend_conn_->set_has_prepared_statement(true);
			response_state_ = RESP_WAITING_PREPARE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_EXECUTE:
		case Mysqlx::ClientMessages_Type_PREPARE_DEALLOCATE:
			response_state_ = RESP_WAITING_PREPARE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_OPEN:
		case Mysqlx::ClientMessages_Type_CURSOR_FETCH:
		case Mysqlx::ClientMessages_Type_CURSOR_CLOSE:
			response_state_ = RESP_WAITING_CURSOR;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_EXPECT_OPEN:
		case Mysqlx::ClientMessages_Type_EXPECT_CLOSE:
			response_state_ = RESP_WAITING_EXPECT;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_COMPRESSION:
			// Phase 2: when compression has been negotiated, decompress
			// the payload, feed the resulting bytes back into client_ds_'s
			// frame parser, and re-enter the dispatch loop on the next
			// handler tick. handle_compression_message() already pops the
			// frame on every path (success and failure) and sets to_process
			// when there are decompressed frames to dispatch.
			if (compression_algo_ == MYSQLX_COMPR_NONE) {
				client_ds_.pop_frame();
				send_error(5008, "Compression is not supported");
				return 0;
			}
			return handle_compression_message();
		default:
			client_ds_.pop_frame();
			send_error(5000, "Unknown message type", true);
			status_ = X_SESSION_CLOSING; healthy = false;
			return -1;
	}
}

void MysqlxSession::handler_waiting_client_msg() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	dispatch_client_message(msg_type);
}

void MysqlxSession::forward_to_backend() {
	if (server_ds().get_status() != XDS_READY) {
		if (!backend_conn_ || backend_conn_->get_state() != MysqlxConnection::IDLE) {
			status_ = CONNECTING_SERVER;
			to_process = true;
			return;
		}
		server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
	}

	if (client_ds_.has_complete_frame()) {
		const auto& frame = client_ds_.front_frame();
		if (frame.size() > 5) {
			server_ds().enqueue_frame(frame[4], frame.data() + 5, frame.size() - 5);
		} else {
			server_ds().enqueue_frame(frame[4], nullptr, 0);
		}
		client_ds_.pop_frame();
	}

	server_ds().write_to_net();
	status_ = WAITING_SERVER_XMSG;
}

namespace {

bool is_terminal_server_frame_generic(uint8_t msg_type) {
	switch (msg_type) {
		case Mysqlx::ServerMessages_Type_OK:
		case Mysqlx::ServerMessages_Type_ERROR:
		case Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_RESULTSETS:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS:
			return true;
		default:
			return false;
	}
}

}

bool MysqlxSession::is_terminal_for_state(uint8_t msg_type) const {
	if (msg_type == Mysqlx::ServerMessages_Type_ERROR) return true;

	switch (response_state_) {
		case RESP_WAITING_STMT_EXECUTE:
			return msg_type == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE;
		case RESP_WAITING_CRUD:
			return msg_type == Mysqlx::ServerMessages_Type_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_PREPARE:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_CURSOR:
			return msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_EXPECT:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_SESS_RESET:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		default:
			return is_terminal_server_frame_generic(msg_type);
	}
}

void MysqlxSession::handler_waiting_server_msg() {
	if (server_ds().get_fd() < 0) {
		// server_ds fd is -1 means we lost the backend out-of-band
		// (close, error, premature stream reset). Don't put it in the
		// pool as if it were healthy; is_reusable() will refuse it
		// even if we did, but be explicit at the call site too.
		if (backend_conn_) backend_conn_->set_reusable(false);
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	ssize_t r = server_ds().read_from_net();
	if (r == 0) {
		send_error(2013, "Lost connection to backend during query");
		// Mark non-reusable so return_backend_to_pool deletes the
		// connection instead of caching a dead socket. Without this,
		// the next session that pulls from the pool gets a backend
		// whose fd is closed / EOF.
		if (backend_conn_) backend_conn_->set_reusable(false);
		return_backend_to_pool();
		healthy = false;
		return;
	}
	if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		send_error(2013, "Backend read error during query");
		if (backend_conn_) backend_conn_->set_reusable(false);
		return_backend_to_pool();
		healthy = false;
		return;
	}

	bool got_terminal = false;
	while (server_ds().has_complete_frame()) {
		const auto& frame = server_ds().front_frame();
		uint8_t msg_type = frame[4];

		forward_frame_to_client(msg_type, frame);
		server_ds().pop_frame();

		if (msg_type != Mysqlx::ServerMessages_Type_NOTICE &&
		    is_terminal_for_state(msg_type)) {
			got_terminal = true;
		}
	}

	if (got_terminal) {
		// Phase 3: drain any pending batched-Compression frames before
		// we write to the wire. The terminal frame is the natural end
		// of the response, so the client expects everything we've
		// accumulated this round to be visible by the time we go back
		// to WAITING_CLIENT_XMSG. Mid-response (no terminal) we let the
		// batch sit so combine_mixed_messages can actually coalesce
		// across rows; the count cap in send_to_client_compressed()
		// bounds how long any single batch can grow.
		flush_compression_batch();
		response_state_ = RESP_IDLE;
		client_ds_.write_to_net();
		return_backend_to_pool();
		last_active_time_ = monotonic_time_ms();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
	}
}

void MysqlxSession::handler_session_reset_waiting() {
	if (server_ds().get_fd() < 0) {
		if (backend_conn_) backend_conn_->set_reusable(false);
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	ssize_t r = server_ds().read_from_net();
	if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		// Backend died while waiting for the SESS_RESET response — treat
		// the connection as dead, don't recycle it.
		if (backend_conn_) backend_conn_->set_reusable(false);
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	while (server_ds().has_complete_frame()) {
		const auto& frame = server_ds().front_frame();
		uint8_t msg_type = frame[4];

		if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) {
			forward_frame_to_client(msg_type, frame);
			server_ds().pop_frame();
			continue;
		}

		if (msg_type == Mysqlx::ServerMessages_Type_OK) {
			server_ds().pop_frame();
			if (backend_conn_) {
				backend_conn_->set_has_prepared_statement(false);
				backend_conn_->set_in_transaction(false);
			}
			return_backend_to_pool();
			last_active_time_ = monotonic_time_ms();
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		if (msg_type == Mysqlx::ServerMessages_Type_ERROR) {
			forward_frame_to_client(msg_type, frame);
			server_ds().pop_frame();
			// Phase 3: drain the compression batch before writing to
			// the wire — same reasoning as handler_waiting_server_msg.
			flush_compression_batch();
			client_ds_.write_to_net();
			return_backend_to_pool();
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		server_ds().pop_frame();
	}
}

void MysqlxSession::handler_session_closing() {
	return_backend_to_pool();
	healthy = false;
	status_ = X_SESSION_CLOSED;
}

void MysqlxSession::handler_tls_accept_init() {
	if (!client_ds_.ssl_init_done()) {
		SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
		if (!ctx) {
			send_error(3150, "TLS is not configured on server");
			healthy = false;
			return;
		}
		client_ds_.init_ssl(ctx);
	}
	if (!client_ds_.do_ssl_handshake()) {
		if (client_ds_.ssl_handshake_failed()) {
			char err_buf[256];
			unsigned long ssl_err = ERR_get_error();
			if (ssl_err != 0) {
				ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
			} else {
				snprintf(err_buf, sizeof(err_buf), "Unknown TLS error");
			}
			send_error(3151, "TLS handshake failed");
			healthy = false;
			return;
		}
		return;
	}
	status_ = CONNECTING_CLIENT;
	to_process = true;
}

// Translate the authenticated user's identity_->default_route into the
// concrete (target_hostgroup_, target_address_, target_port_) triple that
// handler_connecting_server uses to reach the backend. Invariant: called
// only after the auth handler has populated identity_; missing identity is
// therefore treated as a no-backend programming error (4002) rather than
// an auth failure. The pre-Ok timing matters — once the X-Protocol Ok
// frame is on the wire, there is no clean way to report a routing error,
// so all three failure modes return a nonzero code here and leave the
// caller responsible for sending Error + transitioning to closing state.
int MysqlxSession::resolve_backend_target() {
	if (!identity_) {
		send_error(4002, "No backend available: missing identity");
		mysqlx_stats().record_conn_err("", 0);
		healthy = false;
		return 4002;
	}

	const std::string& route_name = identity_->default_route;
	if (route_name.empty()) {
		send_error(4000, "User has no default_route configured");
		mysqlx_stats().record_conn_err("", 0);
		healthy = false;
		return 4000;
	}

	const MysqlxConfigStore* cs = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
	if (!cs) {
		// Config store unavailable: structurally indistinguishable from a
		// route with no backend from the client's perspective.
		send_error(4002, "No backend available: config store unavailable");
		mysqlx_stats().record_conn_err(route_name, 0);
		healthy = false;
		return 4002;
	}

	if (!cs->route_exists(route_name)) {
		// Distinguished from the no-backend case (4002) via route_exists():
		// route_hostgroup() alone returns 0 for both unknown routes and
		// routes deliberately pointed at hostgroup 0.
		std::string msg = "Route '";
		msg += route_name;
		msg += "' not found";
		send_error(4001, msg.c_str());
		mysqlx_stats().record_conn_err(route_name, 0);
		healthy = false;
		return 4001;
	}

	int hg = cs->route_hostgroup(route_name);
	MysqlxBackendEndpoint ep = cs->pick_endpoint(route_name);
	if (ep.hostname.empty()) {
		std::string msg = "No backend available for route '";
		msg += route_name;
		msg += "'";
		send_error(4002, msg.c_str());
		mysqlx_stats().record_conn_err(route_name, hg);
		healthy = false;
		return 4002;
	}

	target_hostgroup_ = hg;
	target_address_   = ep.hostname;
	target_port_      = ep.mysqlx_port;
	target_use_ssl_   = ep.use_ssl;
	return 0;
}

#ifdef MYSQLX_TEST_BUILD
// Test-only convenience overload. Mirrors what the auth handler does on a
// real client connection: look up the identity via the thread's config
// store, caching the result in identity_. Silently no-ops if the thread
// has no store or the username is unknown, since tests exercising those
// edge cases set up identity_ directly via the other overload.
void MysqlxSession::inject_identity_for_test(const std::string& username) {
	if (!thread_ptr_) return;
	const MysqlxConfigStore* cs = thread_ptr_->get_config_store();
	if (!cs) return;
	auto id = cs->resolve_identity(username);
	if (id) identity_ = *id;
}
#endif /* MYSQLX_TEST_BUILD */

void MysqlxSession::handler_connecting_server() {
	if (!backend_conn_) {
		if (thread_ptr_) {
			backend_conn_ = thread_ptr_->get_connection_from_cache(
				target_hostgroup_, username_.c_str(), schema_.c_str());
		}

		if (backend_conn_) {
			server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		backend_conn_ = new MysqlxConnection();
		backend_conn_->set_hostgroup(target_hostgroup_);
		backend_conn_->set_user(username_.c_str());
		backend_conn_->set_schema(schema_.c_str());
		backend_conn_->set_connect_timeout(10000);

		int rc = backend_conn_->start_connect(target_address_.c_str(), target_port_);
		if (rc == -1) {
			send_error(2003, "Can't connect to backend");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
		if (rc == 1) {
			return;
		}
	}

	if (backend_conn_ && backend_conn_->get_state() == MysqlxConnection::CONNECTING) {
		int rc = backend_conn_->check_connect();
		if (rc == 1) return;
		if (rc == -1) {
			send_error(2003, "Backend connect failed");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	if (backend_conn_ && backend_conn_->get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED) {
		backend_conn_->init_backend_ds(backend_conn_->get_fd());

		// Pick the backend username consistently with the backend password
		// sourced from identity_->backend_password. When backend_auth_mode
		// is `service_account` the mysqlx_users row carries a distinct
		// backend_username; in `mapped` mode (the default) that field is
		// empty and the frontend username_ is reused verbatim. Using the
		// frontend username here while passing the resolved backend password
		// below would pair userA's password with userB's name for
		// service-account rows — backend auth would then fail with
		// access-denied even though both columns are internally consistent.
		// See the MysqlxBackendAuthMode enum in mysqlx_config_store.h for
		// the full set of modes and their semantics.
		const std::string& backend_user =
			(identity_ && !identity_->backend_username.empty())
				? identity_->backend_username
				: username_;
		backend_conn_->set_backend_user(backend_user.c_str());
		backend_conn_->set_backend_schema(schema_.c_str());

		// Backend TLS is enabled when EITHER the operator forced it via
		// the endpoint's use_ssl=1 flag (mysqlx_backend_endpoints.
		// use_ssl, captured into target_use_ssl_ at
		// resolve_backend_target time) OR the client connected to the
		// proxy over TLS. The endpoint-flag path lets operators mandate
		// proxy↔backend encryption even for plaintext clients on a
		// trusted private network — previously the flag was loaded into
		// MysqlxBackendEndpoint but silently dropped here, so plaintext
		// clients always produced plaintext backend traffic regardless
		// of the operator's setting.
		const bool require_backend_tls = target_use_ssl_ || client_ds_.is_encrypted();
		if (require_backend_tls) {
			if (thread_ptr_ && thread_ptr_->get_ssl_ctx()) {
				backend_conn_->set_backend_tls_required(true);
				backend_conn_->set_ssl_ctx(thread_ptr_->get_ssl_ctx());
			}
		}

		if (identity_) {
			backend_conn_->set_backend_password(identity_->backend_password.c_str());
		}
	}

	if (backend_conn_ && backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_DONE &&
	    backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_ERROR) {
		int auth_rc = backend_conn_->step_auth();
		if (auth_rc == 1) {
			return;
		}
		if (auth_rc == -1) {
			if (backend_conn_->get_auth_state() == MysqlxConnection::BACKEND_AUTH_TLS_HANDSHAKE ||
			    backend_conn_->backend_ds().ssl_handshake_failed()) {
				send_error(3152, "Backend TLS handshake failed");
			} else {
				send_error(1045, "Backend authentication failed");
			}
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
	backend_conn_->set_state(MysqlxConnection::IDLE);
	backend_conn_->set_reusable(true);
	status_ = WAITING_CLIENT_XMSG;
	to_process = true;
}

void MysqlxSession::return_backend_to_pool() {
	if (!backend_conn_) return;
	if (thread_ptr_) {
		thread_ptr_->return_connection_to_cache(backend_conn_);
	} else {
		delete backend_conn_;
	}
	backend_conn_ = nullptr;
	// server_ds() now falls through to server_ds_placeholder_ (fd=-1) once
	// backend_conn_ is cleared. The placeholder carries no data-plane state,
	// so no reset is needed.
}

void MysqlxSession::shutdown_notify_client() {
	// Best-effort: enqueue a fatal X-Protocol error frame, then push the
	// queued bytes to the wire. Skip if the client write side is already
	// gone (fd <0) or if the session is already closing. Both branches
	// are reachable in normal lifecycle and we don't want shutdown to
	// hang on a half-closed peer.
	if (client_ds_.get_fd() < 0) return;
	if (status_ == X_SESSION_CLOSED || status_ == X_SESSION_CLOSING) {
		return;
	}
	send_error(1053, "Server is shutting down", /*fatal=*/true);
	// Drain the queued frame to the wire. Best-effort: a single
	// write_to_net() pass — if the client is unresponsive we don't want
	// shutdown to block.
	client_ds_.write_to_net();
	// If TLS is active, ask OpenSSL to send close_notify so the peer's
	// TLS stack sees a clean shutdown rather than a torn-down record.
	// SSL_set_quiet_shutdown(1) suppresses the bidirectional handshake
	// — appropriate during process exit when waiting for the peer's
	// close_notify is undesirable.
	if (SSL* ssl = client_ds_.get_ssl()) {
		SSL_set_quiet_shutdown(ssl, 1);
		SSL_shutdown(ssl);
	}
	status_ = X_SESSION_CLOSING;
	healthy = false;
}

void MysqlxSession::send_error(int code, const char* msg, bool fatal) {
	Mysqlx::Error err;
	err.set_code(code);
	err.set_severity(fatal ? Mysqlx::Error::FATAL : Mysqlx::Error::ERROR);
	err.set_sql_state("HY000");
	err.set_msg(msg);
	std::string s;
	err.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_ok(const char* msg) {
	Mysqlx::Ok ok;
	ok.set_msg(msg);
	std::string s;
	ok.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_OK,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_auth_continue(const std::string& auth_data) {
	Mysqlx::Session::AuthenticateContinue auth_cont;
	auth_cont.set_auth_data(auth_data);
	std::string s;
	auth_cont.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_auth_ok() {
	Mysqlx::Session::AuthenticateOk auth_ok;
	std::string s;
	auth_ok.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_capabilities() {
	Mysqlx::Connection::Capabilities caps;
	auto* auth_cap = caps.add_capabilities();
	auth_cap->set_name("authentication.mechanisms");
	auth_cap->mutable_value()->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = auth_cap->mutable_value()->mutable_array();

	auto* v1 = arr->add_value();
	v1->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v1->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v1->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");

	auto* v2 = arr->add_value();
	v2->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v2->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v2->mutable_scalar()->mutable_v_string()->set_value("PLAIN");

	SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
	if (ctx) {
		auto* tls_cap = caps.add_capabilities();
		tls_cap->set_name("tls");
		auto* tls_val = tls_cap->mutable_value();
		tls_val->set_type(Mysqlx::Datatypes::Any::SCALAR);
		tls_val->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_BOOL);
		tls_val->mutable_scalar()->set_v_bool(true);
	}

	// Advertise compression. Per the X Protocol contract, the value is an
	// OBJECT carrying an `algorithm` array — clients pick one entry from
	// that array and echo it back via CapabilitiesSet.algorithm. We list
	// the algorithms in the order we'd like clients to prefer; both
	// libzstd and liblz4 are statically linked into the plugin already.
	{
		auto* cmp_cap = caps.add_capabilities();
		cmp_cap->set_name("compression");
		auto* obj_val = cmp_cap->mutable_value();
		obj_val->set_type(Mysqlx::Datatypes::Any::OBJECT);
		auto* obj = obj_val->mutable_obj();

		auto* algo_field = obj->add_fld();
		algo_field->set_key("algorithm");
		auto* algo_any = algo_field->mutable_value();
		algo_any->set_type(Mysqlx::Datatypes::Any::ARRAY);
		auto* algo_arr = algo_any->mutable_array();

		auto add_algo = [&](const char* name) {
			auto* v = algo_arr->add_value();
			v->set_type(Mysqlx::Datatypes::Any::SCALAR);
			v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
			v->mutable_scalar()->mutable_v_string()->set_value(name);
		};
		add_algo("zstd_stream");
		add_algo("lz4_message");
	}

	std::string s;
	caps.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// Decompress the payload of a Mysqlx.Connection.Compression message and
// re-inject the result into client_ds_'s frame parser so the existing
// dispatch loop processes it on the next handler tick. Pops the
// compression frame on every path (success or failure) and returns 0 to
// match the dispatch_client_message() contract.
//
// Three payload shapes per spec:
//   1. server_messages set: payload is a single decompressed server
//      message of that type. NEVER expected on the client→server path —
//      reject with 5008.
//   2. client_messages set: payload is a single decompressed client
//      message of that type. We re-frame with that type byte and feed
//      it back through client_ds_.feed_bytes().
//   3. neither set: payload is a sequence of zero or more fully-framed
//      messages (each with its own 5-byte X header). Feed the raw
//      decompressed bytes back through feed_bytes(); the parser will
//      pick up each frame in sequence.
//
// Anti-bomb: hard-cap the decompressed size at the smaller of
// uncompressed_size (when set) and COMPRESSION_MAX_DECOMPRESSED_BYTES.
// Returns -1 on any failure path so the caller can short-circuit, but
// we already emit the X-Protocol Error frame here.
int MysqlxSession::handle_compression_message() {
	const auto& frame = client_ds_.front_frame();
	if (frame.size() <= 5) {
		client_ds_.pop_frame();
		send_error(5008, "Empty Compression message");
		return 0;
	}

	Mysqlx::Connection::Compression cmsg;
	if (!cmsg.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		client_ds_.pop_frame();
		send_error(5008, "Invalid Compression message");
		return 0;
	}
	const std::string& payload = cmsg.payload();
	client_ds_.pop_frame();

	if (cmsg.has_server_messages()) {
		// Server-direction compression on the client→server path is
		// always wrong: only the server is supposed to set
		// server_messages, and only when sending to the client.
		send_error(5008, "Compression message has server_messages on client→server path");
		return 0;
	}

	// Compute the size cap for this message.
	size_t cap = COMPRESSION_MAX_DECOMPRESSED_BYTES;
	if (cmsg.has_uncompressed_size()) {
		uint64_t hint = cmsg.uncompressed_size();
		if (hint == 0) {
			// Hint of 0 with a non-empty payload is malformed; treat
			// as a parse error rather than letting it through.
			send_error(5008, "Compression: uncompressed_size hint is 0");
			return 0;
		}
		if (hint < cap) cap = static_cast<size_t>(hint);
	}

	// Decompress into a flat buffer. Picked sizing rationale:
	//   - zstd: use a working buffer that grows in 64 KiB chunks until
	//     either the stream finishes or we hit `cap`.
	//   - lz4_message: one-shot; allocate exactly `cap` bytes (LZ4 has
	//     no streaming context for the per-message variant).
	std::vector<uint8_t> decompressed;
	if (compression_algo_ == MYSQLX_COMPR_LZ4_MESSAGE) {
		// Allocate cap bytes; LZ4_decompress_safe writes at most
		// dstCapacity, so this naturally enforces the size limit.
		decompressed.resize(cap);
		int produced = LZ4_decompress_safe(payload.data(),
		                                   reinterpret_cast<char*>(decompressed.data()),
		                                   static_cast<int>(payload.size()),
		                                   static_cast<int>(cap));
		if (produced < 0) {
			send_error(5008, "Compression: lz4 decompression failed");
			return 0;
		}
		decompressed.resize(static_cast<size_t>(produced));
	} else if (compression_algo_ == MYSQLX_COMPR_ZSTD_STREAM) {
		if (!zstd_dctx_) {
			zstd_dctx_ = ZSTD_createDCtx();
			if (!zstd_dctx_) {
				send_error(5008, "Compression: out of memory");
				return 0;
			}
		}
		ZSTD_inBuffer zin{ payload.data(), payload.size(), 0 };
		// Reserve a starting chunk to amortize realloc cost. The recommended
		// ZSTD output block size is ~128 KiB; we cap each grow step at that.
		const size_t grow_step = ZSTD_DStreamOutSize();
		while (zin.pos < zin.size) {
			if (decompressed.size() >= cap) {
				// Hit the cap — bail out before zstd writes more.
				send_error(5008, "Compression: decompressed payload exceeds cap");
				return 0;
			}
			size_t old_sz = decompressed.size();
			size_t new_sz = old_sz + grow_step;
			if (new_sz > cap) new_sz = cap;
			decompressed.resize(new_sz);

			ZSTD_outBuffer zout{ decompressed.data() + old_sz,
			                     new_sz - old_sz, 0 };
			size_t r = ZSTD_decompressStream(zstd_dctx_, &zout, &zin);
			decompressed.resize(old_sz + zout.pos);
			if (ZSTD_isError(r)) {
				send_error(5008, "Compression: zstd decompression failed");
				return 0;
			}
			if (zout.pos == 0 && zin.pos < zin.size) {
				// No forward progress despite remaining input; would
				// otherwise be an infinite loop. Treat as a corrupt
				// stream and bail.
				send_error(5008, "Compression: zstd stalled (no progress)");
				return 0;
			}
		}
	} else {
		// Negotiated to NONE somehow; we've already filtered NONE in the
		// dispatch site, so this is a defensive branch only.
		send_error(5008, "Compression algorithm not initialized");
		return 0;
	}

	// Re-inject the decompressed bytes into the frame parser. Two shapes:
	//   - client_messages set: payload is a SINGLE message body of that
	//     type. Wrap it in a 5-byte X-frame header before feeding so the
	//     parser sees a normal frame.
	//   - neither: payload is already a sequence of full X-frames. Feed
	//     verbatim.
	if (cmsg.has_client_messages()) {
		uint8_t msg_type = static_cast<uint8_t>(cmsg.client_messages());
		std::vector<uint8_t> framed;
		framed.reserve(5 + decompressed.size());
		append_x_frame(framed, msg_type, decompressed.data(), decompressed.size());
		client_ds_.feed_bytes(framed.data(), framed.size());
	} else {
		client_ds_.feed_bytes(decompressed.data(), decompressed.size());
	}

	if (client_ds_.has_parse_error()) {
		// Decompressed bytes did not yield valid X frames. Signal the
		// session as unhealthy so we close cleanly.
		send_error(5008, "Compression: decompressed payload is malformed");
		healthy = false;
		return -1;
	}

	if (client_ds_.has_complete_frame()) {
		// Drive the dispatch loop on the next tick so the just-decoded
		// frames are processed without blocking on more network I/O.
		to_process = true;
	}
	return 0;
}

// ---------------------------------------------------------------------------
// Phase 3: outbound compression helpers
//
// Decision matrix in send_to_client_compressed():
//
//   compression_algo_ == NONE                 → enqueue verbatim
//   body_len < MIN_OUTPUT_BYTES               → enqueue verbatim (overhead
//                                                wins below the threshold)
//   combine_mixed_messages == false           → emit_single_compressed():
//                                                wrap one body in a
//                                                Compression message with
//                                                server_messages set
//   combine_mixed_messages == true            → buffer the framed body in
//                                                compress_batch_framed_;
//                                                flush either when the
//                                                count cap is hit OR the
//                                                caller invokes
//                                                flush_compression_batch()
//                                                at the end of a draining
//                                                round
//
// On any compressor error (out of memory, ZSTD_isError, lz4 returning <=
// 0) we fall back to enqueueing the body uncompressed — losing the
// compression benefit beats dropping the message. The session itself
// stays healthy.
// ---------------------------------------------------------------------------

bool MysqlxSession::emit_single_compressed(uint8_t msg_type, const uint8_t* body, size_t body_len) {
	std::string compressed;
	if (compression_algo_ == MYSQLX_COMPR_LZ4_MESSAGE) {
		int bound = LZ4_compressBound(static_cast<int>(body_len));
		if (bound <= 0) return false;
		compressed.resize(static_cast<size_t>(bound));
		int produced = LZ4_compress_default(
			reinterpret_cast<const char*>(body),
			compressed.data(),
			static_cast<int>(body_len),
			bound);
		if (produced <= 0) return false;
		compressed.resize(static_cast<size_t>(produced));
	} else if (compression_algo_ == MYSQLX_COMPR_ZSTD_STREAM) {
		if (!zstd_cctx_) {
			zstd_cctx_ = ZSTD_createCCtx();
			if (!zstd_cctx_) return false;
		}
		// One-shot compress is fine here: the spec lets us start a fresh
		// zstd frame per Compression message as long as the decompressor
		// can handle the concatenation, which the streaming decompressor
		// on the client side does.
		size_t bound = ZSTD_compressBound(body_len);
		if (ZSTD_isError(bound)) return false;
		compressed.resize(bound);
		size_t produced = ZSTD_compressCCtx(zstd_cctx_,
		                                   compressed.data(), compressed.size(),
		                                   body, body_len, 3);
		if (ZSTD_isError(produced)) return false;
		compressed.resize(produced);
	} else {
		return false;
	}

	Mysqlx::Connection::Compression cmsg;
	cmsg.set_uncompressed_size(body_len);
	cmsg.set_server_messages(static_cast<Mysqlx::ServerMessages::Type>(msg_type));
	cmsg.set_payload(std::move(compressed));
	std::string serialized;
	cmsg.SerializeToString(&serialized);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
	return true;
}

bool MysqlxSession::emit_batched_compressed() {
	if (compress_batch_framed_.empty()) return true;

	std::string compressed;
	size_t uncompressed_size = compress_batch_framed_.size();
	if (compression_algo_ == MYSQLX_COMPR_LZ4_MESSAGE) {
		int bound = LZ4_compressBound(static_cast<int>(uncompressed_size));
		if (bound <= 0) return false;
		compressed.resize(static_cast<size_t>(bound));
		int produced = LZ4_compress_default(
			reinterpret_cast<const char*>(compress_batch_framed_.data()),
			compressed.data(),
			static_cast<int>(uncompressed_size),
			bound);
		if (produced <= 0) return false;
		compressed.resize(static_cast<size_t>(produced));
	} else if (compression_algo_ == MYSQLX_COMPR_ZSTD_STREAM) {
		if (!zstd_cctx_) {
			zstd_cctx_ = ZSTD_createCCtx();
			if (!zstd_cctx_) return false;
		}
		size_t bound = ZSTD_compressBound(uncompressed_size);
		if (ZSTD_isError(bound)) return false;
		compressed.resize(bound);
		size_t produced = ZSTD_compressCCtx(zstd_cctx_,
		                                   compressed.data(), compressed.size(),
		                                   compress_batch_framed_.data(), uncompressed_size,
		                                   3);
		if (ZSTD_isError(produced)) return false;
		compressed.resize(produced);
	} else {
		return false;
	}

	// Batched mode: neither client_messages nor server_messages set;
	// payload contains a sequence of fully-framed messages.
	Mysqlx::Connection::Compression cmsg;
	cmsg.set_uncompressed_size(uncompressed_size);
	cmsg.set_payload(std::move(compressed));
	std::string serialized;
	cmsg.SerializeToString(&serialized);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	compress_batch_framed_.clear();
	compress_batch_count_ = 0;
	return true;
}

void MysqlxSession::flush_compression_batch() {
	if (compress_batch_count_ == 0) return;
	if (emit_batched_compressed()) return;

	// Compression failed — re-iterate the buffered fully-framed messages
	// and enqueue each one verbatim, so the client sees the same sequence
	// of frames it would have seen if compression had never been on.
	// compress_batch_framed_ is { [4-byte size][1-byte type][payload], ... }
	// so we walk it the same way MysqlxDataStream::try_parse_frame does.
	size_t off = 0;
	while (off + 5 <= compress_batch_framed_.size()) {
		const uint8_t* hdr = compress_batch_framed_.data() + off;
		uint32_t payload_size =
			static_cast<uint32_t>(hdr[0]) |
			(static_cast<uint32_t>(hdr[1]) << 8) |
			(static_cast<uint32_t>(hdr[2]) << 16) |
			(static_cast<uint32_t>(hdr[3]) << 24);
		if (payload_size < 1 || off + 4 + payload_size > compress_batch_framed_.size()) break;
		uint8_t mt = hdr[4];
		const uint8_t* body = (payload_size > 1) ? hdr + 5 : nullptr;
		size_t body_len = (payload_size > 1) ? payload_size - 1 : 0;
		client_ds_.enqueue_frame(mt, body, body_len);
		off += 4 + payload_size;
	}
	compress_batch_framed_.clear();
	compress_batch_count_ = 0;
}

void MysqlxSession::send_to_client_compressed(uint8_t msg_type, const uint8_t* body, size_t body_len) {
	// Fast path: compression disabled or body too small to benefit.
	if (compression_algo_ == MYSQLX_COMPR_NONE ||
	    body_len < COMPRESSION_MIN_OUTPUT_BYTES) {
		client_ds_.enqueue_frame(msg_type, body, body_len);
		return;
	}

	if (!compression_combine_mixed_messages_) {
		// Single-message wrap. On compressor error, fall back to direct.
		if (!emit_single_compressed(msg_type, body, body_len)) {
			client_ds_.enqueue_frame(msg_type, body, body_len);
		}
		return;
	}

	// Batched mode: append one fully-framed message into the batch
	// buffer. We frame here (not at the call site) so the buffer always
	// holds a self-contained sequence the receiver can re-iterate after
	// decompression.
	append_x_frame(compress_batch_framed_, msg_type, body, body_len);
	compress_batch_count_++;

	uint32_t cap = compression_max_combine_messages_;
	if (cap == 0) cap = COMPRESSION_DEFAULT_MAX_COMBINE;
	if (compress_batch_count_ >= cap) {
		flush_compression_batch();
	}
}
