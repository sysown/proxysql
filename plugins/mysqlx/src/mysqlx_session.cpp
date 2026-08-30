#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_protocol.h"
#include "mysqlx_stats.h"
#include "proxysql.h"
#include "proxysql_debug.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_notice.pb.h"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <zstd.h>
#include <lz4.h>

// mysqlx_resolve_backend_tls_decision
//
// Pure function — translates the four runtime inputs governing the
// proxy<->backend TLS posture into a (require_tls, fallback_allowed)
// pair. Lives at file scope (not in the anonymous namespace) so the
// unit test in mysqlx_message_dispatch_unit-t.cpp can exercise the 8
// (mode x frontend_tls) combinations directly without driving the
// session state machine.
//
// Inputs:
//   * mode -- mysqlx_tls_backend_mode runtime variable, parsed by
//     MysqlxConfigStore. Drives the four documented modes.
//   * endpoint_use_ssl_override -- mysqlx_backend_endpoints.use_ssl=1
//     for the resolved endpoint (target_use_ssl_ at the call site).
//     Operator-controlled override that mandates TLS regardless of
//     mode. Used when a single sensitive backend must always be
//     encrypted even under mode=disabled.
//   * frontend_is_encrypted -- client_ds_.is_encrypted() at the call
//     site. Consulted only by mode=as_client (Router AsClient parity).
//
// Decisions:
//   * disabled  -> require_tls=false, fallback=false.
//                  Endpoint override can still force TLS. Plaintext
//                  by policy otherwise.
//   * preferred -> require_tls=true, fallback=true.
//                  Send CapabilitiesSet(tls=true). On Mysqlx::Error
//                  from the backend, downgrade to plaintext. The
//                  fallback path itself is wired in a follow-up
//                  commit; today fallback_allowed=true is read-only
//                  metadata.
//   * required  -> require_tls=true, fallback=false.
//                  Hard-fail the backend connect on Mysqlx::Error.
//   * as_client -> mirror frontend.
//                  require_tls = frontend_is_encrypted; never falls
//                  back (fallback_allowed=false). The intent is to
//                  preserve the client's posture exactly.
//
// The endpoint-override step is applied AFTER the mode dispatch — it
// can only PROMOTE a plaintext decision to TLS, never DEMOTE TLS to
// plaintext. This matches the existing operator contract from before
// the mode-aware rewrite (mysqlx_backend_endpoints.use_ssl was already
// an OR with the implicit AsClient behaviour).
MysqlxBackendTlsDecision mysqlx_resolve_backend_tls_decision(
	MysqlxBackendTlsMode mode,
	bool endpoint_use_ssl_override,
	bool frontend_is_encrypted)
{
	MysqlxBackendTlsDecision out;
	switch (mode) {
		case MysqlxBackendTlsMode::disabled:
			out.require_tls = false;
			out.fallback_allowed = false;
			break;
		case MysqlxBackendTlsMode::preferred:
			out.require_tls = true;
			out.fallback_allowed = true;
			break;
		case MysqlxBackendTlsMode::required:
			out.require_tls = true;
			out.fallback_allowed = false;
			break;
		case MysqlxBackendTlsMode::as_client:
			out.require_tls = frontend_is_encrypted;
			out.fallback_allowed = false;
			break;
	}
	// Per-endpoint operator override (mysqlx_backend_endpoints.use_ssl=1):
	// promotes plaintext to TLS regardless of mode. When promoted under
	// mode=preferred, leave fallback_allowed=true (the operator wants
	// best-effort TLS); when promoted under any other mode, fallback
	// is not allowed because there's no soft "preferred" semantics in
	// play.
	if (endpoint_use_ssl_override) {
		out.require_tls = true;
	}
	return out;
}

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
	, seen_column_metadata_(false)
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
		// If the frontend session is being destroyed while a backend
		// operation is still outstanding, the backend socket can still
		// have unread response frames. Pooling it would hand dirty wire
		// state to the next frontend session.
		if (status_ == WAITING_SERVER_XMSG ||
		    status_ == X_SESSION_RESET_WAITING ||
		    status_ == X_PASSTHROUGH_BACKEND_CONNECTING ||
		    status_ == X_PASSTHROUGH_FORWARD ||
		    response_state_ != RESP_IDLE) {
			backend_conn_->set_reusable(false);
		}
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
	init(fd, thread_ptr, std::string {});
}

void MysqlxSession::init(int fd, Mysqlx_Thread* thread_ptr, const std::string& listener_route) {
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
	route_name_.clear();
	listener_route_name_ = listener_route;
	identity_.reset();
	start_time_ = monotonic_time_ms();
	last_active_time_ = start_time_;
	compression_algo_ = MYSQLX_COMPR_NONE;
	compression_combine_mixed_messages_ = false;
	compression_max_combine_messages_ = 0;
	reset_compression_state();
	response_state_ = RESP_IDLE;
	seen_column_metadata_ = false;
	passthrough_c2b_backlog_.clear();
	passthrough_b2c_backlog_.clear();
	passthrough_pending_capset_frame_.clear();
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
	route_name_.clear();
	listener_route_name_.clear();
	identity_.reset();
	compression_algo_ = MYSQLX_COMPR_NONE;
	compression_combine_mixed_messages_ = false;
	compression_max_combine_messages_ = 0;
	reset_compression_state();
	pre_auth_cap_msgs_ = 0;
	response_state_ = RESP_IDLE;
	seen_column_metadata_ = false;
	passthrough_c2b_backlog_.clear();
	passthrough_b2c_backlog_.clear();
	passthrough_pending_capset_frame_.clear();
}

int MysqlxSession::handler() {
	if (!to_process) return 0;
	to_process = false;

	// Passthrough fast path. Skip the X-Protocol read/parse stage —
	// any bytes on the client fd are now opaque (TLS handshake +
	// application data) and must be forwarded verbatim to the
	// backend, not decoded as X-Protocol frames. handler_passthrough_
	// forward() pumps both directions itself and updates status_ on
	// EOF/error; it intentionally does not consult client_ds_'s
	// frame parser.
	if (status_ == X_PASSTHROUGH_FORWARD) {
		handler_passthrough_forward();
		return healthy ? 0 : -1;
	}
	// Passthrough setup state. The client has just sent
	// CapabilitiesSet(tls=true) on a passthrough route; we are
	// driving the backend connect + forward CapabilitiesSet bytes
	// + read backend response sequence. Like the FORWARD case we
	// skip the client X-Protocol read/parse — the client's next
	// bytes after CapabilitiesSet are its TLS ClientHello, which
	// cannot be parsed as an X-Protocol frame. The handler reads
	// from the BACKEND data stream directly.
	if (status_ == X_PASSTHROUGH_BACKEND_CONNECTING) {
		handler_passthrough_backend_connecting();
		return healthy ? 0 : -1;
	}

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
		case X_PASSTHROUGH_BACKEND_CONNECTING: handler_passthrough_backend_connecting(); break;
		case X_PASSTHROUGH_FORWARD:  handler_passthrough_forward(); break;
		case X_SESSION_RESET_WAITING: handler_session_reset_waiting(); break;
		case X_SESSION_CLOSING:      handler_session_closing(); break;
		default: break;
	}

	if (to_process) {
		to_process = false;
		// Don't loop into the X-Protocol dispatch once we've entered
		// either passthrough state — their handlers are reachable
		// through the fast path at the top of handler() on subsequent
		// ticks, and re-entering here would re-read client_ds_ into
		// the X frame parser. For X_PASSTHROUGH_FORWARD that defeats
		// the splice contract; for X_PASSTHROUGH_BACKEND_CONNECTING
		// the client's next bytes are the TLS ClientHello which
		// cannot be parsed as an X-Protocol frame.
		if (status_ == X_PASSTHROUGH_FORWARD ||
		    status_ == X_PASSTHROUGH_BACKEND_CONNECTING) {
			return healthy ? 0 : -1;
		}
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
			send_ok();
			healthy = false;
			break;

		default:
			client_ds_.pop_frame();
			send_error(5000, "Unexpected message during handshake");
			healthy = false;
			break;
	}
}

// Effective per-route TLS posture (issue #5710 follow-up). Pure
// query — no session-state mutation. Returns `inherit` when there's
// no listener route or no config store, since both cases collapse to
// the historical "global default" behaviour from before the per-route
// taxonomy was introduced. The caller is responsible for translating
// `inherit` into whatever the global setting calls for; this helper
// only resolves the per-route override.
MysqlxRouteTlsMode MysqlxSession::effective_route_tls_mode() const {
	if (listener_route_name_.empty()) {
		return MysqlxRouteTlsMode::inherit;
	}
	const MysqlxConfigStore* cs = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
	if (!cs) {
		return MysqlxRouteTlsMode::inherit;
	}
	return cs->route_tls_mode(listener_route_name_);
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
	if (status_ != WAITING_CLIENT_XMSG) {
		++pre_auth_cap_msgs_;
		if (pre_auth_cap_msgs_ > MAX_PRE_AUTH_CAP_MSGS) {
			client_ds_.pop_frame();
			send_error(5008, "Too many pre-auth capability messages", true);
			healthy = false;
			return;
		}
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
	if (status_ != WAITING_CLIENT_XMSG) {
		++pre_auth_cap_msgs_;
		if (pre_auth_cap_msgs_ > MAX_PRE_AUTH_CAP_MSGS) {
			client_ds_.pop_frame();
			send_error(5008, "Too many pre-auth capability messages", true);
			healthy = false;
			return;
		}
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
				// Snapshot the original CapabilitiesSet frame BEFORE
				// the pop. The passthrough entry path needs the bytes
				// verbatim (they're forwarded to the backend so the
				// backend's TLS handler sees the same negotiation the
				// client started). The non-passthrough paths discard
				// these bytes via pop_frame() as before.
				const auto& full_frame = client_ds_.front_frame();
				std::vector<uint8_t> capset_frame(full_frame.begin(), full_frame.end());
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

				// Per-route tls_mode wiring (issue #5710). The route's
				// TLS posture decides whether this CapabilitiesSet
				// (tls=true) should:
				//   * be REFUSED (tls_mode='disabled' — we never
				//     advertised TLS for this route, so a client
				//     asking for it is misconfigured/hostile);
				//   * trigger PASSTHROUGH backend setup
				//     (tls_mode='passthrough' — open a new backend
				//     TCP connection, forward the CapabilitiesSet
				//     verbatim, then splice raw bytes the rest of
				//     the way; the proxy never terminates this TLS
				//     session);
				//   * proceed with the historical proxy-terminated
				//     handshake (inherit / preferred / required —
				//     the proxy decrypts, parses, re-encrypts).
				const MysqlxRouteTlsMode route_mode = effective_route_tls_mode();
				if (route_mode == MysqlxRouteTlsMode::disabled) {
					// Symmetric with the advertise gate in
					// send_capabilities(): we never told the client
					// TLS was available on this route, so refuse.
					send_error(5052, "TLS is not enabled on this route", true);
					healthy = false;
					return;
				}
				if (route_mode == MysqlxRouteTlsMode::passthrough) {
					// Buffer the original CapabilitiesSet frame for
					// forwarding once the backend TCP connect
					// completes. resolve_passthrough_backend_target()
					// populates target_address_/target_port_ from the
					// listener route's destination_hostgroup; on
					// failure it has already emitted the error frame
					// and marked the session unhealthy.
					if (resolve_passthrough_backend_target() != 0) {
						return;
					}
					passthrough_pending_capset_frame_ = std::move(capset_frame);
					tls_mode_ = TLS_PASSTHROUGH;
					status_ = X_PASSTHROUGH_BACKEND_CONNECTING;
					to_process = true;
					return;
				}

				// Default (proxy-terminated) TLS path — same as
				// before this commit.
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

// Comma-separated, case-insensitive membership test. Tokens are trimmed
// of leading/trailing ASCII whitespace; empty tokens are skipped.
static bool csv_contains_ci(const std::string& list, const std::string& needle) {
	size_t pos = 0;
	while (pos < list.size()) {
		size_t comma = list.find(',', pos);
		if (comma == std::string::npos) comma = list.size();
		std::string token = list.substr(pos, comma - pos);
		while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(token.begin());
		while (!token.empty() && (token.back()  == ' ' || token.back()  == '\t')) token.pop_back();
		if (!token.empty() && strcasecmp(token.c_str(), needle.c_str()) == 0) {
			return true;
		}
		pos = comma + 1;
	}
	return false;
}

bool MysqlxSession::enforce_identity_policy() {
	if (!identity_) {
		return true;  // nothing to enforce
	}

	// backend_auth_mode='pass_through' is parsed and round-trips through
	// the config store but the backend-auth state machine does not
	// actually forward AuthStart unmodified to the backend (the existing
	// code maps the user's frontend creds to backend creds either via
	// the mapped or service_account paths). Per the design spec
	// (docs/superpowers/specs/2026-04-07-mysqlx-plugin-design.md §
	// "Backend authentication", around the pass_through bullet:
	// "configuration validation should reject pass_through rather than
	// silently downgrading it"), refuse the auth attempt instead of
	// approximating it. The accepted modes today are 'mapped' (default)
	// and 'service_account'; pass_through is reserved for a future
	// implementation that forwards the client's AuthStart frame
	// verbatim to the backend.
	if (identity_->backend_auth_mode == MysqlxBackendAuthMode::pass_through) {
		send_error(1045, "backend_auth_mode 'pass_through' is not yet implemented; refusing rather than silently downgrading");
		return false;
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
	if (!identity_->allowed_auth_methods.empty() &&
	    !csv_contains_ci(identity_->allowed_auth_methods, auth_method_)) {
		send_error(1045, "Authentication mechanism not allowed for user");
		return false;
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
	// AuthenticateContinue.auth_data carries the MYSQL41 client response.
	// Three on-the-wire shapes are accepted here:
	//   1. Standard MySQL X protocol, raw scramble:
	//        `<authzid>\0<authcid>\0<20 raw bytes>`
	//      (mysql-connector-python, MySQL Shell, libmysqlxclient — what
	//      every off-the-shelf X-Protocol client sends; matches what the
	//      upstream MySQL X plugin expects on the backend side.)
	//   2. Standard MySQL X protocol, hex-encoded scramble:
	//        `<authzid>\0<authcid>\0*<40 hex chars>`
	//      (older mysql-shell and some Java drivers prefer this form.)
	//   3. Legacy ProxySQL bare hex form: `*<40 hex chars>`
	//      (emitted by our older TAP tests and in-tree unit tests that
	//      drove the original wire protocol — kept for back-compat.)
	// Pre-fix, shape #1 was treated as "missing `*hex` marker" and any
	// stock client got 1045 even with valid credentials; that is the
	// root cause behind the Python soak harness failure.
	std::vector<uint8_t> scramble;
	bool scramble_ok = false;
	{
		// Find the response body — for shapes #1 and #2 it lives after the
		// second NUL; for shape #3 the whole buffer is the body.
		// While we're at it, harvest the authcid (username) from the
		// prefix and adopt it if the AuthStart leg left username_ empty.
		// Stock X-protocol clients (the ones that send shape #1) put no
		// credentials at all in AuthStart and only carry the user in
		// AuthContinue; without this step identity_lookup_("") fails and
		// reports a misleading 1045 even when the scramble checks out.
		size_t body_start = 0;
		size_t first_nul = auth_data.find('\0');
		if (first_nul != std::string::npos) {
			size_t second_nul = auth_data.find('\0', first_nul + 1);
			if (second_nul != std::string::npos) {
				body_start = second_nul + 1;
				if (username_.empty()) {
					username_ = auth_data.substr(first_nul + 1, second_nul - first_nul - 1);
				}
				if (schema_.empty()) {
					schema_ = auth_data.substr(0, first_nul);
				}
			}
		}
		std::string body = auth_data.substr(body_start);
		// Stock X-Protocol clients pad the MYSQL41 AuthContinue payload
		// with a trailing NUL (the empty third field of `<authzid>\0<authcid>\0<response>\0`).
		// Strip a single trailing NUL so the hex-decode path doesn't trip
		// over the padding byte and misclassify a valid response as
		// "Invalid scramble format".
		while (!body.empty() && body.back() == '\0') body.pop_back();
		if (!body.empty() && body[0] == '*') {
			// Shapes #2 and #3: hex-encoded scramble after `*`.
			std::string hex_scramble = body.substr(1);
			if (mysqlx_hex_decode(hex_scramble, scramble) && scramble.size() == 20) {
				scramble_ok = true;
			}
		} else if (body.size() == 20) {
			// Shape #1: raw 20-byte SHA1 response.
			scramble.assign(body.begin(), body.end());
			scramble_ok = true;
		}
	}
	if (scramble_ok) {

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
			send_ok();
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
			seen_column_metadata_ = false;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CRUD_FIND:
		case Mysqlx::ClientMessages_Type_CRUD_INSERT:
		case Mysqlx::ClientMessages_Type_CRUD_UPDATE:
		case Mysqlx::ClientMessages_Type_CRUD_DELETE:
		case Mysqlx::ClientMessages_Type_CRUD_CREATE_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_MODIFY_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_DROP_VIEW:
			response_state_ = RESP_WAITING_CRUD;
			seen_column_metadata_ = false;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_PREPARE:
			if (backend_conn_) backend_conn_->set_has_prepared_statement(true);
			response_state_ = RESP_WAITING_PREPARE_PREPARE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_EXECUTE:
			response_state_ = RESP_WAITING_PREPARE_EXECUTE;
			seen_column_metadata_ = false;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_DEALLOCATE:
			response_state_ = RESP_WAITING_PREPARE_DEALLOCATE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_OPEN:
			response_state_ = RESP_WAITING_CURSOR_OPEN;
			seen_column_metadata_ = false;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_FETCH:
			// NOT cleared — Cursor::Fetch reuses ColumnMetaData from
			// the preceding Cursor::Open, so the sub-state must carry
			// across.
			response_state_ = RESP_WAITING_CURSOR_FETCH;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_CLOSE:
			response_state_ = RESP_WAITING_CURSOR_CLOSE;
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
				// Match upstream MySQL X plugin: ER_X_FRAME_COMPRESSION_DISABLED
				// (5170) — see plugin/x/src/xpl_error.h in mysql-8.4 source.
				// The upstream message is literally "Client didn't enable the
				// compression."; we reproduce it verbatim so clients written
				// against the upstream contract see the exact same shape.
				send_error(5170, "Client didn't enable the compression.");
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
		server_ds().set_status(XDS_READY);
	}

	if (client_ds_.has_complete_frame()) {
		const auto& frame = client_ds_.front_frame();
		if (frame.size() > 5) {
			server_ds().enqueue_frame(frame[4], frame.data() + 5, frame.size() - 5);
			// Account the X-Protocol payload bytes (excluding the 5-byte
			// frame header) the proxy is forwarding to the backend. This
			// is the "client → proxy → backend" leg; the counter is
			// charged to the resolved route so operators can compare
			// request volume across routes.
			mysqlx_stats().record_bytes_sent(route_name_, target_hostgroup_, frame.size() - 5);
		} else {
			server_ds().enqueue_frame(frame[4], nullptr, 0);
		}
		client_ds_.pop_frame();
	}

	server_ds().write_to_net();
	status_ = WAITING_SERVER_XMSG;
}

// Per-state allowed-frame contract for backend frames. Returns true iff
// a backend message of msg_type is acceptable to forward in the current
// response_state_. Disallowed frames are rejected by the validation
// hook in handler_waiting_server_msg() with X-Protocol Error 4006.
//
// Universal frames (allowed in every state):
//   - NOTICE   (non-terminal status messages, may be interleaved freely)
//   - ERROR    (terminates the response sequence with a per-message error)
//
// Per-state extras (in addition to the terminal frames already enumerated
// in is_terminal_frame): COLUMN_META_DATA, RESULTSET_ROW, and the
// non-terminal FETCH_DONE_MORE_* boundaries. RESULTSET_ROW is only
// allowed once seen_column_metadata_ has been set by a preceding
// COLUMN_META_DATA frame in the same response, except in CURSOR_FETCH
// where the metadata was sent at Cursor::Open and is already in scope.
//
// RESP_IDLE accepts no frames at all — any backend frame in that state
// is unsolicited and indicates a protocol-confused backend.
bool MysqlxSession::is_frame_allowed(uint8_t msg_type) const {
	if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) return true;
	if (msg_type == Mysqlx::ServerMessages_Type_ERROR) return true;
	if (is_terminal_frame(msg_type)) return true;

	switch (response_state_) {
		case RESP_WAITING_STMT_EXECUTE:
		case RESP_WAITING_CRUD:
		case RESP_WAITING_PREPARE_EXECUTE:
		case RESP_WAITING_CURSOR_OPEN:
			// Resultset shape: ColumnMetaData, then zero or more Row,
			// then non-terminal FetchDoneMore* boundaries between
			// resultsets / out-params before the actual terminator.
			if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA) {
				return true;
			}
			if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_ROW) {
				// Row is only legal after metadata has been forwarded
				// in this response. Without this guard a hostile
				// backend could spray rows the client cannot parse.
				return seen_column_metadata_;
			}
			if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_RESULTSETS) {
				return true;
			}
			if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE) {
				return response_state_ == RESP_WAITING_STMT_EXECUTE ||
				       response_state_ == RESP_WAITING_PREPARE_EXECUTE;
			}
			// FETCH_DONE_MORE_OUT_PARAMS only flows through stored-proc
			// shapes; STMT_EXECUTE and PREPARE_EXECUTE both can produce
			// it. Allow on those two; CRUD doesn't have out-params but
			// the allow is harmless (still requires a real terminator
			// to advance the state machine).
			if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS) {
				return response_state_ == RESP_WAITING_STMT_EXECUTE ||
				       response_state_ == RESP_WAITING_PREPARE_EXECUTE;
			}
			return false;
		case RESP_WAITING_CURSOR_FETCH:
			// Cursor::Fetch only carries Row frames (metadata was at
			// Cursor::Open). FETCH_DONE / FETCH_SUSPENDED are terminal
			// and already accepted via is_terminal_frame above.
			return msg_type == Mysqlx::ServerMessages_Type_RESULTSET_ROW;
		case RESP_WAITING_PREPARE_PREPARE:
		case RESP_WAITING_PREPARE_DEALLOCATE:
		case RESP_WAITING_CURSOR_CLOSE:
		case RESP_WAITING_EXPECT:
		case RESP_WAITING_SESS_RESET:
			// These responses carry only their terminal Mysqlx.Ok
			// (already handled above) plus universal NOTICE/ERROR.
			return false;
		case RESP_IDLE:
			// No outstanding response — any backend frame here is
			// unsolicited.
			return false;
	}
	return false;
}

bool MysqlxSession::is_terminal_frame(uint8_t msg_type) const {
	// ERROR is terminal in every state — once the backend reports a
	// per-message error the response sequence is over regardless of
	// what state we were in. NOTICE never terminates: the X protocol
	// allows backends to interleave Notice frames with rows / EOF
	// markers, and they're explicitly non-terminal in the spec.
	if (msg_type == Mysqlx::ServerMessages_Type_ERROR) return true;
	if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) return false;

	switch (response_state_) {
		case RESP_WAITING_STMT_EXECUTE:
			return msg_type == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK;
		case RESP_WAITING_CRUD:
			return msg_type == Mysqlx::ServerMessages_Type_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_PREPARE_PREPARE:
			// Prepare::Prepare returns only Mysqlx.Ok on success.
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_PREPARE_EXECUTE:
			// Prepare::Execute behaves like the underlying request — for
			// statement preparations the terminator is SQL_STMT_EXECUTE_OK,
			// for CRUD it's Ok, for cursor-bound preparations it's
			// FETCH_DONE / FETCH_SUSPENDED. Accept all four; the proxy
			// can't tell at this layer which kind was prepared.
			return msg_type == Mysqlx::ServerMessages_Type_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_PREPARE_DEALLOCATE:
			// Prepare::Deallocate returns only Mysqlx.Ok.
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_CURSOR_OPEN:
			return msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_CURSOR_FETCH:
			return msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_CURSOR_CLOSE:
			// Cursor::Close returns only Mysqlx.Ok.
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_EXPECT:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_SESS_RESET:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_IDLE:
			// No outstanding response — a frame here is unsolicited and
			// will be treated as a protocol violation once the validation
			// hook is wired (next commit). For terminality alone, return
			// false so the dispatch loop's "got_terminal" tracking does
			// nothing surprising while RESP_IDLE.
			return false;
	}
	return false;
}

// is_notice_frame_valid
//
// Parse the NOTICE body as a Mysqlx::Notice::Frame and assert that
// frame.type is in the spec-defined enum range (1..5). Returns false
// for any of:
//   - empty body (a Notice MUST carry a non-empty payload per the proto;
//     the `type` field is required)
//   - protobuf ParseFromArray failure (malformed envelope)
//   - frame.type outside the known WARNING..SERVER_HELLO range as
//     enumerated in mysqlx_notice.pb.h
//
// The protobuf-generated Frame_Type_IsValid() enumerates the known
// values; new entries added in future MySQL versions would need a proto
// regeneration before they'd be accepted here, which is the right
// failure mode — we'd rather surface the spec mismatch than silently
// forward a notice the proxy doesn't understand.
//
// We deliberately do NOT validate the inner `payload` field: that's a
// type-specific protobuf the client will parse, and the proxy has no
// business reaching into it. The outer `type` is the load-bearing
// field for client-side branching, so that's where we focus.
bool MysqlxSession::is_notice_frame_valid(const uint8_t* body, size_t body_len) const {
	if (body == nullptr || body_len == 0) {
		// A Notice with no body has no type field, which is required.
		return false;
	}
	Mysqlx::Notice::Frame nframe;
	if (!nframe.ParseFromArray(body, static_cast<int>(body_len))) {
		// Malformed envelope — protobuf wire format violation or a
		// non-Notice payload mistakenly typed as NOTICE.
		return false;
	}
	if (!nframe.has_type()) {
		// Required field absent — strictly invalid per the proto.
		return false;
	}
	// Frame_Type_IsValid is generated by protoc and returns true iff the
	// integer is one of the named values. Unknown enum values from a
	// newer/older backend, or a malicious sender shipping a random
	// integer, fail this check.
	if (!Mysqlx::Notice::Frame_Type_IsValid(nframe.type())) {
		return false;
	}
	return true;
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

		// Per-message response state machine: drop and reject any
		// backend frame that is not in the allowed set for the
		// current response_state_. This guards against a buggy or
		// hostile backend pushing an out-of-shape frame the client
		// would otherwise have to parse (and potentially desync on).
		// The canonical case: a Row before its ColumnMetaData. We
		// emit X-Protocol Error 4006 fatal, mark the backend
		// non-reusable so it gets evicted (not pooled) by
		// return_backend_to_pool, and transition the session to
		// X_SESSION_CLOSING. The disallowed frame is dropped, not
		// forwarded — so the bytes_recv counter (charged below in
		// the happy path) is naturally not incremented for it.
		if (!is_frame_allowed(msg_type)) {
			server_ds().pop_frame();
			send_error(4006,
				"Backend sent an unexpected message in the current response state; closing session.",
				/*fatal=*/true);
			if (backend_conn_) backend_conn_->set_reusable(false);
			return_backend_to_pool();
			healthy = false;
			status_ = X_SESSION_CLOSING;
			client_ds_.write_to_net();
			return;
		}

		// Notice-type validation (issue #5695). Mysqlx::Notice::Frame
		// frames carry an outer `type` enum (1..5) the client branches
		// on; previously the proxy forwarded NOTICEs uncritically, so
		// a buggy/hostile backend (or MITM that bypassed TLS) could
		// inject a frame with an unknown type field and confuse a
		// strict client. Drop unknown types instead, log a warning,
		// and continue draining — the response sequence itself is
		// still valid (NOTICE is non-terminal in every state).
		if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) {
			const uint8_t* body = (frame.size() > 5) ? (frame.data() + 5) : nullptr;
			size_t body_len = (frame.size() > 5) ? (frame.size() - 5) : 0;
			if (!is_notice_frame_valid(body, body_len)) {
				proxy_error("mysqlx: dropping malformed/unknown-type NOTICE frame from backend "
				            "(route=%s, hostgroup=%d, body_len=%zu)\n",
				            route_name_.c_str(), target_hostgroup_, body_len);
				server_ds().pop_frame();
				continue;
			}
		}

		forward_frame_to_client(msg_type, frame);
		// Track that the backend has shipped ColumnMetaData in this
		// response so subsequent Row frames pass the gating check
		// in is_frame_allowed. Set after the forward (the forward
		// itself can fail TLS write, etc., but we don't unwind state
		// on partial-write — the next iteration drives the data plane).
		if (msg_type == Mysqlx::ServerMessages_Type_RESULTSET_COLUMN_META_DATA) {
			seen_column_metadata_ = true;
		}
		// Account the X-Protocol payload bytes the proxy is forwarding
		// from the backend to the client (size minus the 5-byte frame
		// header; 0-payload OK/EOF frames contribute 0). Charged to the
		// resolved route. NOTICE frames are also counted here — they're
		// part of the data plane the operator paid for forwarding.
		if (frame.size() > 5) {
			mysqlx_stats().record_bytes_recv(route_name_, target_hostgroup_, frame.size() - 5);
		}
		server_ds().pop_frame();

		if (is_terminal_frame(msg_type)) {
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
		// Clear the column-metadata sub-state on every response
		// boundary. CURSOR_FETCH does not need the flag carried
		// across (its allowed-frame set in is_frame_allowed accepts
		// RESULTSET_ROW unconditionally because ColumnMetaData was
		// sent at Cursor::Open); STMT_EXECUTE / CRUD /
		// PREPARE_EXECUTE / CURSOR_OPEN all explicitly clear the
		// flag at dispatch time.
		seen_column_metadata_ = false;
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
			// Notice-type validation also applies in the SESS_RESET path
			// (issue #5695): drop NOTICEs with malformed bodies or
			// unknown enum types. SESS_RESET commonly emits a
			// SESSION_STATE_CHANGED notice carrying the new client_id;
			// we want to forward those, just not unrecognized variants.
			const uint8_t* body = (frame.size() > 5) ? (frame.data() + 5) : nullptr;
			size_t body_len = (frame.size() > 5) ? (frame.size() - 5) : 0;
			if (!is_notice_frame_valid(body, body_len)) {
				proxy_error("mysqlx: dropping malformed/unknown-type NOTICE frame "
				            "during SESS_RESET (route=%s, hostgroup=%d, body_len=%zu)\n",
				            route_name_.c_str(), target_hostgroup_, body_len);
				server_ds().pop_frame();
				continue;
			}
			forward_frame_to_client(msg_type, frame);
			server_ds().pop_frame();
			continue;
		}

		if (msg_type == Mysqlx::ServerMessages_Type_OK) {
			server_ds().pop_frame();
			if (backend_conn_) {
				backend_conn_->set_has_prepared_statement(false);
				backend_conn_->set_in_transaction(false);
				// Issue #5697: mark the connection non-cacheable. A
				// successful Session::Reset wiped backend session state
				// (schema, isolation level, charset, prepared stmts,
				// session vars); returning it to the pool would leak
				// blank state to a future client expecting per-identity
				// defaults. is_reusable() honors this flag and the
				// subsequent return_backend_to_pool() will delete the
				// connection instead of caching it.
				backend_conn_->set_needs_post_reset_rehandshake(true);
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

// handler_passthrough_backend_connecting
//
// Drives the passthrough entry sequence after the client has sent
// CapabilitiesSet(tls=true) on a tls_mode='passthrough' route:
//
//   1. Allocate / pick up the backend connection. Start a non-
//      blocking TCP connect if we haven't already.
//   2. Poll the connect to completion (check_connect()).
//   3. Forward the buffered CapabilitiesSet bytes verbatim to the
//      backend.
//   4. Read exactly one X-Protocol frame from the backend (via the
//      backend data stream's frame parser). LAST X-Protocol parse
//      this session will do.
//   5. If the frame is CONN_CAPABILITIES_OK (Mysqlx::Ok), forward
//      it to the client and transition to X_PASSTHROUGH_FORWARD.
//      The client now sees a TLS-ready socket; everything past this
//      tick is opaque bytes.
//   6. If the frame is Mysqlx::Error, propagate to the client and
//      close the session.
//
// Each step yields back to the dispatch loop on EAGAIN. The state
// transitions are encoded by which intermediate fields are populated
// (backend_conn_ presence, connecting state, pending bytes).
void MysqlxSession::handler_passthrough_backend_connecting() {
	// Step 1: ensure backend_conn_ exists with a TCP connect in
	// flight. We pull from the cache only when the cache key would
	// match — a passthrough connection is single-use anyway, so for
	// simplicity we always start fresh here. (The cache lookup
	// would require a TLS-active key the proxy doesn't have post-
	// passthrough negotiation.)
	if (!backend_conn_) {
		backend_conn_ = new MysqlxConnection();
		backend_conn_->set_hostgroup(target_hostgroup_);
		backend_conn_->set_connect_timeout(10000);
		// Mark non-reusable up front: passthrough connections never
		// re-enter the pool (the proxy did not see plaintext past
		// CapabilitiesSet, so it has no idea what session state
		// the backend ended up in).
		backend_conn_->set_reusable(false);

		int rc = backend_conn_->start_connect(target_address_.c_str(), target_port_);
		if (rc == -1) {
			send_error(2003, "Can't connect to backend (passthrough)");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
		if (rc == 1) {
			// Connect in progress; wait for the next handler tick.
			return;
		}
		// rc == 0: immediate success, fall through to step 2.
	}

	// Step 2: drive the non-blocking connect to completion.
	if (backend_conn_->get_state() == MysqlxConnection::CONNECTING) {
		int rc = backend_conn_->check_connect();
		if (rc == 1) return;  // still connecting
		if (rc == -1) {
			send_error(2003, "Backend connect failed (passthrough)");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
		// rc == 0: connected. Initialize the backend data stream so
		// we can run one X-Protocol read for the backend's
		// CapabilitiesSet response.
		backend_conn_->init_backend_ds(backend_conn_->get_fd());
	}

	// Step 3: forward the buffered CapabilitiesSet bytes verbatim
	// to the backend. Idempotent — once we drain
	// passthrough_pending_capset_frame_ we don't try again. Use a
	// blocking-ish style: write_raw on the backend_ds; the fd is
	// non-blocking, so partial writes append to the c2b backlog and
	// resume next tick. Given the frame is at most a few KiB, in
	// practice this completes in one call.
	if (!passthrough_pending_capset_frame_.empty()) {
		ssize_t want = static_cast<ssize_t>(passthrough_pending_capset_frame_.size());
		ssize_t w = write(backend_conn_->get_fd(),
		                  passthrough_pending_capset_frame_.data(),
		                  passthrough_pending_capset_frame_.size());
		if (w < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				return;  // try again next tick
			}
			send_error(2003, "Backend write failed (passthrough setup)");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
		if (w < want) {
			// Partial write: drop the prefix, retry the rest.
			passthrough_pending_capset_frame_.erase(
				passthrough_pending_capset_frame_.begin(),
				passthrough_pending_capset_frame_.begin() + w);
			return;
		}
		// Full write — clear and proceed to read.
		passthrough_pending_capset_frame_.clear();
	}

	// Step 4: read one X-Protocol frame from the backend. This is
	// the LAST decode the proxy does on this session. We use the
	// backend_conn_'s data stream frame parser to handle partial
	// reads safely.
	MysqlxDataStream& bds = backend_conn_->backend_ds();
	bds.read_from_net();
	if (!bds.has_complete_frame()) {
		return;  // wait for more bytes
	}

	const auto& backend_frame = bds.front_frame();
	if (backend_frame.size() < 5) {
		send_error(2003, "Malformed backend frame (passthrough setup)");
		bds.pop_frame();
		delete backend_conn_; backend_conn_ = nullptr;
		status_ = X_SESSION_CLOSING; healthy = false;
		return;
	}
	const uint8_t backend_msg_type = backend_frame[4];

	// Step 5/6: branch on the backend's response type. We accept
	// only Mysqlx::Ok (in response to CapabilitiesSet) as the green
	// light to splice. Anything else is propagated to the client
	// and the session closes.
	if (backend_msg_type == Mysqlx::ServerMessages_Type_OK) {
		// Forward the OK frame to the client verbatim. The client's
		// TLS stack will then send a ClientHello on the next bytes
		// it pushes — those land on this session, which is now in
		// X_PASSTHROUGH_FORWARD and splices them straight to the
		// backend.
		const uint8_t* body = (backend_frame.size() > 5)
			? backend_frame.data() + 5 : nullptr;
		size_t body_len = (backend_frame.size() > 5) ? backend_frame.size() - 5 : 0;
		client_ds_.enqueue_frame(backend_msg_type, body, body_len);
		bds.pop_frame();
		client_ds_.write_to_net();

		// Bind the data stream so server_ds() resolves to the
		// backend connection's fd (matches handler_passthrough_
		// forward()'s client_fd / backend_fd lookup).
		server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
		server_ds().set_status(XDS_READY);
		// Mark the connection IN_USE so MysqlxConnection's reuse
		// invariants hold; reusable_ remains false from start_connect.
		backend_conn_->set_state(MysqlxConnection::IN_USE);

		tls_mode_ = TLS_PASSTHROUGH;
		status_ = X_PASSTHROUGH_FORWARD;
		to_process = true;
		return;
	}

	// Backend rejected (Error) — forward verbatim, close.
	if (backend_msg_type == Mysqlx::ServerMessages_Type_ERROR) {
		const uint8_t* body = (backend_frame.size() > 5)
			? backend_frame.data() + 5 : nullptr;
		size_t body_len = (backend_frame.size() > 5) ? backend_frame.size() - 5 : 0;
		client_ds_.enqueue_frame(backend_msg_type, body, body_len);
		bds.pop_frame();
		client_ds_.write_to_net();
		delete backend_conn_; backend_conn_ = nullptr;
		status_ = X_SESSION_CLOSING; healthy = false;
		return;
	}

	// Any other frame type is unexpected at this point.
	send_error(5000, "Unexpected backend frame in passthrough setup");
	bds.pop_frame();
	delete backend_conn_; backend_conn_ = nullptr;
	status_ = X_SESSION_CLOSING; healthy = false;
}

// handler_passthrough_forward
//
// Once the route's tls_mode='passthrough' policy is honoured at
// CapabilitiesSet(tls=true) time, the proxy stops parsing frames and
// just splices bytes between the two ends. Every byte the client emits
// (TLS ClientHello, application data, ...) is opaque from here on —
// the proxy cannot multiplex queries, evaluate routing rules, run the
// query cache, or pool the backend.
//
// The pump uses bog-standard read(2)/write(2). EAGAIN/EWOULDBLOCK on
// the read side ends the round (poll will wake us again when more bytes
// arrive); a 0-byte read means the peer closed cleanly; any other I/O
// error puts the session into X_SESSION_CLOSING.
//
// EAGAIN on the WRITE side is NOT fatal (issue #5710 follow-up). When
// the destination's kernel send buffer fills (slow client / slow
// backend / asymmetric throughput), we used to kill the session — that
// turns a transient back-pressure event into a connection drop. Now
// the unwritten bytes are appended to a per-direction backlog
// (passthrough_c2b_backlog_ / passthrough_b2c_backlog_) and re-tried
// on the next handler tick. The libev loop wakes us on EV_READ for
// either fd, which is sufficient for the backlog to drain in practice:
// the next time the source side has bytes (or the next poll tick), we
// re-enter handler_passthrough_forward(), drain the backlog first, and
// only then resume reading. We keep `to_process = true` while a
// backlog is non-empty so the outer dispatch loop will re-call us
// without waiting for a new fd-readable event — this mirrors the
// pattern used by handler_waiting_server_msg() for buffered work.
//
// Backlog cap: PASSTHROUGH_BACKLOG_CAP per direction (1 MiB). If a
// direction's backlog exceeds the cap, the slow consumer is treated as
// a memory-DoS source; the session is killed (X_SESSION_CLOSING). Cap
// chosen as a balance between "absorbs a typical TLS record burst"
// (TLS records can be up to 16 KiB but applications emit them in
// fragments) and "bounded memory per session". An operator hitting
// this in practice should investigate the slow side, not raise the
// cap.
//
// We deliberately pump up to BURST_BYTES per direction per call so a
// chatty session does not starve other sessions sharing this thread.
// 64 KiB is the size of a typical TLS record + a few application
// frames, plenty per scheduler tick.
void MysqlxSession::handler_passthrough_forward() {
	// No backend? The session is malformed — the entry path
	// (handler_capabilities_set, or the test-only injection helper)
	// is responsible for ensuring backend_conn_ is attached before
	// status_ flips to X_PASSTHROUGH_FORWARD. Failing closed here.
	if (!backend_conn_) {
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return;
	}

	const int client_fd  = client_ds_.get_fd();
	const int backend_fd = backend_conn_->get_fd();
	if (client_fd < 0 || backend_fd < 0) {
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return;
	}

	uint8_t buf[16384];
	constexpr size_t BURST_BYTES = 65536;

	// Drain whatever is in `backlog` to to_fd. Returns true on
	// success or partial-success (writes that left some bytes
	// pending — caller should NOT proceed to a fresh read in that
	// case so we don't grow the backlog further). Returns false if
	// the destination signalled a fatal error or the backlog
	// exceeded the cap (in either case session_closing is set).
	auto drain_backlog = [&](std::vector<uint8_t>& backlog, int to_fd) -> bool {
		while (!backlog.empty()) {
			ssize_t w = write(to_fd, backlog.data(), backlog.size());
			if (w > 0) {
				backlog.erase(backlog.begin(), backlog.begin() + w);
				continue;
			}
			if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
				// Destination still not ready; leave backlog in
				// place and signal "back off this direction this
				// tick" — caller treats false-with-healthy as a
				// non-fatal pause.
				return false;
			}
			// Genuine write error / EOF on the destination.
			healthy = false;
			status_ = X_SESSION_CLOSING;
			return false;
		}
		return true;
	};

	// Append `bytes` to backlog and trip session-closing if the
	// total would exceed the per-direction cap. Returns true on
	// success, false if the cap was hit (session is closing).
	auto append_to_backlog = [&](std::vector<uint8_t>& backlog,
	                             const uint8_t* bytes, size_t n) -> bool {
		if (backlog.size() + n > PASSTHROUGH_BACKLOG_CAP) {
			// Slow-consumer DoS protection. Kill the session rather
			// than grow memory unbounded. reusable_=false on the
			// passthrough connection keeps it out of the pool; the
			// thread-side teardown closes both fds.
			healthy = false;
			status_ = X_SESSION_CLOSING;
			return false;
		}
		backlog.insert(backlog.end(), bytes, bytes + n);
		return true;
	};

	auto pump_one_direction = [&](int from_fd, int to_fd,
	                              std::vector<uint8_t>& backlog) -> bool {
		// Drain pending bytes BEFORE reading more. If the destination
		// is still EAGAIN, skip reading from this direction this tick;
		// kernel-buffering on `from_fd` covers the source side.
		if (!backlog.empty()) {
			if (!drain_backlog(backlog, to_fd)) {
				// Either destination still EAGAIN (healthy true,
				// status unchanged) or fatal write error (healthy
				// false, status = closing). Either way we leave
				// this direction alone for now.
				return healthy;
			}
		}

		size_t bytes_this_round = 0;
		while (bytes_this_round < BURST_BYTES) {
			ssize_t r = read(from_fd, buf, sizeof(buf));
			if (r > 0) {
				size_t written = 0;
				while (written < static_cast<size_t>(r)) {
					ssize_t w = write(to_fd, buf + written, r - written);
					if (w > 0) {
						written += w;
						continue;
					}
					if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
						// Destination buffer is full — buffer the
						// unwritten tail in this direction's backlog
						// and stop reading further. Next tick will
						// drain. Backlog-cap hit kills the session.
						if (!append_to_backlog(backlog,
						                       buf + written,
						                       static_cast<size_t>(r) - written)) {
							return false;
						}
						return true;
					}
					// Other write error or EOF on the destination.
					healthy = false;
					status_ = X_SESSION_CLOSING;
					return false;
				}
				bytes_this_round += static_cast<size_t>(r);
				continue;
			}
			if (r == 0) {
				// Peer closed. Tear down — passthrough sessions are
				// not reusable.
				healthy = false;
				status_ = X_SESSION_CLOSING;
				return false;
			}
			// r < 0
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				return true;  // normal "no more bytes" exit
			}
			healthy = false;
			status_ = X_SESSION_CLOSING;
			return false;
		}
		// Hit BURST_BYTES — return so the other direction can run
		// before we keep draining this one.
		return true;
	};

	if (!pump_one_direction(client_fd, backend_fd, passthrough_c2b_backlog_)) return;
	if (!pump_one_direction(backend_fd, client_fd, passthrough_b2c_backlog_)) return;

	// Re-arm so the outer dispatch loop calls us again on the next
	// tick when there's a backlog to drain. Without this, a long
	// stall on the destination side would wait for the next
	// fd-readable event (which may not come until the source sends
	// more — by which time the backlog has only grown). The libev
	// poll wakeup still drives most ticks; this just guarantees
	// that an existing backlog gets a fair shot at draining even
	// when no new bytes arrive on the source.
	if (!passthrough_c2b_backlog_.empty() || !passthrough_b2c_backlog_.empty()) {
		to_process = true;
	}

	last_active_time_ = monotonic_time_ms();
}

#ifdef MYSQLX_TEST_BUILD
// Test fixture: drop the session into X_PASSTHROUGH_FORWARD bound to
// `backend_fd` (typically a socketpair leg). Bypasses CapabilitiesSet,
// auth, and resolve_backend_target — the splice mechanics are exactly
// what we want to assert in isolation.
//
// We allocate a stub MysqlxConnection on the heap so the standard
// ~MysqlxSession() / return_backend_to_pool() teardown path runs
// unchanged. set_reusable(false) mirrors the production-side
// invariant: a passthrough connection NEVER returns to the pool (we
// never saw plaintext, so we have no idea what state the backend's
// session is in past the handshake).
void MysqlxSession::enter_passthrough_for_test(int backend_fd) {
	if (backend_conn_ == nullptr) {
		backend_conn_ = new MysqlxConnection();
	}
	backend_conn_->set_fd(backend_fd);
	backend_conn_->set_state(MysqlxConnection::IN_USE);
	backend_conn_->set_reusable(false);
	tls_mode_ = TLS_PASSTHROUGH;
	status_ = X_PASSTHROUGH_FORWARD;
}
#endif /* MYSQLX_TEST_BUILD */

void MysqlxSession::handler_tls_accept_init() {
	if (!client_ds_.ssl_init_done()) {
		SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
		if (!ctx) {
			// NO_SSL_CTX class — distinct from "handshake failed"
			// since this is a configuration error, not a wire-level
			// issue. Maps to 3150 in the frontend codespace.
			send_error(mysqlx_frontend_tls_error_code(MysqlxTlsErrorClass::NO_SSL_CTX),
			           mysqlx_frontend_tls_error_message(MysqlxTlsErrorClass::NO_SSL_CTX));
			healthy = false;
			return;
		}
		client_ds_.init_ssl(ctx);
	}
	if (!client_ds_.do_ssl_handshake()) {
		if (client_ds_.ssl_handshake_failed()) {
			// Issue #5698: classify the frontend handshake failure.
			// Threat model is asymmetric — the client may BE the
			// attacker, so we MUST NOT leak cert-chain detail in the
			// response. mysqlx_frontend_tls_error_message collapses
			// most classes onto "TLS handshake failed" for that reason;
			// only PROTOCOL_MISMATCH and NO_SSL_CTX get a distinct
			// code. We still log the OpenSSL queue strings to stderr
			// for the operator's benefit (server-side info).
			MysqlxTlsErrorClass cls = mysqlx_classify_tls_error(
				client_ds_.get_ssl(), /*peek_err_queue=*/true);
			char err_buf[256];
			unsigned long ssl_err = ERR_get_error();
			if (ssl_err != 0) {
				ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
				proxy_error("mysqlx: frontend TLS handshake failed (class=%d): %s\n",
				            static_cast<int>(cls), err_buf);
			} else {
				proxy_error("mysqlx: frontend TLS handshake failed (class=%d, no OpenSSL detail)\n",
				            static_cast<int>(cls));
			}
			send_error(mysqlx_frontend_tls_error_code(cls),
			           mysqlx_frontend_tls_error_message(cls));
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
	route_name_       = route_name;
	return 0;
}

// Pre-auth, route-keyed backend resolution for the passthrough
// entry path (issue #5710). Unlike resolve_backend_target() — which
// keys off identity_->default_route — this looks at the
// listener_route_name_ the client connected through. There is NO
// authenticated identity yet (and there never will be on the proxy
// side: passthrough authenticates end-to-end between client and
// backend), so we route purely by the listener's logical name.
//
// Failure modes mirror resolve_backend_target's: empty route, route
// not found in config store, or no endpoint available. Each emits an
// X-Protocol Error frame, marks the session unhealthy + closing, and
// returns the corresponding code.
int MysqlxSession::resolve_passthrough_backend_target() {
	if (listener_route_name_.empty()) {
		// Sessions accepted via the unit-test path lack a listener
		// route. Refuse — this is a programming error, not a runtime
		// failure mode for production traffic.
		send_error(4000, "Passthrough requires a listener route");
		mysqlx_stats().record_conn_err("", 0);
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return 4000;
	}
	const MysqlxConfigStore* cs = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
	if (!cs) {
		send_error(4002, "No backend available: config store unavailable");
		mysqlx_stats().record_conn_err(listener_route_name_, 0);
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return 4002;
	}
	if (!cs->route_exists(listener_route_name_)) {
		std::string msg = "Route '";
		msg += listener_route_name_;
		msg += "' not found";
		send_error(4001, msg.c_str());
		mysqlx_stats().record_conn_err(listener_route_name_, 0);
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return 4001;
	}
	int hg = cs->route_hostgroup(listener_route_name_);
	MysqlxBackendEndpoint ep = cs->pick_endpoint(listener_route_name_);
	if (ep.hostname.empty()) {
		std::string msg = "No backend available for route '";
		msg += listener_route_name_;
		msg += "'";
		send_error(4002, msg.c_str());
		mysqlx_stats().record_conn_err(listener_route_name_, hg);
		healthy = false;
		status_ = X_SESSION_CLOSING;
		return 4002;
	}
	target_hostgroup_ = hg;
	target_address_   = ep.hostname;
	target_port_      = ep.mysqlx_port;
	target_use_ssl_   = ep.use_ssl;
	route_name_       = listener_route_name_;
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
	// Resolve the backend TLS posture for THIS session up front so that
	//   (a) the connection-cache lookup can match on tls_active, and
	//   (b) a fresh backend connection is configured with the same
	//       backend_tls_required_ / backend_tls_fallback_allowed_ flags.
	// The decision is per-session, not per-connection, because the
	// pool key includes tls_active — connections with the wrong
	// encryption posture for this session will simply not match.
	const MysqlxConfigStore* cs_for_tls = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
	const MysqlxBackendTlsMode tls_mode = cs_for_tls
		? cs_for_tls->get_backend_tls_mode()
		: MysqlxBackendTlsMode::as_client;
	const MysqlxBackendTlsDecision tls_decision = mysqlx_resolve_backend_tls_decision(
		tls_mode, target_use_ssl_, client_ds_.is_encrypted());
	const bool desired_backend_tls = tls_decision.require_tls;
	const bool tls_fallback_allowed = tls_decision.fallback_allowed;

	if (!backend_conn_) {
		if (thread_ptr_) {
			backend_conn_ = thread_ptr_->get_connection_from_cache(
				target_hostgroup_, username_.c_str(), schema_.c_str(),
				desired_backend_tls);
		}

		if (backend_conn_) {
			// Cache hit — pulled a pre-warmed backend connection out of the
			// per-thread pool. conn_used is the "took an existing connection
			// off the cache" counter; conn_ok (further down) is the
			// "established a fresh connection from scratch" counter.
			mysqlx_stats().record_conn_used(
				identity_ ? identity_->default_route : std::string(),
				target_hostgroup_);
			server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
			server_ds().set_status(XDS_READY);
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

		// Backend TLS posture is resolved once at the top of
		// handler_connecting_server() (search for "desired_backend_tls"
		// above) using mysqlx_tls_backend_mode + per-endpoint
		// use_ssl override + frontend TLS state. Replicate the decision
		// here onto the freshly-allocated MysqlxConnection.
		//
		// Fail-closed contract: if backend TLS is desired but no SSL_CTX
		// is available on this worker, refuse the connection rather than
		// silently downgrading to plaintext. The earlier code had `if
		// (desired_backend_tls) { if (ctx) { ... } }` — the inner ctx
		// check was a guard, but the missing else-branch meant a
		// missing/misconfigured SSL_CTX silently produced a plaintext
		// connection in TLS-required and AsClient-on-TLS-frontend
		// scenarios. CodeRabbit flagged this on PR #5707; fixed here.
		if (desired_backend_tls) {
			SSL_CTX* ssl_ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
			if (ssl_ctx == nullptr) {
				send_error(2026, "Backend TLS required but no SSL context configured on this worker");
				delete backend_conn_; backend_conn_ = nullptr;
				status_ = X_SESSION_CLOSING; healthy = false;
				return;
			}
			backend_conn_->set_backend_tls_required(true);
			backend_conn_->set_ssl_ctx(ssl_ctx);
			backend_conn_->set_backend_tls_fallback_allowed(tls_fallback_allowed);
		}

		if (identity_) {
			// Pair the backend password with the backend username pick above:
			// service_account rows carry both backend_username and backend_password
			// explicitly; mapped rows leave both empty and reuse the frontend
			// credentials (username_ above, identity_->password here). Without
			// this fallback, `mapped` mode sends an empty password to the
			// backend X plugin and every backend auth fails with 1045
			// regardless of how the frontend was provisioned.
			const std::string& backend_password =
				(identity_ && !identity_->backend_password.empty())
					? identity_->backend_password
					: identity_->password;
			backend_conn_->set_backend_password(backend_password.c_str());
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
				// Issue #5698: emit a classified error code/message
				// based on what the OpenSSL error queue / cert chain
				// said. step_auth_tls_handshake() recorded the class
				// on the connection at the failure site (the OpenSSL
				// queue is thread-local FIFO and must be drained
				// while fresh, so we couldn't defer the classification
				// to here). Falls back to HANDSHAKE_FAILED if the
				// connection didn't classify (e.g. failure happened in
				// CapabilitiesSet rather than the TLS handshake itself).
				MysqlxTlsErrorClass cls = backend_conn_->get_tls_error_class();
				if (cls == MysqlxTlsErrorClass::UNKNOWN) {
					cls = MysqlxTlsErrorClass::HANDSHAKE_FAILED;
				}
				send_error(mysqlx_backend_tls_error_code(cls),
				           mysqlx_backend_tls_error_message(cls));
			} else {
				send_error(1045, "Backend authentication failed");
			}
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	// Fresh-connection success: TCP connect, optional TLS handshake, and
	// backend-auth all completed without a return earlier in this handler.
	// Counts a brand-new backend connection only — cache hits go through
	// the early-return branch above.
	mysqlx_stats().record_conn_ok(
		identity_ ? identity_->default_route : std::string(),
		target_hostgroup_);
	server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
	server_ds().set_status(XDS_READY);
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

	// TLS advertise gating: per-route tls_mode='disabled' suppresses
	// the `tls` capability in the response, even if the worker has an
	// SSL_CTX configured. Operator opt-out for a single route. Other
	// modes (inherit / preferred / required / passthrough) advertise
	// TLS the same way historic behaviour does — passthrough is
	// special only at CapabilitiesSet(tls=true) time, not at advertise
	// time (a passthrough route MUST advertise TLS so the client even
	// thinks to upgrade). See MysqlxRouteTlsMode in
	// mysqlx_config_store.h for the full taxonomy.
	const bool advertise_tls = (effective_route_tls_mode() != MysqlxRouteTlsMode::disabled);
	SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
	if (ctx && advertise_tls) {
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
//      reject with ER_X_BAD_MESSAGE (5000).
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
//
// Error code mapping (matches upstream MySQL plugin/x/src/xpl_error.h):
//   - 5170 ER_X_FRAME_COMPRESSION_DISABLED — frame arrives without a
//     negotiated algorithm. Handled in dispatch_client_message().
//   - 5174 ER_X_BAD_COMPRESSED_FRAME — structural problem with the
//     Compression envelope itself (empty body, malformed protobuf,
//     bogus uncompressed_size hint, decompressed payload that doesn't
//     reframe into valid X messages).
//   - 5171 ER_X_DECOMPRESSION_FAILED — the algorithm rejects the
//     payload (lz4/zstd error, OOM, stall, exceeds cap).
//   - 5000 ER_X_BAD_MESSAGE — server-direction compression on the
//     client→server path; this is a wrong-direction message rather
//     than a compression-specific failure.
int MysqlxSession::handle_compression_message() {
	const auto& frame = client_ds_.front_frame();
	if (frame.size() <= 5) {
		client_ds_.pop_frame();
		send_error(5174, "Empty Compression message");
		return 0;
	}

	Mysqlx::Connection::Compression cmsg;
	if (!cmsg.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		client_ds_.pop_frame();
		send_error(5174, "Invalid Compression message");
		return 0;
	}
	const std::string& payload = cmsg.payload();
	client_ds_.pop_frame();

	if (cmsg.has_server_messages()) {
		// Server-direction compression on the client→server path is
		// always wrong: only the server is supposed to set
		// server_messages, and only when sending to the client.
		send_error(5000, "Compression message has server_messages on client→server path");
		return 0;
	}

	// Compute the size cap for this message.
	size_t cap = COMPRESSION_MAX_DECOMPRESSED_BYTES;
	if (cmsg.has_uncompressed_size()) {
		uint64_t hint = cmsg.uncompressed_size();
		if (hint == 0) {
			// Hint of 0 with a non-empty payload is malformed; treat
			// as a parse error rather than letting it through.
			send_error(5174, "Compression: uncompressed_size hint is 0");
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
			send_error(5171, "Compression: lz4 decompression failed");
			return 0;
		}
		decompressed.resize(static_cast<size_t>(produced));
	} else if (compression_algo_ == MYSQLX_COMPR_ZSTD_STREAM) {
		if (!zstd_dctx_) {
			zstd_dctx_ = ZSTD_createDCtx();
			if (!zstd_dctx_) {
				send_error(5171, "Compression: out of memory");
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
				send_error(5171, "Compression: decompressed payload exceeds cap");
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
				send_error(5171, "Compression: zstd decompression failed");
				return 0;
			}
			if (zout.pos == 0 && zin.pos < zin.size) {
				// No forward progress despite remaining input; would
				// otherwise be an infinite loop. Treat as a corrupt
				// stream and bail.
				send_error(5171, "Compression: zstd stalled (no progress)");
				return 0;
			}
		}
	} else {
		// Negotiated to NONE somehow; we've already filtered NONE in the
		// dispatch site, so this is a defensive branch only. Use 5170
		// (frame compression disabled) since the underlying issue is
		// "no algorithm selected".
		send_error(5170, "Compression algorithm not initialized");
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
		// session as unhealthy so we close cleanly. Treated as a
		// bad-compressed-frame condition rather than a decompression
		// failure: decompression itself succeeded but produced output
		// that isn't a valid X-Protocol message stream.
		send_error(5174, "Compression: decompressed payload is malformed");
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
