#ifndef PROXYSQL_MYSQLX_PROTOCOL_H
#define PROXYSQL_MYSQLX_PROTOCOL_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// X Protocol frame header: 4-byte payload_size (LE) + 1-byte message_type.
// payload_size includes the message_type byte.
struct MysqlxFrameHeader {
	uint32_t payload_size { 0 };
	uint8_t message_type { 0 };
};

static constexpr size_t MYSQLX_FRAME_HEADER_SIZE = 5; // 4 + 1

// Maximum allowed X Protocol frame payload (16 MB).  Protects against
// OOM from a malicious client claiming a multi-GB payload.
static constexpr uint32_t MYSQLX_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

// Encode a frame header into a 5-byte buffer.
std::vector<uint8_t> mysqlx_encode_frame_header(const MysqlxFrameHeader& hdr);

// Decode a frame header from raw bytes.  Returns nullopt if len < 5.
std::optional<MysqlxFrameHeader> mysqlx_decode_frame_header(const uint8_t* data, size_t len);

// Check if an auth method name is supported by our plugin (Phase 1).
bool mysqlx_is_supported_auth_method(const std::string& method);

// Build a complete X Protocol frame: header + serialized protobuf payload.
std::vector<uint8_t> mysqlx_build_frame(uint8_t message_type, const std::string& serialized_payload);

// Read exactly `len` bytes from fd into buf.  Returns false on error/EOF.
bool mysqlx_read_exact(int fd, uint8_t* buf, size_t len);

// Read one complete X Protocol frame from fd.  Fills header and payload.
bool mysqlx_read_frame(int fd, MysqlxFrameHeader& header, std::vector<uint8_t>& payload);

// Write a complete buffer to fd.  Returns false on error.
bool mysqlx_write_all(int fd, const uint8_t* data, size_t len);

// Build and send an X Protocol Error frame.
bool mysqlx_send_error(int fd, uint16_t code, const std::string& msg, const std::string& sql_state = "HY000");

// Build and send an X Protocol Ok frame.
bool mysqlx_send_ok(int fd, const std::string& msg = "");

// Hex encoding for MYSQL41 wire format.
std::string mysqlx_hex_encode(const std::vector<uint8_t>& data);
bool mysqlx_hex_decode(const std::string& hex, std::vector<uint8_t>& out);

// MYSQL41 auth helpers
std::vector<uint8_t> mysqlx_mysql41_hash(const std::string& password);
std::vector<uint8_t> mysqlx_mysql41_scramble(const std::vector<uint8_t>& challenge,
                                              const std::string& password);
bool mysqlx_mysql41_verify(const std::vector<uint8_t>& challenge,
                            const std::vector<uint8_t>& client_response,
                            const std::string& password);

bool mysqlx_mysql41_verify_hash(const std::vector<uint8_t>& challenge,
                                 const std::vector<uint8_t>& client_response,
                                 const std::vector<uint8_t>& stored_hash);

// =====================================================================
// TLS handshake error classification (issue #5698).
//
// Translates an OpenSSL handshake failure into one of a handful of
// distinct classes so the proxy can emit a meaningful X-Protocol Error
// frame instead of a generic "TLS handshake failed". MySQL Router
// distinguishes cert verification, hostname mismatch, protocol
// mismatch, etc.; this enum mirrors that contract.
//
// Design notes:
//   * Backend leg: detail is operationally helpful (operators want to
//     know "expired cert" vs "self-signed CA"). The classification
//     consults SSL_get_verify_result() first (cert-chain reasons take
//     precedence over generic handshake reasons), then ERR_get_error()
//     for non-cert protocol failures.
//   * Frontend leg: detail is a leak risk — an attacker-supplied cert
//     chain shouldn't bleed into a public error message. Frontend
//     callers map most classes back to HANDSHAKE_FAILED before
//     emitting; only PROTOCOL_MISMATCH and NO_SSL_CTX get a distinct
//     code.
//   * UNKNOWN is the fallthrough — if neither queue gives us a useful
//     reason, we emit the generic class.
enum class MysqlxTlsErrorClass {
	UNKNOWN = 0,
	HANDSHAKE_FAILED,         // generic — couldn't classify further
	CERT_VERIFY_FAILED,       // generic verify failure (untrusted chain etc.)
	CERT_EXPIRED,             // X509_V_ERR_CERT_HAS_EXPIRED
	HOSTNAME_MISMATCH,        // X509_V_ERR_HOSTNAME_MISMATCH
	PROTOCOL_MISMATCH,        // SSL_R_UNSUPPORTED_PROTOCOL etc.
	UNKNOWN_CA,               // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
	NO_SSL_CTX                // SSL_CTX is null (frontend-side: TLS not configured)
};

// X-Protocol error codes for backend TLS classification. Allocated
// from the 3150-3199 range that already hosts ProxySQL's TLS-specific
// codes (3150 = "TLS not configured on server", 3151 = "TLS handshake
// failed" for frontend; 3152 was the old generic backend code).
//
// Codes 3153..3157 are NEW with this commit; existing 3150-3152 keep
// their meaning so older clients continue to recognize them.
static constexpr int MYSQLX_BACKEND_TLS_ERR_HANDSHAKE_FAILED   = 3152;
static constexpr int MYSQLX_BACKEND_TLS_ERR_CERT_VERIFY_FAILED = 3153;
static constexpr int MYSQLX_BACKEND_TLS_ERR_CERT_EXPIRED       = 3154;
static constexpr int MYSQLX_BACKEND_TLS_ERR_HOSTNAME_MISMATCH  = 3155;
static constexpr int MYSQLX_BACKEND_TLS_ERR_PROTOCOL_MISMATCH  = 3156;
static constexpr int MYSQLX_BACKEND_TLS_ERR_UNKNOWN_CA         = 3157;

// X-Protocol error codes for frontend TLS classification. Frontend
// detail is intentionally limited to avoid leaking attacker-supplied
// cert info into the response — most classes collapse onto
// HANDSHAKE_FAILED.
static constexpr int MYSQLX_FRONTEND_TLS_ERR_NOT_CONFIGURED      = 3150;
static constexpr int MYSQLX_FRONTEND_TLS_ERR_HANDSHAKE_FAILED    = 3151;
static constexpr int MYSQLX_FRONTEND_TLS_ERR_PROTOCOL_MISMATCH   = 3158;

// Forward decl for OpenSSL SSL* (avoids dragging openssl/ssl.h into
// every includer of this header).
struct ssl_st;
typedef struct ssl_st SSL;

// Classify an SSL_do_handshake failure into MysqlxTlsErrorClass.
// Inputs:
//   * ssl: the SSL* whose handshake just failed (may be nullptr — in
//     that case we return NO_SSL_CTX). Reads SSL_get_verify_result()
//     non-destructively. Caller retains ownership.
//   * peek_err_queue: if true, walks ERR_get_error() (DESTRUCTIVE — the
//     OpenSSL error queue is a thread-local FIFO and ERR_get_error pops
//     entries off it). Pass false for follow-up calls in the same
//     scope, or after you've already drained the queue elsewhere.
//
// Pure with respect to the SSL* (never modifies it) and the cert
// chain inside; cert pointers are weak references. Caller is
// responsible for any further OpenSSL state cleanup.
MysqlxTlsErrorClass mysqlx_classify_tls_error(SSL* ssl, bool peek_err_queue);

// Map a backend MysqlxTlsErrorClass to (code, message) suitable for
// passing to MysqlxSession::send_error(). The code/message pair
// includes a human-readable reason but does NOT include OpenSSL queue
// detail (the caller may include that separately in a log line, but
// not in the wire-level frame, since exposing chain details to the
// client raises the same kind of MITM-leak concerns the frontend has).
const char* mysqlx_backend_tls_error_message(MysqlxTlsErrorClass cls);
int mysqlx_backend_tls_error_code(MysqlxTlsErrorClass cls);

// Frontend equivalent — collapses most classes onto HANDSHAKE_FAILED
// (no leak detail). NO_SSL_CTX → 3150, PROTOCOL_MISMATCH → 3158, all
// others → 3151.
const char* mysqlx_frontend_tls_error_message(MysqlxTlsErrorClass cls);
int mysqlx_frontend_tls_error_code(MysqlxTlsErrorClass cls);

#endif /* PROXYSQL_MYSQLX_PROTOCOL_H */
