#ifndef __CLASS_PGSQL_BACKEND_PROTOCOL_H
#define __CLASS_PGSQL_BACKEND_PROTOCOL_H
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <openssl/ssl.h>

enum PgSQL_Frame_Result { FRAME_OK, FRAME_NEED_MORE, FRAME_ERROR };

// Phase-1 safety ceiling for a single backend message. PostgreSQL caps a single
// field (varlena) at ~1 GiB, so this bounds a single framed message and prevents a
// malicious/garbled backend from forcing unbounded buffering. Revisit if Phase 2
// result streaming needs larger framed messages.
static const uint32_t PGSQL_MAX_BACKEND_MSG_LEN = 0x40000000u; // 1 GiB

struct PgSQL_Backend_Msg {
    char type;
    const unsigned char* payload;   // points into the framer's fed buffer
    uint32_t payload_len;
};

// Frames raw backend bytes into messages. Caller feeds bytes (possibly partial);
// next() returns FRAME_OK with a message view, FRAME_NEED_MORE when the trailing
// bytes are an incomplete message, or FRAME_ERROR on a malformed length.
class PgSQL_Backend_Msg_Framer {
    public:
    PgSQL_Backend_Msg_Framer() = default;
    // Owns a malloc'd buffer freed in the destructor; copying would double-free.
    PgSQL_Backend_Msg_Framer(const PgSQL_Backend_Msg_Framer&) = delete;
    PgSQL_Backend_Msg_Framer& operator=(const PgSQL_Backend_Msg_Framer&) = delete;
    ~PgSQL_Backend_Msg_Framer() { free(buf); }
    void feed(const unsigned char* data, size_t len);
    PgSQL_Frame_Result next(PgSQL_Backend_Msg& out);
    void reset();
    private:
    unsigned char* buf = nullptr;
    size_t len = 0, cap = 0, pos = 0;
    bool failed = false;   // sticky error state set on feed() failure (overflow/realloc); cleared only by reset()
};

// --- Pure startup/SSL request encoders (no I/O, no connection state) ---

// Writes the fixed 8-byte SSLRequest packet: length=8, code=80877103 (0x04d2162f).
void pg_build_ssl_request(unsigned char out[8]);

// Encodes a protocol-3.0 StartupMessage into out[0..*out_len).
// Layout: int32 length (incl. itself), int32 protocol (196608 = 0x00030000),
// then "user\0<user>\0database\0<database>\0" and a terminating empty key (\0).
// Bounds: writes nothing past out_cap. If the encoded message would exceed
// out_cap, sets *out_len = 0 and returns false (no partial/oversized write).
// Returns true on success with *out_len set to the number of bytes written.
bool pg_build_startup(unsigned char* out, size_t* out_len, size_t out_cap,
                      const char* user, const char* database);

// Builds the PostgreSQL AuthenticationMD5Password response into out[36]:
//   "md5" + hex(md5( hex(md5(password+user)) + salt[4] ))
// Result is the 35-char "md5..." string plus a terminating NUL (36 bytes total).
void pg_build_md5(char out[36], const char* user, const char* password, const unsigned char salt[4]);

// Computes the tls-server-end-point channel-binding data for a finished TLS
// session: the digest of the peer cert's DER encoding, using the cert's own
// signature hash algorithm, upgraded to SHA-256 if it would otherwise be
// MD5 or SHA-1 (RFC 5929 §4.1). Returns the digest length on success, -1
// on failure (no peer cert, unknown signature hash, NULL ssl, etc.).
// out must have room for at least EVP_MAX_MD_SIZE (64) bytes.
int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len);

// Composes the channel-binding input buffer for SCRAM-SHA-256-PLUS with
// tls-server-end-point. Writes "p=tls-server-end-point,," (24 bytes) || digest
// into out. The caller sizes out_cap >= 24 + 64 = 88 to cover the largest
// digest we accept (SHA-512). Returns the total bytes written, or -1 if
// out_cap is too small or any pointer is NULL.
int pg_scram_build_cbind_input_tls_server_end_point(
    const unsigned char* digest, size_t digest_len,
    unsigned char* out, size_t out_cap);

// --- SCRAM-SHA-256 client exchange (thin wrappers over vendored libscram) ---
//
// SCRAM-SHA-256, and SCRAM-SHA-256-PLUS when a cbind input has been installed via
// pg_scram_set_cbind() before building client-first. The wrapper owns a libscram
// ScramState plus a cached PgCredentials; it is defined in lib/PgSQL_Backend_Auth.cpp
// so this header stays free of scram.h. Usage mirrors a SCRAM client driving the
// PostgreSQL SASL handshake:
//   1. pg_scram_client_first()        -> SASLInitialResponse SCRAM body (client-first)
//   2. server sends AuthenticationSASLContinue (server-first)
//   3. pg_scram_client_final(server_first, password) -> client-final WITH proof
//   4. server sends AuthenticationSASLFinal (server-final)
//   5. pg_scram_verify_server_final(server_final) -> true if server signature checks out
//
// All returned C-strings are owned by the PgSQL_Scram_State and remain valid until the
// next call that produces a message of the same kind, or until pg_scram_free(). Callers
// that need to retain a message past that point must copy it.
struct PgSQL_Scram_State;   // opaque; defined in lib/PgSQL_Backend_Auth.cpp

// Allocates a new SCRAM client state. Returns nullptr on allocation failure.
PgSQL_Scram_State* pg_scram_new();

// Frees the state and the underlying libscram ScramState. Safe on nullptr.
void pg_scram_free(PgSQL_Scram_State* s);

// Builds the client-first message (the SASLInitialResponse SCRAM body). libscram
// generates a fresh random client nonce internally. With channel_binding=false the
// gs2 header is "n,," (no channel binding) and the username field is empty ("n="),
// matching the PostgreSQL convention where the real username travels in the startup
// packet. Returns the owned message string, or nullptr on error (see scram_error()).
// With channel_binding=true the gs2 header is "p=tls-server-end-point,," and the
// caller MUST have installed a matching cbind input via pg_scram_set_cbind() first;
// returns nullptr if it has not, rather than emit a header that contradicts the
// advertised -PLUS mechanism.
const char* pg_scram_client_first(PgSQL_Scram_State* s, bool channel_binding);

// Consumes the server-first message (AuthenticationSASLContinue body) and the plaintext
// password, then produces the client-final message WITH proof. server_first need not be
// NUL-terminated; server_first_len bytes are used. The password is treated as a SCRAM
// plaintext secret (keys derived ad-hoc by libscram). Returns the owned message string,
// or nullptr on error (nonce mismatch, malformed input, etc; see scram_error()).
const char* pg_scram_client_final(PgSQL_Scram_State* s, const char* password,
                                  const char* server_first, size_t server_first_len);

// Verifies the server-final message (AuthenticationSASLFinal body). server_final need
// not be NUL-terminated; len bytes are used. Returns true iff the server signature
// matches the one expected from this exchange. Must be called after a successful
// pg_scram_client_final().
bool pg_scram_verify_server_final(PgSQL_Scram_State* s, const char* server_final, size_t len);

// Sets the channel-binding input for the upcoming SCRAM client-final.
// cbind_input must be the full "p=tls-server-end-point,," (24 bytes) || digest
// blob produced by pg_scram_build_cbind_input_tls_server_end_point. Pass
// nullptr/0 to revert to plain SCRAM. Must be called BEFORE pg_scram_client_final
// so the gs2 header in pg_scram_client_first is also updated to
// "p=tls-server-end-point,,". The state takes its own copy of the input.
void pg_scram_set_cbind(PgSQL_Scram_State* s, const char* cbind_input, int cbind_input_len);

#include <string>

// Build a frontend CopyFail ('f') message: used as a safety net when a
// CopyInResponse reaches the native drive (which cannot supply CopyData).
void pg_native_build_copyfail(std::string& out, const char* reason);

// --- Native frontend-message builders for the extended-query sub-protocol ---
// These are the native replacements for what libpq's PQsendPrepare /
// PQsendQueryPrepared / etc. emit on the wire. All length fields include
// themselves and exclude the leading type byte; strings are NUL-terminated;
// all integers are big-endian.

// Build a frontend Parse ('P') message.
// Layout: len(4) | dest_stmt_name\0 | query\0 | int16 n_oids | int32 oid * n_oids.
void pg_build_parse(std::string& out, const char* stmt_name, const char* query,
                    const uint32_t* param_oids, uint16_t n_oids);

// Build a frontend Bind ('B') message.
// Layout: len(4) | portal\0 | stmt_name\0 | int16 n_param_formats | int16 fmt * n_param_formats |
//         int16 n_params | (int32 value_len | bytes) * n_params | int16 n_result_formats | int16 fmt * n_result_formats.
// param_values[i]==nullptr means SQL NULL (encoded as length -1, no bytes).
// n_param_formats/n_result_formats follow protocol semantics: 0 = all default (text),
// 1 = all params/results use the single given format, n = per-param/per-result format.
void pg_build_bind(std::string& out, const char* portal, const char* stmt_name,
                   const uint16_t* param_formats, uint16_t n_param_formats,
                   const char* const* param_values, const int32_t* param_lengths, uint16_t n_params,
                   const uint16_t* result_formats, uint16_t n_result_formats);

// Build a frontend Describe ('D') message. kind is 'S' (statement) or 'P' (portal).
// Layout: len(4) | kind(1) | name\0.
void pg_build_describe(std::string& out, char kind, const char* name);

// Build a frontend Execute ('E') message.
// Layout: len(4) | portal\0 | int32 max_rows (0 = no limit).
void pg_build_execute(std::string& out, const char* portal, uint32_t max_rows);

// Build a frontend Close ('C') message. kind is 'S' (statement) or 'P' (portal).
// Layout: len(4) | kind(1) | name\0.
void pg_build_close(std::string& out, char kind, const char* name);

// Build a frontend Flush ('H') message. Layout: len(4)==4, no body.
void pg_build_flush(std::string& out);

// Build a frontend Sync ('S') message. Layout: len(4)==4, no body.
void pg_build_sync(std::string& out);

// Build the fixed 16-byte CancelRequest packet (native-mode query cancel).
// No leading type byte: all big-endian: len(16) | code(80877102) | pid | secret.
void pg_build_cancel_request(unsigned char out[16], int32_t pid, int32_t secret);
#endif
