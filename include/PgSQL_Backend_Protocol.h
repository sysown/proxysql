#ifndef __CLASS_PGSQL_BACKEND_PROTOCOL_H
#define __CLASS_PGSQL_BACKEND_PROTOCOL_H
#include <cstdint>
#include <cstddef>
#include <cstdlib>

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

// --- SCRAM-SHA-256 client exchange (thin wrappers over vendored libscram) ---
//
// Plain SCRAM-SHA-256 only: gs2 channel-binding flag is 'n' (no channel binding).
// Channel binding (gs2 flag 'p'/'y') is a separate task. The wrapper owns a libscram
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
// channel_binding=true is not supported by this task and returns nullptr.
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
#endif
