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
#endif
