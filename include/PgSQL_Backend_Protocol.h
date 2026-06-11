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
#endif
