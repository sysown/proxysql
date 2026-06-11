#ifndef __CLASS_PGSQL_BACKEND_PROTOCOL_H
#define __CLASS_PGSQL_BACKEND_PROTOCOL_H
#include <cstdint>
#include <cstddef>
#include <cstdlib>

enum PgSQL_Frame_Result { FRAME_OK, FRAME_NEED_MORE, FRAME_ERROR };

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
    ~PgSQL_Backend_Msg_Framer() { free(buf); }
    void feed(const unsigned char* data, size_t len);
    PgSQL_Frame_Result next(PgSQL_Backend_Msg& out);
    void reset();
    private:
    unsigned char* buf = nullptr;
    size_t len = 0, cap = 0, pos = 0;
};
#endif
