#include "PgSQL_Backend_Protocol.h"
#include <cstdlib>
#include <cstring>

static inline uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void PgSQL_Backend_Msg_Framer::feed(const unsigned char* data, size_t n) {
    if (len + n > cap) {
        size_t ncap = cap ? cap : 4096;
        while (ncap < len + n) ncap *= 2;
        buf = (unsigned char*)realloc(buf, ncap);
        cap = ncap;
    }
    memcpy(buf + len, data, n);
    len += n;
}

PgSQL_Frame_Result PgSQL_Backend_Msg_Framer::next(PgSQL_Backend_Msg& out) {
    if (len - pos < 5) return FRAME_NEED_MORE;          // need type + length
    uint32_t msglen = be32(buf + pos + 1);
    if (msglen < 4) return FRAME_ERROR;                 // length includes its own 4 bytes
    size_t total = 1 + msglen;                          // type byte + length-prefixed body
    if (len - pos < total) return FRAME_NEED_MORE;
    out.type = (char)buf[pos];
    out.payload = buf + pos + 5;
    out.payload_len = msglen - 4;
    pos += total;
    if (pos == len) { pos = 0; len = 0; }               // fully drained -> cheap reset
    return FRAME_OK;
}

void PgSQL_Backend_Msg_Framer::reset() { pos = 0; len = 0; }
