#include "PgSQL_Backend_Protocol.h"
#include <cstdlib>
#include <cstring>
#include "proxysql_mem.h"
#include "proxysql_structs.h"
#include <string>
#include <vector>

static inline uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void PgSQL_Backend_Msg_Framer::feed(const unsigned char* data, size_t n) {
    if (failed) return;                                  // already in error state; ignore further bytes
    if (n > SIZE_MAX - len) { failed = true; return; }   // would overflow len+n
    if (len + n > cap) {
        size_t need = len + n;
        size_t ncap = cap ? cap : 4096;
        while (ncap < need) {
            if (ncap > SIZE_MAX / 2) { ncap = need; break; }  // avoid doubling overflow
            ncap *= 2;
        }
        unsigned char* nb = (unsigned char*)realloc(buf, ncap);
        if (!nb) { failed = true; return; }              // old buf still owned/freed by dtor; don't touch it
        buf = nb;
        cap = ncap;
    }
    memcpy(buf + len, data, n);
    len += n;
}

PgSQL_Frame_Result PgSQL_Backend_Msg_Framer::next(PgSQL_Backend_Msg& out) {
    if (failed) return FRAME_ERROR;                     // sticky error from feed()
    if (len - pos < 5) return FRAME_NEED_MORE;          // need type + length
    uint32_t msglen = be32(buf + pos + 1);
    if (msglen < 4 || msglen > PGSQL_MAX_BACKEND_MSG_LEN) return FRAME_ERROR;  // length includes its own 4 bytes; cap guards against DoS
    size_t total = 1 + msglen;                          // type byte + length-prefixed body
    if (len - pos < total) return FRAME_NEED_MORE;
    out.type = (char)buf[pos];
    out.payload = buf + pos + 5;
    out.payload_len = msglen - 4;
    pos += total;
    if (pos == len) { pos = 0; len = 0; }               // fully drained -> cheap reset
    return FRAME_OK;
}

void PgSQL_Backend_Msg_Framer::reset() { pos = 0; len = 0; failed = false; }

static void pg_native_append_be32(std::string& out, uint32_t v) {
	out.push_back((char)((v >> 24) & 0xff));
	out.push_back((char)((v >> 16) & 0xff));
	out.push_back((char)((v >> 8) & 0xff));
	out.push_back((char)(v & 0xff));
}

void pg_native_build_copyfail(std::string& out, const char* reason) {
	const size_t rlen = strlen(reason) + 1;        // include NUL terminator
	out.push_back('f');
	pg_native_append_be32(out, (uint32_t)(4 + rlen));
	out.append(reason, rlen);
}

void pg_native_build_extq_outbuf(std::vector<PtrSize_t>& frame, std::string& out) {
	for (auto& p : frame) {
		if (p.ptr) {
			out.append((const char*)p.ptr, p.size);
			l_free(p.size, p.ptr);
			p.ptr = nullptr;
			p.size = 0;
		}
	}
	frame.clear();
	out.push_back('S');
	pg_native_append_be32(out, 4);
}
