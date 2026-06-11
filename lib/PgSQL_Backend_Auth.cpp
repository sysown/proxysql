#include "PgSQL_Backend_Protocol.h"
#include <cstring>

static void put_be32(unsigned char* p, uint32_t v) {
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}

void pg_build_ssl_request(unsigned char out[8]) {
    put_be32(out, 8);
    put_be32(out + 4, 80877103u);   // 0x04d2162f
}

bool pg_build_startup(unsigned char* out, size_t* out_len, size_t out_cap,
                      const char* user, const char* database) {
    // Compute the required size first so a bound check can reject before any write,
    // guaranteeing no partial/oversized output is left in the caller buffer.
    //   length(4) + protocol(4) + "user\0" + user\0 + "database\0" + database\0 + \0
    size_t need = 8 + 5 + (strlen(user) + 1) + 9 + (strlen(database) + 1) + 1;
    if (need > out_cap) {
        *out_len = 0;
        return false;
    }

    size_t off = 8;                 // reserve length(4) + protocol(4)
    auto add = [&](const char* s) { size_t l = strlen(s) + 1; memcpy(out + off, s, l); off += l; };
    add("user");     add(user);
    add("database"); add(database);
    out[off++] = 0;                 // terminating empty key

    put_be32(out, (uint32_t)off);   // total length (includes the length field itself)
    put_be32(out + 4, 196608u);     // protocol 3.0 = 0x00030000
    *out_len = off;
    return true;
}
