#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <openssl/md5.h>   // project-existing one-shot MD5(); also pulls MD5_DIGEST_LENGTH

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

// Lowercase-hex of an MD5 digest over [in, in+inlen). out_hex receives 32 hex
// chars plus a terminating NUL (33 bytes total).
static void md5_hex(const unsigned char* in, size_t inlen, char out_hex[33]) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(in, inlen, digest);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        out_hex[i * 2]     = hexd[(digest[i] >> 4) & 0xf];
        out_hex[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
    out_hex[MD5_DIGEST_LENGTH * 2] = '\0';
}

void pg_build_md5(char out[36], const char* user, const char* password, const unsigned char salt[4]) {
    // inner = hex(md5(password + user)). Hash the concatenation without an
    // intermediate NUL-terminated copy by passing each part length explicitly.
    size_t plen = strlen(password);
    size_t ulen = strlen(user);
    {
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, password, plen);
        MD5_Update(&ctx, user, ulen);
        MD5_Final(digest, &ctx);
        static const char hexd[] = "0123456789abcdef";
        char inner_hex[33];
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            inner_hex[i * 2]     = hexd[(digest[i] >> 4) & 0xf];
            inner_hex[i * 2 + 1] = hexd[digest[i] & 0xf];
        }
        // outer input = 32 inner hex chars + 4 raw salt bytes (NOT NUL-terminated).
        unsigned char outer_in[MD5_DIGEST_LENGTH * 2 + 4];
        memcpy(outer_in, inner_hex, MD5_DIGEST_LENGTH * 2);
        memcpy(outer_in + MD5_DIGEST_LENGTH * 2, salt, 4);

        char outer_hex[33];
        md5_hex(outer_in, sizeof(outer_in), outer_hex);

        memcpy(out, "md5", 3);
        memcpy(out + 3, outer_hex, 33);   // 32 hex chars + NUL -> out[3..35]
    }
}
