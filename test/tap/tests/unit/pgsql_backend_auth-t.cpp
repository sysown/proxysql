#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include "tap.h"

int main(int, char**) {
    plan(2);

    // SSLRequest is a fixed 8 bytes: length=8, code=80877103 (0x04d2162f).
    unsigned char ssl[8];
    pg_build_ssl_request(ssl);
    unsigned char expect_ssl[8] = {0x00,0x00,0x00,0x08, 0x04,0xd2,0x16,0x2f};
    ok(memcmp(ssl, expect_ssl, 8) == 0, "SSLRequest bytes exact");

    // Startup message: int32 length, int32 protocol 196608 (3.0), then key\0value\0... \0.
    unsigned char sm[256]; size_t smlen = 0;
    pg_build_startup(sm, &smlen, sizeof(sm), "alice", "shop");
    // protocol version at offset 4 must be 0x00030000
    ok(sm[4]==0x00 && sm[5]==0x03 && sm[6]==0x00 && sm[7]==0x00, "startup protocol 3.0");

    return exit_status();
}
