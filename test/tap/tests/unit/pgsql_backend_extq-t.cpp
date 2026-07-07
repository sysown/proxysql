#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <string>
#include "tap.h"

int main(int, char**) {
    plan(4);

    // --- pg_native_build_copyfail ---
    std::string out;
    pg_native_build_copyfail(out, "native COPY not supported");
    const char* reason = "native COPY not supported";
    size_t rlen = strlen(reason) + 1;              // includes NUL
    ok(out.size() == 5 + rlen, "copyfail total size = 5 + reason + NUL");
    ok(out[0] == 'f', "copyfail type byte is 'f'");
    uint32_t len = ((unsigned char)out[1] << 24) | ((unsigned char)out[2] << 16) |
                   ((unsigned char)out[3] << 8) | (unsigned char)out[4];
    ok(len == 4 + rlen, "copyfail length field = 4 + body");
    ok(memcmp(out.data() + 5, reason, rlen) == 0, "copyfail body is NUL-terminated reason");

    return exit_status();
}
