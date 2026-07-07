#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include "proxysql_structs.h"
#include "proxysql_mem.h"
#include <cstring>
#include <string>
#include <vector>
#include "tap.h"

// Helper: allocate a PtrSize_t entry holding one fake client message.
static PtrSize_t mk_entry(const char* bytes, size_t len) {
    PtrSize_t e;
    e.ptr = l_alloc(len);
    memcpy(e.ptr, bytes, len);
    e.size = (unsigned int)len;
    return e;
}

int main(int, char**) {
    plan(8);

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

    // --- pg_native_build_extq_outbuf ---
    // Two fake raw client messages: a Parse-ish and a Bind-ish blob.
    const char m1[] = { 'P', 0, 0, 0, 8, 'a', 'b', 'c', 0 };   // 9 bytes
    const char m2[] = { 'B', 0, 0, 0, 5, 0 };                  // 6 bytes
    std::vector<PtrSize_t> frame;
    frame.push_back(mk_entry(m1, sizeof(m1)));
    frame.push_back(mk_entry(m2, sizeof(m2)));
    std::string ob;
    pg_native_build_extq_outbuf(frame, ob);
    ok(frame.empty(), "frame consumed (entries freed and cleared)");
    ok(ob.size() == sizeof(m1) + sizeof(m2) + 5, "outbuf = msgs + 5-byte Sync");
    ok(memcmp(ob.data(), m1, sizeof(m1)) == 0 &&
       memcmp(ob.data() + sizeof(m1), m2, sizeof(m2)) == 0, "messages concatenated in order");
    const char syncmsg[] = { 'S', 0, 0, 0, 4 };
    ok(memcmp(ob.data() + ob.size() - 5, syncmsg, 5) == 0, "trailing Sync message appended");

    return exit_status();
}
