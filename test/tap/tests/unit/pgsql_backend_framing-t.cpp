#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include "tap.h"

// Build one backend message into buf, return total bytes written.
static size_t put_msg(unsigned char* buf, char type, const char* payload, uint32_t plen) {
    buf[0] = (unsigned char)type;
    uint32_t len = plen + 4;               // length field includes itself, excludes type byte
    buf[1] = (len >> 24) & 0xff; buf[2] = (len >> 16) & 0xff;
    buf[3] = (len >> 8) & 0xff;  buf[4] = len & 0xff;
    memcpy(buf + 5, payload, plen);
    return 5 + plen;
}

int main(int, char**) {
    plan(7);
    PgSQL_Backend_Msg_Framer f;
    unsigned char buf[64];

    size_t n = put_msg(buf, 'Z', "I", 1);  // ReadyForQuery, txn state 'I'
    f.feed(buf, n);
    PgSQL_Backend_Msg m;
    ok(f.next(m) == FRAME_OK, "complete message framed");
    ok(m.type == 'Z', "type is Z");
    ok(m.payload_len == 1 && m.payload[0] == 'I', "payload correct");
    ok(f.next(m) == FRAME_NEED_MORE, "buffer drained -> need more");

    PgSQL_Backend_Msg_Framer f2;
    f2.feed(buf, 3);                        // only 3 of 6 bytes
    ok(f2.next(m) == FRAME_NEED_MORE, "partial message -> need more");
    f2.feed(buf + 3, n - 3);                // rest arrives
    ok(f2.next(m) == FRAME_OK && m.type == 'Z', "completes after remaining bytes");

    // Oversized declared length is rejected as FRAME_ERROR (DoS guard), even with few bytes fed.
    PgSQL_Backend_Msg_Framer f3;
    unsigned char big[5] = { 'D', 0xff, 0xff, 0xff, 0xff };  // type 'D', length ~4GiB
    f3.feed(big, 5);
    ok(f3.next(m) == FRAME_ERROR, "oversized message length rejected");

    return exit_status();
}
