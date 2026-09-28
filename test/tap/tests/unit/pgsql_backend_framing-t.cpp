/**
 * @file pgsql_backend_framing-t.cpp
 * @brief Unit tests for PgSQL_Backend_Msg_Framer — the native backend protocol's
 *        message framer (lib/PgSQL_Backend_Protocol.cpp).
 *
 * The framer is the entry point for every byte the native backend path reads
 * from a PostgreSQL server. It is fed possibly-partial socket reads and yields
 * whole protocol messages. Everything downstream — auth, result streaming, the
 * extended-query pipeline — trusts its framing and its bounds checks.
 *
 * ============================================================================
 *  SCOPE: framing logic only
 * ============================================================================
 *  Framing, bounds and error-state behaviour, all deterministic and with no
 *  dependency on the host.
 *
 *  Buffer RETENTION is deliberately NOT tested here. The framer's cap/len/pos
 *  are private, so a unit test could only infer growth from process RSS -- an
 *  indirect, noisy, Linux-only measurement that no other test in this suite
 *  uses. Retention is covered where it can be observed properly, end to end
 *  through the proxy and its admin stats:
 *
 *      test/tap/tests/pgsql-native_framer_retention-t.cpp
 *
 *  That is the regression guard for the compaction fix (03dd7983b); if buffer
 *  compaction is ever lost, that test is what fails.
 */
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <string>
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

// Write just a 5-byte header with an arbitrary declared length, so length
// validation can be exercised without supplying a body.
static void put_header(unsigned char* buf, char type, uint32_t declared_len) {
    buf[0] = (unsigned char)type;
    buf[1] = (declared_len >> 24) & 0xff; buf[2] = (declared_len >> 16) & 0xff;
    buf[3] = (declared_len >> 8) & 0xff;  buf[4] = declared_len & 0xff;
}

// Append a complete message of `payload` bytes to `s`.
static void append_msg(std::string& s, char type, size_t payload_len) {
    s.push_back(type);
    uint32_t L = (uint32_t)(payload_len + 4);
    s.push_back((char)((L >> 24) & 0xff));
    s.push_back((char)((L >> 16) & 0xff));
    s.push_back((char)((L >> 8) & 0xff));
    s.push_back((char)(L & 0xff));
    s.append(payload_len, 'x');
}

int main(int, char**) {
    plan(21);

    PgSQL_Backend_Msg m;

    // ---------------------------------------------------------------- basics
    {
        PgSQL_Backend_Msg_Framer f;
        unsigned char buf[64];
        size_t n = put_msg(buf, 'Z', "I", 1);  // ReadyForQuery, txn state 'I'
        f.feed(buf, n);
        ok(f.next(m) == FRAME_OK, "complete message framed");
        ok(m.type == 'Z', "type is Z");
        ok(m.payload_len == 1 && m.payload[0] == 'I', "payload correct");
        ok(f.next(m) == FRAME_NEED_MORE, "buffer drained -> need more");
    }
    {
        PgSQL_Backend_Msg_Framer f;
        unsigned char buf[64];
        size_t n = put_msg(buf, 'Z', "I", 1);
        f.feed(buf, 3);                        // only 3 of 6 bytes
        ok(f.next(m) == FRAME_NEED_MORE, "partial message -> need more");
        f.feed(buf + 3, n - 3);                // rest arrives
        ok(f.next(m) == FRAME_OK && m.type == 'Z', "completes after remaining bytes");
    }

    // ------------------------------------------------- declared-length bounds
    // The length field counts itself, so anything below 4 is malformed. A
    // hostile or garbled backend reaching these branches must be rejected
    // rather than trusted into a huge/negative payload_len.
    for (uint32_t bad = 0; bad < 4; bad++) {
        PgSQL_Backend_Msg_Framer f;
        unsigned char hdr[5];
        put_header(hdr, 'D', bad);
        f.feed(hdr, 5);
        ok(f.next(m) == FRAME_ERROR, "declared length %u (< 4) rejected", bad);
    }
    {
        // Length exactly 4 is legal and means an empty payload.
        PgSQL_Backend_Msg_Framer f;
        unsigned char hdr[5];
        put_header(hdr, 'n', 4);               // NoData: no body
        f.feed(hdr, 5);
        PgSQL_Frame_Result r = f.next(m);
        ok(r == FRAME_OK, "declared length 4 (empty payload) accepted");
        ok(m.type == 'n' && m.payload_len == 0,
           "declared length 4 yields payload_len 0");
    }
    {
        // Exactly at the DoS ceiling: legal, so with only a header fed the
        // framer must ask for more rather than reject. Distinguishes "at the
        // cap" from "over the cap" — an off-by-one here would reject the
        // largest legitimate message PostgreSQL can send.
        PgSQL_Backend_Msg_Framer f;
        unsigned char hdr[5];
        put_header(hdr, 'D', PGSQL_MAX_BACKEND_MSG_LEN);
        f.feed(hdr, 5);
        ok(f.next(m) == FRAME_NEED_MORE, "declared length == cap is accepted (awaits body)");
    }
    {
        PgSQL_Backend_Msg_Framer f;
        unsigned char hdr[5];
        put_header(hdr, 'D', PGSQL_MAX_BACKEND_MSG_LEN + 1);
        f.feed(hdr, 5);
        ok(f.next(m) == FRAME_ERROR, "declared length == cap + 1 rejected");
    }

    // ------------------------------------------------ sticky failure + reset
    // Once framing is lost the stream cannot be resynchronised, so the error
    // must latch: a caller that keeps feeding must not be handed garbage that
    // happens to parse.
    {
        PgSQL_Backend_Msg_Framer f;
        unsigned char hdr[5];
        put_header(hdr, 'D', 2);               // malformed
        f.feed(hdr, 5);
        ok(f.next(m) == FRAME_ERROR, "sticky: first next() reports the error");

        unsigned char good[64];
        size_t n = put_msg(good, 'Z', "I", 1); // perfectly valid message
        f.feed(good, n);
        ok(f.next(m) == FRAME_ERROR, "sticky: valid bytes after an error do not clear it");

        f.reset();
        f.feed(good, n);
        ok(f.next(m) == FRAME_OK && m.type == 'Z', "reset() clears the error and framing resumes");
    }

    // ------------------------------------------- maximal read fragmentation
    // A TCP read can split anywhere, including inside a length field. Feed
    // three messages one byte at a time and require all three back in order.
    {
        std::string s;
        append_msg(s, 'T', 7);
        append_msg(s, 'D', 0);                 // zero-length payload mid-stream
        append_msg(s, 'C', 11);

        PgSQL_Backend_Msg_Framer f;
        char types[3] = { 0, 0, 0 };
        uint32_t lens[3] = { 0, 0, 0 };
        int got = 0;
        for (size_t i = 0; i < s.size(); i++) {
            f.feed((const unsigned char*)s.data() + i, 1);
            for (;;) {
                PgSQL_Frame_Result r = f.next(m);
                if (r != FRAME_OK) break;
                if (got < 3) { types[got] = m.type; lens[got] = m.payload_len; }
                got++;
            }
        }
        ok(got == 3, "byte-at-a-time: exactly 3 messages framed (got %d)", got);
        ok(types[0] == 'T' && lens[0] == 7, "byte-at-a-time: message 1 intact");
        ok(types[1] == 'D' && lens[1] == 0 && types[2] == 'C' && lens[2] == 11,
           "byte-at-a-time: zero-length message and message 3 intact");
    }

    // ------------------------------------------- many messages in one feed
    {
        std::string s;
        const int N = 500;
        for (int i = 0; i < N; i++) append_msg(s, 'D', (size_t)(i % 37));
        PgSQL_Backend_Msg_Framer f;
        f.feed((const unsigned char*)s.data(), s.size());
        int got = 0;
        bool all_good = true;
        for (;;) {
            PgSQL_Frame_Result r = f.next(m);
            if (r != FRAME_OK) break;
            if (m.type != 'D' || m.payload_len != (uint32_t)(got % 37)) all_good = false;
            got++;
        }
        ok(got == N && all_good, "single feed of %d messages framed in order (got %d)", N, got);
    }

    return exit_status();
}
