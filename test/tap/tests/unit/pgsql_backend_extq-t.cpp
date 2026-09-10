#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <string>
#include "tap.h"

// Reads a big-endian uint32 out of a string at byte offset `off`.
static uint32_t be32_at(const std::string& s, size_t off) {
    return ((unsigned char)s[off] << 24) | ((unsigned char)s[off + 1] << 16) |
           ((unsigned char)s[off + 2] << 8) | (unsigned char)s[off + 3];
}

// Reads a big-endian uint16 out of a string at byte offset `off`.
static uint16_t be16_at(const std::string& s, size_t off) {
    return (uint16_t)(((unsigned char)s[off] << 8) | (unsigned char)s[off + 1]);
}

int main(int, char**) {
    plan(65);

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

    // --- pg_build_parse ---
    // Wire layout ('P'): len(4) | dest_stmt_name\0 | query\0 | int16 n_oids | int32 oid * n
    {
        // 0 OIDs, empty statement name (unnamed statement / common case).
        std::string p;
        pg_build_parse(p, "", "SELECT 1", nullptr, 0);
        size_t expect_len = 4 /*len*/ + 1 /*\0 stmt*/ + strlen("SELECT 1") + 1 /*\0 query*/ + 2 /*n_oids*/;
        ok(p.size() == 1 + expect_len, "parse(0 oids): total size");
        ok(p[0] == 'P', "parse(0 oids): type byte");
        ok(be32_at(p, 1) == expect_len, "parse(0 oids): length field");
        size_t off = 5;
        ok(p[off] == '\0', "parse(0 oids): empty stmt name terminator");
        off += 1;
        ok(memcmp(p.data() + off, "SELECT 1\0", strlen("SELECT 1") + 1) == 0, "parse(0 oids): query NUL-terminated");
        off += strlen("SELECT 1") + 1;
        ok(be16_at(p, off) == 0, "parse(0 oids): n_oids == 0");
        off += 2;
        ok(off == p.size(), "parse(0 oids): no trailing bytes");
    }
    {
        // 2 OIDs, named statement.
        std::string p;
        const uint32_t oids[2] = { 23, 25 };
        pg_build_parse(p, "proxysql_ps_1", "SELECT $1, $2", oids, 2);
        size_t expect_len = 4 + strlen("proxysql_ps_1") + 1 + strlen("SELECT $1, $2") + 1 + 2 + 4 * 2;
        ok(p.size() == 1 + expect_len, "parse(2 oids): total size");
        ok(be32_at(p, 1) == expect_len, "parse(2 oids): length field");
        size_t off = 5 + strlen("proxysql_ps_1") + 1 + strlen("SELECT $1, $2") + 1;
        ok(be16_at(p, off) == 2, "parse(2 oids): n_oids == 2");
        off += 2;
        ok(be32_at(p, off) == 23 && be32_at(p, off + 4) == 25, "parse(2 oids): oid values in order");
    }

    // --- pg_build_bind ---
    // Wire layout ('B'): len(4) | portal\0 | stmt\0 | int16 n_param_formats | fmt*n |
    //                    int16 n_params | (int32 value_len | bytes)*n | int16 n_result_formats | fmt*n
    {
        // 0 params, 0 formats, empty portal/statement (common unnamed case).
        std::string b;
        pg_build_bind(b, "", "", nullptr, 0, nullptr, nullptr, 0, nullptr, 0);
        size_t expect_len = 4 + 1 /*portal\0*/ + 1 /*stmt\0*/ + 2 /*n_param_formats*/ + 2 /*n_params*/ + 2 /*n_result_formats*/;
        ok(b.size() == 1 + expect_len, "bind(0 params): total size");
        ok(b[0] == 'B', "bind(0 params): type byte");
        ok(be32_at(b, 1) == expect_len, "bind(0 params): length field");
        size_t off = 5;
        ok(b[off] == '\0' && b[off + 1] == '\0', "bind(0 params): empty portal/stmt terminators");
        off += 2;
        ok(be16_at(b, off) == 0, "bind(0 params): n_param_formats == 0");
        off += 2;
        ok(be16_at(b, off) == 0, "bind(0 params): n_params == 0");
        off += 2;
        ok(be16_at(b, off) == 0, "bind(0 params): n_result_formats == 0");
        off += 2;
        ok(off == b.size(), "bind(0 params): no trailing bytes");
    }
    {
        // 2 params, one NULL (-1 length, no bytes), per-param formats (n_param_formats == 2).
        std::string b;
        const uint16_t pfmts[2] = { 0, 1 };            // text, binary
        const char* pvals[2] = { "abc", nullptr };     // second is SQL NULL
        const int32_t plens[2] = { 3, -1 };
        const uint16_t rfmts[1] = { 1 };
        pg_build_bind(b, "myportal", "mystmt", pfmts, 2, pvals, plens, 2, rfmts, 1);
        size_t expect_len = 4 + strlen("myportal") + 1 + strlen("mystmt") + 1
            + 2 /*n_param_formats*/ + 2 * 2 /*format values*/
            + 2 /*n_params*/ + (4 + 3) /*param0 len+data*/ + (4 + 0) /*param1 (NULL) len only*/
            + 2 /*n_result_formats*/ + 1 * 2 /*result format values*/;
        ok(b.size() == 1 + expect_len, "bind(2 params): total size");
        ok(b[0] == 'B', "bind(2 params): type byte");
        ok(be32_at(b, 1) == expect_len, "bind(2 params): length field");
        size_t off = 5 + strlen("myportal") + 1 + strlen("mystmt") + 1;
        ok(be16_at(b, off) == 2, "bind(2 params): n_param_formats == 2");
        off += 2;
        ok(be16_at(b, off) == 0 && be16_at(b, off + 2) == 1, "bind(2 params): per-param formats in order");
        off += 4;
        ok(be16_at(b, off) == 2, "bind(2 params): n_params == 2");
        off += 2;
        ok(be32_at(b, off) == 3, "bind(2 params): param0 length == 3");
        off += 4;
        ok(memcmp(b.data() + off, "abc", 3) == 0, "bind(2 params): param0 bytes == 'abc'");
        off += 3;
        ok((int32_t)be32_at(b, off) == -1, "bind(2 params): param1 (NULL) length == -1");
        off += 4;                                       // no bytes follow a NULL
        ok(be16_at(b, off) == 1, "bind(2 params): n_result_formats == 1");
        off += 2;
        ok(be16_at(b, off) == 1, "bind(2 params): result format == 1 (binary)");
        off += 2;
        ok(off == b.size(), "bind(2 params): no trailing bytes");
    }
    {
        // Broadcast param format: n_param_formats == 1 applies to all params.
        std::string b;
        const uint16_t pfmts[1] = { 1 };
        const char* pvals[2] = { "x", "y" };
        const int32_t plens[2] = { 1, 1 };
        pg_build_bind(b, "p", "s", pfmts, 1, pvals, plens, 2, nullptr, 0);
        size_t expect_len = 4 + 1 + 1 /*portal\0*/ + 1 + 1 /*stmt\0*/
            + 2 /*n_param_formats*/ + 1 * 2 /*single broadcast format value*/
            + 2 /*n_params*/ + (4 + 1) * 2 /*param0+param1 len+data*/
            + 2 /*n_result_formats*/ + 0 * 2 /*no result formats*/;
        ok(b.size() == 1 + expect_len, "bind(broadcast fmt): total size");
        ok(b[0] == 'B', "bind(broadcast fmt): type byte");
        ok(be32_at(b, 1) == expect_len, "bind(broadcast fmt): length field");
        size_t off = 5 + 2 + 2; // portal\0 + stmt\0
        ok(be16_at(b, off) == 1, "bind(broadcast fmt): n_param_formats == 1");
        off += 2;
        ok(be16_at(b, off) == 1, "bind(broadcast fmt): single broadcast format value == 1");
    }

    // --- pg_build_describe ---
    // Wire layout ('D'): len(4) | 'S'|'P' | name\0
    {
        std::string d;
        pg_build_describe(d, 'S', "mystmt");
        size_t expect_len = 4 + 1 + strlen("mystmt") + 1;
        ok(d.size() == 1 + expect_len, "describe(S): total size");
        ok(d[0] == 'D', "describe(S): type byte");
        ok(be32_at(d, 1) == expect_len, "describe(S): length field");
        ok(d[5] == 'S' && memcmp(d.data() + 6, "mystmt\0", 7) == 0, "describe(S): kind + NUL-terminated name");
    }
    {
        std::string d;
        pg_build_describe(d, 'P', "");
        size_t expect_len = 4 + 1 + 1;
        ok(d.size() == 1 + expect_len, "describe(P, empty name): total size");
        ok(be32_at(d, 1) == expect_len, "describe(P, empty name): length field");
        ok(d[5] == 'P', "describe(P, empty name): kind byte");
        ok(d[6] == '\0', "describe(P, empty name): empty name terminator");
    }

    // --- pg_build_execute ---
    // Wire layout ('E'): len(4) | portal\0 | int32 max_rows
    {
        std::string e;
        pg_build_execute(e, "", 0);
        size_t expect_len = 4 + 1 + 4;
        ok(e.size() == 1 + expect_len, "execute(max_rows=0): total size");
        ok(e[0] == 'E', "execute(max_rows=0): type byte");
        ok(be32_at(e, 1) == expect_len, "execute(max_rows=0): length field");
        ok(e[5] == '\0' && be32_at(e, 6) == 0, "execute(max_rows=0): empty portal + max_rows == 0");
    }
    {
        std::string e;
        pg_build_execute(e, "myportal", 5);
        size_t off = 5 + strlen("myportal") + 1;
        ok(be32_at(e, off) == 5, "execute(max_rows=5): max_rows == 5");
    }

    // --- pg_build_close ---
    // Wire layout ('C'): len(4) | 'S'|'P' | name\0
    {
        std::string c;
        pg_build_close(c, 'S', "mystmt");
        size_t expect_len = 4 + 1 + strlen("mystmt") + 1;
        ok(c.size() == 1 + expect_len, "close(S): total size");
        ok(c[0] == 'C', "close(S): type byte");
        ok(be32_at(c, 1) == expect_len, "close(S): length field");
        ok(c[5] == 'S' && memcmp(c.data() + 6, "mystmt\0", 7) == 0, "close(S): kind + NUL-terminated name");
    }
    {
        // Empty-name case (unnamed portal/statement), mirroring the
        // describe(P, empty name) coverage above.
        std::string c;
        pg_build_close(c, 'P', "");
        size_t expect_len = 4 + 1 + 1;
        ok(c.size() == 1 + expect_len, "close(P, empty name): total size");
        ok(be32_at(c, 1) == expect_len, "close(P, empty name): length field");
        ok(c[5] == 'P', "close(P, empty name): kind byte");
        ok(c[6] == '\0', "close(P, empty name): empty name terminator");
    }

    // --- pg_build_flush / pg_build_sync ---
    // Wire layout: 'H' len(4)==4 ; 'S' len(4)==4  (no body)
    {
        std::string h;
        pg_build_flush(h);
        ok(h.size() == 5, "flush: total size == 5");
        ok(h[0] == 'H' && be32_at(h, 1) == 4, "flush: type byte + length == 4");
    }
    {
        std::string s;
        pg_build_sync(s);
        ok(s.size() == 5, "sync: total size == 5");
        ok(s[0] == 'S' && be32_at(s, 1) == 4, "sync: type byte + length == 4");
    }

    return exit_status();
}
