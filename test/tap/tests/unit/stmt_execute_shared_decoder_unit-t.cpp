#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_Protocol.h"
#include "MySQL_PreparedStatement.h"
#include <cstdlib>
#include <cstring>
#include <vector>

static PtrSize_t packet(const std::vector<unsigned char>& tail) {
    PtrSize_t p{}; p.size = 14 + tail.size(); p.ptr = calloc(1, p.size);
    auto b = static_cast<unsigned char*>(p.ptr); b[4] = 0x17; b[5] = 7; b[10] = 1;
    if (!tail.empty()) memcpy(b + 14, tail.data(), tail.size());
    return p;
}
static void release_packet(stmt_execute_metadata_t* m) { free(m->pkt); m->pkt = nullptr; }
int main() {
    plan(NO_PLAN); test_init_minimal();
    stmt_execute_metadata_t* meta = nullptr;
    auto p = packet({0,1, MYSQL_TYPE_LONG});
    ok(!MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta), "truncated type rejected");
    ok(meta == nullptr, "failure leaves uncached metadata absent"); free(p.ptr);
    p = packet({0,1,MYSQL_TYPE_LONG,0,1,2});
    ok(!MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta), "truncated payload rejected"); free(p.ptr);
    p = packet({0,1,MYSQL_TYPE_LONG,0,0xfe,0xff,0xff,0xff});
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta);
    ok(meta && !meta->binds[0].is_unsigned && static_cast<unsigned char*>(meta->binds[0].buffer)[0] == 0xfe, "signed integer decoded");
    if (!meta) { free(p.ptr); test_cleanup_minimal(); return exit_status(); }
    release_packet(meta);
    auto* saved_binds = meta->binds;
    p = packet({0,1,MYSQL_TYPE_LONG,0,MYSQL_TYPE_LONG,0,1,0,0,0,2,0,0,0});
    ok(!MySQL_Protocol::decode_stmt_execute(p, 2, nullptr, &meta) &&
       meta->num_params == 1 && meta->binds == saved_binds && !meta->pkt,
       "cache count mismatch preserves metadata and caller packet");
    free(p.ptr);
    p = packet({0,1,MYSQL_TYPE_LONG});
    ok(!MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta) && meta->pkt == nullptr,
       "truncated types leave cached metadata and packet owned by caller");
    free(p.ptr);
    const unsigned char types[] = {MYSQL_TYPE_LONG, 0x80};
    p = packet({0,0,0xff,0xff,0xff,0xff});
    auto reused = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta, types);
    ok(reused == meta && meta->binds[0].is_unsigned, "explicit types reused with unsigned flag");
    if (reused) release_packet(meta); else free(p.ptr);
    delete meta; meta = nullptr;
    p = packet({0,1,MYSQL_TYPE_BLOB,0,3,'a',0,'b'});
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta);
    ok(meta && *meta->binds[0].length == 3 && !memcmp(meta->binds[0].buffer, "a\0b", 3), "blob preserves embedded NUL");
    if (meta) { release_packet(meta); delete meta; meta = nullptr; } else free(p.ptr);
    p = packet({0,1,MYSQL_TYPE_STRING,0,3,'a',0,'b'});
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta);
    ok(meta && *meta->binds[0].length == 3 && !memcmp(meta->binds[0].buffer, "a\0b", 3), "string preserves embedded NUL");
    if (meta) { release_packet(meta); delete meta; meta = nullptr; } else free(p.ptr);
    p = packet({0,0,1,0,0,0});
    ok(!MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta) && !meta,
       "first execution without types rejected and packet retained");
    free(p.ptr);
    p = packet({0,0,1,0,0,0});
    const unsigned char initial_types[] = {MYSQL_TYPE_LONG, 0};
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta, initial_types);
    ok(meta && meta->binds[0].buffer_type == MYSQL_TYPE_LONG &&
       static_cast<unsigned char*>(meta->binds[0].buffer)[0] == 1,
       "first execution accepts explicit effective types");
    if (meta) { release_packet(meta); delete meta; meta = nullptr; } else free(p.ptr);
    StmtLongDataHandler long_data; char empty = 0; long_data.add(7, 0, &empty, 0);
    p = packet({0,1,MYSQL_TYPE_STRING,0});
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, &long_data, &meta);
    ok(meta && meta->binds[0].buffer && !*meta->binds[0].is_null && *meta->binds[0].length == 0, "empty long data is not NULL");
    if (meta) { release_packet(meta); delete meta; meta = nullptr; } else free(p.ptr);
    long_data.reset(7);
    p = packet({1,1,MYSQL_TYPE_STRING,0});
    meta = MySQL_Protocol::decode_stmt_execute(p, 1, nullptr, &meta);
    ok(meta && *meta->binds[0].is_null, "NULL bitmap remains distinct from empty long data");
    if (meta) { release_packet(meta); delete meta; } else free(p.ptr);
    test_cleanup_minimal(); return exit_status();
}
