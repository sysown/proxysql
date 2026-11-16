#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "Embedded_MySQL_Prepared.h"
#include "Embedded_SQLite_Adapter.h"
#include "MySQL_Protocol.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Session.h"
#include "mysql_connection.h"
#include "Embedded_Execution.h"
#include "Embedded_MySQL_Result.h"

#include <cstring>
#include <string>
#include <vector>

static MySQL_Session* make_session(MySQL_Data_Stream*& stream_out, MySQL_Protocol*& proto_out) {
    MySQL_Session* s = new MySQL_Session();
    s->session_type = PROXYSQL_SESSION_MYSQL_EMU;
    s->connections_handler = true;
    MySQL_Data_Stream* st = new MySQL_Data_Stream();
    st->sess = s;
    st->PSarrayOUT = new PtrSizeArray();
    s->client_myds = st;
    st->myprot.init(&s->client_myds, nullptr, s);
    MySQL_Connection* conn = new MySQL_Connection();
    st->myconn = conn;
    s->client_myds = st;
    s->thread = nullptr;
    s->mybes = nullptr;
    s->sess_STMTs_meta = nullptr;
    s->SLDH = nullptr;
    stream_out = st;
    proto_out = nullptr;
    return s;
}

static PtrSize_t make_packet(const std::vector<unsigned char>& payload_after_header) {
    // payload_after_header includes command byte onward; we add 4-byte header
    PtrSize_t p{};
    p.size = 4 + payload_after_header.size();
    p.ptr = calloc(1, p.size);
    auto b = static_cast<unsigned char*>(p.ptr);
    b[0] = (unsigned char)(payload_after_header.size() & 0xff);
    b[1] = (unsigned char)((payload_after_header.size() >> 8) & 0xff);
    b[2] = (unsigned char)((payload_after_header.size() >> 16) & 0xff);
    b[3] = 0;
    if (!payload_after_header.empty())
        memcpy(b + 4, payload_after_header.data(), payload_after_header.size());
    return p;
}

static void clear_ps(PtrSizeArray* ps) {
    if (!ps) return;
    for (unsigned i = 0; i < ps->len; i++) {
        auto pp = ps->index(i);
        if (pp->ptr) l_free(pp->size, pp->ptr);
    }
    ps->len = 0;
}

struct SimplePolicy : embedded::EndpointPolicy {
    embedded::Status authorize_prepare(const std::string&) override { return {}; }
    embedded::Status authorize_execute(const std::string&, const std::vector<embedded::Value>&) override { return {}; }
    embedded::Status authorize_fetch(const std::string&) override { return {}; }
};

// Forward to the real SQLite engine while allowing a reset failure to be injected.
struct ResetFailureAdapter : embedded::Adapter {
    embedded::SQLiteAdapter inner;
    bool fail_reset = false;
    explicit ResetFailureAdapter(sqlite3* db) : inner(db) {}
    embedded::Status prepare(const std::string& q, std::unique_ptr<embedded::Statement>& o) override { return inner.prepare(q, o); }
    embedded::Status describe_parameters(embedded::Statement& s, std::vector<embedded::Type>& o) override { return inner.describe_parameters(s, o); }
    embedded::Status describe_result(embedded::Statement& s, std::vector<embedded::Column>& o) override { return inner.describe_result(s, o); }
    embedded::Status bind(embedded::Statement& s, const std::vector<embedded::Value>& v) override { return inner.bind(s, v); }
    embedded::Status execute(embedded::Statement& s, embedded::ExecInfo& o) override { return inner.execute(s, o); }
    embedded::Status fetch(embedded::Statement& s, embedded::Row& r, bool& d, size_t b) override { return inner.fetch(s, r, d, b); }
    embedded::Status reset(embedded::Statement& s) override {
        if (fail_reset) return embedded::Error{embedded::ErrorKind::engine, SQLITE_BUSY, "injected reset failure", "HY000"};
        return inner.reset(s);
    }
    void finalize(std::unique_ptr<embedded::Statement> s) noexcept override { inner.finalize(std::move(s)); }
};

int main() {
    plan(NO_PLAN);
    test_init_minimal();

    {
    sqlite3* db = nullptr;
    proxy_sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    embedded::SQLiteAdapter adapter(db);
    SimplePolicy policy;

    // non-registered pass-through
    {
        MySQL_Data_Stream* st = nullptr; MySQL_Protocol* pr = nullptr;
        MySQL_Session* s = make_session(st, pr);
        PtrSize_t pkt = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(!rc, "unregistered session returns false");
        ok(!embedded::reset_mysql_prepared(*s), "unregistered reset is a successful no-op");
        ok(pkt.ptr != nullptr, "unregistered does not consume packet");
        free(pkt.ptr);
        delete st->myconn; st->myconn = nullptr; delete s;
    }

    // register
    MySQL_Data_Stream* st = nullptr; MySQL_Protocol* pr = nullptr;
    MySQL_Session* s = make_session(st, pr);
    auto status_cb = []() -> uint16_t { return 0; };
    embedded::MySQLPreparedLimits limits;
    limits.statements = 4;
    limits.response_bytes = 1024 * 1024;
    embedded::Status reg = embedded::register_mysql_prepared(*s, adapter, policy, status_cb, limits);
    ok(!reg, "registration succeeds");

    // reject ordinary proxy mysql session
    {
        MySQL_Session os; os.session_type = PROXYSQL_SESSION_MYSQL; os.thread = nullptr; os.mybes = nullptr; os.sess_STMTs_meta = nullptr; os.SLDH = nullptr; os.client_myds = nullptr; os.connections_handler = true;
        embedded::Status r = embedded::register_mysql_prepared(os, adapter, policy, status_cb, limits);
        ok((bool)r, "ordinary proxy MySQL session rejected");
    }

    // prepare SELECT 1
    uint32_t wire_id = 0;
    {
        std::string sql = "SELECT 1";
        std::vector<unsigned char> payload = {0x16};
        for (char c : sql) payload.push_back((unsigned char)c);
        PtrSize_t pkt = make_packet(payload);
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(rc, "prepare returns true");
        ok(pkt.ptr == nullptr, "prepare consumes packet");
        // wire id is 1
        wire_id = 1;
        ok(st->PSarrayOUT->len >= 1, "prepare emits packets");
        clear_ps(st->PSarrayOUT);
    }

    // execute prepared statement
    {
        std::vector<unsigned char> payload = {0x17};
        // stmt id
        for (int i = 0; i < 4; i++) payload.push_back((unsigned char)((wire_id >> (8*i)) & 0xff));
        payload.push_back(0); // flags
        // iteration count 1
        payload.push_back(1); payload.push_back(0); payload.push_back(0); payload.push_back(0);
        PtrSize_t pkt = make_packet(payload);
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(rc, "execute returns true");
        ok(pkt.ptr == nullptr, "execute consumes packet");
        // check no error packet (first byte after header != 0xff) maybe
        bool is_err = (st->PSarrayOUT->len > 0 && st->PSarrayOUT->index(0)->size >= 5 &&
                      static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0xff);
        ok(st->PSarrayOUT->len >= 4 && !is_err, "execute emits result packets");
        clear_ps(st->PSarrayOUT);
    }

    // unknown id execute
    {
        std::vector<unsigned char> payload = {0x17};
        uint32_t bad = 999;
        for (int i = 0; i < 4; i++) payload.push_back((unsigned char)((bad >> (8*i)) & 0xff));
        payload.push_back(0);
        payload.push_back(1); payload.push_back(0); payload.push_back(0); payload.push_back(0);
        PtrSize_t pkt = make_packet(payload);
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(rc, "unknown execute returns true");
        bool is_err = (st->PSarrayOUT->len > 0 && st->PSarrayOUT->index(0)->size >= 7 &&
                      static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0xff);
        ok(is_err, "unknown execute returns error");
        if (is_err) {
            uint16_t code = *reinterpret_cast<uint16_t*>(static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr) + 5);
            ok(code == 1243, "unknown id error code 1243");
        } else ok(false, "unknown id error code 1243");
        clear_ps(st->PSarrayOUT);

    }

    // malformed packet execute
    {
        std::vector<unsigned char> payload = {0x17, 1,2,3}; // too short
        PtrSize_t pkt = make_packet(payload);
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(rc, "malformed execute returns true");
        clear_ps(st->PSarrayOUT);
        if (pkt.ptr) free(pkt.ptr);
    }

    // Parameter type reuse and reset keep client bindings while clearing long data.
    {
        std::string sql = "SELECT ?";
        std::vector<unsigned char> payload{0x16};
        payload.insert(payload.end(), sql.begin(), sql.end());
        PtrSize_t pkt = make_packet(payload);
        embedded::handle_mysql_prepared(*s, pkt);
        ok(st->PSarrayOUT->len > 0 && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0,
           "parameterized prepare emits prepare OK");
        uint32_t id = 0;
        memcpy(&id, static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr) + 5, 4);
        clear_ps(st->PSarrayOUT);
        auto execute = [&](unsigned char typeflag, bool include_type, unsigned char value) {
            std::vector<unsigned char> e{0x17, (unsigned char)id, 0, 0, 0, 0, 1, 0, 0, 0, 0, typeflag};
            if (include_type) { e.push_back(MYSQL_TYPE_TINY); e.push_back(0); }
            e.push_back(value);
            PtrSize_t packet = make_packet(e);
            embedded::handle_mysql_prepared(*s, packet);
            bool result = st->PSarrayOUT->len >= 4 && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] != 0xff;
            clear_ps(st->PSarrayOUT);
            return result;
        };
        ok(execute(1, true, 7), "execute accepts fresh parameter type");
        ok(execute(0, false, 9), "execute reuses parameter type");
        PtrSize_t reset = make_packet({0x1a, (unsigned char)id, 0, 0, 0});
        embedded::handle_mysql_prepared(*s, reset);
        ok(st->PSarrayOUT->len == 1 && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0,
           "statement reset emits OK");
        clear_ps(st->PSarrayOUT);
        ok(execute(0, false, 3), "statement reset preserves cached type");
        ok(!execute(2, true, 3), "invalid parameter type flag is rejected");
        PtrSize_t ld = make_packet({0x18, (unsigned char)id, 0, 0, 0, 1, 0, 'x'});
        embedded::handle_mysql_prepared(*s, ld);
        ok(st->PSarrayOUT->len == 0, "invalid long data is deferred without response");
        ok(!execute(0, false, 4), "deferred long data error rejects execute");
        ok(execute(0, false, 5), "execute recovers after deferred error");
        PtrSize_t cursor = make_packet({0x17, (unsigned char)id, 0, 0, 0, 1, 1, 0, 0, 0});
        embedded::handle_mysql_prepared(*s, cursor);
        ok(st->PSarrayOUT->len == 1 && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "cursor execute is rejected");
        clear_ps(st->PSarrayOUT);
    }

    // reset_mysql_prepared
    {
        embedded::Status r = embedded::reset_mysql_prepared(*s);
        ok(!r, "reset_mysql_prepared succeeds");
    }

    // close command
    {
        // prepare again
        std::string sql = "SELECT 2";
        std::vector<unsigned char> payload = {0x16};
        for (char c : sql) payload.push_back((unsigned char)c);
        PtrSize_t pkt = make_packet(payload);
        embedded::handle_mysql_prepared(*s, pkt);
        clear_ps(st->PSarrayOUT);
        // close wire id 2? Actually after reset, next_wire_id retained, so new id 2
        uint32_t id = 3;
        std::vector<unsigned char> cpayload = {0x19};
        for (int i = 0; i < 4; i++) cpayload.push_back((unsigned char)((id >> (8*i)) & 0xff));
        PtrSize_t cpkt = make_packet(cpayload);
        bool rc = embedded::handle_mysql_prepared(*s, cpkt);
        ok(rc, "close returns true");
        ok(cpkt.ptr == nullptr, "close consumes packet");
    }

    // DML must execute against the same in-memory database and return OK.
    {
        proxy_sqlite3_exec(db, "CREATE TABLE items (v INTEGER)", nullptr, nullptr, nullptr);
        std::string sql = "INSERT INTO items VALUES (42)";
        std::vector<unsigned char> payload{0x16};
        payload.insert(payload.end(), sql.begin(), sql.end());
        PtrSize_t p = make_packet(payload);
        embedded::handle_mysql_prepared(*s, p);
        bool prepared = st->PSarrayOUT->len && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0;
        uint32_t id = 0;
        if (prepared) memcpy(&id, static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr) + 5, 4);
        ok(prepared, "DML prepare succeeds");
        clear_ps(st->PSarrayOUT);
        PtrSize_t e = make_packet({0x17, (unsigned char)id, 0, 0, 0, 0, 1, 0, 0, 0});
        embedded::handle_mysql_prepared(*s, e);
        ok(st->PSarrayOUT->len == 1 && static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0,
           "DML execute returns an OK packet");
        clear_ps(st->PSarrayOUT);
        sqlite3_stmt* query = nullptr;
        proxy_sqlite3_prepare_v2(db, "SELECT count(*) FROM items", -1, &query, nullptr);
        bool inserted = proxy_sqlite3_step(query) == SQLITE_ROW && proxy_sqlite3_column_int(query, 0) == 1;
        proxy_sqlite3_finalize(query);
        ok(inserted, "DML changes the database once");
    }

    // Malformed trailing close must not close; reset failures must report ERR.
    {
        ResetFailureAdapter failing(db);
        MySQL_Data_Stream* fs = nullptr; MySQL_Protocol* fp = nullptr;
        MySQL_Session* f = make_session(fs, fp);
        embedded::register_mysql_prepared(*f, failing, policy, status_cb);
        PtrSize_t p = make_packet({0x16,'S','E','L','E','C','T',' ','1'});
        embedded::handle_mysql_prepared(*f, p);
        uint32_t id = 0; memcpy(&id, static_cast<unsigned char*>(fs->PSarrayOUT->index(0)->ptr)+5, 4);
        clear_ps(fs->PSarrayOUT);
        PtrSize_t badclose = make_packet({0x19,(unsigned char)id,0,0,0,9});
        embedded::handle_mysql_prepared(*f, badclose);
        ok(fs->PSarrayOUT->len == 0, "malformed close has no response");
        PtrSize_t badreset = make_packet({0x1a,(unsigned char)id,0,0,0,9});
        embedded::handle_mysql_prepared(*f, badreset);
        ok(fs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(fs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "trailing reset bytes return an error");
        clear_ps(fs->PSarrayOUT);
        failing.fail_reset = true;
        PtrSize_t reset = make_packet({0x1a,(unsigned char)id,0,0,0});
        embedded::handle_mysql_prepared(*f, reset);
        ok(fs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(fs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "native reset failure returns ERR for still-open statement");
        auto* native_error = static_cast<unsigned char*>(fs->PSarrayOUT->index(0)->ptr);
        ok(fs->PSarrayOUT->index(0)->size >= 7 && native_error[5] == (1105 & 255) && native_error[6] == (1105 >> 8),
           "SQLite native error codes are not exposed as MySQL protocol codes");
        clear_ps(fs->PSarrayOUT);
        failing.fail_reset = false;
        reset = make_packet({0x1a,(unsigned char)id,0,0,0});
        embedded::handle_mysql_prepared(*f, reset);
        ok(fs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(fs->PSarrayOUT->index(0)->ptr)[4] == 0,
           "statement recovers after native reset failure");
        clear_ps(fs->PSarrayOUT);
        embedded::unregister_mysql_prepared(*f);
        delete fs->myconn; fs->myconn = nullptr; delete f;
    }
    // A budget large enough to prepare but too small for an arbitrary OK must
    // reject DML before any database change.
    {
        MySQL_Data_Stream* bs = nullptr; MySQL_Protocol* bp = nullptr;
        MySQL_Session* b = make_session(bs, bp);
        embedded::MySQLPreparedLimits small; small.response_bytes = 16;
        embedded::register_mysql_prepared(*b, adapter, policy, status_cb, small);
        std::string sql = "INSERT INTO items VALUES (99)";
        std::vector<unsigned char> prep{0x16}; prep.insert(prep.end(), sql.begin(), sql.end());
        PtrSize_t p = make_packet(prep); embedded::handle_mysql_prepared(*b, p);
        bool good = bs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(bs->PSarrayOUT->index(0)->ptr)[4] == 0;
        uint32_t id = 0; if (good) memcpy(&id, static_cast<unsigned char*>(bs->PSarrayOUT->index(0)->ptr)+5, 4);
        ok(good, "DML prepare fits its 16-byte response budget"); clear_ps(bs->PSarrayOUT);
        PtrSize_t ex = make_packet({0x17,(unsigned char)id,0,0,0,0,1,0,0,0});
        embedded::handle_mysql_prepared(*b, ex);
        ok(bs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(bs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "insufficient DML OK budget returns ERR");
        clear_ps(bs->PSarrayOUT);
        sqlite3_stmt* query = nullptr; proxy_sqlite3_prepare_v2(db, "SELECT count(*) FROM items WHERE v=99", -1, &query, nullptr);
        bool unchanged = proxy_sqlite3_step(query) == SQLITE_ROW && proxy_sqlite3_column_int(query, 0) == 0;
        proxy_sqlite3_finalize(query);
        ok(unchanged, "insufficient response budget prevents DML effects");
        embedded::unregister_mysql_prepared(*b); delete bs->myconn; bs->myconn = nullptr; delete b;
    }

    // Exercise real binary row payloads for NULL, empty blob and long data.
    {
        MySQL_Data_Stream* vs = nullptr; MySQL_Protocol* vp = nullptr;
        MySQL_Session* v = make_session(vs, vp);
        embedded::MySQLPreparedLimits vl; vl.longdata_per_statement = 2;
        embedded::register_mysql_prepared(*v, adapter, policy, status_cb, vl);
        PtrSize_t prep = make_packet({0x16,'S','E','L','E','C','T',' ','?'});
        embedded::handle_mysql_prepared(*v, prep);
        uint32_t id = 0; memcpy(&id, static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr)+5, 4);
        clear_ps(vs->PSarrayOUT);
        auto run = [&](std::vector<unsigned char> tail) {
            std::vector<unsigned char> body{0x17,(unsigned char)id,0,0,0,0,1,0,0,0};
            body.insert(body.end(), tail.begin(), tail.end());
            PtrSize_t packet = make_packet(body); embedded::handle_mysql_prepared(*v, packet);
        };
        auto row = [&]() -> std::vector<unsigned char> {
            if (vs->PSarrayOUT->len < 4) return {};
            auto* packet = vs->PSarrayOUT->index(3);
            auto* bytes = static_cast<unsigned char*>(packet->ptr);
            return std::vector<unsigned char>(bytes + 4, bytes + packet->size);
        };
        run({1,1,MYSQL_TYPE_BLOB,0});
        auto null_row = row();
        ok(null_row.size() == 2 && null_row[0] == 0 && (null_row[1] & 4), "NULL bind yields binary NULL bitmap");
        clear_ps(vs->PSarrayOUT);
        run({0,1,MYSQL_TYPE_BLOB,0,0});
        auto empty_row = row();
        ok(empty_row.size() == 3 && empty_row[0] == 0 && empty_row[1] == 0 && empty_row[2] == 0,
           "empty blob is encoded as a non-NULL zero-length value");
        clear_ps(vs->PSarrayOUT);
        PtrSize_t ld = make_packet({0x18,(unsigned char)id,0,0,0,0,0,'a','b'});
        embedded::handle_mysql_prepared(*v, ld);
        ok(vs->PSarrayOUT->len == 0, "valid long data has no response");
        run({0,1,MYSQL_TYPE_BLOB,0});
        auto blob_row = row();
        ok(blob_row.size() == 5 && blob_row[2] == 2 && blob_row[3] == 'a' && blob_row[4] == 'b',
           "long data reaches SQLite and returns exact blob bytes");
        clear_ps(vs->PSarrayOUT);
        ld = make_packet({0x18,(unsigned char)id,0,0,0,0,0,'a','b','c'});
        embedded::handle_mysql_prepared(*v, ld);
        run({0,0,0});
        ok(vs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "long data overflow is deferred to execute");
        clear_ps(vs->PSarrayOUT);
        run({0,0,1,'z'});
        auto recovered = row();
        ok(recovered.size() == 4 && recovered[2] == 1 && recovered[3] == 'z',
           "execute recovers after long data overflow");
        clear_ps(vs->PSarrayOUT);
        embedded::unregister_mysql_prepared(*v); delete vs->myconn; vs->myconn = nullptr; delete v;
    }

    // A tiny response limit must not leak a partial prepare response.
    {
        MySQL_Data_Stream* other_stream = nullptr; MySQL_Protocol* other_proto = nullptr;
        MySQL_Session* other = make_session(other_stream, other_proto);
        embedded::MySQLPreparedLimits tiny; tiny.response_bytes = 8;
        ok(!embedded::register_mysql_prepared(*other, adapter, policy, status_cb, tiny),
           "second session has an independent registry entry");
        PtrSize_t p = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        embedded::handle_mysql_prepared(*other, p);
        ok(other_stream->PSarrayOUT->len == 1 &&
           static_cast<unsigned char*>(other_stream->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "response limit sends only an error, without partial metadata");
        clear_ps(other_stream->PSarrayOUT);
        embedded::unregister_mysql_prepared(*other);
        delete other_stream->myconn; other_stream->myconn = nullptr; delete other;
    }

    // unregister
    embedded::unregister_mysql_prepared(*s);
    {
        std::string sql = "SELECT 3";
        std::vector<unsigned char> payload = {0x16};
        for (char c : sql) payload.push_back((unsigned char)c);
        PtrSize_t pkt = make_packet(payload);
        bool rc = embedded::handle_mysql_prepared(*s, pkt);
        ok(!rc, "unregistered returns false");
        free(pkt.ptr);
    }

    delete st->myconn; st->myconn = nullptr; delete s;
    proxy_sqlite3_close_v2(db);
    }
    test_cleanup_minimal();
    return exit_status();
}
