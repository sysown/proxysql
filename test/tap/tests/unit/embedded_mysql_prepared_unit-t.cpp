#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "Embedded_MySQL_Prepared.h"
#include "Embedded_Admin_MySQL_Prepared.h"
#include "Embedded_SQLite_Adapter.h"
#include "MySQL_Protocol.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Session.h"
#include "mysql_connection.h"
#include "Embedded_Execution.h"
#include "Embedded_MySQL_Result.h"

#include <cstring>
#include <stdexcept>
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
    int* active = nullptr;
    int unguarded = 0;
    int native_calls = 0;
    int resets = 0, finalizes = 0;
    bool throw_fetch = false;
    void check() { ++native_calls; if (active && !*active) ++unguarded; }
    explicit ResetFailureAdapter(sqlite3* db) : inner(db) {}
    embedded::Status prepare(const std::string& q, std::unique_ptr<embedded::Statement>& o) override { check(); return inner.prepare(q, o); }
    embedded::Status describe_parameters(embedded::Statement& s, std::vector<embedded::Type>& o) override { check(); return inner.describe_parameters(s, o); }
    embedded::Status describe_result(embedded::Statement& s, std::vector<embedded::Column>& o) override { check(); return inner.describe_result(s, o); }
    embedded::Status bind(embedded::Statement& s, const std::vector<embedded::Value>& v) override { check(); return inner.bind(s, v); }
    embedded::Status execute(embedded::Statement& s, embedded::ExecInfo& o) override { check(); return inner.execute(s, o); }
    embedded::Status fetch(embedded::Statement& s, embedded::Row& r, bool& d, size_t b) override { check(); if (throw_fetch) throw std::runtime_error("injected fetch exception"); return inner.fetch(s, r, d, b); }
    embedded::Status reset(embedded::Statement& s) override {
        check();
        ++resets;
        if (fail_reset) return embedded::Error{embedded::ErrorKind::engine, SQLITE_BUSY, "injected reset failure", "HY000"};
        return inner.reset(s);
    }
    void finalize(std::unique_ptr<embedded::Statement> s) noexcept override { check(); ++finalizes; inner.finalize(std::move(s)); }
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

    // A failed operation guard must consume PREPARE without touching SQLite.
    {
        MySQL_Data_Stream* gs = nullptr; MySQL_Protocol* gp = nullptr;
        MySQL_Session* g = make_session(gs, gp);
        int calls = 0;
        embedded::GuardFactory deny = [&](const embedded::OperationContext& context, std::unique_ptr<embedded::OperationGuard>& out) -> embedded::Status {
            ++calls;
            if (context.operation == embedded::Operation::prepare)
                return embedded::Error{embedded::ErrorKind::resource, 0, "guard denied", "HY000"};
            out.reset(new embedded::OperationGuard); return {};
        };
        embedded::register_mysql_prepared(*g, adapter, policy, [] { return uint16_t(0); }, {}, deny);
        auto packet = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        ok(embedded::handle_mysql_prepared(*g, packet) && !packet.ptr && calls == 1 && gs->PSarrayOUT->len == 1,
           "guard failure consumes prepare and returns error");
        clear_ps(gs->PSarrayOUT);
        embedded::unregister_mysql_prepared(*g);
        delete gs->myconn; gs->myconn = nullptr; delete g;
    }

    // All native operations and teardown run while the factory's guard is held.
    {
        struct Guard : embedded::OperationGuard {
            int& active;
            explicit Guard(int& n) : active(n) { ++active; }
            ~Guard() override { --active; }
        };
        MySQL_Data_Stream* gs = nullptr; MySQL_Protocol* gp = nullptr;
        MySQL_Session* g = make_session(gs, gp);
        ResetFailureAdapter guarded(db);
        int active = 0; guarded.active = &active;
        bool deny = false, throwing = false;
        bool known_sql_seen = false, unknown_sql_seen = false;
        auto factory = [&](const embedded::OperationContext& context, std::unique_ptr<embedded::OperationGuard>& out) -> embedded::Status {
            if (context.operation == embedded::Operation::execute) {
                if (context.sql && *context.sql == "SELECT 1") known_sql_seen = true;
                if (!context.sql) unknown_sql_seen = true;
            }
            if (throwing) { out.reset(new Guard(active)); throw std::runtime_error("injected guard exception"); }
            if (deny) return embedded::Error{embedded::ErrorKind::resource, 0, "denied", "HY000"};
            out.reset(new Guard(active)); return {};
        };
        bool throw_status = true;
        embedded::register_mysql_prepared(*g, guarded, policy, [&]() -> uint16_t {
            if (throw_status) throw std::runtime_error("injected status exception");
            return 0;
        }, {}, factory);
        auto failed_prep = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        try { embedded::handle_mysql_prepared(*g, failed_prep); } catch (const std::runtime_error&) {}
        free(failed_prep.ptr);
        ok(guarded.finalizes == 1 && active == 0 && guarded.unguarded == 0,
           "throwing prepare status callback finalizes the unregistered statement under guard");
        throw_status = false;
        auto prep = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        embedded::handle_mysql_prepared(*g, prep);
        auto bytes = static_cast<unsigned char*>(gs->PSarrayOUT->index(0)->ptr);
        uint32_t id = 0; memcpy(&id, bytes + 5, 4);
        clear_ps(gs->PSarrayOUT);
        std::vector<unsigned char> exbody = {0x17, 0,0,0,0, 0, 1,0,0,0};
        memcpy(exbody.data() + 1, &id, 4);
        auto ex = make_packet(exbody); embedded::handle_mysql_prepared(*g, ex);
        ok(active == 0 && guarded.native_calls >= 6 && guarded.unguarded == 0,
           "prepare describe bind execute and fetch remain guarded until return");
        clear_ps(gs->PSarrayOUT);
        int resets_before = guarded.resets;
        guarded.throw_fetch = true;
        auto failed_fetch = make_packet(exbody);
        try { embedded::handle_mysql_prepared(*g, failed_fetch); } catch (const std::runtime_error&) {}
        free(failed_fetch.ptr);
        guarded.throw_fetch = false;
        ok(guarded.resets == resets_before + 2 && active == 0 && guarded.unguarded == 0,
           "throwing fetch resets the native cursor under guard");
        auto unknown_body = exbody; memset(unknown_body.data() + 1, 0xff, 4);
        auto unknown = make_packet(unknown_body); embedded::handle_mysql_prepared(*g, unknown);
        ok(known_sql_seen && unknown_sql_seen, "execute guard receives original SQL only for known statement");
        clear_ps(gs->PSarrayOUT);
        deny = true;
        std::vector<unsigned char> ld_body = {0x18, 0,0,0,0, 0,0, 'x'};
        memcpy(ld_body.data() + 1, &id, 4);
        auto ld = make_packet(ld_body); embedded::handle_mysql_prepared(*g, ld);
        std::vector<unsigned char> close_body = {0x19, 0,0,0,0};
        memcpy(close_body.data() + 1, &id, 4);
        auto close = make_packet(close_body); embedded::handle_mysql_prepared(*g, close);
        ok(!ld.ptr && !close.ptr && gs->PSarrayOUT->len == 0,
           "long data and close guard failures send no response");
        deny = false;
        ex = make_packet(exbody); embedded::handle_mysql_prepared(*g, ex);
        ok(gs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(gs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "next execute reports deferred long data guard failure");
        clear_ps(gs->PSarrayOUT);
        ex = make_packet(exbody); embedded::handle_mysql_prepared(*g, ex);
        ok(gs->PSarrayOUT->len > 1, "statement survives failed close and recovers after deferred error");
        clear_ps(gs->PSarrayOUT);
        throwing = true; int throw_before = guarded.native_calls;
        auto thrown_prepare = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        embedded::handle_mysql_prepared(*g, thrown_prepare);
        ok(!thrown_prepare.ptr && gs->PSarrayOUT->len == 1 && active == 0 && guarded.native_calls == throw_before,
           "throwing prepare guard releases partial guard, consumes packet and prevents native work");
        clear_ps(gs->PSarrayOUT);
        ex = make_packet(exbody); embedded::handle_mysql_prepared(*g, ex);
        ok(!ex.ptr && gs->PSarrayOUT->len == 1 && active == 0 && guarded.native_calls == throw_before,
           "throwing execute guard releases partial guard, consumes packet and prevents native work");
        clear_ps(gs->PSarrayOUT);
        ok((bool)embedded::reset_mysql_prepared(*g) && active == 0 && guarded.native_calls == throw_before,
           "throwing reset guard returns error without native work");
        throwing = false;
        deny = true; int before = guarded.native_calls;
        ok((bool)embedded::reset_mysql_prepared(*g) && guarded.native_calls == before,
           "failed reset guard leaves native statements untouched");
        deny = false;
        ok(!embedded::reset_mysql_prepared(*g) && active == 0 && guarded.unguarded == 0,
           "reset closes native handles before releasing guard");
        prep = make_packet({0x16, 'S','E','L','E','C','T',' ','1'});
        embedded::handle_mysql_prepared(*g, prep); clear_ps(gs->PSarrayOUT);
        embedded::unregister_mysql_prepared(*g);
        ok(active == 0 && guarded.unguarded == 0, "disconnect closes native handles under guard");
        delete gs->myconn; gs->myconn = nullptr; delete g;
    }

    // Retired wire IDs cannot address statements from a replacement provider.
    {
        MySQL_Data_Stream* ws = nullptr; MySQL_Protocol* wp = nullptr;
        MySQL_Session* w = make_session(ws, wp);
        embedded::SQLiteAdapter replacement(db);
        proxy_sqlite3_exec(db, "CREATE TABLE wire_lifetime (v INTEGER)", nullptr, nullptr, nullptr);
        auto prepare = [&](const char* sql) {
            std::vector<unsigned char> body{0x16};
            body.insert(body.end(), sql, sql + strlen(sql));
            auto p = make_packet(body); embedded::handle_mysql_prepared(*w, p);
            uint32_t id = 0;
            if (ws->PSarrayOUT->len && static_cast<unsigned char*>(ws->PSarrayOUT->index(0)->ptr)[4] == 0)
                memcpy(&id, static_cast<unsigned char*>(ws->PSarrayOUT->index(0)->ptr) + 5, 4);
            clear_ps(ws->PSarrayOUT); return id;
        };
        auto unknown = [&](uint32_t id) {
            std::vector<unsigned char> body{0x17, 0,0,0,0, 0,1,0,0,0};
            memcpy(body.data() + 1, &id, 4);
            auto p = make_packet(body); embedded::handle_mysql_prepared(*w, p);
            bool result = ws->PSarrayOUT->len == 1 && ws->PSarrayOUT->index(0)->size >= 7 &&
                static_cast<unsigned char*>(ws->PSarrayOUT->index(0)->ptr)[4] == 0xff &&
                static_cast<unsigned char*>(ws->PSarrayOUT->index(0)->ptr)[5] == 0xdb &&
                static_cast<unsigned char*>(ws->PSarrayOUT->index(0)->ptr)[6] == 0x04;
            clear_ps(ws->PSarrayOUT); return result;
        };
        embedded::register_mysql_prepared(*w, adapter, policy, [] { return uint16_t(0); });
        uint32_t first = prepare("SELECT 1");
        embedded::unregister_mysql_prepared(*w);
        embedded::register_mysql_prepared(*w, replacement, policy, [] { return uint16_t(0); });
        uint32_t second = prepare("INSERT INTO wire_lifetime VALUES (1)");
        ok(first && second > first, "provider replacement preserves monotonic wire IDs");
        ok(unknown(first), "retired provider ID returns unknown statement");
        sqlite3_stmt* count = nullptr;
        proxy_sqlite3_prepare_v2(db, "SELECT count(*) FROM wire_lifetime", -1, &count, nullptr);
        bool empty = proxy_sqlite3_step(count) == SQLITE_ROW && proxy_sqlite3_column_int(count, 0) == 0;
        proxy_sqlite3_finalize(count);
        ok(empty, "retired provider ID cannot execute replacement statement");
        embedded::reset_mysql_prepared(*w);
        uint32_t third = prepare("SELECT 3");
        ok(third > second && unknown(second), "reset retires IDs while retaining allocator");
        embedded::destroy_mysql_prepared(*w);
        embedded::register_mysql_prepared(*w, adapter, policy, [] { return uint16_t(0); });
        ok(prepare("SELECT 4") == 1, "destroy releases the session wire allocator");
        embedded::destroy_mysql_prepared(*w);
        delete ws->myconn; ws->myconn = nullptr; delete w;
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
    embedded::unregister_admin_mysql_prepared(*s);
    {
        PtrSize_t known_owner = make_packet({0x17,99,0,0,0,0,1,0,0,0});
        ok(embedded::handle_mysql_prepared(*s, known_owner) && !known_owner.ptr,
           "Admin provider cleanup preserves another embedded provider registration");
        if (known_owner.ptr) free(known_owner.ptr);
        clear_ps(st->PSarrayOUT);
    }
    {
        embedded::Error error{embedded::ErrorKind::unsupported, 5, "setup failed", "HY000"};
        PtrSize_t failed = make_packet({0x16,'S'});
        embedded::consume_mysql_prepared_error(*s, failed, error);
        ok(!failed.ptr && st->PSarrayOUT->len == 1 &&
           static_cast<unsigned char*>(st->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "endpoint setup error consumes packet and uses shared ERR response");
        clear_ps(st->PSarrayOUT);
        failed = make_packet({0x19,1,0,0,0});
        embedded::consume_mysql_prepared_error(*s, failed, error);
        ok(!failed.ptr && st->PSarrayOUT->len == 0, "endpoint close setup failure retains no-response semantics");
    }


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
        bool deny_execute = false;
        auto value_guard = [&](const embedded::OperationContext& ctx, std::unique_ptr<embedded::OperationGuard>& out) -> embedded::Status {
            if (deny_execute && ctx.operation == embedded::Operation::execute)
                return embedded::Error{embedded::ErrorKind::resource, 0, "denied", "HY000"};
            out.reset(new embedded::OperationGuard); return {};
        };
        embedded::register_mysql_prepared(*v, adapter, policy, status_cb, vl, value_guard);
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
        deny_execute = true;
        run({0,1,MYSQL_TYPE_BLOB,0,1,'q'});
        ok(vs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "first execute can be rejected by an operation guard");
        clear_ps(vs->PSarrayOUT);
        deny_execute = false;
        run({0,0,1,'z'});
        auto cached_after_error = row();
        ok(cached_after_error.size() == 4 && cached_after_error[2] == 1 && cached_after_error[3] == 'z',
           "valid first-execute type metadata survives guard rejection for client reuse");
        clear_ps(vs->PSarrayOUT);
        PtrSize_t stale = make_packet({0x18,(unsigned char)id,0,0,0,0,0,'a','b'});
        embedded::handle_mysql_prepared(*v, stale);
        deny_execute = true;
        run({0,1,MYSQL_TYPE_BLOB,0,1,'x'});
        clear_ps(vs->PSarrayOUT);
        deny_execute = false;
        run({0,1,MYSQL_TYPE_BLOB,0,1,'z'});
        auto fresh = row();
        ok(fresh.size() == 4 && fresh[2] == 1 && fresh[3] == 'z',
           "execute guard failure clears old long data before a fresh normal binding");
        clear_ps(vs->PSarrayOUT);
        stale = make_packet({0x18,(unsigned char)id,0,0,0,0,0,'a','b'});
        embedded::handle_mysql_prepared(*v, stale);
        PtrSize_t malformed = make_packet({0x17,(unsigned char)id,0,0,0});
        embedded::handle_mysql_prepared(*v, malformed);
        ok(!malformed.ptr && vs->PSarrayOUT->len == 1 &&
           static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
           "short execute with a known statement ID is consumed and rejected");
        clear_ps(vs->PSarrayOUT);
        run({0,0,1,'z'});
        fresh = row();
        ok(fresh.size() == 4 && fresh[2] == 1 && fresh[3] == 'z',
           "malformed execute also clears pending long data");
        clear_ps(vs->PSarrayOUT);
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
        for (bool reject_guard : {false, true}) {
            run({0,1,MYSQL_TYPE_TINY,0,1});
            auto signed_row = row();
            ok(signed_row.size() == 4 && signed_row[3] == '1', "establish signed TINY cache before invalid new types");
            clear_ps(vs->PSarrayOUT);
            PtrSize_t invalid_long = make_packet({0x18,(unsigned char)id,0,0,0,0,0,'x'});
            embedded::handle_mysql_prepared(*v, invalid_long);
            deny_execute = reject_guard;
            run({0,1,MYSQL_TYPE_TINY,128,255});
            ok(vs->PSarrayOUT->len == 1 && static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr)[4] == 0xff,
               "invalid long-data integer execution is rejected");
            clear_ps(vs->PSarrayOUT);
            deny_execute = false;
            run({0,0,255});
            const auto* failure = vs->PSarrayOUT->len ? static_cast<unsigned char*>(vs->PSarrayOUT->index(0)->ptr) : nullptr;
            ok(failure && vs->PSarrayOUT->index(0)->size >= 7 && failure[4] == 0xff &&
               failure[5] == (1210 & 255) && failure[6] == (1210 >> 8),
               "failed new-type decoding invalidates the old signedness cache");
            clear_ps(vs->PSarrayOUT);
        }
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

    {
        embedded::QuotaLimits ql; ql.values = {{20, 65536, 65536, 3, 4096}};
        embedded::QuotaPool pool(ql); embedded::MySQLPreparedLimits small; small.response_bytes = 1024;
        ResetFailureAdapter counted(db);
        MySQL_Data_Stream *a_stream = nullptr, *b_stream = nullptr; MySQL_Protocol *a_proto = nullptr, *b_proto = nullptr;
        MySQL_Session *a = make_session(a_stream, a_proto), *b = make_session(b_stream, b_proto);
        embedded::register_mysql_prepared(*a, counted, policy, status_cb, small, {}, &pool);
        embedded::register_mysql_prepared(*b, counted, policy, status_cb, small, {}, &pool);
        auto prep = [&](MySQL_Session *client, MySQL_Data_Stream *stream) {
            auto packet = make_packet({0x16,'S','E','L','E','C','T',' ','?'});
            embedded::handle_mysql_prepared(*client, packet);
            bool success = stream->PSarrayOUT->len && static_cast<unsigned char*>(stream->PSarrayOUT->index(0)->ptr)[4] != 0xff;
            clear_ps(stream->PSarrayOUT); return success;
        };
        ok(prep(a, a_stream) && prep(b, b_stream), "two MySQL clients prepare with shared pool");
        auto long_data = [&](MySQL_Session *client) {
            auto packet = make_packet({0x18,1,0,0,0,0,0,'a','b','c'});
            embedded::handle_mysql_prepared(*client, packet);
        };
        long_data(a); long_data(b);
        ok(a_stream->PSarrayOUT->len == 0 && b_stream->PSarrayOUT->len == 0 &&
           pool.snapshot()[static_cast<size_t>(embedded::Resource::bind_bytes)] == 3,
           "long data quota exhaustion defers response and keeps first client's bytes");
        int calls_before = counted.native_calls;
        auto exec = make_packet({0x17,1,0,0,0,0,1,0,0,0,0,1,MYSQL_TYPE_STRING,0});
        embedded::handle_mysql_prepared(*b, exec);
        ok(b_stream->PSarrayOUT->len == 1 && static_cast<unsigned char*>(b_stream->PSarrayOUT->index(0)->ptr)[4] == 0xff && counted.native_calls == calls_before,
           "deferred global quota error is returned without native execution");
        clear_ps(b_stream->PSarrayOUT);
        auto reset = make_packet({0x1a,1,0,0,0}); embedded::handle_mysql_prepared(*a, reset); clear_ps(a_stream->PSarrayOUT);
        long_data(b);
        ok(pool.snapshot()[static_cast<size_t>(embedded::Resource::bind_bytes)] == 3, "reset releases bind capacity for another client");
        embedded::unregister_mysql_prepared(*a); embedded::unregister_mysql_prepared(*b);
        ok(pool.snapshot() == embedded::ResourceUsage{}, "disconnect releases shared quota");
        delete a_stream->myconn; a_stream->myconn = nullptr; delete a;
        delete b_stream->myconn; b_stream->myconn = nullptr; delete b;
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
