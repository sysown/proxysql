#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "Embedded_PgSQL_Frontend.h"
#include <cstring>
#include <thread>
using namespace embedded;
struct Policy : EndpointPolicy {
    Status authorize_prepare(const std::string &) override {
        return {};
    }
    Status authorize_execute(const std::string &, const std::vector<Value> &) override {
        return {};
    }
    Status authorize_fetch(const std::string &) override {
        return {};
    }
};
struct Guard : OperationGuard {};
struct Stmt : Statement {
    int row = 0;
};
struct AdapterFixture : Adapter {
    int finalized = 0;
    bool fail_second_row = false;
    Status prepare(const std::string &, std::unique_ptr<Statement> &s) override {
        s.reset(new Stmt);
        return {};
    }
    Status describe_parameters(Statement &, std::vector<Type> &p) override {
        p.clear();
        return {};
    }
    Status describe_result(Statement &, std::vector<Column> &c) override {
        c = {{"data", {TypeKind::bytes}}, {"null", {TypeKind::bytes}}};
        return {};
    }
    Status bind(Statement &, const std::vector<Value> &) override {
        return {};
    }
    Status execute(Statement &s, ExecInfo &i) override {
        static_cast<Stmt &>(s).row = 0;
        i.has_result = true;
        return {};
    }
    Status fetch(Statement &s, Row &r, bool &done, size_t) override {
        if (fail_second_row && static_cast<Stmt &>(s).row == 1)
            return Error{ErrorKind::engine, 0, "fetch failed", "XX000"};
        done = static_cast<Stmt &>(s).row++ != 0;
        if (!done)
            r = {Bytes{{0, 255}}, std::monostate{}};
        return {};
    }
    Status reset(Statement &) override {
        return {};
    }
    void finalize(std::unique_ptr<Statement>) noexcept override {
        ++finalized;
    }
    Status describe_parameter_positions(Statement &, std::vector<uint32_t> &o) override {
        o.clear();
        return {};
    }
};
static PtrSize_t packet(char type, std::vector<unsigned char> body = {}) {
    PtrSize_t p{};
    p.size = body.size() + 5;
    p.ptr = malloc(p.size);
    auto *b = static_cast<unsigned char *>(p.ptr);
    b[0] = type;
    uint32_t n = p.size - 1;
    b[1] = n >> 24;
    b[2] = n >> 16;
    b[3] = n >> 8;
    b[4] = n;
    if (!body.empty())
        memcpy(b + 5, body.data(), body.size());
    return p;
}
static std::vector<char> outputs(PgSQL_Data_Stream& stream) {
    std::vector<char> out;
    for (unsigned i = 0; i < stream.PSarrayOUT->len; ++i) {
        const auto* packet = stream.PSarrayOUT->index(i);
        const auto* bytes = static_cast<const unsigned char*>(packet->ptr);
        size_t offset = 0;
        while (offset < packet->size) {
            uint32_t length = 0;
            if (packet->size - offset < 5 ||
                !get_uint32be(bytes + offset + 1, &length) || length < 4 ||
                length > packet->size - offset - 1) {
                out.push_back('?');
                break;
            }
            out.push_back(static_cast<char>(bytes[offset]));
            offset += length + 1;
        }
    }
    return out;
}
static void clear(PgSQL_Data_Stream &stream) {
    for (unsigned i = 0; i < stream.PSarrayOUT->len; ++i)
        free(stream.PSarrayOUT->index(i)->ptr);
    stream.PSarrayOUT->len = 0;
}
int main() {
    plan(NO_PLAN);
    test_init_minimal();
    auto *s = new PgSQL_Session;
    auto *st = new PgSQL_Data_Stream;
    s->session_type = PROXYSQL_SESSION_DUCKDB;
    s->connections_handler = true;
    s->client_myds = st;
    st->sess = s;
    st->PSarrayOUT = new PtrSizeArray;
    AdapterFixture adapter;
    Policy policy;
    ok(!register_pgsql_prepared(*s, adapter, policy), "register embedded session");
    auto *nested = new PgSQL_Session;
    nested->session_type = PROXYSQL_SESSION_DUCKDB;
    nested->connections_handler = true;
    bool nested_ok = false;
    GuardFactory reentrant = [&](const OperationContext &,
                                 std::unique_ptr<OperationGuard> &guard) -> Status {
        guard.reset(new Guard);
        nested_ok = !register_pgsql_prepared(*nested, adapter, policy);
        if (nested_ok)
            unregister_pgsql_prepared(*nested);
        return {};
    };
    ok(bool(register_pgsql_prepared(*s, adapter, policy, {}, reentrant)),
       "duplicate registration rejected");
    ok(nested_ok, "duplicate destruction invokes guard outside registry lock");
    delete nested;
    auto send = [&](char t, std::vector<unsigned char> b = {}) {
        auto p = packet(t, b);
        bool r = handle_pgsql_prepared(*s, p);
        if (p.ptr)
            free(p.ptr);
        return r;
    };
    ok(send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0}), "Parse consumed");
    ok(send('B', {0, 0, 0, 0, 0, 0, 0, 1, 0, 1}), "Bind consumed");
    ok(send('D', {'P', 0}), "Describe consumed");
    ok(send('E', {0, 0, 0, 0, 0}), "Execute consumed");
    ok(send('S'), "Sync consumed");
    auto out = outputs(*st);
    ok(out == std::vector<char>({'1', '2', 'T', 'D', 'C', 'Z'}), "extended response sequence");
    if (out.size() >= 4) {
        auto *p = st->PSarrayOUT->index(3);
        auto *b = static_cast<unsigned char *>(p->ptr);
        ok(p->size == 17 && b[6] == 2 && b[10] == 2 && b[11] == 0 && b[12] == 255 && b[13] == 255 &&
               b[16] == 255,
           "binary row and NULL wire encoding");
    } else
        ok(false, "binary row and NULL wire encoding");
    clear(*st);
    ok(send('P', {0}), "malformed Parse consumed");
    ok(send('Q', {'x', 0}), "simple query discarded while poisoned");
    ok(send('S'), "Sync recovers poisoned cycle");
    ok(outputs(*st) == std::vector<char>({'E', 'Z'}), "error produces one response until Sync");
    clear(*st);
    ok(send('E', {0, 255, 255, 255, 255}), "negative Execute limit consumed");
    ok(outputs(*st) == std::vector<char>({'E'}), "negative Execute limit rejected");
    send('S');
    clear(*st);
    ok(send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0}), "prepare again");
    clear(*st);
    ok(send('B', {0, 0, 0, 1, 0, 2, 0, 0, 0, 0}), "invalid parameter format consumed");
    ok(outputs(*st) == std::vector<char>({'E'}), "invalid parameter format rejected");
    send('S');
    clear(*st);
    auto malformed = packet('P', {0, 0, 0, 0});
    static_cast<unsigned char *>(malformed.ptr)[4] = 3;
    ok(handle_pgsql_prepared(*s, malformed) && !malformed.ptr,
       "bad packet header rejected and consumed");
    ok(outputs(*st) == std::vector<char>({'E'}), "bad packet header emits error");
    send('S');
    clear(*st);
    send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0});
    send('B', {0, 0, 0, 0, 0, 0, 0, 1, 0, 1});
    clear(*st);
    adapter.fail_second_row = true;
    send('E', {0, 0, 0, 0, 0});
    ok(outputs(*st) == std::vector<char>({'E'}), "fetch failure publishes no partial DataRow");
    adapter.fail_second_row = false;
    send('S');
    clear(*st);
    for (unsigned bad = 0; bad < 3; ++bad) {
        send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0});
        clear(*st);
        std::vector<unsigned char> body = {0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        body[5 + bad * 2] = 2;
        send('B', body);
        ok(outputs(*st) == std::vector<char>({'E'}), "invalid format at position %u rejected", bad);
        send('S');
        clear(*st);
    }
    bool other = true;
    std::thread t([&] {
        auto p = packet('P');
        other = handle_pgsql_prepared(*s, p);
        free(p.ptr);
    });
    t.join();
    ok(!other, "wrong owner thread leaves packet untouched");
    ok(!reset_pgsql_prepared(*s), "reset succeeds");
    ok(send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0}),
       "session accepts Parse after reset");
    ok(outputs(*st) == std::vector<char>({'1'}), "reset preserves registration");
    clear(*st);
    unregister_pgsql_prepared(*s);
    ok(adapter.finalized > 0, "unregister finalizes statements");
    bool fail_close = true;
    GuardFactory failing = [&](const OperationContext &c,
                               std::unique_ptr<OperationGuard> &guard) -> Status {
        if (c.operation == Operation::close && fail_close) {
            fail_close = false;
            return Error{ErrorKind::engine, 0, "close failed", "XX000"};
        }
        guard.reset(new Guard);
        return {};
    };
    ok(!register_pgsql_prepared(*s, adapter, policy, {}, failing), "register failing guard");
    ok(send('Q', {'s', 'e', 'l', 'e', 'c', 't', 0}), "simple query failure consumed");
    ok(outputs(*st) == std::vector<char>({'E', 'Z'}),
       "simple query failure sends Error and ReadyForQuery");
    clear(*st);
    ok(send('P', {0, 's', 'e', 'l', 'e', 'c', 't', ' ', '1', 0, 0, 0}),
       "simple query failure recovers cycle");
    clear(*st);
    unregister_pgsql_prepared(*s);
    s->session_type = PROXYSQL_SESSION_PGSQL;
    ok(bool(register_pgsql_prepared(*s, adapter, policy)), "ordinary proxy registration rejected");
    delete s;
    return exit_status();
}
