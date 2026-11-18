#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "Embedded_Plugin_Service.h"
#include "Embedded_Plugin_Adapter.h"
#include "Embedded_MySQL_Prepared.h"
#include "MySQL_Session.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"
#include "mysql_connection.h"
#include "Embedded_PgSQL_Frontend.h"
#include <cstdlib>
#include <cstring>
#include <thread>
#include <stdexcept>

static int prepare(void*, ProxySQL_Embedded_BytesView, void**,
                   ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int params(void*, void*, const ProxySQL_Embedded_Type**, size_t*, const uint32_t**,
                  ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int columns(void*, void*, const ProxySQL_Embedded_Column**, size_t*,
                   ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int bind(void*, void*, const ProxySQL_Embedded_Value*, size_t,
                ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int execute(void*, void*, ProxySQL_Embedded_ExecInfo*, ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int fetch(void*, void*, const ProxySQL_Embedded_Value**, size_t*, uint8_t*, size_t,
                 ProxySQL_Embedded_Error*) noexcept {
    return 1;
}
static int reset(void*, void*, ProxySQL_Embedded_Error*) noexcept { return 0; }
static void finalize(void*, void*) noexcept {}
static int enter(void*, uint32_t, ProxySQL_Embedded_BytesView, void** guard,
                 ProxySQL_Embedded_Error*) noexcept {
    *guard = reinterpret_cast<void*>(1);
    return 0;
}
static void leave(void*, void*) noexcept {}
static int auth(void*, ProxySQL_Embedded_BytesView, ProxySQL_Embedded_Error*) noexcept {
    return 0;
}
static int auth_exec(void*, ProxySQL_Embedded_BytesView, const ProxySQL_Embedded_Value*, size_t,
                     ProxySQL_Embedded_Error*) noexcept {
    return 0;
}
struct LiveContext {
    int prepared = 0;
    int finalized = 0;
    int active_guards = 0;
    int unguarded_finalizes = 0;
    int finalizes_outside_disconnect = 0;
    int disconnect_enters = 0;
    int disconnect_leaves = 0;
    bool disconnect_guard_active = false;
};
static int live_prepare(void* opaque, ProxySQL_Embedded_BytesView, void** handle,
                        ProxySQL_Embedded_Error*) noexcept {
    auto& context = *static_cast<LiveContext*>(opaque);
    ++context.prepared;
    *handle = &context;
    return 0;
}
static int live_params(void*, void*, const ProxySQL_Embedded_Type** types, size_t* count,
                       const uint32_t** positions, ProxySQL_Embedded_Error*) noexcept {
    *types = nullptr;
    *count = 0;
    *positions = nullptr;
    return 0;
}
static int live_columns(void*, void*, const ProxySQL_Embedded_Column** columns, size_t* count,
                        ProxySQL_Embedded_Error*) noexcept {
    *columns = nullptr;
    *count = 0;
    return 0;
}
static void live_finalize(void* opaque, void*) noexcept {
    auto& context = *static_cast<LiveContext*>(opaque);
    ++context.finalized;
    if (!context.active_guards)
        ++context.unguarded_finalizes;
    if (!context.disconnect_guard_active)
        ++context.finalizes_outside_disconnect;
}
static int live_enter(void* opaque, uint32_t operation, ProxySQL_Embedded_BytesView, void** guard,
                      ProxySQL_Embedded_Error*) noexcept {
    auto& context = *static_cast<LiveContext*>(opaque);
    ++context.active_guards;
    if (operation == ProxySQL_Embedded_OPERATION_DISCONNECT) {
        ++context.disconnect_enters;
        context.disconnect_guard_active = true;
    }
    *guard = reinterpret_cast<void*>(static_cast<uintptr_t>(operation));
    return 0;
}
static void live_leave(void* opaque, void* guard) noexcept {
    auto& context = *static_cast<LiveContext*>(opaque);
    if (reinterpret_cast<uintptr_t>(guard) == ProxySQL_Embedded_OPERATION_DISCONNECT) {
        ++context.disconnect_leaves;
        context.disconnect_guard_active = false;
    }
    --context.active_guards;
}
static void live_engine(ProxySQL_Embedded_EngineV1& engine, LiveContext& context) {
    engine.context = &context;
    engine.prepare = live_prepare;
    engine.describe_parameters = live_params;
    engine.describe_result = live_columns;
    engine.finalize = live_finalize;
    engine.guard_enter = live_enter;
    engine.guard_leave = live_leave;
}
static uint16_t mysql_status(void*) noexcept { return 2; }
static uint8_t state = 'T';
static uint8_t pgsql_status(void*) noexcept { return state; }
int main() {
    plan(42);
    test_init_minimal();
    auto* svc = proxysql_embedded_execution_service();
    ok(svc && svc->abi_version == 1 && svc->struct_size == sizeof(*svc),
       "service version and size");
    ProxySQL_Embedded_Error err{};
    ok(svc->register_mysql(nullptr, nullptr, &err) == 1, "null session rejected");
    MySQL_Session mysql;
    mysql.session_type = PROXYSQL_SESSION_ADMIN;
    ok(svc->register_mysql(&mysql, nullptr, &err) == 1, "admin rejected");
    mysql.session_type = PROXYSQL_SESSION_SQLITE;
    ok(svc->register_mysql(&mysql, nullptr, &err) == 1, "null request rejected");
    ProxySQL_Embedded_EngineV1 engine{1, sizeof(engine), nullptr,
        ProxySQL_Embedded_CAP_READ_ONLY | ProxySQL_Embedded_CAP_PARAMETER_POSITIONS, 510,
        prepare, params, columns, bind, execute,
        fetch, reset, finalize, enter, leave};
    ProxySQL_Embedded_PolicyV1 policy{1, sizeof(policy), nullptr, auth, auth_exec, auth};
    ProxySQL_Embedded_RequestV1 req{1, sizeof(req), &engine, &policy,
        ProxySQL_Embedded_REQUEST_READ_ONLY, mysql_status, nullptr, pgsql_status, nullptr};
    auto bad = req;
    bad.abi_version = 2;
    ok(svc->register_mysql(&mysql, &bad, &err) == 1, "bad version rejected");
    bad = req;
    bad.struct_size = 1;
    ok(svc->register_mysql(&mysql, &bad, &err) == 1, "short request rejected");
    bad = req;
    bad.mysql_status = nullptr;
    ok(svc->register_mysql(&mysql, &bad, &err) == 1, "missing status rejected");
    auto old_request = req;
    old_request.struct_size = offsetof(ProxySQL_Embedded_RequestV1, mysql_select_database);
    old_request.mysql_select_database = [](void*, ProxySQL_Embedded_BytesView) noexcept
        -> uint16_t { return 1049; };
    ok(svc->register_mysql(&mysql, &old_request, &err) == 0 &&
           embedded::plugin_mysql_select_database(mysql, "db", 2) == 0,
       "older V1 request registers without reading the optional selector");
    ok(svc->unregister_mysql(&mysql, &err) == 0, "older V1 request unregisters");
    ok(svc->register_mysql(&mysql, &req, &err) == 0, "mysql registered");
    ok(svc->register_mysql(&mysql, &req, &err) == 1, "duplicate rejected");
    int other = 0;
    std::thread t([&] { other = svc->unregister_mysql(&mysql, nullptr); });
    t.join();
    ok(other == 1, "wrong owner rejected");
    ok(svc->unregister_mysql(&mysql, &err) == 0, "owner unregisters");
    ok(svc->unregister_mysql(&mysql, &err) == 1, "missing registration rejected");
    PgSQL_Session pg;
    pg.session_type = PROXYSQL_SESSION_SQLITE;
    req.flags |= ProxySQL_Embedded_REQUEST_PG_IMPLICIT_CYCLES;
    ok(svc->register_pgsql(&pg, &req, &err) == 0, "pgsql registered");
    auto *stream = new PgSQL_Data_Stream;
    pg.connections_handler = true;
    pg.client_myds = stream;
    stream->sess = &pg;
    stream->PSarrayOUT = new PtrSizeArray;
    auto sync = [&] {
        PtrSize_t packet{};
        packet.size = 5;
        packet.ptr = malloc(5);
        const unsigned char bytes[] = {'S', 0, 0, 0, 4};
        memcpy(packet.ptr, bytes, 5);
        return embedded::handle_pgsql_prepared(pg, packet);
    };
    auto output_state = [&] {
        auto* packet = stream->PSarrayOUT->index(0);
        auto* bytes = static_cast<unsigned char*>(packet->ptr);
        return bytes[packet->size - 1];
    };
    auto clear = [&] {
        for (unsigned i = 0; i < stream->PSarrayOUT->len; ++i)
            free(stream->PSarrayOUT->index(i)->ptr);
        stream->PSarrayOUT->len = 0;
    };
    ok(sync() && output_state() == 'T', "Sync reports transaction status T");
    clear();
    state = 'E';
    ok(sync() && output_state() == 'E', "Sync reports transaction status E");
    clear();
    state = 'X';
    ok(sync(), "invalid status Sync consumed");
    ok(!pg.healthy, "invalid transaction status fails closed");
    ok(stream->PSarrayOUT->len && *static_cast<char*>(stream->PSarrayOUT->index(0)->ptr) == 'E',
       "invalid transaction status emits error");
    clear();
    ok(svc->unregister_pgsql(&pg, &err) == 0, "pgsql unregistered");
    embedded::PluginProviderResult provider;
    ok(!embedded::make_plugin_provider(&req, true, provider), "create private provider");
    pg.healthy = true;
    ok(!embedded::register_pgsql_prepared(pg, provider->adapter(), provider->policy(), {}, {}, {}),
       "private registration accepts empty status callback");
    ok(sync() && output_state() == 'I', "empty status callback reports idle");
    clear();
    embedded::unregister_pgsql_prepared(pg);
    auto throwing = []() -> uint8_t { throw std::runtime_error("status failure"); };
    ok(!embedded::register_pgsql_prepared(pg, provider->adapter(), provider->policy(), {}, {},
                                         throwing),
       "private registration accepts throwing status callback");
    ok(sync(), "throwing status Sync consumed");
    ok(!pg.healthy, "throwing status marks session unhealthy");
    ok(stream->PSarrayOUT->len && *static_cast<char*>(stream->PSarrayOUT->index(0)->ptr) == 'E',
       "throwing status emits error");
    clear();
    embedded::unregister_pgsql_prepared(pg);
    pg.healthy = true;
    bool fail_close = true;
    auto failing_close = [&](const embedded::OperationContext& context,
                            std::unique_ptr<embedded::OperationGuard>& guard) -> embedded::Status {
        if (context.operation == embedded::Operation::close && fail_close) {
            fail_close = false;
            return embedded::Error{embedded::ErrorKind::engine, 0, "close failed", "XX000"};
        }
        guard.reset(new embedded::OperationGuard);
        return {};
    };
    ok(!embedded::register_pgsql_prepared(pg, provider->adapter(), provider->policy(), {},
                                         failing_close, throwing),
       "register close failure with throwing status");
    PtrSize_t query{};
    const unsigned char query_bytes[] = {'Q', 0, 0, 0, 6, 'x', 0};
    query.size = sizeof(query_bytes);
    query.ptr = malloc(query.size);
    memcpy(query.ptr, query_bytes, query.size);
    ok(embedded::handle_pgsql_prepared(pg, query) && !pg.healthy,
       "query cleanup and status failure closes session");
    ok(stream->PSarrayOUT->len == 1 && stream->PSarrayOUT->index(0)->size >= 5 &&
           *static_cast<char*>(stream->PSarrayOUT->index(0)->ptr) == 'E' &&
           static_cast<unsigned char*>(stream->PSarrayOUT->index(0)->ptr)[4] + 1 ==
               stream->PSarrayOUT->index(0)->size,
       "query cleanup and status failure emits one error without ReadyForQuery");
    clear();
    embedded::unregister_pgsql_prepared(pg);
    pg.session_type = PROXYSQL_SESSION_ADMIN;
    mysql.session_type = PROXYSQL_SESSION_ADMIN;

    // Both contexts remain alive until after session destruction. The SQLite role is
    // restored to ADMIN only after registration and preparation: that avoids the legacy
    // SQLite reset path's unrelated dependency on a populated thread/gen_args fixture.
    {
        LiveContext context;
        auto callbacks = engine;
        live_engine(callbacks, context);
        auto request = req;
        request.engine = &callbacks;
        request.flags = ProxySQL_Embedded_REQUEST_READ_ONLY;
        auto* session = new MySQL_Session;
        session->session_type = PROXYSQL_SESSION_SQLITE;
        session->connections_handler = true;
        auto* ds = new MySQL_Data_Stream;
        ds->sess = session;
        ds->PSarrayOUT = new PtrSizeArray;
        session->client_myds = ds;
        ds->myprot.init(&session->client_myds, nullptr, session);
        ds->myconn = new MySQL_Connection;
        ok(svc->register_mysql(session, &request, nullptr) == 0,
           "live MySQL provider registered");
        const unsigned char bytes[] = {9, 0, 0, 0, 0x16, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
        PtrSize_t packet{};
        packet.size = sizeof(bytes);
        packet.ptr = malloc(packet.size);
        memcpy(packet.ptr, bytes, packet.size);
        ok(embedded::handle_mysql_prepared(*session, packet) && !packet.ptr &&
               context.prepared == 1 && context.finalized == 0,
           "MySQL prepares a live native handle");
        auto first_id = static_cast<unsigned char*>(ds->PSarrayOUT->index(0)->ptr)[5];
        for (unsigned i = 0; i < ds->PSarrayOUT->len; ++i)
            free(ds->PSarrayOUT->index(i)->ptr);
        ds->PSarrayOUT->len = 0;
        session->session_type = PROXYSQL_SESSION_ADMIN;
        auto reset_status = embedded::reset_mysql_prepared(*session);
        ok(!reset_status && context.finalized == 1 && context.unguarded_finalizes == 0,
           "MySQL prepared reset finalizes the first handle under guard");
        session->session_type = PROXYSQL_SESSION_SQLITE;
        packet.size = sizeof(bytes);
        packet.ptr = malloc(packet.size);
        memcpy(packet.ptr, bytes, packet.size);
        ok(embedded::handle_mysql_prepared(*session, packet) && !packet.ptr &&
               context.prepared == 2 && context.finalized == 1,
           "MySQL prepared reset preserves public registration");
        auto second_id = static_cast<unsigned char*>(ds->PSarrayOUT->index(0)->ptr)[5];
        ok(first_id != second_id, "MySQL prepared reset does not reuse statement IDs");
        session->session_type = PROXYSQL_SESSION_ADMIN;
        delete ds->myconn;
        ds->myconn = nullptr;
        delete session;
        ok(context.finalized == 2 && context.unguarded_finalizes == 0 &&
               context.finalizes_outside_disconnect == 1,
           "MySQL destructor finalizes its live handle once under disconnect guard");
        ok(context.disconnect_enters == 1 && context.disconnect_leaves == 1 &&
               context.active_guards == 0,
           "MySQL disconnect guard completes before context destruction");
    }
    {
        LiveContext context;
        auto callbacks = engine;
        live_engine(callbacks, context);
        auto request = req;
        request.engine = &callbacks;
        auto* session = new PgSQL_Session;
        session->session_type = PROXYSQL_SESSION_SQLITE;
        session->connections_handler = true;
        auto* ds = new PgSQL_Data_Stream;
        ds->sess = session;
        ds->PSarrayOUT = new PtrSizeArray;
        session->client_myds = ds;
        ok(svc->register_pgsql(session, &request, nullptr) == 0,
           "live PostgreSQL provider registered");
        const unsigned char bytes[] = {'P', 0, 0, 0, 16, 0, 'S', 'E', 'L', 'E', 'C', 'T',
                                       ' ', '1', 0, 0, 0};
        PtrSize_t packet{};
        packet.size = sizeof(bytes);
        packet.ptr = malloc(packet.size);
        memcpy(packet.ptr, bytes, packet.size);
        ok(embedded::handle_pgsql_prepared(*session, packet) && !packet.ptr &&
               context.prepared == 1 && context.finalized == 0,
           "PostgreSQL prepares a live native handle");
        session->session_type = PROXYSQL_SESSION_ADMIN;
        delete session;
        ok(context.finalized == 1 && context.unguarded_finalizes == 0 &&
               context.finalizes_outside_disconnect == 0,
           "PostgreSQL destructor finalizes exactly once under disconnect guard");
        ok(context.disconnect_enters == 1 && context.disconnect_leaves == 1 &&
               context.active_guards == 0,
           "PostgreSQL disconnect guard completes before context destruction");
    }
    return exit_status();
}
