#include "Embedded_Plugin_Adapter.h"
#include "tap.h"
#include <cstring>
using namespace embedded;
struct Fake {
    int finalized = 0, resets = 0, executes = 0;
    QuotaPool *observe_pool = nullptr; size_t charge_at_finalize = 0;
    bool change = false, fail_prepare = false, change_execute = false, fail_execute = false;
    ProxySQL_Embedded_Type type{ProxySQL_Embedded_TYPE_INT64, 0, 0, 1};
    uint32_t position = 1;
    int guard_mode = 0, leaves = 0;
    uint32_t operation = 0;
    bool invalidate_params = false;
    bool reset_error = false, custom_row = false, null_params = false, null_columns = false;
    size_t param_count = 1, column_count = 1, row_count = 1, error_size = 7;
    bool null_error = false;
    uint8_t row_done = 0;
    ProxySQL_Embedded_Value bound_value{};
    uint8_t has_result = 1;
    uint32_t bound_kind = 0;
    size_t bound_count = 0;
    std::vector<uint8_t> bound_bytes;
    std::string events, policy_sql;
    uint32_t policy_kind = 0;
    int execute_rc = 0, fetch_rc = 0, reset_rc = 0;
    bool log_finalize = false;
    uint32_t error_kind = 0;
    char state[6]{};
    char message[8] = "failure";
    char name[2] = {'x', 0};
    ProxySQL_Embedded_Column column{{reinterpret_cast<const uint8_t *>(name), 1}, type};
    ProxySQL_Embedded_Value value{};
};
static int prepare(void *c, ProxySQL_Embedded_BytesView, void **h,
                   ProxySQL_Embedded_Error *e) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->events += "P";
    *h = f;
    if (f->fail_prepare) {
        e->kind = ProxySQL_Embedded_ERROR_ENGINE;
        e->message = {reinterpret_cast<const uint8_t *>("failed"), 6};
        return 1;
    }
    return 0;
}
static int params(void *c, void *, const ProxySQL_Embedded_Type **t, size_t *n, const uint32_t **p,
                  ProxySQL_Embedded_Error *) noexcept {
    auto *f = static_cast<Fake *>(c);
    *t = f->null_params ? nullptr : &f->type;
    *n = f->param_count;
    *p = &f->position;
    return 0;
}
static int result(void *c, void *, const ProxySQL_Embedded_Column **p, size_t *n,
                  ProxySQL_Embedded_Error *) noexcept {
    auto *f = static_cast<Fake *>(c);
    *p = f->null_columns ? nullptr : &f->column;
    *n = f->column_count;
    if (f->invalidate_params) {
        f->position = 9;
        f->type.nullable = 0;
    }
    if (f->change)
        f->column.name.size = 0;
    return 0;
}
static int bind(void *c, void *, const ProxySQL_Embedded_Value *v, size_t n,
                ProxySQL_Embedded_Error *) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->bound_count = n;
    if (n) {
        f->bound_kind = v[0].kind;
        f->bound_value = v[0];
        f->bound_bytes.clear();
        if (v[0].kind >= ProxySQL_Embedded_VALUE_TEXT &&
            v[0].kind <= ProxySQL_Embedded_VALUE_DECIMAL && v[0].payload.bytes.size)
            f->bound_bytes.assign(v[0].payload.bytes.data,
                                  v[0].payload.bytes.data + v[0].payload.bytes.size);
    }
    return 0;
}
static int execute(void *c, void *, ProxySQL_Embedded_ExecInfo *i,
                   ProxySQL_Embedded_Error *e) noexcept {
    auto *f = static_cast<Fake *>(c);
    ++f->executes;
    f->events += "X";
    i->has_result = f->has_result;
    i->affected_rows = UINT64_MAX;
    i->last_insert_id = UINT64_MAX;
    if (f->change_execute)
        f->position = 8;
    if (f->fail_execute || f->execute_rc) {
        e->kind = f->error_kind;
        std::memcpy(e->sqlstate, f->state, 6);
        e->message = {f->null_error ? nullptr : reinterpret_cast<const uint8_t *>(f->message),
                      f->error_size};
        return f->execute_rc ? f->execute_rc : 1;
    }
    return 0;
}
static int fetch(void *c, void *, const ProxySQL_Embedded_Value **v, size_t *n, uint8_t *done,
                 size_t, ProxySQL_Embedded_Error *e) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->events += "F";
    if (f->fetch_rc) {
        e->message = {reinterpret_cast<const uint8_t *>(f->message), 7};
        return f->fetch_rc;
    }
    if (!f->custom_row) {
        f->value.kind = ProxySQL_Embedded_VALUE_INT64;
        f->value.payload.int64_value = 42;
    }
    *v = &f->value;
    *n = f->row_count;
    *done = f->row_done;
    return 0;
}
static int reset(void *c, void *, ProxySQL_Embedded_Error *e) noexcept {
    auto *f = static_cast<Fake *>(c);
    ++f->resets;
    f->events += "R";
    if (f->reset_error)
        std::memset(f->message, 'z', 7);
    if (f->reset_rc) {
        e->message = {reinterpret_cast<const uint8_t *>(f->message), 7};
        return f->reset_rc;
    }
    return 0;
}
static int guard_enter(void *c, uint32_t op, ProxySQL_Embedded_BytesView, void **h,
                       ProxySQL_Embedded_Error *e) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->operation = op;
    f->events += "G";
    *h = f->guard_mode == 2 ? nullptr : f;
    if (f->guard_mode == 1) {
        e->message = {reinterpret_cast<const uint8_t *>(f->message), 7};
        return 1;
    }
    return 0;
}
static void guard_leave(void *c, void *) noexcept {
    ++static_cast<Fake *>(c)->leaves;
    static_cast<Fake *>(c)->events += "L";
    if (static_cast<Fake *>(c)->guard_mode == 1)
        std::memset(static_cast<Fake *>(c)->message, 'q', 7);
}
static void finalize(void *c, void *) noexcept {
    auto *f = static_cast<Fake *>(c);
    ++f->finalized;
    if (f->observe_pool) f->charge_at_finalize = f->observe_pool->snapshot()[static_cast<size_t>(Resource::metadata_bytes)];
    if (f->log_finalize) {
        f->events += "Z";
        std::memset(f->message, 'x', 7);
    }
}
static int policy(void *c, ProxySQL_Embedded_BytesView sql, ProxySQL_Embedded_Error *) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->events += "A";
    f->policy_sql.assign(reinterpret_cast<const char *>(sql.data), sql.size);
    return 0;
}
static int policy_values(void *c, ProxySQL_Embedded_BytesView sql,
                         const ProxySQL_Embedded_Value *values, size_t count,
                         ProxySQL_Embedded_Error *) noexcept {
    auto *f = static_cast<Fake *>(c);
    f->events += "E";
    f->policy_sql.assign(reinterpret_cast<const char *>(sql.data), sql.size);
    f->policy_kind = count ? values[0].kind : 0;
    return 0;
}
static uint16_t status(void *) noexcept {
    return 0;
}
static uint8_t pg_status(void *) noexcept {
    return 'I';
}
static PluginProviderResult make(Fake &f, PluginLimits limits = {}, bool guards = false, QuotaPool *pool = nullptr) {
    ProxySQL_Embedded_EngineV1 e{1,
                                 sizeof(e),
                                 &f,
                                 ProxySQL_Embedded_CAP_READ_ONLY |
                                     ProxySQL_Embedded_CAP_PARAMETER_POSITIONS,
                                 0x1fe,
                                 prepare,
                                 params,
                                 result,
                                 bind,
                                 execute,
                                 fetch,
                                 reset,
                                 finalize,
                                 guards ? guard_enter : nullptr,
                                 guards ? guard_leave : nullptr};
    ProxySQL_Embedded_PolicyV1 p{1, sizeof(p), &f, policy, policy_values, policy};
    ProxySQL_Embedded_RequestV1 r{
        1,      sizeof(r), &e,        &p,     ProxySQL_Embedded_REQUEST_READ_ONLY,
        status, nullptr,   pg_status, nullptr};
    PluginProviderResult out;
    if (make_plugin_provider(&r, false, out, limits, pool))
        return {};
    return out;
}
int main() {
    plan(126);
    PluginProviderResult out;
    ok(make_plugin_provider(nullptr, false, out).has_value(), "null request rejected");
    struct Prefix {
        uint32_t version, size;
    } prefix{1, 8};
    ok(make_plugin_provider(reinterpret_cast<ProxySQL_Embedded_RequestV1 *>(&prefix), false, out)
           .has_value(),
       "truncated request rejected");
    Fake f;
    auto provider = make(f);
    ok(bool(provider), "copies local callback descriptors");
    std::unique_ptr<Statement> statement;
    ok(!provider->adapter().prepare("select ?", statement), "prepare succeeds");
    f.name[0] = 'y';
    f.position = 7;
    std::vector<Column> columns;
    std::vector<uint32_t> positions;
    ok(!provider->adapter().describe_result(*statement, columns) && columns[0].name == "x",
       "metadata is owned");
    ok(!provider->adapter().describe_parameter_positions(*statement, positions) &&
           positions[0] == 1,
       "positions are owned");
    ExecInfo info;
    auto changed = provider->adapter().execute(*statement, info);
    ok(changed && changed->kind == ErrorKind::schema_changed && f.executes == 0 && f.resets == 1,
       "schema change prevents execution and resets");
    f.name[0] = 'x';
    f.position = 1;
    ok(!provider->adapter().execute(*statement, info) && info.has_result, "execute succeeds");
    Row row;
    bool done = true;
    ok(!provider->adapter().fetch(*statement, row, done, 8) && !done &&
           std::get<int64_t>(row[0]) == 42,
       "fetch copies value");
    ok(provider->adapter().fetch(*statement, row, done, 7).has_value() && row.empty(),
       "fetch budget enforced atomically");
    Fake other;
    auto second = make(other);
    ok(second->adapter().execute(*statement, info).has_value(), "foreign adapter rejected");
    provider->adapter().finalize(std::move(statement));
    ok(f.finalized == 1, "native handle finalized once");
    f.fail_prepare = true;
    ok(provider->adapter().prepare("select ?", statement).has_value() && !statement &&
           f.finalized == 2,
       "partial failed prepare finalized");
    f.fail_prepare = false;
    ok(!provider->adapter().prepare("select ?", statement), "second prepare succeeds");
    f.change_execute = true;
    auto after = provider->adapter().execute(*statement, info);
    ok(after && after->kind == ErrorKind::schema_changed && f.executes == 2,
       "post execute schema change detected without replay");
    f.change_execute = false;
    f.position = 1;
    f.fail_execute = true;
    int resets = f.resets;
    ok(provider->adapter().execute(*statement, info).has_value() && f.resets == resets + 1,
       "native failure resets result");
    f.fail_execute = false;
    auto guard_factory = provider->guard_factory();
    std::unique_ptr<OperationGuard> guard;
    OperationContext context{Operation::execute, nullptr};
    ok(!guard_factory(context, guard) && bool(guard),
       "absent guard callbacks provide owned no-op guard");
    PluginLimits small;
    small.parameters = 0;
    auto limited = make(other, small);
    std::unique_ptr<Statement> rejected;
    ok(limited->adapter().prepare("select ?", rejected).has_value() && !rejected &&
           other.finalized == 1,
       "parameter limit finalizes rejected handle");
    auto guarded = make(other, {}, true);
    auto gf = guarded->guard_factory();
    other.guard_mode = 1;
    other.leaves = 0;
    guard.reset();
    auto ge = gf(context, guard);
    ok(ge && ge->message == "failure" && !guard && other.leaves == 1,
       "failed partial guard copies error and leaves");
    other.guard_mode = 2;
    ok(gf(context, guard).has_value() && !guard && other.leaves == 1,
       "successful null guard rejected");
    other.guard_mode = 0;
    ok(!gf(context, guard) && guard && other.operation == ProxySQL_Embedded_OPERATION_EXECUTE,
       "guard maps execute operation");
    guard.reset();
    ok(other.leaves == 2, "guard destructor leaves once");
    OperationContext disconnect{Operation::disconnect, nullptr};
    ok(!gf(disconnect, guard) && other.operation == ProxySQL_Embedded_OPERATION_DISCONNECT,
       "guard maps disconnect operation");
    guard.reset();
    PluginLimits small_sql;
    small_sql.sql = 2;
    auto sql_limited = make(other, small_sql);
    std::unique_ptr<Statement> too_long;
    ok(sql_limited->adapter().prepare("select ?", too_long).has_value() && !too_long,
       "SQL budget checked before callback");
    Fake malformed;
    auto mp = make(malformed);
    std::unique_ptr<Statement> bad;
    malformed.param_count = SIZE_MAX;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad,
       "huge parameter count rejected before array access");
    malformed.param_count = 1;
    malformed.null_params = true;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad, "null parameter array rejected");
    malformed.null_params = false;
    malformed.column_count = SIZE_MAX;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad,
       "huge column count rejected before array access");
    malformed.column_count = 1;
    malformed.null_columns = true;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad, "null column array rejected");
    malformed.null_columns = false;
    malformed.column.name = {nullptr, 1};
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad,
       "null nonempty column name rejected");
    malformed.column.name = {reinterpret_cast<const uint8_t *>(malformed.name), 1};
    malformed.column.type.kind = ProxySQL_Embedded_TYPE_UNKNOWN;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad, "unknown result type rejected");
    malformed.column.type = malformed.type;
    malformed.type.kind = ProxySQL_Embedded_TYPE_DECIMAL;
    malformed.type.precision = 0;
    ok(mp->adapter().prepare("select ?", bad).has_value() && !bad,
       "invalid decimal metadata rejected");
    malformed.type = {ProxySQL_Embedded_TYPE_INT64, 0, 0, 1};
    ok(!mp->adapter().prepare("select ?", bad), "prepare after malformed metadata succeeds");
    malformed.fail_execute = true;
    malformed.reset_error = true;
    malformed.error_kind = ProxySQL_Embedded_ERROR_POLICY;
    std::memcpy(malformed.state, "42501", 6);
    auto copied = mp->adapter().execute(*bad, info);
    ok(copied && copied->kind == ErrorKind::policy && copied->message == "failure" &&
           copied->sqlstate == "42501",
       "error copied before reset invalidates borrowed message");
    malformed.fail_execute = false;
    malformed.execute_rc = 9;
    auto invalid_rc = mp->adapter().execute(*bad, info);
    ok(invalid_rc && invalid_rc->kind == ErrorKind::internal, "nonbinary callback status rejected");
    malformed.execute_rc = 0;
    malformed.reset_error = false;
    malformed.column.type.kind = ProxySQL_Embedded_TYPE_DYNAMIC;
    mp->adapter().finalize(std::move(bad));
    ok(!mp->adapter().prepare("select ?", bad) && !mp->adapter().execute(*bad, info),
       "dynamic result metadata accepted");
    malformed.custom_row = true;
    malformed.value = {};
    malformed.value.kind = ProxySQL_Embedded_VALUE_UINT64;
    malformed.value.payload.uint64_value = UINT64_MAX;
    ok(!mp->adapter().fetch(*bad, row, done, 8) && std::get<uint64_t>(row[0]) == UINT64_MAX,
       "uint64 copied exactly");
    malformed.value.kind = ProxySQL_Embedded_VALUE_BOOLEAN;
    malformed.value.payload.boolean_value = 1;
    ok(!mp->adapter().fetch(*bad, row, done, 1) && std::get<bool>(row[0]), "boolean copied");
    malformed.value.payload.boolean_value = 2;
    ok(mp->adapter().fetch(*bad, row, done, 1).has_value() && row.empty(),
       "invalid boolean rejected");
    ok(!mp->adapter().execute(*bad, info), "reexecute after invalid row");
    malformed.value.kind = ProxySQL_Embedded_VALUE_DECIMAL;
    malformed.value.payload.bytes = {reinterpret_cast<const uint8_t *>("123.45"), 6};
    ok(!mp->adapter().fetch(*bad, row, done, 6) && std::get<Decimal>(row[0]).exact == "123.45",
       "decimal preserved as text");
    const uint8_t arbitrary[] = {0, 255};
    malformed.value.kind = ProxySQL_Embedded_VALUE_BYTES;
    malformed.value.payload.bytes = {arbitrary, 2};
    ok(!mp->adapter().fetch(*bad, row, done, 2) &&
           std::get<Bytes>(row[0]).bytes == std::vector<uint8_t>({0, 255}),
       "binary bytes preserved");
    malformed.value.kind = ProxySQL_Embedded_VALUE_TEXT;
    malformed.value.payload.bytes = {nullptr, 0};
    ok(!mp->adapter().fetch(*bad, row, done, 0) && std::get<Text>(row[0]).bytes.empty(),
       "empty text distinguished from null");
    malformed.value.kind = ProxySQL_Embedded_VALUE_NULL;
    ok(!mp->adapter().fetch(*bad, row, done, 0) && std::holds_alternative<std::monostate>(row[0]),
       "null remains distinct");
    malformed.value.kind = ProxySQL_Embedded_VALUE_TEXT;
    malformed.value.payload.bytes = {nullptr, SIZE_MAX};
    ok(mp->adapter().fetch(*bad, row, done, SIZE_MAX).has_value() && row.empty(),
       "null huge view rejected without access");
    ok(!mp->adapter().execute(*bad, info), "reexecute after malformed view");
    malformed.row_done = 1;
    malformed.row_count = 1;
    ok(mp->adapter().fetch(*bad, row, done, 8).has_value() && row.empty(), "EOF with row rejected");
    other.events.clear();
    OperationContext prep_context{Operation::prepare, nullptr};
    std::unique_ptr<OperationGuard> operation_guard;
    auto ordering_guard = guarded->guard_factory();
    ordering_guard(prep_context, operation_guard);
    guarded->policy().authorize_prepare("select ?");
    std::unique_ptr<Statement> ordered;
    guarded->adapter().prepare("select ?", ordered);
    operation_guard.reset();
    ok(other.events == "GAPL", "guard surrounds policy and native prepare");
    std::vector<Value> candidates{std::monostate{}, int64_t(-3),     uint64_t(UINT64_MAX), 2.5,
                                  Text{""},         Bytes{{0, 255}}, Decimal{"1.25"},      true};
    bool binds = true;
    uint32_t expected = 1;
    for (const auto &candidate : candidates) {
        binds = binds && !guarded->adapter().bind(*ordered, {candidate}) &&
                other.bound_count == 1 && other.bound_kind == expected++;
    }
    ok(binds, "all value kinds converted to public bind tags");
    ok(guarded->adapter().bind(*ordered, {}).has_value(), "bind arity rejected");
    PluginLimits bind_limit;
    bind_limit.bind = 1;
    auto bp = make(other, bind_limit);
    std::unique_ptr<Statement> bs;
    bp->adapter().prepare("select ?", bs);
    ok(bp->adapter().bind(*bs, {Text{"ab"}}).has_value(), "bind payload budget enforced");
    PluginLimits metadata_limit;
    metadata_limit.metadata = 1;
    auto lp = make(other, metadata_limit);
    std::unique_ptr<Statement> ls;
    ok(lp->adapter().prepare("select ?", ls).has_value() && !ls, "metadata budget enforced");
    PluginLimits column_limit;
    column_limit.columns = 0;
    auto cp = make(other, column_limit);
    ok(cp->adapter().prepare("select ?", ls).has_value() && !ls, "column count budget enforced");
    malformed.row_done = 2;
    malformed.row_count = 0;
    mp->adapter().execute(*bad, info);
    ok(mp->adapter().fetch(*bad, row, done, 8).has_value(), "invalid EOF flag rejected");
    malformed.row_done = 1;
    malformed.row_count = 0;
    mp->adapter().execute(*bad, info);
    ok(!mp->adapter().fetch(*bad, row, done, 0) && done && row.empty(), "empty EOF accepted");
    ProxySQL_Embedded_EngineV1 engine{
        1,        sizeof(engine),
        &other,   ProxySQL_Embedded_CAP_READ_ONLY | ProxySQL_Embedded_CAP_PARAMETER_POSITIONS,
        0x1fe,    prepare,
        params,   result,
        bind,     execute,
        fetch,    reset,
        finalize, nullptr,
        nullptr};
    ProxySQL_Embedded_PolicyV1 pol{1, sizeof(pol), &other, policy, policy_values, policy};
    ProxySQL_Embedded_RequestV1 request{
        1,      sizeof(request), &engine,   &pol,   ProxySQL_Embedded_REQUEST_READ_ONLY,
        status, nullptr,         pg_status, nullptr};
    PluginProviderResult rejected_provider;
    engine.value_type_mask = 0x1fc;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "mask requires NULL bit");
    engine.value_type_mask = 0x3fe;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unknown value mask rejected");
    engine.value_type_mask = 0x1fe;
    engine.capabilities |= 4;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unknown capability rejected");
    engine.capabilities = ProxySQL_Embedded_CAP_READ_ONLY;
    request.flags = 3;
    ok(make_plugin_provider(&request, true, rejected_provider).has_value(),
       "PostgreSQL requires positions capability");
    engine.capabilities |= ProxySQL_Embedded_CAP_PARAMETER_POSITIONS;
    ok(!make_plugin_provider(&request, true, rejected_provider),
       "PostgreSQL accepts read-only implicit cycles");
    request.flags = 1;
    ok(make_plugin_provider(&request, true, rejected_provider).has_value(),
       "PostgreSQL requires implicit cycles flag");
    request.flags = 3;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "MySQL rejects PostgreSQL flags");
    request.flags = 1;
    request.mysql_status = nullptr;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "MySQL requires status callback");
    request.mysql_status = status;
    engine.fetch = nullptr;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "missing engine callback rejected");
    engine.fetch = fetch;
    pol.authorize_fetch = nullptr;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "missing policy callback rejected");
    pol.authorize_fetch = policy;
    engine.guard_enter = guard_enter;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unpaired guard rejected");
    engine.guard_enter = nullptr;
    engine.abi_version = 2;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unknown engine ABI rejected");
    struct Prefix prefix_engine {
        1, 8
    };
    engine.abi_version = 1;
    request.engine = reinterpret_cast<ProxySQL_Embedded_EngineV1 *>(&prefix_engine);
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "truncated engine rejected before tail access");
    request.engine = &engine;
    request.policy = reinterpret_cast<ProxySQL_Embedded_PolicyV1 *>(&prefix_engine);
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "truncated policy rejected before tail access");
    request.policy = &pol;
    request.abi_version = 2;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unknown request ABI rejected");
    request.abi_version = 1;
    pol.abi_version = 2;
    ok(make_plugin_provider(&request, false, rejected_provider).has_value(),
       "unknown policy ABI rejected");
    Fake incompatible;
    auto ip = make(incompatible);
    std::unique_ptr<Statement> is;
    ip->adapter().prepare("select ?", is);
    ip->adapter().execute(*is, info);
    incompatible.custom_row = true;
    incompatible.value.kind = ProxySQL_Embedded_VALUE_TEXT;
    incompatible.value.payload.bytes = {nullptr, 0};
    ok(ip->adapter().fetch(*is, row, done, 8).has_value(), "row type mismatch rejected");
    incompatible.value.kind = ProxySQL_Embedded_VALUE_NULL;
    incompatible.column.type.nullable = 0;
    ip->adapter().finalize(std::move(is));
    ip->adapter().prepare("select ?", is);
    ip->adapter().execute(*is, info);
    ok(ip->adapter().fetch(*is, row, done, 8).has_value(), "null rejected for nonnullable column");
    incompatible.column.type.nullable = 1;
    ip->adapter().finalize(std::move(is));
    ip->adapter().prepare("select ?", is);
    incompatible.fail_execute = true;
    std::memcpy(incompatible.state, "00000", 6);
    auto no_state = ip->adapter().execute(*is, info);
    ok(no_state && no_state->sqlstate.empty(), "success class error SQLSTATE discarded");
    incompatible.fail_execute = false;
    incompatible.type.kind = ProxySQL_Embedded_TYPE_DYNAMIC;
    ip->adapter().finalize(std::move(is));
    ok(ip->adapter().prepare("select ?", is).has_value(), "ambiguous dynamic parameter rejected");
    Fake errors;
    auto ep = make(errors);
    std::unique_ptr<Statement> es;
    ep->adapter().prepare("select ?", es);
    errors.fail_execute = true;
    const ErrorKind mapped[] = {ErrorKind::syntax,         ErrorKind::unsupported,
                                ErrorKind::policy,         ErrorKind::invalid_parameter,
                                ErrorKind::range,          ErrorKind::resource,
                                ErrorKind::schema_changed, ErrorKind::transaction,
                                ErrorKind::engine,         ErrorKind::internal};
    bool mapping = true;
    for (uint32_t k = 1; k <= 10; ++k) {
        errors.error_kind = k;
        auto result = ep->adapter().execute(*es, info);
        mapping = mapping && result && result->kind == mapped[k - 1];
    }
    ok(mapping, "all public error kinds mapped explicitly");
    errors.error_kind = 999;
    auto fallback = ep->adapter().execute(*es, info);
    ok(fallback && fallback->kind == ErrorKind::engine, "unknown error kind uses engine fallback");
    errors.error_size = 4097;
    auto oversized = ep->adapter().execute(*es, info);
    ok(oversized && oversized->kind == ErrorKind::internal,
       "oversized error message rejected before access");
    errors.error_size = 1;
    errors.null_error = true;
    auto null_message = ep->adapter().execute(*es, info);
    ok(null_message && null_message->kind == ErrorKind::internal,
       "null nonempty error message rejected");
    errors.error_size = 0;
    errors.null_error = false;
    std::memcpy(errors.state, "ABc12", 6);
    auto invalid_state = ep->adapter().execute(*es, info);
    ok(invalid_state && invalid_state->sqlstate.empty(),
       "invalid SQLSTATE falls back to typed mapping");
    const Operation operations[] = {Operation::prepare,  Operation::execute, Operation::fetch,
                                    Operation::reset,    Operation::close,   Operation::disconnect,
                                    Operation::long_data};
    const uint32_t tags[] = {
        ProxySQL_Embedded_OPERATION_PREPARE,  ProxySQL_Embedded_OPERATION_EXECUTE,
        ProxySQL_Embedded_OPERATION_FETCH,    ProxySQL_Embedded_OPERATION_RESET,
        ProxySQL_Embedded_OPERATION_CLOSE,    ProxySQL_Embedded_OPERATION_DISCONNECT,
        ProxySQL_Embedded_OPERATION_LONG_DATA};
    bool tags_match = true;
    for (size_t i = 0; i < 7; ++i) {
        OperationContext op{operations[i], nullptr};
        tags_match = tags_match && !gf(op, guard) && other.operation == tags[i];
        guard.reset();
    }
    ok(tags_match, "all guard operation tags mapped explicitly");
    std::string bad_sql("x\0y", 3);
    std::unique_ptr<Statement> sql_stmt;
    other.events.clear();
    ok(guarded->adapter().prepare(bad_sql, sql_stmt).has_value() && other.events.empty(),
       "embedded SQL NUL rejected before native callback");
    errors.column.name = {reinterpret_cast<const uint8_t *>(errors.name), SIZE_MAX};
    errors.fail_execute = false;
    ep->adapter().finalize(std::move(es));
    ok(ep->adapter().prepare("select ?", es).has_value(),
       "huge metadata name rejected before copy");
    request.policy = &pol;
    pol.abi_version = 1;
    request.flags = 3;
    request.pgsql_status = nullptr;
    ok(make_plugin_provider(&request, true, rejected_provider).has_value(),
       "PostgreSQL requires status callback");
    request.pgsql_status = pg_status;
    request.pgsql_status_context = &other;
    ok(!make_plugin_provider(&request, true, rejected_provider) &&
           rejected_provider->pgsql_status() == pg_status &&
           rejected_provider->pgsql_status_context() == &other,
       "PostgreSQL status callback and context copied");
    Fake invalidation;
    invalidation.invalidate_params = true;
    auto vp = make(invalidation);
    std::unique_ptr<Statement> vs;
    vp->adapter().prepare("select ?", vs);
    std::vector<Type> cached_types;
    vp->adapter().describe_parameter_positions(*vs, positions);
    vp->adapter().describe_parameters(*vs, cached_types);
    ok(positions[0] == 1 && cached_types[0].nullable,
       "parameter views copied before result callback invalidates them");
    Fake failure;
    failure.null_columns = true;
    auto fp = make(failure);
    std::unique_ptr<Statement> fs;
    auto meta_fail = fp->adapter().prepare("select ?", fs);
    ok(meta_fail && failure.resets == 1 && failure.finalized == 1,
       "metadata refusal resets and finalizes native handle");
    guarded->adapter().bind(*ordered, {Bytes{{0, 255}}});
    ok(other.bound_bytes == std::vector<uint8_t>({0, 255}), "bind preserves binary payload");
    guarded->adapter().bind(*ordered, {Decimal{"-12.30"}});
    ok(std::string(other.bound_bytes.begin(), other.bound_bytes.end()) == "-12.30",
       "bind preserves decimal text");
    Fake values;
    values.column.type.kind = ProxySQL_Embedded_TYPE_DYNAMIC;
    auto va = make(values);
    std::unique_ptr<Statement> vstmt;
    va->adapter().prepare("select ?", vstmt);
    va->adapter().execute(*vstmt, info);
    values.custom_row = true;
    values.value.kind = ProxySQL_Embedded_VALUE_FLOAT64;
    values.value.payload.float64_value = 2.25;
    ok(!va->adapter().fetch(*vstmt, row, done, 8) && std::get<double>(row[0]) == 2.25,
       "floating value copied");
    uint8_t invalid_utf8[] = {0xff};
    values.value.kind = ProxySQL_Embedded_VALUE_TEXT;
    values.value.payload.bytes = {invalid_utf8, 1};
    ok(!va->adapter().fetch(*vstmt, row, done, 1) && std::get<Text>(row[0]).bytes.size() == 1,
       "text bytes preserved for frontend UTF-8 validation");
    values.value.kind = 99;
    ok(va->adapter().fetch(*vstmt, row, done, 8).has_value(), "unknown value tag rejected");
    va->adapter().execute(*vstmt, info);
    values.row_count = SIZE_MAX;
    ok(va->adapter().fetch(*vstmt, row, done, 8).has_value(),
       "huge row count rejected before value access");
    va->adapter().execute(*vstmt, info);
    values.row_count = 1;
    values.value.kind = ProxySQL_Embedded_VALUE_BYTES;
    values.value.payload.bytes = {invalid_utf8, SIZE_MAX};
    ok(va->adapter().fetch(*vstmt, row, done, SIZE_MAX).has_value(),
       "huge nonnull row view rejected before copy");
    values.column.name = {reinterpret_cast<const uint8_t *>("a\0b"), 3};
    va->adapter().finalize(std::move(vstmt));
    ok(va->adapter().prepare("select ?", vstmt).has_value(), "column name containing NUL rejected");
    other.events.clear();
    other.fail_execute = true;
    other.reset_error = true;
    std::memcpy(other.message, "failure", 8);
    auto operation_status = ordering_guard(context, operation_guard);
    auto execution_error = guarded->adapter().execute(*ordered, info);
    operation_guard.reset();
    ok(!operation_status && execution_error && execution_error->message == "failure" &&
           other.events == "GXRL",
       "execute failure resets under guard before release");
    other.fail_execute = false;
    other.reset_error = false;
    guarded->adapter().execute(*ordered, info);
    other.events.clear();
    other.fetch_rc = 1;
    ordering_guard(context, operation_guard);
    auto fetch_error = guarded->adapter().fetch(*ordered, row, done, 8);
    operation_guard.reset();
    ok(fetch_error && other.events == "GFRL", "fetch failure resets under guard before release");
    other.fetch_rc = 0;
    other.null_columns = true;
    other.events.clear();
    ordering_guard(prep_context, operation_guard);
    std::unique_ptr<Statement> refused;
    auto metadata_error = guarded->adapter().prepare("select ?", refused);
    operation_guard.reset();
    ok(metadata_error && other.events == "GPRL",
       "metadata failure resets under guard before release");
    other.events.clear();
    ok(!guarded->policy().authorize_execute("SELECT ? /* unchanged */", {Decimal{"1.00"}}) &&
           other.policy_sql == "SELECT ? /* unchanged */" &&
           other.policy_kind == ProxySQL_Embedded_VALUE_DECIMAL,
       "policy receives unchanged SQL and converted value");
    other.null_columns = false;
    engine.value_type_mask = (UINT64_C(1) << ProxySQL_Embedded_VALUE_NULL) |
                             (UINT64_C(1) << ProxySQL_Embedded_VALUE_INT64);
    request.flags = 1;
    request.mysql_status = status;
    request.engine = &engine;
    request.policy = &pol;
    auto restricted_status = make_plugin_provider(&request, false, rejected_provider);
    std::unique_ptr<Statement> restricted_statement;
    if (!restricted_status)
        rejected_provider->adapter().prepare("select ?", restricted_statement);
    other.bound_kind = 0;
    ok(!restricted_status && restricted_statement &&
           rejected_provider->adapter().bind(*restricted_statement, {Text{"text"}}).has_value() &&
           other.bound_kind == 0,
       "unsupported bind value rejected before native callback");
    other.events.clear();
    ok(rejected_provider->policy().authorize_execute("select ?", {Text{"text"}}).has_value() &&
           other.events.empty(),
       "unsupported policy value rejected before callback");
    guarded->adapter().bind(*ordered, {uint64_t(UINT64_MAX)});
    ok(other.bound_value.payload.uint64_value == UINT64_MAX, "bind preserves uint64 payload");
    guarded->adapter().bind(*ordered, {true});
    ok(other.bound_value.payload.boolean_value == 1, "bind preserves boolean payload");
    Fake flags;
    auto flag_provider = make(flags);
    std::unique_ptr<Statement> flag_stmt;
    flag_provider->adapter().prepare("select ?", flag_stmt);
    flags.has_result = 2;
    ok(flag_provider->adapter().execute(*flag_stmt, info).has_value(),
       "nonbinary result flag rejected");
    flags.has_result = 0;
    ok(flag_provider->adapter().execute(*flag_stmt, info).has_value(),
       "result flag inconsistent with columns rejected");
    flags.has_result = 1;
    ok(!flag_provider->adapter().execute(*flag_stmt, info) && info.affected_rows == UINT64_MAX &&
           info.last_insert_id == UINT64_MAX,
       "execution counters preserve full unsigned range");
    Fake metadata_cases;
    metadata_cases.position = 0;
    auto metadata_provider = make(metadata_cases);
    std::unique_ptr<Statement> metadata_statement;
    ok(!metadata_provider->adapter().prepare("select ?", metadata_statement) &&
           !metadata_provider->adapter().describe_parameter_positions(*metadata_statement,
                                                                      positions) &&
           positions[0] == 0,
       "unknown parameter position retained for frontend validation");
    metadata_provider->adapter().finalize(std::move(metadata_statement));
    metadata_cases.type = {ProxySQL_Embedded_TYPE_DECIMAL, 1000, 1000, 1};
    ok(!metadata_provider->adapter().prepare("select ?", metadata_statement),
       "maximum decimal precision and scale accepted");
    metadata_provider->adapter().finalize(std::move(metadata_statement));
    metadata_cases.type.scale = 1001;
    ok(metadata_provider->adapter().prepare("select ?", metadata_statement).has_value(),
       "decimal scale above precision rejected");
    metadata_cases.type = {ProxySQL_Embedded_TYPE_INT64, 1, 0, 1};
    ok(metadata_provider->adapter().prepare("select ?", metadata_statement).has_value(),
       "nondecimal precision rejected");
    Fake cleanup;
    cleanup.log_finalize = true;
    auto cleanup_provider = make(cleanup, {}, true);
    std::unique_ptr<Statement> cleanup_statement;
    cleanup_provider->adapter().prepare("select ?", cleanup_statement);
    cleanup_provider->adapter().execute(*cleanup_statement, info);
    cleanup.fetch_rc = 1;
    cleanup.reset_rc = 1;
    cleanup.reset_error = true;
    cleanup.events.clear();
    auto cleanup_guard = cleanup_provider->guard_factory();
    cleanup_guard(context, operation_guard);
    auto original = cleanup_provider->adapter().fetch(*cleanup_statement, row, done, 8);
    bool closed_under_guard = cleanup.finalized == 1 && cleanup.events == "GFRZ";
    operation_guard.reset();
    ok(original && original->message == "failure" && closed_under_guard &&
           cleanup.events == "GFRZL",
       "failed reset finalizes under guard and preserves original fetch error");
    cleanup.events.clear();
    ok(cleanup_provider->adapter().execute(*cleanup_statement, info).has_value() &&
           cleanup.events.empty(),
       "closed native statement rejects reuse without callbacks");
    cleanup_provider->adapter().finalize(std::move(cleanup_statement));
    ok(cleanup.finalized == 1, "closed native statement is finalized once");
    cleanup.fetch_rc = 0;
    cleanup.reset_rc = 0;
    cleanup.log_finalize = false;
    cleanup_provider->adapter().prepare("select ?", cleanup_statement);
    cleanup.reset_rc = 1;
    cleanup.log_finalize = true;
    cleanup.events.clear();
    auto reset_failure = cleanup_provider->adapter().reset(*cleanup_statement);
    ok(reset_failure && reset_failure->message == "zzzzzzz" && cleanup.finalized == 2 &&
           cleanup.events == "RZ",
       "explicit reset failure copies error then finalizes immediately");
    cleanup.events.clear();
    ok(cleanup_provider->adapter().reset(*cleanup_statement).has_value() && cleanup.events.empty(),
       "explicit reset cannot reuse closed native handle");
    cleanup.events.clear();
    OperationContext unknown{static_cast<Operation>(999), nullptr};
    ok(cleanup_guard(unknown, operation_guard).has_value() && !operation_guard &&
           cleanup.events.empty(),
       "unknown operation rejected before guard callback");
    Fake metadata_cleanup;
    metadata_cleanup.null_columns = true;
    metadata_cleanup.reset_rc = 7;
    auto metadata_cleanup_provider = make(metadata_cleanup);
    std::unique_ptr<Statement> metadata_bad;
    auto metadata_original = metadata_cleanup_provider->adapter().prepare("select ?", metadata_bad);
    ok(metadata_original && !metadata_bad && metadata_cleanup.resets == 1 &&
           metadata_cleanup.finalized == 1,
       "metadata refusal and invalid reset finalize once");
    Fake successful_reset;
    auto successful_provider = make(successful_reset);
    std::unique_ptr<Statement> reusable;
    successful_provider->adapter().prepare("select ?", reusable);
    ok(!successful_provider->adapter().reset(*reusable) &&
           !successful_provider->adapter().execute(*reusable, info) &&
           successful_reset.finalized == 0,
       "successful reset leaves handle reusable");
    cleanup.reset_rc = 0;
    cleanup_provider->adapter().finalize(std::move(cleanup_statement));
    ok(!cleanup_provider->adapter().prepare("select ?", cleanup_statement),
       "new prepare restores usable statement after reset failure");
    const size_t cache = sizeof(Type) + sizeof(uint32_t) + sizeof(Column) + 1;
    QuotaLimits qlimits;
    qlimits.values[static_cast<size_t>(Resource::metadata_bytes)] = cache;
    QuotaPool pool(qlimits);
    Fake qa, qb;
    qa.observe_pool = &pool;
    auto pa = make(qa, {}, false, &pool);
    auto pb = make(qb, {}, false, &pool);
    std::unique_ptr<Statement> sa, sb;
    ok(!pa->adapter().prepare("select ?", sa), "first provider reserves metadata");
    ok(pool.snapshot()[static_cast<size_t>(Resource::metadata_bytes)] == cache, "complete cache charged");
    ok(pb->adapter().prepare("select ?", sb).has_value() && !sb, "shared pool rejects second provider");
    ok(qb.finalized == 1 && pool.snapshot()[static_cast<size_t>(Resource::metadata_bytes)] == cache, "rejection finalizes once and rolls back partial charge");
    pa->adapter().finalize(std::move(sa));
    ok(qa.charge_at_finalize == cache, "charge remains during native finalization");
    ok(pool.snapshot()[static_cast<size_t>(Resource::metadata_bytes)] == 0, "finalization releases cache charge");
    ok(!pb->adapter().prepare("select ?", sb), "released quota permits another provider");
    pb->adapter().finalize(std::move(sb));
    ok(qb.finalized == 2 && pool.snapshot()[static_cast<size_t>(Resource::metadata_bytes)] == 0, "second finalization releases charge once");
    return exit_status();
}
