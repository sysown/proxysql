#include "Embedded_PgSQL_Prepared.h"
#include "Embedded_PgSQL_Value.h"
#include "tap.h"
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
struct Fake : Adapter {
    struct S : Statement {
        int fetches = 0;
        int64_t value = 0;
    };
    int executes = 0, finals = 0, prepares = 0;
    bool mutate = false, bad_position = false, fail_fetch = false, boolean_parameters = false;
    bool active_result = false, reset_guarded = true, fail_reset = false, no_result = false;
    Command command = Command::select;
    uint64_t affected_rows = 0;
    int *guard_depth = nullptr;
    bool all_guarded = true;
    std::vector<Value> bound;
    std::string sql;
    Status prepare(const std::string &q, std::unique_ptr<Statement> &s) override {
        sql = q;
        ++prepares;
        s.reset(new S);
        return {};
    }
    Status describe_parameters(Statement &, std::vector<Type> &p) override {
        p.assign(3, Type{boolean_parameters ? TypeKind::boolean : TypeKind::signed_integer});
        return {};
    }
    Status describe_parameter_positions(Statement &, std::vector<uint32_t> &p) override {
        p = bad_position ? std::vector<uint32_t>{2, 0, 2} : std::vector<uint32_t>{2, 1, 2};
        return {};
    }
    Status describe_result(Statement &, std::vector<Column> &c) override {
        c = {{mutate && prepares > 1 ? "changed" : "v", Type{TypeKind::signed_integer}}};
        return {};
    }
    Status bind(Statement &statement, const std::vector<Value> &v) override {
        bound = v;
        if (!v.empty() && std::holds_alternative<int64_t>(v[0]))
            static_cast<S &>(statement).value = std::get<int64_t>(v[0]);
        return {};
    }
    Status execute(Statement &, ExecInfo &i) override {
        ++executes;
        active_result = true;
        i.has_result = !no_result;
        i.command = command;
        i.affected_rows = affected_rows;
        return {};
    }
    Status fetch(Statement &s, Row &r, bool &done, size_t) override {
        if (guard_depth)
            all_guarded &= *guard_depth == 1;
        if (fail_fetch)
            return Error{ErrorKind::engine, 0, "fetch failed", "XX000"};
        auto &x = static_cast<S &>(s);
        done = x.fetches++ >= 2;
        if (!done)
            r = {x.value + x.fetches};
        return {};
    }
    Status reset(Statement &) override {
        if (active_result && guard_depth) reset_guarded &= *guard_depth == 1;
        if (active_result && fail_reset) return Error{ErrorKind::engine, 0, "reset failed", "XX000"};
        active_result = false;
        return {};
    }
    void finalize(std::unique_ptr<Statement>) noexcept override {
        if (active_result && guard_depth) reset_guarded &= *guard_depth == 1;
        active_result = false;
        ++finals;
    }
};
int main() {
    plan(NO_PLAN);
    Fake a;
    Policy policy;
    int depth = 0;
    bool guarded = true;
    struct G : OperationGuard {
        int &d;
        explicit G(int &x) : d(x) {
            ++d;
        }
        ~G() {
            --d;
        }
    };
    GuardFactory factory = [&](const OperationContext &,
                               std::unique_ptr<OperationGuard> &out) -> Status {
        guarded &= depth == 0;
        out.reset(new G(depth));
        return {};
    };
    a.guard_depth = &depth;
    PgSQLPrepared p(a, policy, factory);
    PgSQLDescription desc;
    PgSQLExecution result;
    { Fake boolean_adapter; boolean_adapter.boolean_parameters = true;
      PgSQLPrepared boolean_controller(boolean_adapter, policy, factory);
      PgSQLDescription boolean_desc;
      ok(!boolean_controller.parse("bool", "SELECT", {0, 0}) && !boolean_controller.describe_statement("bool", boolean_desc) && boolean_desc.parameter_oids == std::vector<uint32_t>({16, 16}), "inferred Boolean OID");
      const unsigned char t[] = {'t'}, f[] = {'f'};
      ok(!boolean_controller.bind("bool_portal", "bool", {{t, 1, 0}, {f, 1, 0}}, {}) && !boolean_controller.execute("bool_portal", 0, result) && boolean_adapter.bound.size() == 3 && std::holds_alternative<bool>(boolean_adapter.bound[0]) && !std::get<bool>(boolean_adapter.bound[0]) && std::get<bool>(boolean_adapter.bound[1]), "Boolean parameters reach adapter as bool"); }

    ok(!p.parse("s", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}),
       "parse accepts mapped parameters");
    ok(a.sql == "SELECT $2, $1, $2", "SQL is not rewritten");
    const unsigned char one[] = {'1'}, two[] = {'2'};
    std::vector<PgSQLDatum> data = {{one, 1, 0}, {two, 1, 0}};
    ok(!p.bind("p", "s", data, {}), "bind succeeds");
    ok(!p.bind("q", "s", data, {}), "second portal succeeds");
    ok(a.executes == 0, "parse and bind never execute");
    ok(!p.close_statement("s"), "close statement preserves portals");
    ok(!p.execute("p", 2, result) && result.rows.size() == 2 && result.suspended &&
       !a.active_result && a.reset_guarded,
       "exact boundary suspends");
    ok(a.bound.size() == 3 && std::get<int64_t>(a.bound[0]) == 2 &&
           std::get<int64_t>(a.bound[1]) == 1 && std::get<int64_t>(a.bound[2]) == 2,
       "native slots follow logical positions");
    ok(!p.execute("p", 2, result) && result.rows.empty() && !result.suspended &&
           result.row_count == 2 && result.command == Command::select,
       "next execution completes with total row count");
    ok(!p.execute("p", 0, result) && result.rows.empty() && a.executes == 1,
       "completed portal never reexecutes");
    ok(!p.execute("q", 0, result) && result.rows.size() == 2 && a.executes == 2,
       "other portal executes independently");
    { Fake dml; dml.command = Command::update; dml.affected_rows = 7;
      dml.no_result = true;
      PgSQLPrepared dml_controller(dml, policy);
      ok(!dml_controller.parse("d", "UPDATE", {pgsql_oid_int8, pgsql_oid_int8}) &&
         !dml_controller.bind("dp", "d", data, {}) &&
         !dml_controller.execute("dp", 0, result) && result.command == Command::update &&
         result.row_count == 7, "completion preserves native command and affected rows"); }
    { Fake returning; returning.command = Command::insert; returning.affected_rows = 99;
      PgSQLPrepared returning_controller(returning, policy);
      ok(!returning_controller.parse("r", "INSERT RETURNING", {pgsql_oid_int8, pgsql_oid_int8}) &&
         !returning_controller.bind("rp", "r", data, {}) &&
         !returning_controller.execute("rp", 0, result) && result.command == Command::insert &&
         result.row_count == 2, "RETURNING completion counts returned rows"); }
    ok(!p.parse("s", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}), "parse again");
    auto e = p.parse("s", "x", {});
    ok(e && e->sqlstate == "42P05" && p.ignoring(), "duplicate poisons cycle");
    ok(!p.describe_statement("s", desc) && desc.columns.empty(), "operations ignored after error");
    p.sync();
    ok(!p.ignoring(), "sync clears error");
    ok(!p.close_statement("missing") && !p.close_portal("missing"),
       "closing unknown objects succeeds");
    e = p.describe_portal("q", desc);
    ok(e && e->sqlstate == "34000", "sync closes portals");
    p.sync();
    ok(guarded && a.all_guarded && depth == 0, "guards cover every fetch and end at return");
    p.disconnect();
    ok(a.finals == 4, "all native handles finalized");
    Fake b;
    PgSQLPrepared limited(b, policy, {},
                          PgSQLPreparedLimits{1, 1, 3, 1, 1024, 1024, 1024, 1024, 1024, 1024});
    ok(!limited.parse("s", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}),
       "bounded statement parses");
    e = limited.bind("p", "s", data, {0, 1});
    ok(e && e->sqlstate == "08P01" && b.executes == 0,
       "invalid result formats rejected without execution");
    limited.sync();
    ok(!limited.bind("p", "s", data, {}), "valid bind after sync");
    e = limited.bind("q", "s", data, {});
    ok(e && e->sqlstate == "54000" && b.executes == 0, "portal limit fails without execution");
    limited.sync();
    Fake c;
    PgSQLPrepared unsupported(c, policy);
    e = unsupported.parse("s", "SELECT $2, $1, $2", {99999, pgsql_oid_int8});
    ok(e && e->sqlstate == "0A000" && c.executes == 0,
       "unsupported explicit OID rejected at parse");
    unsupported.sync();
    Fake snapshot_fake;
    PgSQLPrepared snapshots(snapshot_fake, policy);
    ok(!snapshots.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}),
       "snapshot statement parses");
    unsigned char mutable_two[] = {'2'};
    std::vector<PgSQLDatum> mutable_data = {{one, 1, 0}, {mutable_two, 1, 0}};
    ok(!snapshots.bind("first", "s", mutable_data, {}), "first snapshot bound");
    mutable_two[0] = '9';
    ok(!snapshots.bind("second", "s", mutable_data, {}), "second snapshot bound");
    mutable_two[0] = '4';
    ok(!snapshots.execute("first", 0, result) &&
           result.rows[0][0].payload == std::vector<unsigned char>{'3'},
       "first portal owns its original bind snapshot");
    ok(!snapshots.execute("second", 0, result) &&
           result.rows[0][0].payload == std::vector<unsigned char>{'1', '0'},
       "second portal owns an independent snapshot");
    Fake invalid;
    invalid.bad_position = true;
    PgSQLPrepared zero_position(invalid, policy);
    e = zero_position.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8});
    ok(e && e->sqlstate == "42P18" && invalid.executes == 0,
       "zero native parameter position rejected");
    Fake failing_fetch;
    PgSQLPrepared atomic(failing_fetch, policy);
    ok(!atomic.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !atomic.bind("p", "s", data, {}),
       "portal for fetch failure created");
    failing_fetch.fail_fetch = true;
    result.rows.resize(1);
    e = atomic.execute("p", 0, result);
    ok(e && result.rows.empty() && !result.suspended && result.row_count == 0,
       "fetch failure clears the entire response");
    Fake binary_fake;
    PgSQLPrepared binary(binary_fake, policy);
    ok(!binary.parse("s", "SELECT", {pgsql_oid_numeric, pgsql_oid_int8}),
       "numeric OID accepted in parse");
    std::vector<PgSQLDatum> numeric_binary = {{nullptr, -1, 1}, {nullptr, -1, 0}};
    e = binary.bind("p", "s", numeric_binary, {});
    ok(e && e->sqlstate == "0A000" && binary_fake.executes == 0,
       "binary numeric rejected for NULL at bind");
    Fake clean_fake;
    bool fail_close = true;
    GuardFactory close_guard = [&](const OperationContext &ctx,
                                   std::unique_ptr<OperationGuard> &g) -> Status {
        if (ctx.operation == Operation::close && fail_close)
            return Error{ErrorKind::engine, 0, "lease failed", "XX000"};
        g.reset(new OperationGuard);
        return {};
    };
    PgSQLPrepared guarded_sync(clean_fake, policy, close_guard);
    ok(!guarded_sync.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !guarded_sync.bind("p", "s", data, {}),
       "portal created for failed sync guard");
    e = guarded_sync.sync();
    ok(e && guarded_sync.ignoring() && clean_fake.finals == 0,
       "failed sync lease preserves handles and poisons cycle");
    fail_close = false;
    ok(!guarded_sync.sync() && !guarded_sync.ignoring() && clean_fake.finals == 1,
       "successful sync retries cleanup and clears poison");
    PgSQLPreparedLimits bind_limit;
    bind_limit.bind_total = 3 * sizeof(Value) + 24;
    Fake exact_fake;
    PgSQLPrepared exact(exact_fake, policy, {}, bind_limit);
    ok(!exact.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !exact.bind("p", "s", data, {}),
       "expanded duplicate parameter budget accepts exact size");
    --bind_limit.bind_total;
    Fake short_fake;
    PgSQLPrepared short_budget(short_fake, policy, {}, bind_limit);
    ok(!short_budget.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}),
       "one-less budget statement parses");
    e = short_budget.bind("p", "s", data, {});
    ok(e && e->sqlstate == "54000" && short_fake.executes == 0 && short_fake.prepares == 1,
       "expanded duplicate budget fails before native clone");
    PgSQLPreparedLimits result_limit;
    result_limit.result_total = 2 * (5 + 2 + sizeof(PgSQLFieldRow) + sizeof(PgSQLField) + 4 + 1);
    Fake exact_result_fake;
    PgSQLPrepared exact_result(exact_result_fake, policy, {}, result_limit);
    ok(!exact_result.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !exact_result.bind("p", "s", data, {}) && !exact_result.execute("p", 0, result) &&
           result.rows.size() == 2,
       "result budget accepts exact framing and payload size");
    --result_limit.result_total;
    Fake short_result_fake;
    PgSQLPrepared short_result(short_result_fake, policy, {}, result_limit);
    ok(!short_result.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !short_result.bind("p", "s", data, {}),
       "short result budget portal created");
    result.rows.resize(1);
    e = short_result.execute("p", 0, result);
    ok(e && result.rows.empty() && short_result.ignoring(),
       "one-less result budget clears partial rows and poisons");
    PgSQLPreparedLimits names;
    names.name_per = 1;
    Fake names_fake;
    PgSQLPrepared name_limit(names_fake, policy, {}, names);
    e = name_limit.parse("xx", "SELECT", {pgsql_oid_int8, pgsql_oid_int8});
    ok(e && e->sqlstate == "54000" && names_fake.prepares == 0,
       "oversized name rejected before prepare");
    Fake values_fake;
    PgSQLPrepared values(values_fake, policy);
    ok(!values.parse("s", "SELECT", {pgsql_oid_text, pgsql_oid_int8}),
       "mixed text and integer parameters parse");
    const unsigned char binary_two[] = {0, 0, 0, 0, 0, 0, 0, 2};
    std::vector<PgSQLDatum> mixed = {{nullptr, 0, 0}, {binary_two, 8, 1}};
    ok(!values.bind("p", "s", mixed, {}) && !values.execute("p", 0, result),
       "empty text and binary integer bind and execute");
    ok(std::holds_alternative<Text>(values_fake.bound[1]) &&
           std::get<Text>(values_fake.bound[1]).bytes.empty() &&
           std::get<int64_t>(values_fake.bound[0]) == 2,
       "empty text remains distinct and binary integer decodes");
    values.sync();
    std::vector<PgSQLDatum> malformed = {{nullptr, 1, 0}, {binary_two, 8, 1}};
    e = values.bind("q", "s", malformed, {});
    ok(e && e->sqlstate == "08P01", "malformed non-null datum is rejected");
    Fake simple_fake;
    PgSQLPrepared simple(simple_fake, policy);
    ok(!simple.parse("named", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}),
       "named statement parses");
    ok(!simple.parse("", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}),
       "unnamed statement parses");
    ok(!simple.bind("", "", data, {}), "unnamed portal binds");
    ok(!simple.simple_query(), "simple query cleanup succeeds");
    ok(!simple.describe_statement("named", desc), "simple query retains named statement");
    e = simple.describe_statement("", desc);
    ok(e && e->sqlstate == "26000", "simple query drops unnamed statement");
    simple.sync();
    e = simple.reject(Error{ErrorKind::syntax, 0, "bad packet", "08P01"});
    ok(e && e->sqlstate == "08P01" && simple.ignoring(), "transport rejection poisons cycle");
    ok(!simple.simple_query() && simple.ignoring(), "simple query ignored in failed cycle");
    simple.sync();
    Fake changed;
    changed.mutate = true;
    PgSQLPrepared checked(changed, policy);
    ok(!checked.parse("s", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8}),
       "original metadata accepted");
    e = checked.bind("p", "s", data, {});
    ok(e && e->sqlstate == "0A000" && changed.executes == 0,
       "changed clone descriptor is rejected before execution");
    Fake replace_fake;
    PgSQLPrepared replace(replace_fake, policy);
    ok(!replace.parse("", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !replace.bind("", "", data, {}),
       "unnamed objects created");
    ok(!replace.parse("", "SELECT again", {pgsql_oid_int8, pgsql_oid_int8}),
       "unnamed statement replacement succeeds");
    ok(!replace.execute("", 0, result) && result.rows.size() == 2,
       "portal survives unnamed statement replacement");
    ok(!replace.bind("", "", data, {}) && replace_fake.finals == 2,
       "unnamed portal replacement finalizes previous handle");
    Fake null_guard_fake;
    GuardFactory null_guard = [](const OperationContext &ctx,
                                 std::unique_ptr<OperationGuard> &g) -> Status {
        if (ctx.operation == Operation::disconnect)
            g.reset(new OperationGuard);
        return {};
    };
    PgSQLPrepared no_guard(null_guard_fake, policy, null_guard);
    e = no_guard.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8});
    ok(e && e->sqlstate == "XX000" && null_guard_fake.prepares == 0,
       "missing guard rejects operation before native prepare");
    Fake throws;
    GuardFactory throwing = [](const OperationContext &ctx,
                               std::unique_ptr<OperationGuard> &g) -> Status {
        if (ctx.operation == Operation::prepare)
            throw 1;
        g.reset(new OperationGuard);
        return {};
    };
    PgSQLPrepared exceptional(throws, policy, throwing);
    e = exceptional.parse("s", "SELECT $2, $1, $2", {pgsql_oid_int8, pgsql_oid_int8});
    ok(e && e->sqlstate == "XX000" && exceptional.ignoring(),
       "throwing guard becomes error and poisons cycle");
    // Disconnect must succeed by contract, so use a factory that throws only on prepare.

    {
        QuotaLimits ql; ql.values = {{20, 65536, 65536, 65536, 200}};
        QuotaPool pool(ql); Fake f1, f2;
        f1.guard_depth = &depth; f2.guard_depth = &depth;
        PgSQLPrepared x(f1, policy, factory, {}, &pool), y(f2, policy, factory, {}, &pool);
        ok(!x.parse("x", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) &&
           !y.parse("y", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}), "controllers share quota pool");
        ok(!x.bind("p", "x", data, {}) && !y.bind("p", "y", data, {}), "portal binds reserve shared pool");
        ok(pool.snapshot()[static_cast<size_t>(Resource::bind_bytes)] > 0, "bound portal values are charged");
        PgSQLExecution first, second;
        ok(!x.execute("p", 1, first) && first.rows.size() == 1, "first portal materializes result");
        auto exhausted = y.execute("p", 0, second);
        ok(exhausted && exhausted->sqlstate == "54000" && second.rows.empty() && !f2.active_result && f2.reset_guarded, "shared result quota rejects without partial rows and resets under guard");
        auto retained_sql = pool.snapshot()[static_cast<size_t>(Resource::sql_bytes)];
        ok(!x.sync() && pool.snapshot()[static_cast<size_t>(Resource::sql_bytes)] < retained_sql &&
           pool.snapshot()[static_cast<size_t>(Resource::sql_bytes)] > 0, "sync releases portal while retaining named statements");
        ok(!y.sync() && !y.bind("again", "y", data, {}) && !y.execute("again", 0, second), "sync frees result capacity for another controller");
        x.disconnect(); y.disconnect();
        ok(pool.snapshot() == ResourceUsage{}, "disconnect releases frontend and core quota");
    }
    {
        QuotaLimits ql; ql.values = {{20, 65536, 65536, 0, 65536}};
        QuotaPool pool(ql); Fake f; PgSQLPrepared x(f, policy, {}, {}, &pool);
        ok(!x.parse("", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}), "unnamed statement prepared under quota");
        auto before = pool.snapshot();
        auto denied = x.bind("", "", data, {});
        ok(denied && denied->sqlstate == "54000" && pool.snapshot() == before,
           "bind quota failure releases attempted portal copies");
        ok(!x.sync() && !x.parse("", "SELECT replacement", {pgsql_oid_int8, pgsql_oid_int8}),
           "unnamed statement replacement succeeds with temporary reservations");
        x.disconnect();
        ok(pool.snapshot() == ResourceUsage{}, "replaced unnamed statement releases all quota");
    }
    {
        QuotaLimits ql; ql.values = {{20, 65536, 65536, 65536, 65536}};
        QuotaPool pool(ql); Fake f; PgSQLPrepared x(f, policy, {}, {}, &pool);
        ok(!x.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) && !x.bind("p", "s", data, {}), "fetch failure fixture prepared");
        f.fail_fetch = true; PgSQLExecution failed;
        auto e = x.execute("p", 0, failed);
        ok(e && failed.rows.empty() && pool.snapshot()[static_cast<size_t>(Resource::result_bytes)] == 0,
           "fetch failure exposes no rows and releases materialization lease");
        x.disconnect(); ok(pool.snapshot() == ResourceUsage{}, "failure cleanup releases all quota");
    }
    {
        QuotaLimits ql; ql.values = {{20, 65536, 65536, 65536, 65536}};
        QuotaPool pool(ql); Fake f; f.guard_depth = &depth;
        PgSQLPrepared x(f, policy, factory, {}, &pool);
        ok(!x.parse("s", "SELECT", {pgsql_oid_int8, pgsql_oid_int8}) && !x.bind("p", "s", data, {}), "reset failure fixture prepared");
        f.fail_reset = true; PgSQLExecution failed;
        int finals = f.finals;
        auto e = x.execute("p", 0, failed);
        ok(e && failed.rows.empty() && !f.active_result && f.reset_guarded && f.finals == finals + 1 && x.ignoring(),
           "failed native reset finalizes under guard and publishes no rows");
        ok(!x.sync(), "sync recovers after native reset failure");
        x.disconnect(); ok(pool.snapshot() == ResourceUsage{}, "reset failure releases quota");
    }
    return exit_status();
}
