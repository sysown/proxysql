#include "Embedded_Prepared.h"
#include "tap.h"
#include <stdexcept>
using namespace embedded;

struct Fake : Adapter {
    struct S : Statement {};
    int prepares = 0, finals = 0, executions = 0, fetches = 0, resets = 0, binds = 0;
    bool stepped = false, fail_reset = false, custom_row = false;
    Value next_value;
    bool fail_prepare = false, throw_prepare = false, throw_describe = false;
    bool fail_description = false, fail_execute = false, fail_fetch = false;
    bool oversized = false, malformed = false, no_result = false, two_rows = false;

    Status prepare(const std::string&, std::unique_ptr<Statement>& out) override {
        ++prepares;
        out.reset(new S);
        if (throw_prepare) throw std::runtime_error("prepare");
        if (fail_prepare) return Error{ErrorKind::engine, 0, "prepare", ""};
        return {};
    }
    Status describe_parameters(Statement&, std::vector<Type>& out) override {
        if (throw_describe) throw std::runtime_error("describe");
        out.resize(1);
        return {};
    }
    Status describe_result(Statement&, std::vector<Column>& out) override {
        if (fail_description) return Error{ErrorKind::engine, 0, "describe", ""};
        out.resize(1);
        return {};
    }
    Status bind(Statement&, const std::vector<Value>&) override {
        ++binds;
        if (stepped) return Error{ErrorKind::engine, 0, "still stepped", ""};
        return {};
    }
    Status execute(Statement&, ExecInfo& info) override {
        ++executions;
        info.has_result = !no_result;
        if (fail_execute) return Error{ErrorKind::engine, 0, "execute", ""};
        return {};
    }
    Status fetch(Statement&, Row& row, bool& done, size_t) override {
        ++fetches;
        stepped = true;
        if (custom_row) { row.push_back(next_value); done = false; return {}; }
        if (fail_fetch) { row.push_back(int64_t(1)); done = true; return Error{ErrorKind::engine, 0, "fetch", ""}; }
        if (oversized) { row.push_back(Text{std::string(5, 'x')}); done = false; }
        else if (malformed) { row.push_back(int64_t(1)); row.push_back(int64_t(2)); done = false; }
        else if (two_rows && fetches == 1) { row.push_back(Text{"x"}); done = false; }
        else done = true;
        return {};
    }
    Status reset(Statement&) override {
        ++resets;
        if (fail_reset) return Error{ErrorKind::engine, 42, "reset failed", ""};
        stepped = false;
        return {};
    }
    void finalize(std::unique_ptr<Statement> handle) noexcept override { if (handle) ++finals; }
};

struct Policy : EndpointPolicy {
    bool allow = true, throw_execute = false;
    Status check() { return allow ? Status{} : Status{Error{ErrorKind::policy, 0, "denied", ""}}; }
    Status authorize_prepare(const std::string&) override { return check(); }
    Status authorize_execute(const std::string&, const std::vector<Value>&) override {
        if (throw_execute) throw std::runtime_error("policy");
        return check();
    }
    Status authorize_fetch(const std::string&) override { return check(); }
};

static void lifecycle() {
    Fake fake; Policy policy;
    {
        Session session(fake, policy, 1);
        uint64_t id = 0, other = 0;
        Row row; bool done = false; ExecInfo info;
        ok(!session.prepare("select ?", id), "prepare succeeds");
        std::vector<Type> params; std::vector<Column> columns;
        ok(!session.describe(id, params, columns), "metadata is available");
        ok(params.size() == 1 && columns.size() == 1, "metadata has owned parameter and column");
        ok(bool(session.prepare("another", other)), "statement limit enforced");
        ok(other == 0, "failed prepare clears id");
        ok(bool(session.fetch(id, row, done)), "fetch before execution rejected");
        ok(bool(session.execute(id, {}, info)), "bad parameter arity rejected");
        policy.allow = false;
        ok(bool(session.execute(id, {int64_t(1)}, info)), "policy denies execution");
        ok(fake.executions == 0, "denied execution has no engine effect");
        policy.allow = true; fake.fail_execute = true;
        ok(bool(session.execute(id, {int64_t(1)}, info)), "engine execution failure reported");
        ok(fake.executions == 1, "failed execution attempted once");
        ok(bool(session.fetch(id, row, done)), "failed execution has no fetchable result");
        ok(fake.executions == 1, "fetch does not replay execution");
        fake.fail_execute = false;
        ok(!session.execute(id, {int64_t(1)}, info), "execution succeeds");
        policy.allow = false;
        ok(bool(session.fetch(id, row, done)), "policy denies fetch");
        ok(fake.fetches == 0, "denied fetch does not reach engine");
        policy.allow = true;
        ok(!session.execute(id, {int64_t(1)}, info), "new execution succeeds");
        ok(!session.fetch(id, row, done) && done, "empty result reaches EOF");
        ok(bool(session.fetch(id, row, done)), "fetch after EOF rejected");
        ok(!session.reset(id), "reset succeeds");
        ok(bool(session.fetch(id, row, done)), "reset removes active result");
        ok(!session.close(id), "close succeeds");
        ok(bool(session.close(id)), "second close rejected");
        ok(fake.finals == 1, "close finalizes once");
        fake.fail_prepare = true;
        ok(bool(session.prepare("bad", id)), "failed prepare reported");
        fake.fail_prepare = false;
        ok(!session.prepare("good", id), "failed prepare did not consume capacity");
    }
    ok(fake.finals == 3, "failed prepare and session destruction finalize handles");
}

static void ownership_and_policy() {
    Fake fake; Policy policy; Session session(fake, policy);
    uint64_t id = 99;
    policy.allow = false;
    ok(bool(session.prepare("denied", id)), "prepare policy denial reported");
    ok(id == 0 && fake.prepares == 0, "denied prepare clears id without engine call");
    policy.allow = true; fake.throw_prepare = true;
    try { session.prepare("throw", id); ok(false, "prepare exception propagates"); }
    catch (const std::runtime_error&) { ok(id == 0, "throwing prepare clears id"); }
    ok(fake.finals == 1, "handle from throwing prepare finalized");
    fake.throw_prepare = false; fake.throw_describe = true;
    try { session.prepare("throw", id); ok(false, "describe exception propagates"); }
    catch (const std::runtime_error&) { ok(id == 0, "throwing describe clears id"); }
    ok(fake.finals == 2, "handle from throwing describe finalized");
    fake.throw_describe = false; fake.fail_description = true;
    ok(bool(session.prepare("bad description", id)), "result description failure reported");
    ok(fake.finals == 3, "description failure finalizes handle");
    fake.fail_description = false;
    ok(!session.prepare("valid", id), "prepare after errors succeeds");
    ExecInfo info; Row row; bool done = false;
    ok(!session.execute(id, {int64_t(1)}, info), "result active before policy exception");
    policy.throw_execute = true;
    try { session.execute(id, {int64_t(1)}, info); ok(false, "policy exception propagates"); }
    catch (const std::runtime_error&) { ok(true, "policy exception propagated"); }
    ok(bool(session.fetch(id, row, done)), "policy exception invalidates prior result");
    ok(fake.fetches == 0, "old result was not read");
    std::vector<Type> params(1); std::vector<Column> columns(1);
    ok(bool(session.describe(999, params, columns)), "unknown metadata request rejected");
    ok(params.empty() && columns.empty(), "unknown metadata clears outputs");
}

static void fetch_behaviour() {
    Fake fake; Policy policy; Session session(fake, policy, 1, 4);
    uint64_t id = 0; ExecInfo info; Row row; bool done = false;
    ok(!session.prepare("select ?", id), "fetch test statement prepared");
    fake.no_result = true;
    ok(!session.execute(id, {int64_t(1)}, info), "no-result execution succeeds");
    ok(bool(session.fetch(id, row, done)), "no-result fetch rejected");
    ok(fake.fetches == 0, "no-result fetch does not call adapter");
    fake.no_result = false; fake.fail_fetch = true;
    ok(!session.execute(id, {int64_t(1)}, info), "execution before fetch failure succeeds");
    row.push_back(int64_t(7)); done = true;
    ok(bool(session.fetch(id, row, done)), "adapter fetch failure reported");
    ok(row.empty() && !done, "fetch failure clears outputs");
    ok(bool(session.fetch(id, row, done)), "fetch failure invalidates result");
    fake.fail_fetch = false; fake.malformed = true;
    ok(!session.execute(id, {int64_t(1)}, info), "execution before malformed row succeeds");
    ok(bool(session.fetch(id, row, done)), "malformed adapter row rejected");
    ok(row.empty() && !done, "malformed row is not exposed");
    fake.malformed = false; fake.oversized = true;
    ok(!session.execute(id, {int64_t(1)}, info), "execution before oversized row succeeds");
    ok(bool(session.fetch(id, row, done)), "oversized row rejected");
    ok(row.empty(), "oversized row is not exposed");
    fake.oversized = false; fake.two_rows = true; fake.fetches = 0;
    ok(!session.execute(id, {int64_t(1)}, info), "execution before normal fetch succeeds");
    ok(!session.fetch(id, row, done) && !done && row.size() == 1, "first fetch returns row");
    ok(!session.fetch(id, row, done) && done && row.empty(), "second fetch returns EOF");
    ok(bool(session.fetch(id, row, done)), "further fetch after EOF rejected");
    ok(fake.fetches == 2, "adapter is not called again after EOF");
}

static void execution_reset() {
    Fake fake; Policy policy; Session session(fake, policy);
    uint64_t id = 0; ExecInfo info; Row row; bool done = false;
    ok(!session.prepare("select ?", id), "reset test statement prepared");
    fake.two_rows = true;
    ok(!session.execute(id, {int64_t(1)}, info), "first explicit execution succeeds");
    ok(!session.fetch(id, row, done) && !done, "first execution has active row");
    ok(!session.execute(id, {int64_t(1)}, info), "re-execution before EOF resets stepped statement");
    ok(!session.fetch(id, row, done) && done, "second execution reaches EOF");
    ok(!session.execute(id, {int64_t(1)}, info), "re-execution after EOF resets stepped statement");
    fake.fail_fetch = true;
    ok(bool(session.fetch(id, row, done)), "fetch error occurs after stepping");
    fake.fail_fetch = false;
    ok(!session.execute(id, {int64_t(1)}, info), "re-execution after fetch error resets statement");
    int resets = fake.resets, binds = fake.binds, executes = fake.executions;
    policy.allow = false;
    ok(bool(session.execute(id, {int64_t(1)}, info)), "policy denies explicit execution");
    ok(fake.resets == resets && fake.binds == binds && fake.executions == executes,
       "policy denial precedes reset, bind and execute");
    policy.allow = true; fake.fail_reset = true;
    auto err = session.execute(id, {int64_t(1)}, info);
    ok(err && err->native_code == 42 && err->message == "reset failed", "reset error returned unchanged");
    ok(fake.binds == binds && fake.executions == executes, "reset failure prevents bind and execute");
}

static void payload_budget() {
    ok(value_payload_bytes(Value{true}) == 1 && value_payload_bytes(Value{false}) == 1, "Boolean payload is one byte");
    ok(value_payload_bytes(std::monostate{}) == 0, "NULL payload is zero");
    ok(value_payload_bytes(Text{""}) == 0 && value_payload_bytes(Bytes{}) == 0, "empty text and bytes payload is zero");
    ok(value_payload_bytes(int64_t(1)) == 8 && value_payload_bytes(uint64_t(1)) == 8 && value_payload_bytes(1.0) == 8,
       "numeric payload is eight bytes");
    for (const Value& value : {Value{std::monostate{}}, Value{Text{""}}, Value{Bytes{}}}) {
        Fake fake; Policy policy; Session session(fake, policy, 1, 0);
        uint64_t id = 0; ExecInfo info; Row row; bool done = false;
        fake.custom_row = true; fake.next_value = value;
        ok(!session.prepare("x", id) && !session.execute(id, {int64_t(1)}, info), "zero-budget statement executes");
        ok(!session.fetch(id, row, done) && row.size() == 1, "zero-byte value fits zero budget");
    }
    for (size_t budget : {size_t(7), size_t(8)}) {
        Fake fake; Policy policy; Session session(fake, policy, 1, budget);
        uint64_t id = 0; ExecInfo info; Row row; bool done = false;
        fake.custom_row = true; fake.next_value = int64_t(1);
        ok(!session.prepare("x", id) && !session.execute(id, {int64_t(1)}, info), "numeric budget statement executes");
        auto err = session.fetch(id, row, done);
        ok(budget == 7 ? bool(err) && row.empty() : !err && row.size() == 1,
           "numeric payload obeys seven/eight byte boundary");
    }
}

static void shared_quota() {
    QuotaLimits limits; limits.values = {{1, 4, 4096, 100, 100}};
    QuotaPool pool(limits); Fake fake; Policy policy;
    Session first(fake, policy, 10, 1024, &pool), second(fake, policy, 10, 1024, &pool);
    uint64_t a = 0, b = 0;
    policy.allow = false;
    ok(bool(first.prepare("no", a)) && pool.snapshot() == ResourceUsage{}, "policy refusal does not charge quota");
    policy.allow = true;
    ok(!first.prepare("1234", a), "first session consumes exact SQL and handle quota");
    auto denied = second.prepare("x", b);
    ok(denied && denied->kind == ErrorKind::resource && denied->sqlstate == "54000" && fake.prepares == 1, "shared quota denies before native prepare");
    ok(!first.reset(a) && bool(second.prepare("x", b)), "reset retains quota");
    ok(!first.close(a) && !second.prepare("x", b), "close allows other session to reuse quota");
    ok(!second.close(b) && pool.snapshot() == ResourceUsage{}, "close releases all charges");
    limits.values[2] = 0; QuotaPool no_metadata(limits);
    Session third(fake, policy, 10, 1024, &no_metadata);
    int finals = fake.finals;
    auto metadata_error = third.prepare("x", b);
    ok(metadata_error && metadata_error->sqlstate == "54000" && fake.finals == finals + 1 && no_metadata.snapshot() == ResourceUsage{}, "metadata rejection finalizes handle and releases quota");
    fake.throw_describe = true;
    try { third.prepare("x", b); } catch (const std::runtime_error&) {}
    ok(no_metadata.snapshot() == ResourceUsage{} && fake.finals == finals + 2, "exception releases handle and quota");
}

int main() {
    plan(NO_PLAN);
    shared_quota();
    lifecycle();
    ownership_and_policy();
    fetch_behaviour();
    execution_reset();
    payload_budget();
    return exit_status();
}
