#include "Embedded_Prepared.h"
#include "Embedded_SQLite_Adapter.h"
#include "sqlite3db.h"
#include "tap.h"
#include <vector>
using namespace embedded;
struct Policy : EndpointPolicy {
 Status authorize_prepare(const std::string&) override { return {}; }
 Status authorize_execute(const std::string&, const std::vector<Value>&) override { return {}; }
 Status authorize_fetch(const std::string&) override { return {}; }
};
struct Fake : Adapter {
 int mode = 0; int executions = 0;
 struct S : Statement {};
 Status prepare(const std::string&, std::unique_ptr<Statement>& s) override { s.reset(new S); return {}; }
 Status describe_parameters(Statement&, std::vector<Type>& p) override { p.resize(1); return {}; }
 Status describe_result(Statement&, std::vector<Column>&) override { return {}; }
 Status bind(Statement&, const std::vector<Value>&) override { return {}; }
 Status execute(Statement&, ExecInfo&) override { ++executions; return {}; }
 Status fetch(Statement&, Row&, bool&, size_t) override { return {}; }
 Status reset(Statement&) override { return {}; }
 void finalize(std::unique_ptr<Statement>) noexcept override {}
 Status describe_parameter_positions(Statement& s, std::vector<uint32_t>& out) override {
  if (!mode) return Adapter::describe_parameter_positions(s, out);
  out = {1, 2};
  if (mode == 1) return Error{ErrorKind::engine, 0, "failure", ""};
  return {};
 }
};
int main() {
 plan(31);
 sqlite3* db = nullptr;
 ok(sqlite3_open(":memory:", &db) == SQLITE_OK, "open SQLite");
 {
 SQLiteAdapter adapter(db); Policy policy; Session session(adapter, policy);
 uint64_t id = 0; std::vector<uint32_t> positions;
 auto check = [&](const char* sql, std::vector<uint32_t> expected, const char* name) {
  uint64_t n = 0; auto e = session.prepare(sql, n);
  if (!e) e = session.describe_parameter_positions(n, positions);
  ok(!e && positions == expected, "%s", name);
  if (n) session.close(n);
 };
 ok(!session.prepare("SELECT $2,$1", id), "prepare reversed parameters");
 ok(!session.describe_parameter_positions(id, positions) && positions == std::vector<uint32_t>({2,1}), "native slots preserve protocol positions");
 std::vector<Value> wire{int64_t(11), int64_t(22)}, native;
 for (auto p : positions) native.push_back(wire.at(p-1));
 ExecInfo info; Row row; bool done = false;
 ok(!session.execute(id, native, info), "execute mapped values");
 ok(!session.fetch(id, row, done) && !done && row.size()==2 && std::get<int64_t>(row[0])==22 && std::get<int64_t>(row[1])==11, "mapped values reach original SQL columns");
 ok(!session.reset(id) && !session.describe_parameter_positions(id, positions) && positions == std::vector<uint32_t>({2,1}), "metadata survives reset");
 check("SELECT $1,$1", {1}, "repeated name shares slot");
 check("SELECT $01,$1", {1,1}, "distinct names may share protocol position");
 check("SELECT $2", {2}, "protocol position may have holes");
 check("SELECT ?", {0}, "anonymous parameter unknown");
 check("SELECT ?1", {0}, "SQLite numbered parameter unknown");
 check("SELECT :name", {0}, "colon parameter unknown");
 check("SELECT @name", {0}, "at parameter unknown");
 check("SELECT $name", {0}, "nonnumeric dollar parameter unknown");
 check("SELECT 1", {}, "no parameters");
 for (const char* sql : {"SELECT $0", "SELECT $4294967296"}) {
  uint64_t n=0; auto e=session.prepare(sql,n); positions={99}; if (!e) e=session.describe_parameter_positions(n,positions);
  ok(e && (e->kind==ErrorKind::invalid_parameter || e->kind==ErrorKind::range) && positions.empty(), "invalid numeric position rejected");
  if(n) session.close(n);
 }
 check("SELECT $1::text", {0}, "native Tcl-style parameter names are not mistaken for numbered parameters");
 positions={99}; auto saved=proxy_sqlite3_bind_parameter_name; proxy_sqlite3_bind_parameter_name=nullptr;
 auto e=session.describe_parameter_positions(id,positions);
 ok(e && e->kind==ErrorKind::unsupported && positions.empty(), "missing optional capability clears output");
 check("SELECT 1", {}, "no parameters succeeds without optional capability");
 proxy_sqlite3_bind_parameter_name=saved;
 positions={99}; e=session.describe_parameter_positions(99999,positions);
 ok(e && positions.empty(), "unknown ID clears output");
 ok(!session.close(id), "close statement");
 positions={99}; e=session.describe_parameter_positions(id,positions);
 ok(e && positions.empty(), "closed ID clears output");
 Fake fake; Session other(fake,policy); uint64_t f=0; ok(!other.prepare("x",f), "prepare legacy adapter");
 ok(fake.executions == 0, "prepare does not execute");
 positions={99}; e=other.describe_parameter_positions(f,positions);
 ok(e && e->kind==ErrorKind::unsupported && positions.empty(), "legacy adapter defaults to unsupported");
 fake.mode=1; positions={99}; e=other.describe_parameter_positions(f,positions);
 ok(e && e->kind==ErrorKind::engine && positions.empty(), "metadata failure clears output");
 fake.mode=2; positions={99}; e=other.describe_parameter_positions(f,positions);
 ok(e && e->kind==ErrorKind::schema_changed && positions.empty(), "metadata count mismatch clears output");
 std::unique_ptr<Statement> owned; ok(!adapter.prepare("SELECT $1", owned), "prepare native handle");
 SQLiteAdapter other_adapter(db); positions={99}; e=other_adapter.describe_parameter_positions(*owned,positions);
 ok(e && positions.empty(), "wrong adapter owner rejected");
 adapter.finalize(std::move(owned));
 }
 ok(sqlite3_close(db) == SQLITE_OK, "all native handles finalized before closing connection");
 return exit_status();
}
