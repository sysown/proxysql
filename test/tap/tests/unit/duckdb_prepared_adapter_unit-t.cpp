#include "duckdb_prepared_adapter.h"
#include "tap.h"
#include <iostream>
#include <limits>
using namespace embedded;
static void check(bool b,const char* name) { ok(b, "%s", name); }
static bool query(duckdb_connection c,const char* sql) { duckdb_result r{}; auto rc=duckdb_query(c,sql,&r); if(rc!=DuckDBSuccess) std::cerr<<duckdb_result_error(&r)<<"\n"; duckdb_destroy_result(&r); return rc==DuckDBSuccess; }
int main() {
 plan(NO_PLAN);
 duckdb_database db; duckdb_connection c; if(duckdb_open(nullptr,&db)!=DuckDBSuccess || duckdb_connect(db,&c)!=DuckDBSuccess) return 1;
 {
 DuckDBAdapter a(c); std::unique_ptr<Statement> s; std::vector<Column> cols; std::vector<Type> params; ExecInfo info; Row row; bool done=false;
 std::vector<uint32_t> positions; Adapter& base=a;
 check(!a.prepare("SELECT $2::BIGINT AS second, $1::BIGINT AS first",s),"prepare reversed numbered parameters");
 check(!base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({1,2}),"native numbered positions follow bind slots");
 std::vector<Value> client{int64_t(11),int64_t(22)}, native;
 for (auto pos:positions) if (pos && pos<=client.size()) native.push_back(client[pos-1]);
 check(!a.bind(*s,native) && !a.execute(*s,info) && !a.fetch(*s,row,done,16) && std::get<int64_t>(row[0])==22 && std::get<int64_t>(row[1])==11,"positions map client bindings to reversed output");
 check(!a.reset(*s) && !base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({1,2}),"reset retains positions");
 DuckDBAdapter other(c); positions={99}; check(bool(other.describe_parameter_positions(*s,positions)) && positions.empty(),"foreign owner clears positions");
 struct Foreign final : Statement {} foreign; positions={99}; check(bool(base.describe_parameter_positions(foreign,positions)) && positions.empty(),"foreign handle clears positions");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT $1::BIGINT, $1::BIGINT",s) && !base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({1}),"repeated numbered parameter shares slot"); a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::BIGINT",s) && !base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({1}),"anonymous parameter engine name"); a.finalize(std::move(s));
 check(!a.prepare("SELECT $foo::BIGINT",s) && !base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({0}),"named parameter is unknown position"); a.finalize(std::move(s));
 check(!a.prepare("SELECT $001::BIGINT",s) && !base.describe_parameter_positions(*s,positions) && positions==std::vector<uint32_t>({1}),"leading zero normalized by engine"); a.finalize(std::move(s));
 check(!a.prepare("SELECT 1::BIGINT",s) && !base.describe_parameter_positions(*s,positions) && positions.empty(),"zero parameters"); a.finalize(std::move(s));
 check(query(c,"CREATE SEQUENCE metadata_probe START 1") && !a.prepare("SELECT nextval('metadata_probe')::BIGINT, $1::BIGINT",s) && !base.describe_parameter_positions(*s,positions),"describe side effect fixture");
 duckdb_result probe{}; auto probe_rc=duckdb_query(c,"SELECT nextval('metadata_probe')",&probe);
 check(probe_rc==DuckDBSuccess && duckdb_value_int64(&probe,0,0)==1,"describing positions does not execute"); duckdb_destroy_result(&probe); a.finalize(std::move(s));
 check(bool(a.prepare("SELECT $0::BIGINT",s)),"zero parameter rejected by engine");
 check(!a.prepare("SELECT $4294967296::BIGINT",s) && (positions={99}, bool(base.describe_parameter_positions(*s,positions))) && positions.empty(),"unavailable oversized parameter metadata rejected"); a.finalize(std::move(s));
 check(!a.prepare("SELECT CAST(? AS BIGINT) AS x",s),"prepare select");
 check(!a.describe_parameters(*s,params) && params.size()==1 && params[0].kind==TypeKind::signed_integer,"parameter metadata");
 check(!a.describe_result(*s,cols) && cols.size()==1 && cols[0].name=="x" && cols[0].type.kind==TypeKind::signed_integer,"owned result metadata");
 check(bool(a.bind(*s,{})),"arity rejected");
 check(!a.bind(*s,{int64_t(42)}),"bind integer");
 check(!a.execute(*s,info) && info.has_result,"execute integer select");
 check(bool(a.fetch(*s,row,done,7)) && row.empty(),"row budget checked");
 check(!a.fetch(*s,row,done,8) && !done && std::get<int64_t>(row[0])==42,"fetch after budget rejection");
 check(!a.fetch(*s,row,done,8) && done && row.empty(),"EOF");
 check(!a.reset(*s) && !a.bind(*s,{int64_t(-7)}) && !a.execute(*s,info) && !a.fetch(*s,row,done,8) && std::get<int64_t>(row[0])==-7,"reset and rebind");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::VARCHAR, ?::BLOB, ?::VARCHAR, ?::BLOB, ?::VARCHAR",s),"prepare text and blob");
 Text t{std::string("a\0b",3)}; Bytes b{{0,1,255}};
 check(!a.bind(*s,{t,b,Text{""},Bytes{},std::monostate{}}),"bind text, blob and NULL");
 check(!a.execute(*s,info),"execute text and blob select");
 check(!a.fetch(*s,row,done,6) && std::get<Text>(row[0]).bytes==t.bytes && std::get<Bytes>(row[1]).bytes==b.bytes && std::get<Text>(row[2]).bytes.empty() && std::get<Bytes>(row[3]).bytes.empty() && std::holds_alternative<std::monostate>(row[4]),"NUL, empty, blob and NULL round trip");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::UBIGINT, ?::DECIMAL(38,4)",s),"prepare unsigned and decimal");
 check(!a.describe_result(*s,cols) && cols[1].type.precision==38 && cols[1].type.scale==4,"decimal metadata");
 check(!a.bind(*s,{std::numeric_limits<uint64_t>::max(),Decimal{"-1234567890123456789012345678901234.1200"}}),"bind uint64 max and decimal");
 check(!a.execute(*s,info),"execute unsigned and decimal select");
 check(!a.fetch(*s,row,done,100) && std::get<uint64_t>(row[0])==std::numeric_limits<uint64_t>::max() && std::get<Decimal>(row[1]).exact=="-1234567890123456789012345678901234.1200","uint64 max and 38-digit decimal exactness");
 check(!a.reset(*s) && bool(a.bind(*s,{uint64_t(1),Decimal{"1.2.3"}})) && !a.bind(*s,{uint64_t(1),Decimal{"0.0100"}}) && !a.execute(*s,info) && !a.fetch(*s,row,done,100) && std::get<Decimal>(row[1]).exact=="0.0100","invalid decimal recovery");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::DECIMAL(4,4), ?::DECIMAL(4,4), ?::DECIMAL(4,4)",s),"prepare fractional decimals");
 check(!a.bind(*s,{Decimal{"0.1234"},Decimal{"-0.1234"},Decimal{"0000.0001"}}),"bind fractional decimals");
 check(!a.execute(*s,info),"execute fractional decimals");
 check(!a.fetch(*s,row,done,100) && std::get<Decimal>(row[0]).exact=="0.1234" && std::get<Decimal>(row[1]).exact=="-0.1234" && std::get<Decimal>(row[2]).exact=="0.0001","decimal fractional precision ignores leading zeroes");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::DECIMAL(4,4), ?::DECIMAL(4,4), ?::DECIMAL(4,4), ?::DECIMAL(4,4), ?::DECIMAL(4,4)",s),"prepare fractional zero and boundaries");
 check(!a.bind(*s,{Decimal{"0"},Decimal{"-0"},Decimal{"0.0000"},Decimal{"0.0001"},Decimal{"-0.9999"}}),"bind fractional zero and boundaries");
 check(!a.execute(*s,info),"execute fractional zero and boundaries");
 check(!a.fetch(*s,row,done,100) && std::get<Decimal>(row[0]).exact=="0.0000" && std::get<Decimal>(row[1]).exact=="0.0000" && std::get<Decimal>(row[2]).exact=="0.0000" && std::get<Decimal>(row[3]).exact=="0.0001" && std::get<Decimal>(row[4]).exact=="-0.9999","fractional zero preserves fixed scale");
 check(!a.reset(*s) && bool(a.bind(*s,{Decimal{"0"},Decimal{"-0"},Decimal{"0.0000"},Decimal{"0.0001"},Decimal{"1"}})),"fractional overflow refused");
 check(!a.reset(*s) && bool(a.bind(*s,{Decimal{"0"},Decimal{"-0"},Decimal{"0.0000"},Decimal{"0.0001"},Decimal{"-1"}})),"negative fractional overflow refused");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT ?::TINYINT",s) && !a.bind(*s,{int64_t(1000)}) && bool(a.execute(*s,info)) && !a.reset(*s) && !a.bind(*s,{int64_t(7)}) && !a.execute(*s,info) && !a.fetch(*s,row,done,8) && std::get<int64_t>(row[0])==7,"execution failure reset and recovery");
 a.finalize(std::move(s));
 check(bool(a.prepare("SELECT 1::HUGEINT",s)) && !s,"hugeint rejected");
 check(bool(a.prepare("SELECT current_date",s)) && !s,"temporal rejected");
 check(bool(a.prepare("SELECT true",s)) && !s,"boolean rejected");
 check(bool(a.prepare("SELECT [1,2]",s)) && !s,"nested type rejected");
 check(bool(a.prepare("SELECT ?",s)) && !s,"unresolved result rejected");
 check(bool(a.prepare("SELECT 1; SELECT 2",s)) && !s,"multiple statements rejected");
 check(bool(a.prepare(std::string("SELECT 1\0; SELECT 2",19),s)) && !s,"embedded SQL NUL rejected");
 check(query(c,"CREATE TABLE test_write(i INTEGER)"),"fixture table");
 check(bool(a.prepare("INSERT INTO test_write VALUES (1) RETURNING i",s)) && !s,"write returning rejected before execution");
 check(!a.prepare("SELECT count(*) FROM test_write",s) && !a.bind(*s,{}) && !a.execute(*s,info) && !a.fetch(*s,row,done,8) && std::get<int64_t>(row[0])==0,"rejected write did not mutate");
 a.finalize(std::move(s));
 check(query(c,"BEGIN") && query(c,"INSERT INTO test_write VALUES (2)"),"owner transaction setup");
 check(bool(a.prepare("COMMIT",s)) && !a.prepare("SELECT count(*) FROM test_write",s) && !a.bind(*s,{}) && !a.execute(*s,info) && !a.fetch(*s,row,done,8) && std::get<int64_t>(row[0])==1,"owner transaction visible and adapter commit refused");
 a.finalize(std::move(s)); check(query(c,"ROLLBACK"),"owner rollback");
 check(!a.prepare("SELECT count(*) FROM test_write",s) && !a.bind(*s,{}) && !a.execute(*s,info) && !a.fetch(*s,row,done,8) && std::get<int64_t>(row[0])==0,"rollback remains effective");
 a.finalize(std::move(s));
 check(!a.prepare("SELECT * FROM test_write",s) && query(c,"ALTER TABLE test_write ADD COLUMN j INTEGER") && !a.bind(*s,{}) && bool(a.execute(*s,info)) && bool(a.fetch(*s,row,done,100)),"schema change rejected before fetch");
 }
 duckdb_disconnect(&c); duckdb_close(&db); return exit_status();
}
