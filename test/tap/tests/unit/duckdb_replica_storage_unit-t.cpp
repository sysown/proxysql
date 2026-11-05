#include "duckdb_replica.h"
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb.h"
#include "tap.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>
// Exercise the built-in snapshot boundary directly, bypassing config validation.
DuckDBReplicaLoadResult duckdb_replica_load_snapshot(
	DuckDBEngine&, const DuckDBReplicaSource&, const std::vector<DuckDBReplicaTable>&,
	const DuckDBReplicaProbeResult&, const std::function<bool()>&,
	const std::function<void(void*)>&, const std::function<void(const std::string&, uint64_t)>&);

namespace {
std::string ident(const std::string& s) {
	std::string out = "\"";
	for (char c : s) {
		out += c;
		if (c == '"')
			out += c;
	}
	return out + '"';
}
std::string literal(const std::string& s) {
	std::string out = "'";
	for (char c : s) {
		out += c;
		if (c == '\'')
			out += c;
	}
	return out + '\'';
}
struct Store {
	std::string dir, path, catalog, error;
	DuckDBEngine engine;
	duckdb_connection conn = nullptr;
	explicit Store(const std::string& name) : catalog(name) {
		char pattern[] = "/tmp/proxysql-replica-storage-XXXXXX";
		char* created = mkdtemp(pattern);
		if (!created)
			BAIL_OUT("mkdtemp failed");
		dir = created;
		path = dir + "/" + name + ".duckdb";
		DuckDBConfigStore cfg;
		cfg.set("database_path", path, error);
		if (!engine.open(cfg, error) || !engine.connect(&conn, error))
			BAIL_OUT("storage fixture open failed: %s", error.c_str());
	}
	~Store() {
		engine.disconnect(&conn);
		engine.close();
		std::remove(path.c_str());
		std::remove((path + ".wal").c_str());
		rmdir(dir.c_str());
	}
	std::string name(const std::string& schema, const std::string& table) const {
		return ident(catalog) + "." + ident(schema) + "." + ident(table);
	}
	bool exec(const std::string& sql) {
		duckdb_result r;
		auto state = duckdb_query(conn, sql.c_str(), &r);
		if (state != DuckDBSuccess)
			error = duckdb_result_error(&r);
		duckdb_destroy_result(&r);
		return state == DuckDBSuccess;
	}
	void must(const std::string& sql) {
		if (!exec(sql))
			BAIL_OUT("fixture query failed: %s", error.c_str());
	}
	int count(const std::string& schema, const std::string& table) {
		duckdb_result r;
		const std::string sql =
			"SELECT COUNT(*) FROM system.information_schema.tables WHERE table_catalog=" +
			literal(catalog) + " AND table_schema=" + literal(schema) +
			" AND table_name=" + literal(table);
		if (duckdb_query(conn, sql.c_str(), &r) != DuckDBSuccess) {
			duckdb_destroy_result(&r);
			return -1;
		}
		int n = duckdb_value_int32(&r, 0, 0);
		duckdb_destroy_result(&r);
		return n;
	}
	void metadata(const std::vector<std::pair<std::string, std::string>>& tables) {
		must("CREATE SCHEMA " + ident(catalog) + ".proxysql_replica");
		must("CREATE TABLE " + name("proxysql_replica", "position") +
			 "(source_id VARCHAR,binlog_pos BIGINT)");
		must("INSERT INTO " + name("proxysql_replica", "position") + " VALUES('s',1234)");
		must("CREATE TABLE " + name("proxysql_replica", "tables") +
			 "(source_id VARCHAR,schema_name VARCHAR,table_name VARCHAR,primary_key VARCHAR)");
		for (const auto& table : tables)
			must("INSERT INTO " + name("proxysql_replica", "tables") + " VALUES('s'," +
				 literal(table.first) + "," + literal(table.second) + ",'id')");
	}
};
} // namespace
int main() {
	plan(NO_PLAN);
	{
		DuckDBEngine closed_engine;
		DuckDBReplicaTable table;
		table.schema_name = "ProxySQL_Replica";
		table.table_name = "tables";
		const auto result =
			duckdb_replica_load_snapshot(closed_engine, {}, {table}, {}, {}, {}, {});
		ok(result.code == DuckDBReplicaLoadResult::Code::failed &&
			   result.error.find("reserved") != std::string::npos,
		   "snapshot rejects mixed-case metadata schema before opening storage or source");
	}
	{
		Store s("app");
		s.must("CREATE SCHEMA app.app");
		DuckDBReplicaMappedColumn column;
		duckdb_replica_map_column("id", "int", "int", "", "PRI", false, column);
		s.must(duckdb_replica_create_table_sql("app", "events", {column}, "app"));
		s.must("CREATE TABLE app.app.child(id INT REFERENCES app.events(id))");
		s.must("DROP TABLE app.app.child");
		s.metadata({{"app", "events"}});
		const std::string error = duckdb_replica_drop_snapshot(s.engine);
		ok(error.empty() && s.count("app", "events") == 0,
		   "RESET qualifies a table when catalog and schema share the same name");
		ok(s.count("proxysql_replica", "position") == 0 &&
			   s.count("proxysql_replica", "tables") == 0,
		   "successful RESET removes both metadata tables");
	}
	{
		Store s("store");
		s.must("CREATE SCHEMA store.app");
		s.must("CREATE TABLE store.app.a(id INT PRIMARY KEY)");
		s.must("CREATE TABLE store.app.zparent(id INT PRIMARY KEY)");
		s.must("CREATE TABLE store.app.child(id INT REFERENCES app.zparent(id))");
		s.must("CREATE TABLE store.app.unrelated(id INT)");
		s.must("INSERT INTO store.app.unrelated VALUES(42)");
		s.metadata({{"app", "a"}, {"app", "zparent"}});
		const std::string error = duckdb_replica_drop_snapshot(s.engine);
		ok(!error.empty(),
		   "RESET reports an actual DROP failure caused by an unrelated foreign-key dependency");
		ok(s.count("app", "a") == 1 && s.count("app", "zparent") == 1,
		   "failed RESET rolls back earlier successful table drops");
		ok(s.count("proxysql_replica", "position") == 1 &&
			   s.count("proxysql_replica", "tables") == 1,
		   "failed RESET preserves checkpoint and ownership manifest");
		ok(s.count("app", "child") == 1 && s.count("app", "unrelated") == 1,
		   "failed RESET preserves unrelated tables");
		s.must("DROP TABLE store.app.child");
		const std::string retry = duckdb_replica_drop_snapshot(s.engine);
		ok(retry.empty() && s.count("app", "a") == 0 && s.count("app", "zparent") == 0,
		   "RESET removes tables recorded in the persisted ownership manifest");
		ok(s.count("app", "unrelated") == 1,
		   "successful RESET preserves a configured inactive table that was never replicated");
		ok(duckdb_replica_drop_snapshot(s.engine).empty(),
		   "RESET is idempotent after successful cleanup");
	}
	{
		Store s("proxysql_replica");
		s.must("CREATE SCHEMA proxysql_replica.app");
		s.must("CREATE TABLE proxysql_replica.app.events(id INT)");
		s.metadata({{"app", "events"}});
		const std::string error = duckdb_replica_drop_snapshot(s.engine);
		ok(error.empty() && s.count("app", "events") == 0 &&
			   s.count("proxysql_replica", "position") == 0 &&
			   s.count("proxysql_replica", "tables") == 0,
		   "RESET qualifies metadata even when the catalog is named proxysql_replica");
	}
	{
		Store s("odd\"catalog");
		s.must("CREATE SCHEMA " + ident(s.catalog) + "." + ident("odd\"schema"));
		s.must("CREATE TABLE " + s.name("odd\"schema", "odd\"table") + "(id INT)");
		s.metadata({{"odd\"schema", "odd\"table"}});
		const std::string error = duckdb_replica_drop_snapshot(s.engine);
		ok(error.empty() && s.count("odd\"schema", "odd\"table") == 0,
		   "RESET safely quotes catalog, schema and table identifiers");
	}
	{
		Store s("fresh");
		ok(duckdb_replica_drop_snapshot(s.engine).empty(),
		   "RESET before snapshot tolerates missing metadata and schemas");
	}
	{
		Store s("information_schema");
		s.must("CREATE SCHEMA information_schema.app");
		s.must("CREATE TABLE information_schema.app.events(id INT)");
		s.metadata({{"app", "events"}});
		ok(duckdb_replica_drop_snapshot(s.engine).empty() && s.count("app", "events") == 0,
		   "RESET metadata inspection is unambiguous for an information_schema catalog");
	}
	{
		Store s("missing");
		s.metadata({{"absent", "gone"}});
		ok(duckdb_replica_drop_snapshot(s.engine).empty() &&
			   s.count("proxysql_replica", "position") == 0,
		   "RESET tolerates an already-missing manifest-owned schema and table");
	}
	{
		Store s("unowned");
		s.must("CREATE TABLE unowned.main.local_table(id INT)");
		ok(duckdb_replica_drop_snapshot(s.engine).empty() && s.count("main", "local_table") == 1,
		   "RESET before snapshot preserves tables absent from the ownership manifest");
	}
	return exit_status();
}
