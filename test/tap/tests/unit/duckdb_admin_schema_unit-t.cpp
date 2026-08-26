#include "duckdb_admin_schema.h"
#include "duckdb_config.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

int main() {
	plan(10);

	SQLite3DB db;
	// SQLite3DB::open() forwards its flags to sqlite3_open_v2(), which
	// requires at least one of READONLY/READWRITE/CREATE; with flags=0
	// the database never opens. Assert the open succeeded before
	// proceeding, so a future regression fails loudly instead of running
	// every later assertion against a null handle.
	const int rc = db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(rc == 0, "in-memory sqlite db opens successfully");

	ok(db.execute(kDuckDBVariablesTableDef), "duckdb_variables DDL is valid SQLite");
	ok(db.execute(kRuntimeDuckDBVariablesTableDef),
	   "runtime_duckdb_variables DDL is valid SQLite");

	// --- admin table -> module ----------------------------------------
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('threads','8')");
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('database_path','/tmp/x.db')");

	DuckDBConfigStore store;
	std::string err;
	ok(duckdb_install_variables_from_admin(db, store, err), "install from admin succeeds");
	ok(store.threads() == 8, "threads was installed into the module");
	ok(store.database_path() == "/tmp/x.db", "database_path was installed into the module");

	// An unknown row must not abort the whole load, but must be reported.
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('nonsense','1')");
	err.clear();
	ok(duckdb_install_variables_from_admin(db, store, err) && !err.empty(),
	   "an unknown variable is skipped and reported, not fatal");

	// --- module -> admin table ----------------------------------------
	DuckDBConfigStore other;
	err.clear();
	ok(duckdb_save_variables_to_admin(db, other, err), "save to admin succeeds");
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT variable_value FROM duckdb_variables "
			                     "WHERE variable_name='threads'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "2",
		   "save overwrote the admin row with the module default");
	}

	// --- runtime view projection --------------------------------------
	db.execute("INSERT INTO runtime_duckdb_variables VALUES ('stale','stale')");
	duckdb_refresh_runtime_variables(&db, &other);
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT COUNT(*) FROM runtime_duckdb_variables "
			                     "WHERE variable_name='stale'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "0",
		   "refresh wipes stale rows before re-projecting");
	}

	return exit_status();
}
