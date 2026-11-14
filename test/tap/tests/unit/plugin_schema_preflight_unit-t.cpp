/**
 * @file plugin_schema_preflight_unit-t.cpp
 * @brief Focused tests for the generic persistent plugin schema preflight.
 *
 * The preflight runs before any core schema upgrade or materialization. It
 * must accept fresh/current registered tables, reject every other existing
 * object fail-closed, and never mutate data while rejecting a late mismatch.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"

#include <cstring>
#include <string>

namespace {

void open_memory(SQLite3DB& db) {
	db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
}

std::string stored_sql(SQLite3DB& db, const char* table_name) {
	sqlite3_stmt* statement = nullptr;
	const char* query = "SELECT sql FROM sqlite_master WHERE name = ?1 COLLATE NOCASE";
	if ((*proxy_sqlite3_prepare_v2)(db.get_db(), query, -1, &statement, nullptr) != SQLITE_OK) {
		return {};
	}
	(*proxy_sqlite3_bind_text)(statement, 1, table_name, -1, SQLITE_TRANSIENT);
	std::string result;
	if ((*proxy_sqlite3_step)(statement) == SQLITE_ROW) {
		const unsigned char* text = (*proxy_sqlite3_column_text)(statement, 0);
		const int bytes = (*proxy_sqlite3_column_bytes)(statement, 0);
		if (text != nullptr && bytes > 0) {
			result.assign(reinterpret_cast<const char*>(text), static_cast<size_t>(bytes));
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	return result;
}

int failing_prepare(sqlite3*, const char*, int, sqlite3_stmt** statement, const char**) {
	if (statement != nullptr) *statement = nullptr;
	return SQLITE_ERROR;
}

std::string metadata_snapshot(SQLite3DB& db) {
	sqlite3_stmt* statement = nullptr;
	const char* query =
		"SELECT typeof(type), type, typeof(name), name,"
		" typeof(tbl_name), tbl_name, typeof(sql), sql"
		" FROM sqlite_master ORDER BY rowid";
	if ((*proxy_sqlite3_prepare_v2)(db.get_db(), query, -1, &statement, nullptr) != SQLITE_OK) {
		return {};
	}
	std::string result;
	while ((*proxy_sqlite3_step)(statement) == SQLITE_ROW) {
		for (int column = 0; column < 8; ++column) {
			const unsigned char* text = (*proxy_sqlite3_column_text)(statement, column);
			const int bytes = (*proxy_sqlite3_column_bytes)(statement, column);
			const int marker = text == nullptr ? -1 : bytes;
			result.append(reinterpret_cast<const char*>(&marker), sizeof(marker));
			if (text != nullptr && bytes > 0) {
				result.append(reinterpret_cast<const char*>(text), static_cast<size_t>(bytes));
			}
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	return result;
}

bool write_metadata(SQLite3DB& db, const char* sql, const void* value, int bytes, bool as_blob) {
	sqlite3_stmt* statement = nullptr;
	if ((*proxy_sqlite3_prepare_v2)(db.get_db(), sql, -1, &statement, nullptr) != SQLITE_OK) {
		return false;
	}
	const int bind_rc = as_blob
		? (*proxy_sqlite3_bind_blob)(statement, 1, value, bytes, SQLITE_TRANSIENT)
		: (*proxy_sqlite3_bind_text)(statement, 1, static_cast<const char*>(value), bytes, SQLITE_TRANSIENT);
	const int step_rc = bind_rc == SQLITE_OK ? (*proxy_sqlite3_step)(statement) : bind_rc;
	(*proxy_sqlite3_finalize)(statement);
	return bind_rc == SQLITE_OK && step_rc == SQLITE_DONE;
}

void register_config_table(ProxySQL_PluginManager& manager, const char* name, const char* ddl) {
	manager.register_table_for_test({ProxySQL_PluginDBKind::config_db, name, ddl});
}

} // namespace

int main() {
	plan(51);
	test_init_minimal();

	const char* current_ddl =
		"CREATE TABLE p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')";

	{
		// A fresh database has no sqlite_master row: accepted, to be created later.
		SQLite3DB db;
		open_memory(db);
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(manager.preflight_config_schemas(&db, error),
		   "fresh registered table is accepted without creating it");
	}

	{
		// Canonicalization must strip IF NOT EXISTS exactly like
		// SQLite3DB::check_table_structure().
		SQLite3DB db;
		open_memory(db);
		db.execute("CREATE TABLE p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current",
			"CREATE TABLE IF NOT EXISTS p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')");
		std::string error;
		ok(manager.preflight_config_schemas(&db, error),
		   "IF NOT EXISTS registration accepts the canonical stored definition");
	}

	{
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (7, 'kept')");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(manager.preflight_config_schemas(&db, error),
		   "exact canonical current definition is accepted");
	}

	{
		SQLite3DB db;
		open_memory(db);
		db.execute("CREATE TABLE p_current ( id INTEGER PRIMARY KEY, unexpected TEXT )");
		db.execute("INSERT INTO p_current(id, unexpected) VALUES (8, 'must-survive')");
		const std::string before = stored_sql(db, "p_current");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		const bool accepted = manager.preflight_config_schemas(&db, error);
		ok(!accepted, "a mismatching existing table is rejected");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_current") == 1 &&
		   db.return_one_int("SELECT COUNT(*) FROM p_current WHERE id=8 AND unexpected='must-survive'") == 1,
		   "rejection preserves existing plugin rows");
		ok(stored_sql(db, "p_current") == before,
		   "rejection preserves the existing plugin schema");
		ok(error.find("p_current") != std::string::npos,
		   "diagnostic names the mismatching table");
		ok(error.find("offline schema-migration tool") != std::string::npos,
		   "diagnostic names the required offline migration tool");
	}

	{
		// A late mismatch must be detected read-only, after an earlier matching
		// definition was inspected and before any builder could recreate it.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (7, 'earlier')");
		db.execute("CREATE TABLE p_late ( id INTEGER PRIMARY KEY, old_layout TEXT )");
		db.execute("INSERT INTO p_late(id, old_layout) VALUES (9, 'later')");
		const std::string current_before = stored_sql(db, "p_current");
		const std::string late_before = stored_sql(db, "p_late");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		register_config_table(manager, "p_late", "CREATE TABLE p_late ( id INTEGER PRIMARY KEY, new_layout TEXT )");
		std::string error;
		ok(!manager.preflight_config_schemas(&db, error),
		   "a late registered mismatch still fails the whole preflight");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_current WHERE id=7 AND note='earlier'") == 1,
		   "earlier matching plugin rows are untouched");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_late WHERE id=9 AND old_layout='later'") == 1,
		   "later mismatching plugin rows are untouched");
		ok(stored_sql(db, "p_current") == current_before,
		   "earlier matching plugin schema is untouched");
		ok(stored_sql(db, "p_late") == late_before,
		   "later mismatching plugin schema is untouched");
	}

	{
		SQLite3DB db;
		open_memory(db);
		db.execute("CREATE VIEW p_current AS SELECT 1 AS id");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(!manager.preflight_config_schemas(&db, error),
		   "a VIEW with a registered table name is refused instead of being treated as missing");
		ok(error.find("view") != std::string::npos,
		   "VIEW diagnostic names the unexpected object type");
		ok(error.find("offline schema-migration tool") != std::string::npos,
		   "VIEW diagnostic is actionable");
	}

	{
		// Stored DDL can be damaged by a partial write or tooling. It must be
		// reported as a mismatch, never treated as a missing/fresh table.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("PRAGMA writable_schema=ON");
		db.execute("UPDATE sqlite_master SET sql='CREATE TABLE p_current (broken' WHERE name='p_current'");
		db.execute("PRAGMA writable_schema=OFF");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(!manager.preflight_config_schemas(&db, error) &&
		   error.find("schema mismatch") != std::string::npos,
		   "malformed stored DDL fails closed as a schema mismatch");
	}

	{
		// A stored definition equal to the registered DDL followed by a NUL
		// and garbage is readable through sqlite3_column_text() as a prefix
		// match, but the exact builder comparison rejects it. The guard must
		// use the complete TEXT byte length and preserve the table/row.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (7, 'nul-survivor')");
		std::string corrupted(current_ddl);
		corrupted.push_back('\0');
		corrupted += "garbage";
		db.execute("PRAGMA writable_schema=ON");
		sqlite3_stmt* update = nullptr;
		ok((*proxy_sqlite3_prepare_v2)(db.get_db(),
			"UPDATE sqlite_master SET sql=?1 WHERE name='p_current'", -1, &update, nullptr) == SQLITE_OK,
		   "NUL-suffix fixture prepares its writable_schema update");
		ok((*proxy_sqlite3_bind_text)(update, 1, corrupted.data(),
			static_cast<int>(corrupted.size()), SQLITE_TRANSIENT) == SQLITE_OK &&
		   (*proxy_sqlite3_step)(update) == SQLITE_DONE,
		   "NUL-suffix fixture stores the complete corrupted SQL text");
		(*proxy_sqlite3_finalize)(update);
		db.execute("PRAGMA writable_schema=OFF");
		const std::string schema_before = stored_sql(db, "p_current");
		const int builder_count = db.check_table_structure("p_current", current_ddl);
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		const bool accepted = manager.preflight_config_schemas(&db, error);
		ok(schema_before.size() > std::strlen(current_ddl) &&
		   builder_count == 0,
		   "NUL-suffix stored SQL is readable and rejected by the exact builder");
		ok(!accepted && error.find("embedded NUL") != std::string::npos,
		   "preflight rejects an embedded-NUL stored definition");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_current WHERE id=7 AND note='nul-survivor'") == 1,
		   "embedded-NUL refusal preserves the actual table row");
		ok(stored_sql(db, "p_current") == schema_before,
		   "embedded-NUL refusal preserves the stored schema bytes");
	}

	{
		// sqlite_master.sql may be stored as BLOB with bytes identical to the
		// canonical DDL. SQLite still resolves the table, but the builder's
		// sql=?TEXT comparison does not. The guard must check storage class.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (21, 'sql-blob-survivor')");
		db.execute("PRAGMA writable_schema=ON");
		const bool wrote = write_metadata(db,
			"UPDATE sqlite_master SET sql=?1 WHERE name='p_current'",
			current_ddl, static_cast<int>(std::strlen(current_ddl)), true);
		db.execute("PRAGMA writable_schema=OFF");
		const std::string before = metadata_snapshot(db);
		const int builder_count = db.check_table_structure("p_current", current_ddl);
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		const bool accepted = manager.preflight_config_schemas(&db, error);
		ok(wrote && builder_count == 0 && !accepted &&
		   error.find("non-TEXT stored DDL") != std::string::npos,
		   "BLOB stored SQL with identical bytes is refused before rebuild");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_current WHERE id=21 AND note='sql-blob-survivor'") == 1,
		   "BLOB stored SQL refusal preserves the saved row");
		ok(metadata_snapshot(db) == before,
		   "BLOB stored SQL refusal preserves schema bytes and storage types");
	}

	{
		// SQLite resolves an uppercase sqlite_master.name, but the builder's
		// exact name=? comparison does not. Case-only name metadata must fail.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (22, 'namecase-survivor')");
		db.execute("PRAGMA writable_schema=ON");
		const bool wrote = write_metadata(db,
			"UPDATE sqlite_master SET name=?1, tbl_name=?1 WHERE name='p_current'",
			"P_CURRENT", static_cast<int>(std::strlen("P_CURRENT")), false);
		db.execute("PRAGMA writable_schema=OFF");
		const std::string before = metadata_snapshot(db);
		const int builder_count = db.check_table_structure("p_current", current_ddl);
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		const bool accepted = manager.preflight_config_schemas(&db, error);
		ok(wrote && builder_count == 0 && !accepted &&
		   error.find("differs in case or bytes") != std::string::npos,
		   "case-only sqlite_master.name is refused despite NOCASE discovery");
		ok(db.return_one_int("SELECT COUNT(*) FROM \"P_CURRENT\" WHERE id=22 AND note='namecase-survivor'") == 1,
		   "case-only name refusal preserves the saved row");
		ok(metadata_snapshot(db) == before,
		   "case-only name refusal preserves metadata bytes and storage types");
	}

	{
		// Broad metadata scan: BLOB/NUL type and name aliases outside the exact
		// registered lookup must not evade the builder-equivalence check.
		struct alias_case_t {
			const char* label;
			const char* sql;
			std::string value;
			bool as_blob;
			const char* diagnostic;
		};
		std::string nul_name = "p_current";
		nul_name.push_back('\0');
		nul_name += "tail";
		std::string nul_type = "table";
		nul_type.push_back('\0');
		nul_type += "tail";
		const alias_case_t aliases[] = {
			{"BLOB name metadata",
				"UPDATE sqlite_master SET name=?1 WHERE name='p_current'",
				"p_current", true, "non-TEXT"},
			{"NUL-suffixed name metadata",
				"UPDATE sqlite_master SET name=?1 WHERE name='p_current'",
				nul_name, false, "embedded NUL"},
			{"BLOB type metadata",
				"UPDATE sqlite_master SET type=?1 WHERE name='p_current'",
				"table", true, "non-TEXT"},
			{"NUL-suffixed type metadata",
				"UPDATE sqlite_master SET type=?1 WHERE name='p_current'",
				nul_type, false, "embedded NUL"},
		};
		for (const alias_case_t& alias : aliases) {
			SQLite3DB db;
			open_memory(db);
			db.execute(current_ddl);
			db.execute("INSERT INTO p_current(id, note) VALUES (23, 'alias-survivor')");
			db.execute("PRAGMA writable_schema=ON");
			const bool wrote = write_metadata(db, alias.sql, alias.value.data(),
				static_cast<int>(alias.value.size()), alias.as_blob);
			db.execute("PRAGMA writable_schema=OFF");
			const std::string before = metadata_snapshot(db);
			ProxySQL_PluginManager manager;
			register_config_table(manager, "p_current", current_ddl);
			std::string error;
			const bool accepted = manager.preflight_config_schemas(&db, error);
			ok(wrote && !accepted &&
			   error.find(alias.diagnostic) != std::string::npos,
			   "%s is refused by the metadata scan", alias.label);
			ok(metadata_snapshot(db) == before,
			   "%s refusal preserves metadata bytes and storage types", alias.label);
		}
	}

	{
		// Preflight and the real builder must agree for every leading-keyword
		// canonicalization variant; body/identifier differences must fail both.
		struct variant_t {
			const char* label;
			const char* ddl;
			bool expected;
		};
		const variant_t variants[] = {
			{"exact definition", current_ddl, true},
			{"IF NOT EXISTS registration",
				"CREATE TABLE IF NOT EXISTS p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')",
				true},
			{"mixed keyword case and whitespace",
				"cReAtE\n\tTaBlE  p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')",
				true},
			{"leading whitespace and mixed case",
				"\n\t cReAtE  TABLE p_current ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')",
				true},
			{"body mismatch",
				"CREATE TABLE p_current ( id INTEGER PRIMARY KEY, extra TEXT )",
				false},
			{"identifier mismatch",
				"CREATE TABLE p_other ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')",
				false},
		};
		for (const variant_t& variant : variants) {
			SQLite3DB db;
			open_memory(db);
			db.execute(current_ddl);
			ProxySQL_PluginManager manager;
			register_config_table(manager, "p_current", variant.ddl);
			std::string error;
			const bool accepted = manager.preflight_config_schemas(&db, error);
			const bool builder_accepts = db.check_table_structure("p_current", variant.ddl) != 0;
			ok(builder_accepts == variant.expected && accepted == variant.expected,
			   "preflight matches builder for %s", variant.label);
		}
	}

	{
		// Inject a metadata-query prepare failure. The guard must fail closed
		// with an actionable table diagnostic and leave rows untouched.
		SQLite3DB db;
		open_memory(db);
		db.execute(current_ddl);
		db.execute("INSERT INTO p_current(id, note) VALUES (12, 'query-error-survivor')");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		auto saved_prepare = proxy_sqlite3_prepare_v2;
		proxy_sqlite3_prepare_v2 = &failing_prepare;
		std::string error;
		const bool accepted = manager.preflight_config_schemas(&db, error);
		proxy_sqlite3_prepare_v2 = saved_prepare;
		ok(!accepted, "metadata-query prepare failure fails closed");
		ok(error.find("sqlite_master") != std::string::npos &&
		   error.find("offline schema-migration tool") != std::string::npos,
		   "metadata-query failure diagnostic names sqlite_master and migration tool");
		ok(db.return_one_int("SELECT COUNT(*) FROM p_current WHERE id=12 AND note='query-error-survivor'") == 1,
		   "metadata-query failure preserves rows");
	}

	{
		// A matching table row with sql NULL must be rejected, not treated as
		// a fresh/missing table.
		SQLite3DB db;
		open_memory(db);
		db.execute("PRAGMA writable_schema=ON");
		sqlite3_stmt* insert = nullptr;
		const int prepared = (*proxy_sqlite3_prepare_v2)(db.get_db(),
			"INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql)"
			" VALUES('table','p_current','p_current',0,NULL)", -1, &insert, nullptr);
		const int inserted = prepared == SQLITE_OK ? (*proxy_sqlite3_step)(insert) : prepared;
		(*proxy_sqlite3_finalize)(insert);
		db.execute("PRAGMA writable_schema=OFF");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(prepared == SQLITE_OK && inserted == SQLITE_DONE &&
		   !manager.preflight_config_schemas(&db, error) &&
		   error.find("without readable stored DDL") != std::string::npos,
		   "NULL stored SQL for a registered table fails closed");
	}

	{
		SQLite3DB db;
		open_memory(db);
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		db.quarantine();
		std::string error;
		ok(!manager.preflight_config_schemas(&db, error),
		   "an unavailable/closed config_db connection fails closed");
		ok(!error.empty() && error.find("config_db") != std::string::npos,
		   "unavailable connection diagnostic identifies config_db");
	}

	{
		// Only config_db registrations participate in the config_db preflight.
		SQLite3DB db;
		open_memory(db);
		db.execute("CREATE TABLE p_admin ( id INTEGER PRIMARY KEY, old_layout TEXT )");
		ProxySQL_PluginManager manager;
		manager.register_table_for_test({ProxySQL_PluginDBKind::admin_db, "p_admin",
			"CREATE TABLE p_admin ( id INTEGER PRIMARY KEY, new_layout TEXT )"});
		std::string error;
		ok(manager.preflight_config_schemas(&db, error),
		   "non-config_db plugin tables are outside the config_db preflight");
	}

	{
		// Registered names are matched case-insensitively. An uppercase object
		// with different stored name bytes must be rejected, not ignored as a
		// fresh table (DROP TABLE would otherwise destroy it).
		SQLite3DB db;
		open_memory(db);
		db.execute("CREATE TABLE P_CURRENT ( id INTEGER PRIMARY KEY CHECK(id >= 0), note TEXT NOT NULL DEFAULT '')");
		db.execute("INSERT INTO P_CURRENT(id, note) VALUES (11, 'case')");
		ProxySQL_PluginManager manager;
		register_config_table(manager, "p_current", current_ddl);
		std::string error;
		ok(!manager.preflight_config_schemas(&db, error),
		   "case-different existing object is inspected and rejected");
	}

	test_cleanup_minimal();
	return exit_status();
}
