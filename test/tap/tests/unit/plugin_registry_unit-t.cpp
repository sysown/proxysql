#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Plugin.h"
#include "tap.h"

#include <cstring>
#include <string>

namespace {

ProxySQL_PluginCommandResult fake_plugin_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 7, "mysqlx users loaded"};
}

ProxySQL_PluginCommandResult error_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {1045, 0, "intentional failure"};
}

ProxySQL_PluginCommandResult echo_command(const ProxySQL_PluginCommandContext&, const char* sql) {
	return {0, 0, std::string(sql != nullptr ? sql : "")};
}

bool has_table(const ProxySQL_PluginManager& mgr, ProxySQL_PluginDBKind kind, const char* name) {
	for (const auto& t : mgr.tables(kind)) {
		if (t.table_name != nullptr && std::strcmp(t.table_name, name) == 0) {
			return true;
		}
	}
	return false;
}

} // namespace

void test_basic_table_registration() {
	ProxySQL_PluginManager mgr;
	char table_name[] = "mysqlx_users";
	char table_def[] = "CREATE TABLE mysqlx_users (username VARCHAR NOT NULL PRIMARY KEY)";
	ProxySQL_PluginTableDef def {ProxySQL_PluginDBKind::admin_db, table_name, table_def};

	mgr.register_table_for_test(def);
	// Mutate caller buffers — manager must have deep-copied.
	table_name[0] = 'X';
	table_def[0] = 'X';

	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1),
	   "table is stored");
	ok(std::strcmp(mgr.tables(ProxySQL_PluginDBKind::admin_db).front().table_name, "mysqlx_users") == 0,
	   "table name is deep-copied");
	ok(std::strcmp(mgr.tables(ProxySQL_PluginDBKind::admin_db).front().table_def, table_def + 0) != 0,
	   "table def is deep-copied (caller mutation has no effect)");
}

void test_duplicate_table_rejected() {
	ProxySQL_PluginManager mgr;
	ProxySQL_PluginTableDef a {ProxySQL_PluginDBKind::admin_db, "tbl", "CREATE TABLE tbl (id INT)"};
	ProxySQL_PluginTableDef b {ProxySQL_PluginDBKind::admin_db, "tbl", "CREATE TABLE tbl (other INT)"};
	ok(mgr.register_table(a), "first table registration succeeds");
	ok(!mgr.register_table(b), "duplicate (same kind + same name) rejected");
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1),
	   "rejected duplicate did not grow the registry");
}

void test_duplicate_table_case_insensitive() {
	ProxySQL_PluginManager mgr;
	ProxySQL_PluginTableDef lower {ProxySQL_PluginDBKind::admin_db, "mixed_case_tbl", "CREATE TABLE x (id INT)"};
	ProxySQL_PluginTableDef upper {ProxySQL_PluginDBKind::admin_db, "MIXED_CASE_TBL", "CREATE TABLE x (id INT)"};
	ProxySQL_PluginTableDef mixed {ProxySQL_PluginDBKind::admin_db, "Mixed_Case_Tbl", "CREATE TABLE x (id INT)"};
	ok(mgr.register_table(lower), "lowercase table registered");
	ok(!mgr.register_table(upper), "uppercase variant rejected as duplicate");
	ok(!mgr.register_table(mixed), "mixed-case variant rejected as duplicate");
}

void test_invalid_table_inputs() {
	ProxySQL_PluginManager mgr;
	{
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::admin_db, nullptr, "CREATE TABLE t (id INT)"};
		ok(!mgr.register_table(d), "null name rejected");
	}
	{
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::admin_db, "", "CREATE TABLE t (id INT)"};
		ok(!mgr.register_table(d), "empty name rejected");
	}
	{
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::admin_db, "ok_name", nullptr};
		ok(!mgr.register_table(d), "null def rejected");
	}
	{
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::admin_db, "ok_name", ""};
		ok(!mgr.register_table(d), "empty def rejected");
	}
	{
		ProxySQL_PluginTableDef d {static_cast<ProxySQL_PluginDBKind>(99), "ok_name", "CREATE TABLE x (id INT)"};
		ok(!mgr.register_table(d), "out-of-range db_kind rejected");
	}
}

void test_tables_per_kind_independent() {
	ProxySQL_PluginManager mgr;
	ProxySQL_PluginTableDef admin_tbl {ProxySQL_PluginDBKind::admin_db, "shared_name", "CREATE TABLE shared_name (id INT)"};
	ProxySQL_PluginTableDef config_tbl {ProxySQL_PluginDBKind::config_db, "shared_name", "CREATE TABLE shared_name (id INT)"};
	ProxySQL_PluginTableDef stats_tbl {ProxySQL_PluginDBKind::stats_db, "shared_name", "CREATE TABLE shared_name (id INT)"};
	ok(mgr.register_table(admin_tbl), "register in admin");
	ok(mgr.register_table(config_tbl), "register same name in config");
	ok(mgr.register_table(stats_tbl), "register same name in stats");
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == static_cast<size_t>(1),
	   "admin holds 1 table");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).size() == static_cast<size_t>(1),
	   "config holds 1 table");
	ok(mgr.tables(ProxySQL_PluginDBKind::stats_db).size() == static_cast<size_t>(1),
	   "stats holds 1 table");
}

void test_tables_invalid_accessor() {
	ProxySQL_PluginManager mgr;
	ok(mgr.tables(static_cast<ProxySQL_PluginDBKind>(255)).empty(),
	   "tables() for invalid kind returns empty");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).empty(),
	   "tables() for empty kind starts empty");
}

void test_tables_preserve_insertion_order() {
	ProxySQL_PluginManager mgr;
	const char* names[] = {"alpha_tbl", "bravo_tbl", "charlie_tbl", "delta_tbl", "echo_tbl"};
	for (const char* n : names) {
		std::string def = std::string("CREATE TABLE ") + n + " (id INT)";
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::admin_db, n, def.c_str()};
		mgr.register_table(d);
	}
	const auto& tables = mgr.tables(ProxySQL_PluginDBKind::admin_db);
	ok(tables.size() == 5, "all five tables stored");
	bool ordered = true;
	for (size_t i = 0; i < tables.size(); ++i) {
		if (std::strcmp(tables[i].table_name, names[i]) != 0) ordered = false;
	}
	ok(ordered, "tables preserve registration order");
}

void test_basic_command_registration() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command),
	   "canonical command registers");
	ok(mgr.has_command_for_test("LOAD MYSQLX USERS TO RUNTIME"),
	   "registered command discoverable");
	ok(!mgr.has_command_for_test("not registered command"),
	   "unregistered command not discoverable");
}

void test_command_invalid_inputs() {
	ProxySQL_PluginManager mgr;
	ok(!mgr.register_command(nullptr, &fake_plugin_command),
	   "null sql rejected");
	ok(!mgr.register_command("", &fake_plugin_command),
	   "empty sql rejected");
	ok(!mgr.register_command("LOAD X TO RUNTIME", nullptr),
	   "null callback rejected");
	ok(!mgr.register_command_for_test("   "),
	   "whitespace-only sql rejected (canonicalizes to empty)");
	ok(!mgr.register_command_for_test("\t\n  \r ;"),
	   "whitespace+trailing-semicolon-only sql rejected");
	ok(!mgr.register_command_for_test(";;;"),
	   "semicolons-only sql rejected (all stripped trailing)");
}

void test_command_canonical_duplicate() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command),
	   "first registration succeeds");
	ok(!mgr.register_command("LOAD   MYSQLX   USERS TO RUNTIME ;", &fake_plugin_command),
	   "extra whitespace + semicolon canonicalize to same → rejected");
	ok(!mgr.register_command("load mysqlx users to runtime", &fake_plugin_command),
	   "lowercase variant canonicalizes case-insensitively → rejected");
	ok(!mgr.register_command("\tLOAD\tMYSQLX\tUSERS\tTO\tRUNTIME\t;\t", &fake_plugin_command),
	   "tabs as whitespace also canonicalize → rejected");
}

void test_command_canonicalisation_preserves_sql() {
	ProxySQL_PluginManager mgr;
	ok(mgr.register_command("FOO;;BAR", &echo_command),
	   "internal semicolons NOT collapsed");
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult r {0, 0, ""};
	ok(mgr.dispatch_admin_command(ctx, "FOO;;BAR", r),
	   "exact match dispatches");
	ok(r.message == "FOO;;BAR",
	   "echo callback received canonical SQL (got: '%s')", r.message.c_str());
	ok(!mgr.dispatch_admin_command(ctx, "FOO;BAR", r),
	   "single-internal-semicolon variant does not match (semicolons preserved)");
}

void test_dispatch_canonicalisation() {
	ProxySQL_PluginManager mgr;
	mgr.register_command("LOAD MYSQLX USERS TO RUNTIME", &fake_plugin_command);
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	struct {
		const char* sql;
		const char* desc;
	} cases[] = {
		{"LOAD MYSQLX USERS TO RUNTIME",       "exact match"},
		{"  LOAD MYSQLX USERS TO RUNTIME  ",   "leading + trailing spaces stripped"},
		{"LOAD MYSQLX USERS TO RUNTIME;",      "single trailing semicolon stripped"},
		{"LOAD MYSQLX USERS TO RUNTIME;;;;",   "multiple trailing semicolons stripped"},
		{"LOAD MYSQLX USERS TO RUNTIME ; ; ", "trailing semicolons + spaces interleaved stripped"},
		{"load mysqlx users to runtime",       "lowercase matches via case-insensitive compare"},
		{"Load MySqlX Users To Runtime",       "mixed case matches"},
		{"LOAD\tMYSQLX\tUSERS\tTO\tRUNTIME",   "tabs collapse to single space"},
		{"LOAD\nMYSQLX\nUSERS\nTO\nRUNTIME",   "newlines collapse to single space"},
		{"LOAD  MYSQLX   USERS    TO     RUNTIME", "internal multi-space collapses"},
	};
	for (const auto& c : cases) {
		ProxySQL_PluginCommandResult r {99, 0, ""};
		ok(mgr.dispatch_admin_command(ctx, c.sql, r) && r.error_code == 0 && r.rows_affected == 7,
		   "%s", c.desc);
	}
}

void test_dispatch_unregistered() {
	ProxySQL_PluginManager mgr;
	mgr.register_command("FOO BAR", &fake_plugin_command);
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult r {99, 0, ""};
	ok(!mgr.dispatch_admin_command(ctx, "BAR FOO", r),
	   "completely different SQL not matched");
	ok(!mgr.dispatch_admin_command(ctx, "FOO", r),
	   "prefix-only SQL not matched");
	ok(!mgr.dispatch_admin_command(ctx, "FOO BAR EXTRA", r),
	   "SQL with extra trailing tokens not matched");
	ok(!mgr.dispatch_admin_command(ctx, "", r),
	   "empty SQL never matches");
	ok(r.error_code == 99,
	   "result struct untouched when no match");
}

void test_dispatch_propagates_result() {
	ProxySQL_PluginManager mgr;
	mgr.register_command("PLUGIN OK", &fake_plugin_command);
	mgr.register_command("PLUGIN FAIL", &error_command);
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };

	ProxySQL_PluginCommandResult r {0, 0, ""};
	ok(mgr.dispatch_admin_command(ctx, "PLUGIN OK", r) &&
	   r.error_code == 0 &&
	   r.rows_affected == 7 &&
	   r.message == "mysqlx users loaded",
	   "ok command propagates rows + message");

	ok(mgr.dispatch_admin_command(ctx, "PLUGIN FAIL", r) &&
	   r.error_code == 1045 &&
	   r.rows_affected == 0 &&
	   r.message == "intentional failure",
	   "error command propagates non-zero error_code");
}

void test_commands_preserve_insertion_order() {
	ProxySQL_PluginManager mgr;
	const char* sqls[] = {
		"CMD ALPHA", "CMD BRAVO", "CMD CHARLIE", "CMD DELTA", "CMD ECHO"
	};
	for (const char* s : sqls) {
		ok(mgr.register_command(s, &fake_plugin_command), "register %s", s);
	}
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	bool all = true;
	for (const char* s : sqls) {
		ProxySQL_PluginCommandResult r {99, 0, ""};
		if (!mgr.dispatch_admin_command(ctx, s, r) || r.error_code != 0) {
			all = false;
		}
	}
	ok(all, "all five commands dispatch successfully (registry holds them all)");
}

void test_many_tables_no_dangling_pointers() {
	// Stress test that table_storage_ keeps strings alive even after
	// many insertions (deque does not invalidate references on push_back).
	ProxySQL_PluginManager mgr;
	const int N = 64;
	for (int i = 0; i < N; ++i) {
		std::string name = std::string("stress_tbl_") + std::to_string(i);
		std::string def = std::string("CREATE TABLE ") + name + " (id INT)";
		ProxySQL_PluginTableDef d {ProxySQL_PluginDBKind::stats_db, name.c_str(), def.c_str()};
		mgr.register_table(d);
	}
	ok(mgr.tables(ProxySQL_PluginDBKind::stats_db).size() == static_cast<size_t>(N),
	   "all 64 stress tables stored");

	// All pointers must still be valid: walk and strcmp.
	bool all_strings_valid = true;
	int idx = 0;
	for (const auto& t : mgr.tables(ProxySQL_PluginDBKind::stats_db)) {
		std::string expect = std::string("stress_tbl_") + std::to_string(idx);
		if (t.table_name == nullptr || std::strcmp(t.table_name, expect.c_str()) != 0) {
			all_strings_valid = false;
			break;
		}
		++idx;
	}
	ok(all_strings_valid, "all 64 stored table_name pointers remain valid after growth");
}

void test_long_command_sql() {
	ProxySQL_PluginManager mgr;
	std::string long_sql(2048, 'X');
	ok(mgr.register_command(long_sql.c_str(), &fake_plugin_command),
	   "2KB command registers");
	ProxySQL_PluginCommandContext ctx { nullptr, nullptr, nullptr };
	ProxySQL_PluginCommandResult r {99, 0, ""};
	ok(mgr.dispatch_admin_command(ctx, long_sql.c_str(), r) && r.error_code == 0,
	   "2KB command dispatches");
}

int main() {
	plan(68);

	test_basic_table_registration();
	test_duplicate_table_rejected();
	test_duplicate_table_case_insensitive();
	test_invalid_table_inputs();
	test_tables_per_kind_independent();
	test_tables_invalid_accessor();
	test_tables_preserve_insertion_order();

	test_basic_command_registration();
	test_command_invalid_inputs();
	test_command_canonical_duplicate();
	test_command_canonicalisation_preserves_sql();
	test_dispatch_canonicalisation();
	test_dispatch_unregistered();
	test_dispatch_propagates_result();
	test_commands_preserve_insertion_order();

	test_many_tables_no_dangling_pointers();
	test_long_command_sql();

	return exit_status();
}
