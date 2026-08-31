// test_duckdb_admin_tables-t
//
// End-to-end coverage of the duckdb plugin's Admin surface: the
// `duckdb_variables` editable table, its `runtime_duckdb_variables`
// projection, and the `LOAD`/`SAVE` commands (plus their documented
// aliases) that move state between them. Modelled on
// test_mysqlx_admin_tables-t.cpp, but exercised over the real Admin MySQL
// protocol connection (via CommandLine) against a running ProxySQL with
// the duckdb plugin loaded -- not via a direct dlopen() of the .so -- so
// this is a genuine end-to-end test of the command dispatch path, not a
// unit test of the plugin's internals.
//
// Separation-of-duties contract under test (include/ProxySQL_Plugin.h):
// `duckdb_variables` is the editable admin table; the module (the
// plugin's in-memory DuckDBConfigStore) is the runtime source of truth
// once loaded; `runtime_duckdb_variables` is a read-only projection of
// the module, refreshed on demand by the chassis's
// register_runtime_view callback whenever it is queried through the
// admin handler. `LOAD DUCKDB VARIABLES TO RUNTIME` reads the editable
// table and installs it into the module; `SAVE DUCKDB VARIABLES TO
// MEMORY` dumps the module back into the editable table; neither touches
// the runtime view directly.
//
// Idempotency note: the plugin's default `database_path` is ":memory:",
// and more relevantly here, the in-memory DuckDBConfigStore is
// process-lifetime state -- both persist across test invocations against
// the same warm container. This test therefore does not assume any
// particular starting value for `threads`; every assertion compares
// values recorded earlier in the SAME run rather than hard-coding a
// "before" value, and the sequence is designed so that regardless of
// what earlier runs left behind, it converges to the same well-defined
// end state ('5') every time it completes.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

namespace {

MYSQL* g_admin = nullptr;

// Runs `q` against the admin connection. Fails the whole test loudly
// (BAIL_OUT, not a silently-ignored return) on a non-zero mysql_query
// return -- a failure here means the Admin command pipeline itself is
// broken, which no later assertion could meaningfully recover from.
void exec(const char* q) {
	if (mysql_query(g_admin, q) != 0) {
		BAIL_OUT("admin query failed: '%s': %s", q, mysql_error(g_admin));
	}
	// Drain any result set the command may have produced (LOAD/SAVE
	// commands return a one-row status set on this admin dispatch path)
	// so the connection is clean for the next query.
	MYSQL_RES* res = mysql_store_result(g_admin);
	if (res != nullptr) {
		mysql_free_result(res);
	}
}

// Runs `q`, expected to return exactly one row/one column, and returns
// that cell as a string ("" for a real SQL NULL). BAILs out on any
// query failure or on a query that unexpectedly returns no result set.
std::string cell(const char* q) {
	if (mysql_query(g_admin, q) != 0) {
		BAIL_OUT("admin query failed: '%s': %s", q, mysql_error(g_admin));
	}
	MYSQL_RES* res = mysql_store_result(g_admin);
	if (res == nullptr) {
		BAIL_OUT("admin query '%s' returned no result set: %s", q, mysql_error(g_admin));
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	std::string out;
	if (row != nullptr && row[0] != nullptr) {
		out = row[0];
	}
	mysql_free_result(res);
	return out;
}

// Runs a "SELECT COUNT(*) ..." (or any single-integer-cell query) and
// returns it as a long. BAILs out (via cell()) on failure.
long rows_of(const char* q) {
	const std::string v = cell(q);
	if (v.empty()) {
		BAIL_OUT("admin query '%s' returned no usable count", q);
	}
	return std::strtol(v.c_str(), nullptr, 10);
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environment variables");
		return -1;
	}

	plan(7);

	diag("=== test_duckdb_admin_tables-t starting ===");

	g_admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(g_admin != nullptr, "Admin connection established");
	if (g_admin == nullptr) {
		BAIL_OUT("cannot continue without an admin connection");
	}

	// Setup (not itself an assertion): make sure `duckdb_variables` has
	// rows to look at regardless of whether this is the first run ever
	// against this container (table starts genuinely empty -- the
	// plugin seeds no rows on boot, only the in-memory store carries
	// compiled-in defaults) or a later run against a warm one (table
	// already holds whatever the previous run left). `SAVE DUCKDB
	// VARIABLES TO MEMORY` dumps the module's current, always-valid
	// state into the editable table -- exactly the "seed" operation --
	// and is a full replace, not a merge, so it is safe to run on every
	// invocation.
	exec("SAVE DUCKDB VARIABLES TO MEMORY");

	// 1. The plugin's table is registered, and SAVE populates it. Do not
	// call this "seeded" -- the table starts with zero rows on a true
	// cold boot (confirmed by direct inspection of a running container
	// before this test was written: no code path INSERTs default rows
	// into `duckdb_variables`). What this assertion actually proves is
	// that `SAVE DUCKDB VARIABLES TO MEMORY` above dumped the module's
	// state into the table, i.e. the table is registered and reachable
	// and the SAVE command's dump path works end to end.
	ok(rows_of("SELECT COUNT(*) FROM duckdb_variables") > 0,
	   "SAVE DUCKDB VARIABLES TO MEMORY populates the editable table");

	// 2. The runtime view projects module state, not stored rows. Right
	// after the seed SAVE above, the editable table and the module agree
	// by construction; this asserts that the runtime view (queried
	// through the admin handler, which triggers its on-demand refresh)
	// reports the SAME value the module was just seeded with, rather
	// than something stale or unrelated.
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") ==
	   cell("SELECT variable_value FROM duckdb_variables "
	        "WHERE variable_name='threads'"),
	   "runtime view agrees with the editable table at rest");

	// 3. An edit to the editable table is invisible to the runtime view
	// until an explicit LOAD. Record the runtime value BEFORE the edit so
	// this assertion cannot pass by accident of some hard-coded "not 7"
	// check colliding with a leftover value from an earlier run.
	const std::string threads_before_edit =
		cell("SELECT variable_value FROM runtime_duckdb_variables "
		     "WHERE variable_name='threads'");
	exec("UPDATE duckdb_variables SET variable_value='7' WHERE variable_name='threads'");
	const std::string threads_after_edit =
		cell("SELECT variable_value FROM runtime_duckdb_variables "
		     "WHERE variable_name='threads'");
	ok(threads_after_edit == threads_before_edit,
	   "an uncommitted edit is not visible in the runtime view "
	   "(runtime view remains '%s')",
	   threads_after_edit.c_str());

	// 4. LOAD ... TO RUNTIME installs it.
	exec("LOAD DUCKDB VARIABLES TO RUNTIME");
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") == "7",
	   "LOAD DUCKDB VARIABLES TO RUNTIME installs the edit");

	// 5. The documented alias resolves to the same command.
	exec("UPDATE duckdb_variables SET variable_value='5' WHERE variable_name='threads'");
	exec("LOAD DUCKDB VARIABLES FROM MEMORY");
	ok(cell("SELECT variable_value FROM runtime_duckdb_variables "
	        "WHERE variable_name='threads'") == "5",
	   "the FROM MEMORY alias resolves to the canonical command");

	// 6. SAVE ... TO DISK persists. This only copies main.duckdb_variables
	// -> disk.duckdb_variables (see duckdb_admin_schema.cpp); it does not
	// touch the module or the runtime view, so there is nothing further
	// to assert here beyond "the command itself executes without error"
	// -- exec() already BAILs out on a non-zero mysql_query return, so
	// reaching this ok() at all is the proof.
	exec("SAVE DUCKDB VARIABLES TO DISK");
	ok(true, "SAVE DUCKDB VARIABLES TO DISK executes without error");

	mysql_close(g_admin);
	g_admin = nullptr;

	return exit_status();
}
