/**
 * @file pgsql-init_connect-1-t.cpp
 * @brief Global 'pgsql-init_connect': PostgreSQL port of mysql-init_connect-1-t.
 *
 * init_connect runs once on every new backend connection, before ProxySQL syncs the
 * client's tracked parameters. The feature is v3.1+ (PROXYSQL31); the tier is read from
 * the server's 'admin-version', and v3.1 cases run in both native and libpq backend mode.
 *
 * Every marker query carries create_new_connection=1, because a pooled connection keeps
 * the init_connect it was opened with.
 *
 * State touched (restored on exit): 'pgsql-init_connect', 'pgsql-use_native_backend_protocol'.
 */

#include "pgsql_init_connect_common.h"

#include <string>

CommandLine cl;

static constexpr int kPerMode = 2;        // v3.1 cases run once per backend mode
static constexpr int kStableCases = 0;    // v3.0 cases

// A fresh client per case: a timed-out query leaves its connection busy.
static void run_mode(PGconn* admin, bool native) {
	ic_set_global(admin, "SET ic.marker TO 'global'");
	PGConnPtr c1 = ic_connect_client(cl);
	IcResult r = ic_query(c1.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "global",
	   "[native=%d] global init_connect applied (got '%s')", native, r.value.c_str());

	ic_set_global(admin, "SET ic.marker TO 'it''s'");
	PGConnPtr c2 = ic_connect_client(cl);
	r = ic_query(c2.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "it's",
	   "[native=%d] quoted value survives admin storage (got '%s')", native, r.value.c_str());
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}
	PGConnPtr admin_conn = ic_connect_admin(cl);
	PGconn* admin = admin_conn.get();
	if (PQstatus(admin) != CONNECTION_OK) return exit_status();

	const bool v31 = ic_is_v31(admin);
	plan(2 * kPerMode + kStableCases);

	const std::string orig_ic = ic_admin_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-init_connect'");

	if (!v31) {
		skip(2 * kPerMode, "init_connect needs ProxySQL v3.1+");
	} else {
		const std::string orig_native = ic_admin_value(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
		for (bool native : {true, false}) {
			ic_admin(admin, std::string("UPDATE global_variables SET variable_value='") +
				(native ? "true" : "false") + "' WHERE variable_name='pgsql-use_native_backend_protocol'");
			ic_admin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			run_mode(admin, native);
		}
		ic_admin(admin, "UPDATE global_variables SET variable_value=" + ic_literal(orig_native) +
			" WHERE variable_name='pgsql-use_native_backend_protocol'");
	}

	ic_set_global(admin, orig_ic);
	return exit_status();
}
