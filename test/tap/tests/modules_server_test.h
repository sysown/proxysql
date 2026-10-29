/**
 * @brief Extract the current 'MODULE-mysql_ifaces' from ProxySQL config.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @return EXIT_SUCCESS, or one of the following error codes:
 *   - EINVAL if supplied 'proxysql_admin' is NULL.
 *   - EXIT_FAILURE in case other operation failed.
 */
int get_module_ifaces(MYSQL* proxysql_admin, const std::string varname, std::string& module_ifaces) {
	if (proxysql_admin == NULL) {
		return EINVAL;
	}

	int res = EXIT_FAILURE;

	std::string query = "SELECT * FROM global_variables WHERE Variable_name='" + varname + "'";
	diag("Running query: %s", query.c_str());
	MYSQL_QUERY(proxysql_admin, query.c_str());

	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	if (!admin_res) {
		diag("'mysql_store_result' at line %d failed: %s", __LINE__, mysql_error(proxysql_admin));
		goto cleanup;
	}

	{
		MYSQL_ROW row = mysql_fetch_row(admin_res);
		if (!row || row[0] == nullptr || row[1] == nullptr) {
			diag("'mysql_fetch_row' at line %d returned 'NULL'", __LINE__);
			res = -1;
			goto cleanup;
		}

		std::string _module_ifaces { row[1] };
		module_ifaces = _module_ifaces;
		res = EXIT_SUCCESS;
	}

cleanup:

	mysql_free_result(admin_res);

	return res;
}

/**
 * @brief Read a ProxySQL module's listening interface (e.g. `sqliteserver-mysql_ifaces`)
 *        from `global_variables` and return it as a reachable (host, port) pair.
 *
 * `0.0.0.0` is replaced with a concrete address — see the in-body comment for the
 * DOCKER_MODE client-vs-backend distinction.
 *
 * @param proxysql_admin Open connection to ProxySQL Admin.
 * @param varname        Variable to read (e.g. `sqliteserver-mysql_ifaces`,
 *                       `clickhouse-mysql_ifaces`).
 * @param host_port      Out-param populated with (host, port) on success.
 * @param backend_addr   Under DOCKER_MODE, when set to `true`, the function returns
 *                       loopback (`127.0.0.1`) instead of the container hostname.
 *                       No effect outside DOCKER_MODE or when the bound address is
 *                       not `0.0.0.0`. 
 * @return EXIT_SUCCESS, EINVAL (proxysql_admin is NULL), or EXIT_FAILURE
 */
int extract_module_host_port(MYSQL* proxysql_admin, const std::string varname, std::pair<std::string, int>& host_port, bool backend_addr = false) {
	if (proxysql_admin == nullptr) { return EINVAL; }
	int res = EXIT_SUCCESS;

	std::string module_ifaces {};
	int ifaces_err = get_module_ifaces(proxysql_admin, varname, module_ifaces);

	// ProxySQL is likely to have been launched without "--MODULE-server" flag
	if (ifaces_err == -1) {
		if (varname=="sqliteserver-mysql_ifaces") {
			diag("ProxySQL was launched without '--sqlite3-server' flag");
		} else if (varname=="clickhouse-mysql_ifaces") {
			diag("ProxySQL was launched without '--clickhouse-server' flag");
		} else {
			diag("Unknown variable %s", varname.c_str());	
		}
		res = EXIT_FAILURE;
		return res;
	}

	// Module interfaces may contain multiple listeners. Existing tests using
	// this helper connect to the first TCP listener.
	const std::string::size_type first_iface_end = module_ifaces.find(";");
	if (first_iface_end != std::string::npos) {
		module_ifaces.erase(first_iface_end);
	}

	// Extract the correct port to connect to MODULE server
	std::string::size_type colon_pos = module_ifaces.find(":");
	if (colon_pos == std::string::npos) {
		diag("ProxySQL returned a malformed '%s': %s", varname.c_str(), module_ifaces.c_str());
		res = EXIT_FAILURE;
		return res;
	}

	std::string module_host { module_ifaces.substr(0, colon_pos) };
	std::string module_port { module_ifaces.substr(colon_pos + 1) };

	// Check that port has valid conversion
	char* end_pos = nullptr;
	int i_module_port = std::strtol(module_port.c_str(), &end_pos, 10);

	if (errno == ERANGE || (end_pos != &module_port.back() + 1)) {
		diag(
			"ProxySQL returned a invalid port number within '%s': %s",
			varname.c_str(), module_ifaces.c_str()
		);
		res = EXIT_FAILURE;
		return res;
	}

	if (res == EXIT_SUCCESS) {
		// Replace 0.0.0.0 with an appropriate reachable address.
		//
		// The (host, port) returned here is consumed in two ways across TAP tests:
		// 1) As a *client* destination — the test process connects directly to one of
		//    ProxySQL's module listeners (e.g. clickhouse_server, sqlite3_server).
		// 2) As a *backend* in `mysql_servers` — ProxySQL itself connects to this address,
		//    for both query routing and Monitor health checks.
		//
		// Under DOCKER_MODE these two roles need different values:
		//   - Role (1) wants the container hostname `proxysql` (connecting in from outside the container).
		//   - Role (2) wants `127.0.0.1`, because ProxySQL is connecting to itself. Any non-loopback
		//     address trips the "User '%s' can only connect locally" guard in MySQL_Session.cpp
		//     for the internal 'monitor'/'admin'/'stats' users — Monitor pings are rejected,
		//     the backend gets shunned, and routing tests lose connectivity.
		//
		// Callers in role (2) must pass `backend_addr = true` to get loopback.
		if (module_host == "0.0.0.0") {
			const char* docker_mode = getenv("DOCKER_MODE");
			if (!backend_addr && docker_mode != nullptr) {
				host_port = { "proxysql", i_module_port };
			} else {
				host_port = { "127.0.0.1", i_module_port };
			}
		} else {
			host_port = { module_host, i_module_port };
		}
	}

	return res;
}
