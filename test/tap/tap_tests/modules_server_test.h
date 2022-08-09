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

	return res;
}

int extract_module_host_port(MYSQL* proxysql_admin, const std::string varname, std::pair<std::string, int>& host_port) {
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
		host_port = { module_host, i_module_port };
	}

	return res;
}


