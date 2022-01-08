/**
 * @brief Extract the current 'sqliteserver-mysql_ifaces' from ProxySQL config.
 * @param proxysql_admin An already opened connection to ProxySQL Admin.
 * @return EXIT_SUCCESS, or one of the following error codes:
 *   - EINVAL if supplied 'proxysql_admin' is NULL.
 *   - '-1' in case of ProxySQL returns an 'NULL' row for the query selecting
 *     the variable 'sqliteserver-read_only'.
 *   - EXIT_FAILURE in case other operation failed.
 */
int get_sqlite3_ifaces(MYSQL* proxysql_admin, std::string& sqlite3_ifaces) {
	if (proxysql_admin == NULL) {
		return EINVAL;
	}

	int res = EXIT_FAILURE;

	MYSQL_QUERY(
		proxysql_admin,
		"SELECT * FROM global_variables WHERE Variable_name='sqliteserver-mysql_ifaces'"
	);

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

		std::string _sqlite3_ifaces { row[1] };
		sqlite3_ifaces = _sqlite3_ifaces;
		res = EXIT_SUCCESS;
	}

cleanup:

	return res;
}

int extract_sqlite3_host_port(MYSQL* proxysql_admin, std::pair<std::string, int>& host_port) {
	if (proxysql_admin == nullptr) { return EINVAL; }
	int res = EXIT_SUCCESS;

	std::string sqlite3_ifaces {};
	int ifaces_err = get_sqlite3_ifaces(proxysql_admin, sqlite3_ifaces);

	// ProxySQL is likely to have been launched without "--sqlite3-server" flag
	if (ifaces_err == -1) {
		diag("ProxySQL was launched without '--sqlite3-server' flag");
		res = EXIT_FAILURE;
		return res;
	}

	// Extract the correct port to connect to SQLite server
	std::string::size_type colon_pos = sqlite3_ifaces.find(":");
	if (colon_pos == std::string::npos) {
		diag("ProxySQL returned a malformed 'sqliteserver-mysql_ifaces': %s", sqlite3_ifaces.c_str());
		res = EXIT_FAILURE;
		return res;
	}

	std::string sqlite3_host { sqlite3_ifaces.substr(0, colon_pos) };
	std::string sqlite3_port { sqlite3_ifaces.substr(colon_pos + 1) };

	// Check that port has valid conversion
	char* end_pos = nullptr;
	int i_sqlite3_port = std::strtol(sqlite3_port.c_str(), &end_pos, 10);

	if (errno == ERANGE || (end_pos != &sqlite3_port.back() + 1)) {
		diag(
			"ProxySQL returned a invalid port number within 'sqliteserver-mysql_ifaces': %s",
			sqlite3_ifaces.c_str()
		);
		res = EXIT_FAILURE;
		return res;
	}

	if (res == EXIT_SUCCESS) {
		host_port = { sqlite3_host, i_sqlite3_port };
	}

	return res;
}


