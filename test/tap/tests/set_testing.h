std::vector<std::string> split(const std::string& s, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

using nlohmann::json;

struct TestCase {
	std::string command;
	json expected_vars;
	json reset_vars;
};

std::vector<TestCase> testCases;

#define MAX_LINE 10240

#define UNKNOWNVAR	"proxysql_unknown"

const std::vector<std::string> possible_unknown_variables = {
	"aurora_read_replica_read_committed",
	"group_replication_consistency",
	"query_cache_type",
	"wsrep_osu_method",
	};

int readTestCases(const std::string& fileName) {
	FILE* fp = fopen(fileName.c_str(), "r");
	if (!fp) return 0;

	char buf[MAX_LINE], col1[MAX_LINE], col2[MAX_LINE], col3[MAX_LINE] = {0};
	int n = 0;
	for(;;) {
		if (fgets(buf, sizeof(buf), fp) == NULL) break;
		n = sscanf(buf, " \"%[^\"]\", \"%[^\"]\", \"%[^\"]\"", col1, col2, col3);
		if (n == 0) break;

		char *p = col2;
		while(*p++) if(*p == '\'') *p = '\"';

		json vars = json::parse(col2);

		p = col3;
		while(col3[0] != 0 && *p++) if(*p == '\'') *p = '\"';

		json reset_vars;
		if (p != col3) {
			reset_vars = json::parse(col3);
		}

		testCases.push_back({col1, vars, reset_vars});
	}

	fclose(fp);
	return 1;
}


int readTestCasesJSON(const std::string& fileName) {
	FILE* fp = fopen(fileName.c_str(), "r");
	if (!fp) return 0;

	char buf[MAX_LINE] = {0};
	int n = 0;
	int i = 0;
	for(;;) {
		if (fgets(buf, sizeof(buf), fp) == NULL) break;
		i++;
		json j = json::parse(buf);

//		char *p = col2;
//		while(*p++) if(*p == '\'') *p = '\"';

		//json vars = json::parse(j['expected']);
		json vars = j["expected"];

//		p = col3;
//		while(col3[0] != 0 && *p++) if(*p == '\'') *p = '\"';

		json reset_vars;
		if(j.find("reset") != j.end())
			reset_vars = j["reset"];
//		if (p != col3) {
//			reset_vars = json::parse(col3);
//		}
		std::string st = std::string(j["query"].dump(),1,j["query"].dump().length()-2);
		unsigned int l = st.length();
		char newbuf[l+1];
		memset(newbuf,0,l+1);
		char *s = (char *)st.data();
		char *d = newbuf;
		for (unsigned int i=0; i < l; i++) {
			if ((*s == '\\') && (*(s+1) == '"')) {
				s++;
			} else {
				*d = *s;
				d++;
				s++;
			}
		}
		testCases.push_back({newbuf, vars, reset_vars});
		if (i%5000 == 0) {
			fprintf(stderr,"Read %d tests...\n", i);
		}
	}

	fclose(fp);
	return 1;
}

unsigned long long monotonic_time() {
	struct timespec ts;
	//clock_gettime(CLOCK_MONOTONIC_COARSE, &ts); // this is faster, but not precise
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
		begin=end-begin;
	};
	unsigned long long begin;
};


inline int fastrand() {
	g_seed = (214014*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void parseResultJsonColumn(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result)))
		j = json::parse(row[0]);
}

void parseResult(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	unsigned long long nr = mysql_num_rows(result);
	assert(nr > 16);
	while ((row = mysql_fetch_row(result))) {
		if (j.find(row[0]) == j.end()) {
			j[row[0]] = row[1];
		} else {
			if (strcmp(row[1],UNKNOWNVAR)!=0) {
				j[row[0]] = row[1]; // we override only if the new value it is not UNKNOWNVAR
			}
		}
	}
}

void dumpResult(MYSQL_RES *result) {
	if(!result) return;
	MYSQL_ROW row;

	int num_fields = mysql_num_fields(result);

	while ((row = mysql_fetch_row(result)))
	{
		for(int i = 0; i < num_fields; i++)
		{
			printf("%s ", row[i] ? row[i] : "NULL");
		}
		printf("\n");
	}
}

void queryVariables(MYSQL *mysql, json& j, std::string& paddress) {
	// FIXME:
	// unify the use of wsrep_sync_wait no matter if Galera is used or not
	std::stringstream query;

	if (is_mariadb) {
		query << "SELECT /* mysql " << mysql << " " << paddress << " */ lower(variable_name), variable_value FROM information_schema.session_variables WHERE variable_name IN "
			" ("
			"'tx_isolation', 'tx_read_only', 'max_statement_time'";
	}
	else {
		query << "SELECT /* mysql " << mysql << " " << paddress << " */ * FROM performance_schema.session_variables WHERE variable_name IN "
			" ("
			"'session_track_gtids', 'transaction_isolation', 'transaction_read_only', 'max_execution_time'";
	}

	if (is_cluster) {
		query << ", 'wsrep_sync_wait'";
	}
	
	query << ", 'sql_safe_updates', 'max_join_size', 'net_write_timeout', 'sql_select_limit', 'character_set_results'";
	query << ", 'hostname', 'sql_log_bin', 'sql_mode', 'init_connect', 'time_zone', 'sql_auto_is_null'";
	query << ", 'sql_auto_is_null', 'collation_connection', 'character_set_connection', 'character_set_client', 'character_set_database', 'group_concat_max_len'";
	query << ", 'foreign_key_checks', 'unique_checks'";
	query << ", 'auto_increment_increment', 'auto_increment_offset'";
	query << ", 'default_storage_engine', 'default_tmp_storage_engine'";
	query << ", 'innodb_lock_wait_timeout', 'innodb_strict_mode', 'innodb_table_locks'";
	query << ", 'join_buffer_size', 'lock_wait_timeout'";
	query << ", 'sort_buffer_size', 'optimizer_switch', 'optimizer_search_depth', 'optimizer_prune_level'";
	query << ", 'long_query_time', 'tmp_table_size', 'max_heap_table_size'";
	query << ", 'lc_messages', 'lc_time_names', 'timestamp', 'max_sort_length', 'sql_big_selects'";
	// the following variables are likely to not exist on all systems
	for (std::vector<std::string>::const_iterator it = possible_unknown_variables.begin() ; it != possible_unknown_variables.end() ; it++) {
		query << ", '" << *it << "'";
	}
	query << ")";
	// the following variables are likely to not exist on all systems
	// so we artificially add them with an UNION and we will eventually filter them
	for (std::vector<std::string>::const_iterator it = possible_unknown_variables.begin() ; it != possible_unknown_variables.end() ; it++) {
		query << " UNION SELECT '" << *it << "','" << std::string(UNKNOWNVAR) << "'";
	}
	//fprintf(stderr, "TRACE : QUERY 3 : variables %s\n", query.str().c_str());
	if (mysql_query(mysql, query.str().c_str())) {
		if (silent==0) {
			fprintf(stderr,"ERROR while running -- \"%s\" :  (%d) %s\n", query.str().c_str(), mysql_errno(mysql), mysql_error(mysql));
		}
	} else {
		MYSQL_RES *result = mysql_store_result(mysql);
		parseResult(result, j);

		mysql_free_result(result);
		__sync_fetch_and_add(&g_select_OK,1);
	}
}

void queryInternalStatus(MYSQL *mysql, json& j, std::string& paddress) {
	char *query = (char*)"PROXYSQL INTERNAL SESSION";

	//fprintf(stderr, "TRACE : QUERY 4 : variables %s\n", query);
	if (mysql_query(mysql, query)) {
		if (silent==0) {
			fprintf(stderr,"ERROR while running -- \"%s\" :  (%d) %s\n", query, mysql_errno(mysql), mysql_error(mysql));
		}
	} else {
		MYSQL_RES *result = mysql_store_result(mysql);
		parseResultJsonColumn(result, j);

		mysql_free_result(result);
		__sync_fetch_and_add(&g_select_OK,1);
	}

	std::vector<std::string> bools_variables = {
		"sql_auto_is_null",
		"sql_safe_updates",
		"sql_log_bin",
		"foreign_key_checks",
		"unique_checks"
	};
	// value types in mysql and in proxysql are different
	// we should convert proxysql values to mysql format to compare
	for (auto& el : j.items()) {
		if (paddress.length() == 0) {
			if (el.key() == "address") {
				paddress = el.value();
			}
		}
		if (el.key() == "conn") {
/*			
			std::string sql_log_bin_value;

			// sql_log_bin {0|1}
			if (el.value()["sql_log_bin"] == 1) {
				el.value().erase("sql_log_bin");
				j["conn"]["sql_log_bin"] = "ON";
			}
			else if (el.value()["sql_log_bin"] == 0) {
				el.value().erase("sql_log_bin");
				j["conn"]["sql_log_bin"] = "OFF";
			}
*/
			{
				for (std::vector<std::string>::iterator it = bools_variables.begin(); it != bools_variables.end(); it++) {
					std::string v = el.value()[*it].dump();
					if (
						(strcasecmp(v.c_str(),"ON")==0)
						||
						(strcasecmp(v.c_str(),"1")==0)
					) {
						el.value().erase(*it);
						j["conn"][*it] = "ON";
					} else {
						if (
							(strcasecmp(v.c_str(),"OFF")==0)
							||
							(strcasecmp(v.c_str(),"0")==0)
						) {
							el.value().erase(*it);
							j["conn"][*it] = "OFF";
						}
					}
				}
			}

/*
			// sql_auto_is_null {true|false}
			if (!el.value()["sql_auto_is_null"].dump().compare("ON") ||
					!el.value()["sql_auto_is_null"].dump().compare("1") ||
					!el.value()["sql_auto_is_null"].dump().compare("on") ||
					el.value()["sql_auto_is_null"] == 1) {
				el.value().erase("sql_auto_is_null");
				j["conn"]["sql_auto_is_null"] = "ON";
			}
			else if (!el.value()["sql_auto_is_null"].dump().compare("OFF") ||
					!el.value()["sql_auto_is_null"].dump().compare("0") ||
					!el.value()["sql_auto_is_null"].dump().compare("off") ||
					el.value()["sql_auto_is_null"] == 0) {
				el.value().erase("sql_auto_is_null");
				j["conn"]["sql_auto_is_null"] = "OFF";
			}
*/
			// completely remove autocommit test
/*
			// autocommit {true|false}
			if (!el.value()["autocommit"].dump().compare("ON") ||
					!el.value()["autocommit"].dump().compare("1") ||
					!el.value()["autocommit"].dump().compare("on") ||
					el.value()["autocommit"] == 1) {
				el.value().erase("autocommit");
				j["conn"]["autocommit"] = "ON";
			}
			else if (!el.value()["autocommit"].dump().compare("OFF") ||
					!el.value()["autocommit"].dump().compare("0") ||
					!el.value()["autocommit"].dump().compare("off") ||
					el.value()["autocommit"] == 0) {
				el.value().erase("autocommit");
				j["conn"]["autocommit"] = "OFF";
			}
*/
/*
			// sql_safe_updates
			if (!el.value()["sql_safe_updates"].dump().compare("\"ON\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"1\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"on\"") ||
					el.value()["sql_safe_updates"] == 1) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "ON";
			}
			else if (!el.value()["sql_safe_updates"].dump().compare("\"OFF\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"0\"") ||
					!el.value()["sql_safe_updates"].dump().compare("\"off\"") ||
					el.value()["sql_safe_updates"] == 0) {
				el.value().erase("sql_safe_updates");
				j["conn"]["sql_safe_updates"] = "OFF";
			}
*/
			std::stringstream ss;
			ss << 0xFFFFFFFFFFFFFFFF;
			// sql_select_limit
			if (!el.value()["sql_select_limit"].dump().compare("\"DEFAULT\"")) {
				el.value().erase("sql_select_limit");
				j["conn"]["sql_select_limit"] = strdup(ss.str().c_str());
			}

			if (!is_mariadb) {
				// transaction_isolation (level)
				if (!el.value()["isolation_level"].dump().compare("\"REPEATABLE READ\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "REPEATABLE-READ";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ COMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "READ-COMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ UNCOMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "READ-UNCOMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"SERIALIZABLE\"")) {
					el.value().erase("isolation_level");
					j["conn"]["transaction_isolation"] = "SERIALIZABLE";
				}
			}
			else {
				// transaction_isolation (level)
				if (!el.value()["isolation_level"].dump().compare("\"REPEATABLE READ\"")) {
					el.value().erase("isolation_level");
					j["conn"]["tx_isolation"] = "REPEATABLE-READ";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ COMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["tx_isolation"] = "READ-COMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"READ UNCOMMITTED\"")) {
					el.value().erase("isolation_level");
					j["conn"]["tx_isolation"] = "READ-UNCOMMITTED";
				}
				else if (!el.value()["isolation_level"].dump().compare("\"SERIALIZABLE\"")) {
					el.value().erase("isolation_level");
					j["conn"]["tx_isolation"] = "SERIALIZABLE";
				}
			}

			if (!is_mariadb) {
				// transaction_read (write|only)
				if (!el.value()["transaction_read"].dump().compare("\"ONLY\"")) {
					el.value().erase("transaction_read");
					j["conn"]["transaction_read_only"] = "ON";
				}
				else if (!el.value()["transaction_read"].dump().compare("\"WRITE\"")) {
					el.value().erase("transaction_read");
					j["conn"]["transaction_read_only"] = "OFF";
				}
			} else {
				// transaction_read (write|only)
				if (!el.value()["transaction_read"].dump().compare("\"ONLY\"")) {
					el.value().erase("transaction_read");
					j["conn"]["tx_read_only"] = "ON";
				}
				else if (!el.value()["transaction_read"].dump().compare("\"WRITE\"")) {
					el.value().erase("transaction_read");
					j["conn"]["tx_read_only"] = "OFF";
				}
			}

			if (!is_mariadb) {
				// session_track_gtids
				if (!el.value()["session_track_gtids"].dump().compare("\"OFF\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "OFF";
				}
				else if (!el.value()["session_track_gtids"].dump().compare("\"OWN_GTID\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "OWN_GTID";
				}
				else if (!el.value()["session_track_gtids"].dump().compare("\"ALL_GTIDS\"")) {
					el.value().erase("session_track_gtids");
					j["conn"]["session_track_gtids"] = "ALL_GTIDS";
				}
			}

		}
	}
}

/**
 * @brief Checks that after setting 'session_track_gtids', the new set value follows ProxySQL rules
 * for this particular variable. This is:
 * - backend connections are by default set to `mysql-default_session_track_gtids`.
 * - if `mysql-default_session_track_gtids=OFF` (the default), `session_track_gtids` is not changed on backend.
 * - if the client asks for `session_track_gtids=OFF`, proxysql ignores it (it just acknowledge it).
 * - if the client asks for `session_track_gtids=OWN_GTID`, proxysql will apply it.
 * - if the client asks for `session_track_gtids=ALL_GTIDS`, proxysql will switch to OWN_GTID and generate a warning.
 * - if the backend doesn't support `session_track_gtids` (for example in MySQL 5.5 and MySQL 5.6), proxysql won't apply it. It knows checking server capabilities
 *
 * @param expVal The value to which 'session_track_gtids' have been set.
 * @param sVal The ProxySQL session value for 'session_track_gtids'.
 * @param mVal The MySQL session value for 'session_track_gtids'.
 * @return True in case the check succeed, false otherwise.
 */
bool check_session_track_gtids(const std::string& expVal, const std::string& sVal, const std::string& mVal) {
	bool res = false;

	if (expVal == "OFF") {
		res = expVal == sVal;
	} else if (expVal == "OWN_GTID" && (sVal == mVal && sVal == "OWN_GTID")) {
		res = true;
	} else if (expVal == "ALL_GTIDS" && (sVal == mVal && sVal == "OWN_GTID")) {
		res = true;
	}

	return res;
}

int detect_version(CommandLine& cl, bool& is_mariadb, bool& is_cluster) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return 1;
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n",
				__FILE__, __LINE__, mysql_error(mysql));
		return 1;
	}

	MYSQL_QUERY(mysql, "select @@version");
	MYSQL_RES *result = mysql_store_result(mysql);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result)))
	{
		if (strstr(row[0], "Maria")) {
			is_mariadb = true;
		}
		else {
			is_mariadb = false;
		}
	}
	mysql_free_result(result);
	MYSQL_QUERY(mysql, "SHOW VARIABLES LIKE 'wsrep_sync_wait'");
	result = mysql_store_result(mysql);
	unsigned long long nr = mysql_num_rows(result);
	if (nr == 0) {
		is_cluster = false;
	} else {
		is_cluster = true;
	}
	mysql_free_result(result);
	mysql_close(mysql);
	return 0;
}

