#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include "prometheus/exposer.h"
#include "prometheus/counter.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "Base_Thread.h"

#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "mysql.h"
#include "proxysql_admin.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "proxysql_config.h"
#include "proxysql_restapi.h"
// MCP_Thread.h / ProxySQL_MCP_Server.hpp moved to the genai plugin in
// Step 4.C; GenAI_Thread.h moved in Step 5.  flush_mcp_variables___*()
// are stubbed below; flush_genai_variables___*() were already
// stubbed since Step 4.C (and remain so — Step 5 just removes the
// extern decls).
#include "proxysql_utils.h"
#include "prometheus_helpers.h"
#include "cpp.h"

#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
// GenAI_Thread.h moved to plugins/genai/include/ in Step 5.
#include "SQLite3_Server.h"
#include "Web_Interface.hpp"

#include <dirent.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <fcntl.h>
#include <sys/utsname.h>

#include "platform.h"
#include "microhttpd.h"

#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
// currently only support x86-32, x86-64, ARM, and MIPS on Linux
#include "coredumper/coredumper.h"
#endif

#include <uuid/uuid.h>

#include "PgSQL_Protocol.h"
//#include "usual/time.h"

using std::string;
using std::unique_ptr;

#ifdef WITHGCOV
extern "C" void __gcov_dump();
extern "C" void __gcov_reset();
#endif


#ifdef DEBUG
//#define BENCHMARK_FASTROUTING_LOAD
#endif // DEBUG

//#define MYSQL_THREAD_IMPLEMENTATION

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"

#define READ_ONLY_0 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x30\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

#define READ_ONLY_1 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x31\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

extern struct MHD_Daemon *Admin_HTTP_Server;

extern ProxySQL_Statistics *GloProxyStats;

extern char *ssl_key_fp;
extern char *ssl_cert_fp;
extern char *ssl_ca_fp;

// ProxySQL_Admin shared variables
extern int admin___web_verbosity;
extern char * proxysql_version;

#include "proxysql_find_charset.h"

//extern MySQL_Query_Cache *GloMyQC;
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger* GloPgSQL_Logger;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern MySQL_Monitor *GloMyMon;
extern PgSQL_Threads_Handler* GloPTH;

// MCP_Threads_Handler ownership moved to the genai plugin in Step 4.C.
// GenAI_Threads_Handler / AI_Features_Manager moved in Step 5 — core
// no longer references those globals.

extern void (*flush_logs_function)();

extern Web_Interface *GloWebInterface;

extern ProxySQL_Cluster *GloProxyCluster;
#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */

extern SQLite3_Server *GloSQLite3Server;

extern char * binary_sha1;

extern int ProxySQL_create_or_load_TLS(bool bootstrap, std::string& msg);

bool ProxySQL_Admin::flush_GENERIC_variables__retrieve__database_to_runtime(const std::string& modname, char* &error, int& cols, int& affected_rows, SQLite3_result* &resultset) {
	string q = "SELECT substr(variable_name," + to_string(modname.length()+2) + ") vn, variable_value FROM global_variables WHERE variable_name LIKE '" + modname + "-%'";
	admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q.c_str(), error);
		free(error);
		return false;
	}
	return true;
}
FlushVariableStats ProxySQL_Admin::flush_GENERIC_variables__process__database_to_runtime(
	const string& modname, SQLite3DB *db, SQLite3_result* resultset,
	const bool& lock, const bool& replace,
	const std::unordered_set<std::string>& variables_read_only,
	const std::unordered_set<std::string>& variables_to_delete_silently,
	const std::unordered_set<std::string>& variables_deprecated,
	const std::unordered_set<std::string>& variables_special_values,
	std::function<void(const std::string&, const char *, SQLite3DB *)> special_variable_action,
	std::unordered_set<std::string>* accepted_variables
) {
	FlushVariableStats stats;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		stats.records++;
		bool rc = false;
		if (modname == "admin") {
			rc = set_variable(r->fields[0],r->fields[1], lock);
		} else if (modname == "mysql") {
			rc = GloMTH->set_variable(r->fields[0],r->fields[1]);
		} else if (modname == "sqliteserver") {
			rc = GloSQLite3Server->set_variable(r->fields[0],r->fields[1]);
#ifdef PROXYSQLCLICKHOUSE
		} else if (modname == "clickhouse") {
			rc = GloClickHouseServer->set_variable(r->fields[0],r->fields[1]);
#endif // PROXYSQLCLICKHOUSE
		} else if (modname == "ldap") {
			rc = GloMyLdapAuth->set_variable(r->fields[0],r->fields[1]);
#ifdef PROXYSQLTSDB
		} else if (modname == "tsdb") {
			rc = GloProxyStats->set_variable(r->fields[0],r->fields[1]);
#endif
		}
		const string v = string(r->fields[0]);
		if (rc==false) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			if (replace) {
				char *val = NULL;
				if (modname == "admin") {
					val = get_variable(r->fields[0]);
				} else if (modname == "mysql") {
					val = GloMTH->get_variable(r->fields[0]);
				} else if (modname == "sqliteserver") {
					val = GloSQLite3Server->get_variable(r->fields[0]);
#ifdef PROXYSQLCLICKHOUSE
				} else if (modname == "clickhouse") {
					val = GloClickHouseServer->get_variable(r->fields[0]);
#endif // PROXYSQLCLICKHOUSE
				} else if (modname == "ldap") {
					val = GloMyLdapAuth->get_variable(r->fields[0]);
#ifdef PROXYSQLTSDB
				} else if (modname == "tsdb") {
					val = GloProxyStats->get_variable(r->fields[0]);
#endif
				}
				char q[1000];
					if (val) {
						if (variables_read_only.count(v) > 0) {
							proxy_warning("Impossible to set read-only variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
						} else {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
						}
						stats.rejected++;
						snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"%s-%s\",\"%s\")", modname.c_str(), r->fields[0], val);
						db->execute(q);
						free(val);
					} else {
						if (variables_to_delete_silently.count(v) > 0) {
							stats.rejected++;
							snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
							db->execute(q);
						} else if (variables_deprecated.count(v) > 0) {
							proxy_error("Global variable %s-%s is deprecated.\n", modname.c_str(), r->fields[0]);
							stats.rejected++;
							snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
							stats.unknown++;
						}
						snprintf(q, sizeof(q), "DELETE FROM global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
						db->execute(q);
					}
				}
		} else {
			stats.updated++;
			if (accepted_variables != nullptr) {
				accepted_variables->emplace(v);
			}
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			if (variables_special_values.count(v) > 0) {
				if (special_variable_action != nullptr) {
					special_variable_action(v, r->fields[1], db);
				}
			}
		}
	}
	return stats;
}

FlushVariableStats ProxySQL_Admin::flush_admin_variables___database_to_runtime(
	SQLite3DB *db, bool replace, const string& checksum, const time_t epoch, bool lock
) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ADMIN variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("admin", error, cols, affected_rows, resultset) == true) {
		wrlock();
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("admin", db, resultset, lock, replace, {"version"}, {"debug"}, {}, {});
		//commit(); NOT IMPLEMENTED

		// Checksums are always generated - 'admin-checksum_*' deprecated

		{
			// generate checksum for cluster
			pthread_mutex_lock(&GloVars.checksum_mutex);
			flush_admin_variables___runtime_to_database(admindb, false, false, false, true);
			flush_GENERIC_variables__checksum__database_to_runtime("admin", checksum, epoch);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
		wrunlock();
		{
			load_http_server();
			load_restapi_server();
			// Update the admin variable for 'web_verbosity'
			admin___web_verbosity = variables.web_verbosity;
		}
		if (resultset) delete resultset;
		return stats;
	}
	if (resultset) delete resultset;
	return FlushVariableStats{};
}

void ProxySQL_Admin::flush_pgsql_variables___runtime_to_database(SQLite3DB* db, bool replace, bool del, bool onlyifempty, bool runtime, bool use_lock) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing PgSQL variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (onlyifempty) {
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;
		SQLite3_result* resultset = NULL;
		char* q = (char*)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'pgsql-%'";
		db->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		int matching_rows = 0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		}
		else {
			for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
				SQLite3_row* r = *it;
				matching_rows += atoi(r->fields[0]);
			}
		}
		if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has PgSQL variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting PgSQL variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'pgsql-%'");
	}
	static char* a;
	static char* b;
	if (replace) {
		a = (char*)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	}
	else {
		a = (char*)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	}
	int rc;
	sqlite3_stmt* statement1 = NULL;
	sqlite3_stmt* statement2 = NULL;
	auto [rc1, statement1_unique] = db->prepare_v2(a);
	rc = rc1;
	statement1 = statement1_unique.get();
	ASSERT_SQLITE_OK(rc, db);
	stmt_unique_ptr statement2_unique {};
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'pgsql-%'");
		b = (char*)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(?1, ?2)";
		auto [rc2, prepared_statement2] = db->prepare_v2(b);
		rc = rc2;
		statement2_unique = std::move(prepared_statement2);
		statement2 = statement2_unique.get();
		ASSERT_SQLITE_OK(rc, db);
	}
	if (use_lock) {
		GloPTH->wrlock();
		db->execute("BEGIN");
	}
	char** varnames = GloPTH->get_variables_list();
	for (int i = 0; varnames[i]; i++) {
		char* val = GloPTH->get_variable(varnames[i]);
		size_t qualified_name_len = strlen(varnames[i]) + sizeof("pgsql-");
		char* qualified_name = (char*)malloc(qualified_name_len);
		snprintf(qualified_name, qualified_name_len, "pgsql-%s", varnames[i]);
		rc = (*proxy_sqlite3_bind_text)(statement1, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_text)(statement1, 2, (val ? val : (char*)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		SAFE_SQLITE3_STEP2(statement1);
		rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
		if (runtime) {
			rc = (*proxy_sqlite3_bind_text)(statement2, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement2, 2, (val ? val : (char*)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			SAFE_SQLITE3_STEP2(statement2);
			rc = (*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, db);
		}
		if (val)
			free(val);
		free(qualified_name);
	}
	if (use_lock) {
		db->execute("COMMIT");
		GloPTH->wrunlock();
	}
	for (int i = 0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}

void ProxySQL_Admin::flush_GENERIC_variables__checksum__database_to_runtime(const string& modname, const string& checksum, const time_t epoch) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	std::string q;
	q="SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE '" + modname + "-\%' ";
	if (modname == "mysql") {
		q += " AND variable_name NOT IN ('mysql-threads')";
		if (GloVars.cluster_sync_interfaces == false) {
			q += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_MYSQL);
		}
	} else if (modname == "admin") {
		if (GloVars.cluster_sync_interfaces == false) {
			q += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_ADMIN);
		}
	} else if (modname == "pgsql") {
		if (GloVars.cluster_sync_interfaces == false) {
			q += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_PGSQL);
		}
	}
	q += " ORDER BY variable_name";
	admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
	if (error || resultset == NULL) {
		proxy_error("flush_GENERIC_variables__checksum__database_to_runtime failed for %s: %s\n",
			modname.c_str(), error ? error : "NULL resultset");
		return;
	}
	uint64_t hash1 = resultset->raw_checksum();
	uint32_t d32[2];
	char buf[20];
	memcpy(&d32, &hash1, sizeof(hash1));
	snprintf(buf, sizeof(buf), "0x%0X%0X", d32[0], d32[1]);
	ProxySQL_Checksum_Value *checkvar = NULL;
	if (modname == "admin") {
		checkvar = &GloVars.checksums_values.admin_variables;
	} else if (modname == "mysql") {
		checkvar = &GloVars.checksums_values.mysql_variables;
	} else if (modname == "ldap") {
		checkvar = &GloVars.checksums_values.ldap_variables;
	} else if (modname == "pgsql") {
		checkvar = &GloVars.checksums_values.pgsql_variables;
	}
	assert(checkvar != NULL);
	checkvar->set_checksum(buf);
	checkvar->version++;
	time_t t = time(NULL);
	if (epoch != 0 && checksum != "" && checkvar->checksum == checksum) {
		checkvar->epoch = epoch;
	} else {
		checkvar->epoch = t;
	}
	GloVars.epoch_version = t;
	GloVars.generate_global_checksum();
	GloVars.checksums_values.updates_cnt++;
	string modnameupper = modname;
	for (char &c : modnameupper) { c = std::toupper(c); }
	proxy_info(
		"Computed checksum for 'LOAD %s VARIABLES TO RUNTIME' was '%s', with epoch '%llu'\n",
		modnameupper.c_str(), checkvar->checksum, checkvar->epoch
	);
	delete resultset;
}

FlushVariableStats ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing MySQL variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("mysql", error, cols, affected_rows, resultset) == true) {
		std::unordered_set<std::string> accepted_database_variables;
		GloMTH->wrlock();
		char * previous_default_charset = GloMTH->get_variable_string((char *)"default_charset");
		char * previous_default_collation_connection = GloMTH->get_variable_string((char *)"default_collation_connection");
		assert(previous_default_charset);
		assert(previous_default_collation_connection);
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("mysql", db, resultset, false, replace, {}, {"session_debug"}, {"forward_autocommit"},
			{
				"default_collation_connection",
				"default_charset",
				"show_processlist_extended",
#ifdef IDLE_THREADS
				"session_idle_show_processlist",
#endif // IDLE_THREADS
				"processlist_max_query_length"
			},
			[](const std::string& varname, const char *varvalue, SQLite3DB* db) {
				if (varname == "default_collation_connection" || varname == "default_charset") {
					char *val=GloMTH->get_variable((char *)varname.c_str());
					if (val) {
							if (strcmp(val,varvalue)) {
								char q[1000];
								proxy_warning("Variable %s with value \"%s\" is being replaced with value \"%s\".\n", varname.c_str(), varvalue, val);
								snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")", varname.c_str(), val);
								db->execute(q);
							}
						free(val);
					}
				} else if (varname == "show_processlist_extended") {
					GloAdmin->variables.mysql_processlist.show_extended = atoi(varvalue);
#ifdef IDLE_THREADS
				} else if (varname == "session_idle_show_processlist") {
					GloAdmin->variables.mysql_processlist.show_idle_session =
						strcasecmp(varvalue, "true") == 0 || strcasecmp(varvalue, "1") == 0;
#endif // IDLE_THREADS
				} else if (varname == "processlist_max_query_length") {
					GloAdmin->variables.mysql_processlist.max_query_length = atoi(varvalue);
				}
			},
			&accepted_database_variables
		);
		char q[1000];
		char * default_charset = GloMTH->get_variable_string((char *)"default_charset");
		char * default_collation_connection = GloMTH->get_variable_string((char *)"default_collation_connection");
		assert(default_charset);
		assert(default_collation_connection);
		MARIADB_CHARSET_INFO * ci = NULL;
		ci = proxysql_find_charset_name(default_charset);
		if (ci == NULL) {
			// invalid charset
			proxy_error("Found an incorrect value for mysql-default_charset: %s\n", default_charset);
			// let's try to get a charset from collation connection
			ci = proxysql_find_charset_collate(default_collation_connection);
			if (ci == NULL) {
				proxy_error("Found an incorrect value for mysql-default_collation_connection: %s\n", default_collation_connection);
					const char *p = mysql_tracked_variables[SQL_CHARACTER_SET].default_value;
					ci = proxysql_find_charset_name(p);
					assert(ci);
					proxy_info("Resetting mysql-default_charset to hardcoded default value: %s\n", ci->csname);
					snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
					db->execute(q);
					GloMTH->set_variable((char *)"default_charset",ci->csname);
					proxy_info("Resetting mysql-default_collation_connection to hardcoded default value: %s\n", ci->name);
					snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
					db->execute(q);
					GloMTH->set_variable((char *)"default_collation_connection",ci->name);
				} else {
					proxy_info("Changing mysql-default_charset to %s using configured mysql-default_collation_connection %s\n", ci->csname, ci->name);
					snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
					db->execute(q);
					GloMTH->set_variable((char *)"default_charset",ci->csname);
				}
		} else {
			MARIADB_CHARSET_INFO * cic = NULL;
			cic = proxysql_find_charset_collate(default_collation_connection);
				if (cic == NULL) {
					proxy_error("Found an incorrect value for mysql-default_collation_connection: %s\n", default_collation_connection);
					proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
					snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
					db->execute(q);
					GloMTH->set_variable((char *)"default_collation_connection",ci->name);
				} else {
				if (strcmp(cic->csname,ci->csname)==0) {
					// mysql-default_collation_connection and mysql-default_charset are compatible
				} else {
					proxy_error("Found incompatible values for mysql-default_charset (%s) and mysql-default_collation_connection (%s)\n", default_charset, default_collation_connection);
					bool use_collation = true;
					if (strcmp(default_charset, previous_default_charset)) { // charset changed
						if (strcmp(default_collation_connection, previous_default_collation_connection)==0) { // collation didn't change
							// the user has changed the charset but not the collation
							// we use charset as source of truth
							use_collation = false;
						}
						}
						if (use_collation) {
							proxy_info("Changing mysql-default_charset to %s using configured mysql-default_collation_connection %s\n", cic->csname, cic->name);
							snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", cic->csname);
							db->execute(q);
							GloMTH->set_variable((char *)"default_charset",cic->csname);
						} else {
							proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
							snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
							db->execute(q);
							GloMTH->set_variable((char *)"default_collation_connection",ci->name);
						}
				}
			}
		}
		free(default_charset);
		free(default_collation_connection);
		free(previous_default_charset);
		free(previous_default_collation_connection);
		const MySQLThreadsCommitResult commit_result = GloMTH->commit();
		if (!commit_result.rejected_variables.empty()) {
			int rejected_variables_in_resultset = 0;
			for (const std::string& variable_name : commit_result.rejected_variables) {
				if (accepted_database_variables.count(variable_name) != 0) {
					rejected_variables_in_resultset++;
				}
			}
			stats.updated = std::max(0, stats.updated - rejected_variables_in_resultset);
			stats.rejected += rejected_variables_in_resultset;

			const char* query =
				"INSERT OR REPLACE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
			auto [rc, statement_unique] = db->prepare_v2(query);
			ASSERT_SQLITE_OK(rc, db);
			sqlite3_stmt* statement = statement_unique.get();
			for (const std::string& variable_name : commit_result.rejected_variables) {
				mf_unique_ptr<char> value { GloMTH->get_variable(variable_name.c_str()) };
				const std::string qualified_name = "mysql-" + variable_name;
				rc = (*proxy_sqlite3_bind_text)(
					statement, 1, qualified_name.c_str(), -1, SQLITE_TRANSIENT
				);
				ASSERT_SQLITE_OK(rc, db);
				rc = (*proxy_sqlite3_bind_text)(
					statement, 2, value != nullptr ? value.get() : "", -1, SQLITE_TRANSIENT
				);
				ASSERT_SQLITE_OK(rc, db);
				SAFE_SQLITE3_STEP2(statement);
				rc = (*proxy_sqlite3_clear_bindings)(statement);
				ASSERT_SQLITE_OK(rc, db);
				rc = (*proxy_sqlite3_reset)(statement);
				ASSERT_SQLITE_OK(rc, db);
			}
		}
		GloMTH->wrunlock();

		{
			// NOTE: 'GloMTH->wrunlock()' should have been called before this point to avoid possible
			// deadlocks. See issue #3847.
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_mysql_variables___runtime_to_database(admindb, false, false, false, true, true);
			flush_GENERIC_variables__checksum__database_to_runtime("mysql", checksum, epoch);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}

		/**
		 * @brief Check and warn if TCP keepalive is disabled for MySQL connections.
		 *
		 * This safety check warns users when mysql-use_tcp_keepalive is set to false,
		 * which can cause connection instability in certain deployment scenarios.
		 *
		 * @warning Disabling TCP keepalive is unsafe when ProxySQL is deployed behind:
		 *   - Network load balancers with idle connection timeouts
		 *   - NAT firewalls with connection state timeout
		 *   - Cloud environments with connection pooling
		 *   - Any intermediate network device that drops idle connections
		 *
		 * @why_unsafe TCP keepalive sends periodic keep-alive packets on idle connections.
		 * When disabled:
		 *   - Load balancers may drop connections from their connection pools
		 *   - NAT devices may remove connection state from their tables
		 *   - Cloud load balancers (AWS ELB, GCP Load Balancer, etc.) may terminate
		 *     connections during idle periods
		 *   - Results in sudden connection failures and "connection reset" errors
		 *   - Can cause application downtime and poor user experience
		 *
		 * @recommendation Always set mysql-use_tcp_keepalive=true when deploying
		 * behind load balancers or in cloud environments.
		 */
		// Check for TCP keepalive setting and warn if disabled
		int mysql_use_tcp_keepalive = GloMTH->get_variable_int((char *)"use_tcp_keepalive");
		if (mysql_use_tcp_keepalive == 0) {
			proxy_warning("mysql-use_tcp_keepalive is set to false. This may cause connection drops when ProxySQL is behind a network load balancer. Consider setting this to true.\n");
		}

		const int user_variable_tracking = GloMTH->get_variable_int((char *)"user_variable_tracking");
		const int set_parser_algorithm = GloMTH->get_variable_int((char *)"set_parser_algorithm");
		const int query_processor_parser = GloMTH->get_variable_int((char *)"query_processor_parser");
		if (user_variable_tracking == 1 && set_parser_algorithm != 3 && query_processor_parser != 1) {
			proxy_warning("mysql-user_variable_tracking=1 remains inactive because mysql-set_parser_algorithm is not 3 and mysql-query_processor_parser is not 1. Enable either mysql-set_parser_algorithm=3 or mysql-query_processor_parser=1 to activate user-variable tracking.\n");
		}

		// Cross-variable validation for 'mysql-session_track_variables'.
		//
		// Session variable tracking depends on two other MySQL capability toggles and
		// the interaction is non-obvious: an operator who sets only 'session_track_variables'
		// can end up with the feature silently doing nothing (OPTIONAL) or with client
		// behavior changing unexpectedly (ENFORCED). We emit warnings once per
		// 'LOAD MYSQL VARIABLES TO RUNTIME' so a misconfiguration is visible in the
		// normal operator workflow rather than having to be debugged later.
		//
		// The checks are only relevant when the feature is actually requested: when
		// 'session_track_variables=DISABLED' (the default) none of these interactions
		// matter and we emit nothing. We deliberately do not name specific backends
		// here - this is a global configuration warning; per-backend capability
		// mismatches are logged separately at the point where they are detected in
		// 'MySQL_Session::handle_session_track_capabilities()'.
		int session_track_variables_mode = GloMTH->get_variable_int((char *)"session_track_variables");
		if (session_track_variables_mode != session_track_variables::DISABLED) {
			int enable_client_deprecate_eof = GloMTH->get_variable_int((char *)"enable_client_deprecate_eof");
			int enable_server_deprecate_eof = GloMTH->get_variable_int((char *)"enable_server_deprecate_eof");

			if (session_track_variables_mode == session_track_variables::ENFORCED) {
				// ENFORCED mode guarantees that session tracking is set up on every
				// eligible backend connection, and to do that it must force
				// CLIENT_DEPRECATE_EOF on both the client- and server-facing halves of
				// the protocol even when the operator asked for the opposite. Warn
				// explicitly so the behavior change is never silent: clients that do
				// not negotiate CLIENT_DEPRECATE_EOF will see OK packets where they
				// previously saw EOF packets, which can break older connectors.
				if (enable_client_deprecate_eof == 0) {
					proxy_warning("mysql-session_track_variables=ENFORCED overrides mysql-enable_client_deprecate_eof=false and forces CLIENT_DEPRECATE_EOF on frontend connections. Older clients that do not negotiate CLIENT_DEPRECATE_EOF may be affected.\n");
				}
				if (enable_server_deprecate_eof == 0) {
					proxy_warning("mysql-session_track_variables=ENFORCED overrides mysql-enable_server_deprecate_eof=false and forces CLIENT_DEPRECATE_EOF on backend connections.\n");
				}
			} else if (session_track_variables_mode == session_track_variables::OPTIONAL) {
				// OPTIONAL mode gracefully skips tracking on any backend that lacks the
				// required capabilities - including when ProxySQL itself is configured
				// not to negotiate CLIENT_DEPRECATE_EOF upstream. In that configuration
				// tracking is a no-op: the feature appears enabled in the admin tables
				// but nothing is ever tracked. Make the dependency explicit so the
				// operator is not left wondering why 'PROXYSQL INTERNAL SESSION' shows
				// no tracked variables.
				if (enable_server_deprecate_eof == 0) {
					proxy_warning("mysql-session_track_variables=OPTIONAL has no effect while mysql-enable_server_deprecate_eof=false; backend session tracking will be skipped. Set mysql-enable_server_deprecate_eof=true or use ENFORCED mode to activate tracking.\n");
				}
			}
		}
		if (resultset) delete resultset;
		return stats;
	}
	if (resultset) delete resultset;
	return FlushVariableStats{};
}

FlushVariableStats ProxySQL_Admin::flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing SQLiteServer variables. Replace:%d\n", replace);
	if (
		(GloVars.global.sqlite3_server == false)
		||
		( GloSQLite3Server == NULL )
	) {
		return FlushVariableStats{};
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("sqliteserver", error, cols, affected_rows, resultset) == true) {
		GloSQLite3Server->wrlock();
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("sqliteserver", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
		//GloClickHouse->commit();
		GloSQLite3Server->wrunlock();
		if (resultset) delete resultset;
		return stats;
	}
	if (resultset) delete resultset;
	return FlushVariableStats{};
}

#ifdef PROXYSQLTSDB
FlushVariableStats ProxySQL_Admin::flush_tsdb_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing TSDB variables. Replace:%d\n", replace);
	if (GloProxyStats == NULL) {
		return FlushVariableStats{};
	}

	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;

	if (flush_GENERIC_variables__retrieve__database_to_runtime("tsdb", error, cols, affected_rows, resultset) == true) {
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("tsdb", db, resultset, false, replace, {}, {}, {}, {});
		flush_tsdb_variables___runtime_to_database(admindb, false, false, false, true);
		if (resultset) delete resultset;
		return stats;
	}

	if (resultset) delete resultset;
	return FlushVariableStats{};
}
#endif

void ProxySQL_Admin::flush_sqliteserver_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (GloVars.global.sqlite3_server == false) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'sqliteserver-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ClickHouse variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ClickHouse variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'sqliteserver-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'sqliteserver-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  }
	GloSQLite3Server->wrlock();
	char **varnames=GloSQLite3Server->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloSQLite3Server->get_variable(varnames[i]);
		const char* safe_val = (val ? val : "(null)");
		size_t l = strlen(a) + 200;
		l += (varnames[i] ? strlen(varnames[i]) : 6);
		l += strlen(safe_val);
		char *query=(char *)malloc(l);
		snprintf(query, l, a, varnames[i], safe_val);
		if (runtime) {
			db->execute(query);
			snprintf(query, l, b, varnames[i], safe_val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloSQLite3Server->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}


#ifdef PROXYSQLCLICKHOUSE
FlushVariableStats ProxySQL_Admin::flush_clickhouse_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d\n", replace);
	if (
		(GloVars.global.clickhouse_server == false)
		||
		( GloClickHouseServer == NULL )
	) {
		return FlushVariableStats{};
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("clickhouse", error, cols, affected_rows, resultset) == true) {
		GloClickHouseServer->wrlock();
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("clickhouse", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
		//GloClickHouse->commit();
		GloClickHouseServer->wrunlock();
		if (resultset) delete resultset;
		return stats;
	}
	if (resultset) delete resultset;
	return FlushVariableStats{};
}

void ProxySQL_Admin::flush_clickhouse_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (
		(GloVars.global.clickhouse_server == false)
		||
		( GloClickHouseServer == NULL )
	) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'clickhouse-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ClickHouse variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ClickHouse variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'clickhouse-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'clickhouse-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloClickHouseServer->wrlock();
	char **varnames=GloClickHouseServer->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloClickHouseServer->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		snprintf(query, l, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			snprintf(query, l, b, varnames[i], val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloClickHouseServer->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}
#endif /* PROXYSQLCLICKHOUSE */

FlushVariableStats ProxySQL_Admin::flush_pgsql_variables___database_to_runtime(SQLite3DB* db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing PgSQL variables. Replace:%d\n", replace);
	FlushVariableStats stats;
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	char* q = (char*)"SELECT substr(variable_name,7) vn, variable_value FROM global_variables WHERE variable_name LIKE 'pgsql-%'";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		free(error);
		if (resultset) delete resultset;
		return FlushVariableStats{};
	}
	else {
		GloPTH->wrlock();
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			const char* value = r->fields[1];
			stats.records++;
			bool rc = GloPTH->set_variable(r->fields[0], value);
			if (rc == false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0], value);
				if (replace) {
					char* val = GloPTH->get_variable(r->fields[0]);
					char q[1000];
						if (val) {
							if (strcmp(val, value)) {
								proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0], value, val);
								snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-%s\",\"%s\")", r->fields[0], val);
								db->execute(q);
							}
							free(val);
							stats.rejected++;
					}
						else {
							if (strcmp(r->fields[0], (char*)"session_debug") == 0) {
								snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
								db->execute(q);
								stats.rejected++;
							}
							else {
								if (strcmp(r->fields[0], (char*)"forward_autocommit") == 0) {
									if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
										proxy_error("Global variable pgsql-forward_autocommit is deprecated. See issue #3253\n");
									}
									snprintf(q, sizeof(q), "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
									db->execute(q);
									stats.rejected++;
								}
							else {
								proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0], r->fields[1]);
								stats.unknown++;
								}
							}
							snprintf(q, sizeof(q), "DELETE FROM global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
							db->execute(q);
						}
					}
			}
			else {
				stats.updated++;
				if (
					(strcmp(r->fields[0], "default_collation_connection") == 0)
					|| (strcmp(r->fields[0], "default_charset") == 0)
					) {
					char* val = GloPTH->get_variable(r->fields[0]);
					char q[1000];
						if (val) {
							if (strcmp(val, value)) {
								proxy_warning("Variable %s with value \"%s\" is being replaced with value \"%s\".\n", r->fields[0], value, val);
								snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-%s\",\"%s\")", r->fields[0], val);
								db->execute(q);
							}
							free(val);
					}
				}
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0], value);
				if (strcmp(r->fields[0], (char*)"show_processlist_extended") == 0) {
					variables.pgsql_processlist.show_extended = atoi(value);
#ifdef IDLE_THREADS
				} else if (strcmp(r->fields[0], (char*)"session_idle_show_processlist") == 0) {
					variables.pgsql_processlist.show_idle_session = atoi(value);
#endif // IDLE_THREADS
				} else if (strcmp(r->fields[0], (char*)"processlist_max_query_length") == 0) {
					variables.pgsql_processlist.max_query_length = atoi(value);
				}
			}
			//			}
		}
		
		char q[1000];
		char* default_client_encoding = GloPTH->get_variable_string((char*)"default_client_encoding");
		assert(default_client_encoding);

		int charset_encoding = PgSQL_Connection::char_to_encoding(default_client_encoding);

		if (charset_encoding == -1) {
			// invalid charset_encoding
			proxy_error("Found an incorrect value for pgsql-default_client_encoding: %s\n", default_client_encoding);
				const char* p = pgsql_tracked_variables[PGSQL_CLIENT_ENCODING].default_value;
				charset_encoding = PgSQL_Connection::char_to_encoding(p);
				assert(charset_encoding != -1);
				proxy_info("Resetting pgsql-default_client_encoding to hardcoded default value: %s\n", p);
				snprintf(q, sizeof(q), "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_client_encoding\",\"%s\")", p);
				db->execute(q);
				GloPTH->set_variable((char*)"default_client_encoding", p);
		}
		free(default_client_encoding);
		GloPTH->commit();
		GloPTH->wrunlock();

			{
				// NOTE: 'GloPTH->wrunlock()' should have been called before this point to avoid possible
				// deadlocks. See issue #3847.
				pthread_mutex_lock(&GloVars.checksum_mutex);
				flush_pgsql_variables___runtime_to_database(admindb, false, false, false, true, true);
				flush_GENERIC_variables__checksum__database_to_runtime("pgsql", checksum, epoch);
				pthread_mutex_unlock(&GloVars.checksum_mutex);
			}
	
		/**
		 * @brief Check and warn if TCP keepalive is disabled for PostgreSQL connections.
		 *
		 * This safety check warns users when pgsql-use_tcp_keepalive is set to false,
		 * which can cause connection instability in certain deployment scenarios.
		 *
		 * @warning Disabling TCP keepalive is unsafe when ProxySQL is deployed behind:
		 *   - Network load balancers with idle connection timeouts
		 *   - NAT firewalls with connection state timeout
		 *   - Cloud environments with connection pooling
		 *   - Any intermediate network device that drops idle connections
		 *
		 * @why_unsafe TCP keepalive sends periodic keep-alive packets on idle connections.
		 * When disabled for PostgreSQL:
		 *   - Load balancers may drop connections from their connection pools
		 *   - NAT devices may remove connection state from their tables
		 *   - Cloud load balancers (AWS ELB, GCP Load Balancer, etc.) may terminate
		 *     connections during idle periods
		 *   - PostgreSQL connections may appear "stale" to the database server
		 *   - Results in sudden connection failures and "connection reset" errors
		 *   - Can cause application downtime and poor user experience
		 *
		 * @note PostgreSQL connections are often long-lived and benefit greatly from
		 * TCP keepalive, especially in connection-pooled environments.
		 *
		 * @recommendation Always set pgsql-use_tcp_keepalive=true when deploying
		 * behind load balancers or in cloud environments.
		 */
		// Check for TCP keepalive setting and warn if disabled
		int pgsql_use_tcp_keepalive = GloPTH->get_variable_int((char *)"use_tcp_keepalive");
		if (pgsql_use_tcp_keepalive == 0) {
			proxy_warning("pgsql-use_tcp_keepalive is set to false. This may cause connection drops when ProxySQL is behind a network load balancer. Consider setting this to true.\n");
		}
	}
	if (resultset) delete resultset;
	return stats;
}


void ProxySQL_Admin::flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime, bool use_lock) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing MySQL variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (onlyifempty) {
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'mysql-%'";
		db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
		}
		if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has MySQL variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting MySQL variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'mysql-%'");
	}
	static char *a;
	static char *b;
	if (replace) {
		a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	} else {
		a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	}
	int rc;
	sqlite3_stmt *statement1 = NULL;
	sqlite3_stmt *statement2 = NULL;
	auto [rc1, statement1_unique] = db->prepare_v2(a);
	rc = rc1;
	statement1 = statement1_unique.get();
	ASSERT_SQLITE_OK(rc, db);
	stmt_unique_ptr statement2_unique {};
	if (runtime)  {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(?1, ?2)";

		auto [rc2, prepared_statement2] = db->prepare_v2(b);
		rc = rc2;
		statement2_unique = std::move(prepared_statement2);
		statement2 = statement2_unique.get();
		ASSERT_SQLITE_OK(rc, db);
	}
	if (use_lock) {
		GloMTH->wrlock();
		db->execute("BEGIN");
	}
	char **varnames=GloMTH->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMTH->get_variable(varnames[i]);
		size_t qualified_name_len = strlen(varnames[i]) + sizeof("mysql-");
		char *qualified_name=(char *)malloc(qualified_name_len);
		snprintf(qualified_name, qualified_name_len, "mysql-%s", varnames[i]);
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, (val ? val : (char *)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
		if (runtime) {
			rc=(*proxy_sqlite3_bind_text)(statement2, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc=(*proxy_sqlite3_bind_text)(statement2, 2, (val ? val : (char *)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			SAFE_SQLITE3_STEP2(statement2);
			rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, db);
			rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, db);
		}
		if (val)
			free(val);
		free(qualified_name);
	}
	if (use_lock) {
		db->execute("COMMIT");
		GloMTH->wrunlock();
	}
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}

FlushVariableStats ProxySQL_Admin::flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing LDAP variables. Replace:%d\n", replace);
	if (GloMyLdapAuth == NULL) {
		return FlushVariableStats{};
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("ldap", error, cols, affected_rows, resultset) == true) {
		GloMyLdapAuth->wrlock();
		FlushVariableStats stats = flush_GENERIC_variables__process__database_to_runtime("admin", db, resultset, false, replace, {}, {}, {}, {});
		GloMyLdapAuth->wrunlock();

		// Checksums are always generated - 'admin-checksum_*' deprecated
		{
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_ldap_variables___runtime_to_database(admindb, false, false, false, true);
			flush_GENERIC_variables__checksum__database_to_runtime("ldap", checksum, epoch);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
		if (resultset) delete resultset;
		return stats;
	}
	if (resultset) delete resultset;
	return FlushVariableStats{};
}

void ProxySQL_Admin::flush_ldap_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing LDAP variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (GloMyLdapAuth == NULL) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'ldap-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has LDAP variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting LDAP variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'ldap-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'ldap-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  }
	GloMyLdapAuth->wrlock();
	char **varnames=GloMyLdapAuth->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMyLdapAuth->get_variable(varnames[i]);
		const char* safe_val = (val ? val : "(null)");
		size_t l = strlen(a) + 200;
		l += (varnames[i] ? strlen(varnames[i]) : 6);
		l += strlen(safe_val);
		char *query=(char *)malloc(l);
		snprintf(query, l, a, varnames[i], safe_val);
		if (runtime) {
			db->execute(query);
			snprintf(query, l, b, varnames[i], safe_val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloMyLdapAuth->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}

void ProxySQL_Admin::flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ADMIN variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'admin-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ADMIN variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ADMIN variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'admin-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  }
	char **varnames=get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=get_variable(varnames[i]);
		const char* safe_val = (val ? val : "(null)");
		size_t l = strlen(a) + 200;
		l += (varnames[i] ? strlen(varnames[i]) : 6);
		l += strlen(safe_val);
		char *query=(char *)malloc(l);
		snprintf(query, l, a, varnames[i], safe_val);
		db->execute(query);
		if (runtime) {
			snprintf(query, l, b, varnames[i], safe_val);
			db->execute(query);
		}
		if (val)
			free(val);
		free(query);
	}
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}
