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

template<enum SERVER_TYPE>
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg);

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

void ProxySQL_Admin::flush_GENERIC_variables__process__database_to_runtime(
	const string& modname, SQLite3DB *db, SQLite3_result* resultset,
	const bool& lock, const bool& replace,
	const std::unordered_set<std::string>& variables_read_only,
	const std::unordered_set<std::string>& variables_to_delete_silently,
	const std::unordered_set<std::string>& variables_deprecated,
	const std::unordered_set<std::string>& variables_special_values,
	std::function<void(const std::string&, const char *, SQLite3DB *)> special_variable_action
) {
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
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
				}
				char q[1000];
				if (val) {
					if (variables_read_only.count(v) > 0) {
						proxy_warning("Impossible to set read-only variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
					} else {
						proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
					}
					sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"%s-%s\",\"%s\")", modname.c_str(), r->fields[0],val);
					db->execute(q);
					free(val);
				} else {
					if (variables_to_delete_silently.count(v) > 0) {
						sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
						db->execute(q);
					} else if (variables_deprecated.count(v) > 0) {
						proxy_error("Global variable %s-%s is deprecated.\n", modname.c_str(), r->fields[0]);
						sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
						db->execute(q);
					} else {
						proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
					}
					sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"%s-%s\"", modname.c_str(), r->fields[0]);
					db->execute(q);
				}
			}
		} else {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			if (variables_special_values.count(v) > 0) {
				if (special_variable_action != nullptr) {
					special_variable_action(v, r->fields[1], db);
				}
			}
		}
	}
}

void ProxySQL_Admin::flush_admin_variables___database_to_runtime(
	SQLite3DB *db, bool replace, const string& checksum, const time_t epoch, bool lock
) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ADMIN variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("admin", error, cols, affected_rows, resultset) == true) {
		wrlock();
		flush_GENERIC_variables__process__database_to_runtime("admin", db, resultset, lock, replace, {"version"}, {"debug"}, {}, {});
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
	}
	if (resultset) delete resultset;
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
	//sqlite3 *mydb3=db->get_db();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, a, -1, &statement1, 0);
	rc = db->prepare_v2(a, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'pgsql-%'");
		b = (char*)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(?1, ?2)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, b, -1, &statement2, 0);
		rc = db->prepare_v2(b, &statement2);
		ASSERT_SQLITE_OK(rc, db);
	}
	if (use_lock) {
		GloPTH->wrlock();
		db->execute("BEGIN");
	}
	char** varnames = GloPTH->get_variables_list();
	for (int i = 0; varnames[i]; i++) {
		char* val = GloPTH->get_variable(varnames[i]);
		char* qualified_name = (char*)malloc(strlen(varnames[i]) + 12);
		sprintf(qualified_name, "pgsql-%s", varnames[i]);
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
	(*proxy_sqlite3_finalize)(statement1);
	if (runtime)
		(*proxy_sqlite3_finalize)(statement2);
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
	}
	q += " ORDER BY variable_name";
	admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
	uint64_t hash1 = resultset->raw_checksum();
	uint32_t d32[2];
	char buf[20];
	memcpy(&d32, &hash1, sizeof(hash1));
	sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
	ProxySQL_Checksum_Value *checkvar = NULL;
	if (modname == "admin") {
		checkvar = &GloVars.checksums_values.admin_variables;
	} else if (modname == "mysql") {
		checkvar = &GloVars.checksums_values.mysql_variables;
	} else if (modname == "ldap") {
		checkvar = &GloVars.checksums_values.ldap_variables;
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

void ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing MySQL variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("mysql", error, cols, affected_rows, resultset) == true) {
		GloMTH->wrlock();
		char * previous_default_charset = GloMTH->get_variable_string((char *)"default_charset");
		char * previous_default_collation_connection = GloMTH->get_variable_string((char *)"default_collation_connection");
		assert(previous_default_charset);
		assert(previous_default_collation_connection);
		flush_GENERIC_variables__process__database_to_runtime("mysql", db, resultset, false, replace, {}, {"session_debug"}, {"forward_autocommit"},
			{"default_collation_connection", "default_charset", "show_processlist_extended"},
			[](const std::string& varname, const char *varvalue, SQLite3DB* db) {
				if (varname == "default_collation_connection" || varname == "default_charset") {
					char *val=GloMTH->get_variable((char *)varname.c_str());
					if (val) {
						if (strcmp(val,varvalue)) {
							char q[1000];
							proxy_warning("Variable %s with value \"%s\" is being replaced with value \"%s\".\n", varname.c_str(), varvalue, val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")", varname.c_str() ,val);
							db->execute(q);
						}
						free(val);
					}
				} else if (varname == "show_processlist_extended") {
					GloAdmin->variables.mysql_show_processlist_extended = atoi(varvalue);
				}
			}
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
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloMTH->set_variable((char *)"default_charset",ci->csname);
				proxy_info("Resetting mysql-default_collation_connection to hardcoded default value: %s\n", ci->name);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
				db->execute(q);
				GloMTH->set_variable((char *)"default_collation_connection",ci->name);
			} else {
				proxy_info("Changing mysql-default_charset to %s using configured mysql-default_collation_connection %s\n", ci->csname, ci->name);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloMTH->set_variable((char *)"default_charset",ci->csname);
			}
		} else {
			MARIADB_CHARSET_INFO * cic = NULL;
			cic = proxysql_find_charset_collate(default_collation_connection);
			if (cic == NULL) {
				proxy_error("Found an incorrect value for mysql-default_collation_connection: %s\n", default_collation_connection);
				proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
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
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", cic->csname);
						db->execute(q);
						GloMTH->set_variable((char *)"default_charset",cic->csname);
					} else {
						proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
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
		GloMTH->commit();
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
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing SQLiteServer variables. Replace:%d\n", replace);
	if (
		(GloVars.global.sqlite3_server == false)
		||
		( GloSQLite3Server == NULL )
	) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("sqliteserver", error, cols, affected_rows, resultset) == true) {
		GloSQLite3Server->wrlock();
		flush_GENERIC_variables__process__database_to_runtime("sqliteserver", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
		//GloClickHouse->commit();
		GloSQLite3Server->wrunlock();
	}
	if (resultset) delete resultset;
}

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
  int l=strlen(a)+200;
	GloSQLite3Server->wrlock();
	char **varnames=GloSQLite3Server->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloSQLite3Server->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
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
void ProxySQL_Admin::flush_clickhouse_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d\n", replace);
	if (
		(GloVars.global.clickhouse_server == false)
		||
		( GloClickHouseServer == NULL )
	) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("clickhouse", error, cols, affected_rows, resultset) == true) {
		GloClickHouseServer->wrlock();
		flush_GENERIC_variables__process__database_to_runtime("clickhouse", db, resultset, false, replace, {}, {"session_debug"}, {}, {});
		//GloClickHouse->commit();
		GloClickHouseServer->wrunlock();
	}
	if (resultset) delete resultset;
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
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
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

void ProxySQL_Admin::flush_pgsql_variables___database_to_runtime(SQLite3DB* db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing PgSQL variables. Replace:%d\n", replace);
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	char* q = (char*)"SELECT substr(variable_name,7) vn, variable_value FROM global_variables WHERE variable_name LIKE 'pgsql-%'";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return;
	}
	else {
		GloPTH->wrlock();
		char* previous_default_charset = GloPTH->get_variable_string((char*)"default_charset");
		char* previous_default_collation_connection = GloPTH->get_variable_string((char*)"default_collation_connection");
		assert(previous_default_charset);
		assert(previous_default_collation_connection);
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			const char* value = r->fields[1];
			bool rc = GloPTH->set_variable(r->fields[0], value);
			if (rc == false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0], value);
				if (replace) {
					char* val = GloPTH->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val, value)) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0], value, val);
							sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-%s\",\"%s\")", r->fields[0], val);
							db->execute(q);
						}
						free(val);
					}
					else {
						if (strcmp(r->fields[0], (char*)"session_debug") == 0) {
							sprintf(q, "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
							db->execute(q);
						}
						else {
							if (strcmp(r->fields[0], (char*)"forward_autocommit") == 0) {
								if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
									proxy_error("Global variable pgsql-forward_autocommit is deprecated. See issue #3253\n");
								}
								sprintf(q, "DELETE FROM disk.global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
								db->execute(q);
							}
							else {
								proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0], r->fields[1]);
							}
						}
						sprintf(q, "DELETE FROM global_variables WHERE variable_name=\"pgsql-%s\"", r->fields[0]);
						db->execute(q);
					}
				}
			}
			else {
				if (
					(strcmp(r->fields[0], "default_collation_connection") == 0)
					|| (strcmp(r->fields[0], "default_charset") == 0)
					) {
					char* val = GloPTH->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val, value)) {
							proxy_warning("Variable %s with value \"%s\" is being replaced with value \"%s\".\n", r->fields[0], value, val);
							sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-%s\",\"%s\")", r->fields[0], val);
							db->execute(q);
						}
						free(val);
					}
				}
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0], value);
				if (strcmp(r->fields[0], (char*)"show_processlist_extended") == 0) {
					variables.pgsql_show_processlist_extended = atoi(value);
				}
			}
			//			}
		}

		char q[1000];
		char* default_charset = GloPTH->get_variable_string((char*)"default_charset");
		char* default_collation_connection = GloPTH->get_variable_string((char*)"default_collation_connection");
		assert(default_charset);
		assert(default_collation_connection);
		MARIADB_CHARSET_INFO* ci = NULL;
		ci = proxysql_find_charset_name(default_charset);
		if (ci == NULL) {
			// invalid charset
			proxy_error("Found an incorrect value for pgsql-default_charset: %s\n", default_charset);
			// let's try to get a charset from collation connection
			ci = proxysql_find_charset_collate(default_collation_connection);
			if (ci == NULL) {
				proxy_error("Found an incorrect value for pgsql-default_collation_connection: %s\n", default_collation_connection);
				const char* p = mysql_tracked_variables[SQL_CHARACTER_SET].default_value;
				ci = proxysql_find_charset_name(p);
				assert(ci);
				proxy_info("Resetting pgsql-default_charset to hardcoded default value: %s\n", ci->csname);
				sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloPTH->set_variable((char*)"default_charset", ci->csname);
				proxy_info("Resetting pgsql-default_collation_connection to hardcoded default value: %s\n", ci->name);
				sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_collation_connection\",\"%s\")", ci->name);
				db->execute(q);
				GloPTH->set_variable((char*)"default_collation_connection", ci->name);
			}
			else {
				proxy_info("Changing pgsql-default_charset to %s using configured pgsql-default_collation_connection %s\n", ci->csname, ci->name);
				sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloPTH->set_variable((char*)"default_charset", ci->csname);
			}
		}
		else {
			MARIADB_CHARSET_INFO* cic = NULL;
			cic = proxysql_find_charset_collate(default_collation_connection);
			if (cic == NULL) {
				proxy_error("Found an incorrect value for pgsql-default_collation_connection: %s\n", default_collation_connection);
				proxy_info("Changing pgsql-default_collation_connection to %s using configured pgsql-default_charset: %s\n", ci->name, ci->csname);
				sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_collation_connection\",\"%s\")", ci->name);
				db->execute(q);
				GloPTH->set_variable((char*)"default_collation_connection", ci->name);
			}
			else {
				if (strcmp(cic->csname, ci->csname) == 0) {
					// pgsql-default_collation_connection and pgsql-default_charset are compatible
				}
				else {
					proxy_error("Found incompatible values for pgsql-default_charset (%s) and pgsql-default_collation_connection (%s)\n", default_charset, default_collation_connection);
					bool use_collation = true;
					if (strcmp(default_charset, previous_default_charset)) { // charset changed
						if (strcmp(default_collation_connection, previous_default_collation_connection) == 0) { // collation didn't change
							// the user has changed the charset but not the collation
							// we use charset as source of truth
							use_collation = false;
						}
					}
					if (use_collation) {
						proxy_info("Changing pgsql-default_charset to %s using configured pgsql-default_collation_connection %s\n", cic->csname, cic->name);
						sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_charset\",\"%s\")", cic->csname);
						db->execute(q);
						GloPTH->set_variable((char*)"default_charset", cic->csname);
					}
					else {
						proxy_info("Changing pgsql-default_collation_connection to %s using configured pgsql-default_charset: %s\n", ci->name, ci->csname);
						sprintf(q, "INSERT OR REPLACE INTO global_variables VALUES(\"pgsql-default_collation_connection\",\"%s\")", ci->name);
						db->execute(q);
						GloPTH->set_variable((char*)"default_collation_connection", ci->name);
					}
				}
			}
		}
		free(default_charset);
		free(default_collation_connection);
		free(previous_default_charset);
		free(previous_default_collation_connection);
		GloPTH->commit();
		GloPTH->wrunlock();

		/* Checksums are always generated - 'admin-checksum_*' deprecated
		{
			// NOTE: 'GloPTH->wrunlock()' should have been called before this point to avoid possible
			// deadlocks. See issue #3847.
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_mysql_variables___runtime_to_database(admindb, false, false, false, true, true);
			char* error = NULL;
			int cols = 0;
			int affected_rows = 0;
			SQLite3_result* resultset = NULL;
			std::string q;
			q = "SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE 'mysql-\%' AND variable_name NOT IN ('mysql-threads')";
			if (GloVars.cluster_sync_interfaces == false) {
				q += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_MYSQL);
			}
			q += " ORDER BY variable_name";
			admindb->execute_statement(q.c_str(), &error, &cols, &affected_rows, &resultset);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf, "0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.mysql_variables.set_checksum(buf);
			GloVars.checksums_values.mysql_variables.version++;
			time_t t = time(NULL);
			if (epoch != 0 && checksum != "" && GloVars.checksums_values.mysql_variables.checksum == checksum) {
				GloVars.checksums_values.mysql_variables.epoch = epoch;
			}
			else {
				GloVars.checksums_values.mysql_variables.epoch = t;
			}
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			delete resultset;
		}
		proxy_info(
			"Computed checksum for 'LOAD MYSQL VARIABLES TO RUNTIME' was '%s', with epoch '%llu'\n",
			GloVars.checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.epoch
		);
		*/
	}
	if (resultset) delete resultset;
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
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement2=NULL;

	rc=db->prepare_v2(a, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	if (runtime)  {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(?1, ?2)";

		rc=db->prepare_v2(b, &statement2);
		ASSERT_SQLITE_OK(rc, db);
	}
	if (use_lock) {
		GloMTH->wrlock();
		db->execute("BEGIN");
	}
	char **varnames=GloMTH->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMTH->get_variable(varnames[i]);
		char *qualified_name=(char *)malloc(strlen(varnames[i])+7);
		sprintf(qualified_name, "mysql-%s", varnames[i]);
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
	(*proxy_sqlite3_finalize)(statement1);
	if (runtime)
		(*proxy_sqlite3_finalize)(statement2);
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}

void ProxySQL_Admin::flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing LDAP variables. Replace:%d\n", replace);
	if (GloMyLdapAuth == NULL) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (flush_GENERIC_variables__retrieve__database_to_runtime("ldap", error, cols, affected_rows, resultset) == true) {
		GloMyLdapAuth->wrlock();
		flush_GENERIC_variables__process__database_to_runtime("admin", db, resultset, false, replace, {}, {}, {}, {});
		GloMyLdapAuth->wrunlock();

		// Checksums are always generated - 'admin-checksum_*' deprecated
		{
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_ldap_variables___runtime_to_database(admindb, false, false, false, true);
			flush_GENERIC_variables__checksum__database_to_runtime("ldap", checksum, epoch);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
	}
	if (resultset) delete resultset;
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
  int l=strlen(a)+200;
	GloMyLdapAuth->wrlock();
	char **varnames=GloMyLdapAuth->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMyLdapAuth->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
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
  int l=strlen(a)+200;

	char **varnames=get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		db->execute(query);
		if (runtime) {
			sprintf(query, b, varnames[i], val);
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
