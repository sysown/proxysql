#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "sqlite3db.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <set>
#include "SpookyV2.h"

using namespace std;

#define SAFE_SQLITE3_STEP2(_stmt) do {\
        do {\
                rc=sqlite3_step(_stmt);\
                if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
                        usleep(100);\
                }\
        } while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)


const char * const variable_names[] = { "Access_Denied_Max_Connections", "Access_Denied_Max_User_Connections", "Access_Denied_Wrong_Password", "Active_Transactions", "Backend_query_time_nsec", "Client_Connections_aborted", "Client_Connections_connected", "Client_Connections_created", "Client_Connections_hostgroup_locked", "Client_Connections_non_idle", "Com_autocommit", "Com_autocommit_filtered", "Com_backend_change_user", "Com_backend_init_db", "Com_backend_set_names", "Com_backend_stmt_close", "Com_backend_stmt_execute", "Com_backend_stmt_prepare", "Com_commit", "Com_commit_filtered", "Com_frontend_init_db", "Com_frontend_set_names", "Com_frontend_stmt_close", "Com_frontend_stmt_execute", "Com_frontend_stmt_prepare", "Com_frontend_use_db", "Com_rollback", "Com_rollback_filtered", "ConnPool_get_conn_failure", "ConnPool_get_conn_immediate", "ConnPool_get_conn_latency_awareness", "ConnPool_get_conn_success", "GTID_consistent_queries", "GTID_session_collected", "Mirror_concurrency", "Mirror_queue_length", "MyHGM_myconnpoll_destroy", "MyHGM_myconnpoll_get", "MyHGM_myconnpoll_get_ok", "MyHGM_myconnpoll_push", "MyHGM_myconnpoll_reset", "MySQL_Monitor_Workers", "MySQL_Monitor_Workers_Aux", "MySQL_Monitor_Workers_Started", "MySQL_Monitor_connect_check_ERR", "MySQL_Monitor_connect_check_OK", "MySQL_Monitor_ping_check_ERR", "MySQL_Monitor_ping_check_OK", "MySQL_Monitor_read_only_check_ERR", "MySQL_Monitor_read_only_check_OK", "MySQL_Monitor_replication_lag_check_ERR", "MySQL_Monitor_replication_lag_check_OK", "MySQL_Thread_Workers", "ProxySQL_Uptime", "Queries_backends_bytes_recv", "Queries_backends_bytes_sent", "Queries_frontends_bytes_recv", "Queries_frontends_bytes_sent", "Query_Processor_time_nsec", "Questions", "Selects_for_update__autocommit0", "Server_Connections_aborted", "Server_Connections_connected", "Server_Connections_created", "Server_Connections_delayed", "Servers_table_version", "Slow_queries", "automatic_detected_sql_injection", "aws_aurora_replicas_skipped_during_query", "backend_lagging_during_query", "backend_offline_during_query", "generated_error_packets", "hostgroup_locked_queries", "hostgroup_locked_set_cmds", "max_connect_timeouts", "mysql_backend_buffers_bytes", "mysql_frontend_buffers_bytes", "mysql_killed_backend_connections", "mysql_killed_backend_queries", "mysql_session_internal_bytes", "mysql_unexpected_frontend_com_quit", "mysql_unexpected_frontend_packets", "queries_with_max_lag_ms", "queries_with_max_lag_ms__delayed", "queries_with_max_lag_ms__total_wait_time_us", "whitelisted_sqli_fingerprint" };

void create_table(SQLite3DB& statsdb) {
	statsdb.execute((char *)"DROP TABLE IF EXISTS history_mysql_status_variables_v2");
	int num_vars = sizeof(variable_names)/sizeof(const char *);
	string query = "CREATE TABLE history_mysql_status_variables_v2 (timestamp INT NOT NULL PRIMARY KEY, ";
	for (int i=0; i<num_vars; i++) {
		query += variable_names[i];
		query += " VARCHAR NOT NULL DEFAULT '',";
	}
	query.pop_back();
	query += ")";
	statsdb.execute(query.c_str());
}

void insert_row(SQLite3DB& statsdb, unordered_map<string,int>& varmap, SQLite3_result *res, uint64_t ts) {
	string query = "INSERT INTO history_mysql_status_variables_v2 VALUES (?1,";
	int num_vars = sizeof(variable_names)/sizeof(const char *);
	vector<bool> present;
	for (int i=0; i<num_vars; i++) {
		query += "?" + to_string(i+2) + ","; // ids start at 1. And 1 is ts, so + 2
	present.push_back(false); // initialization
	}
	query.pop_back();
	query += ")";
    sqlite3_stmt *statement=NULL;
	int rc = statsdb.prepare_v2(query.c_str(), &statement);
	assert(rc==SQLITE_OK);
	for (auto it = res->rows.begin() ; it != res->rows.end(); ++it) {
		SQLite3_row *r=*it;
		auto it2 = varmap.find(r->fields[0]);
		if (it2 != varmap.end()) {
			int id = it2->second; // ids are already offset by 2
			rc=sqlite3_bind_text(statement, id, r->fields[1] , -1, SQLITE_TRANSIENT);
			assert(rc==SQLITE_OK);
			present[id-2] = true;
		}
	}
	for (int i=0; i<num_vars; i++) { // find unassigned variables
		if (present[i] == false) {
			// insert empty string
			rc=sqlite3_bind_text(statement, i+2, (char *)"" , -1, SQLITE_TRANSIENT);
			assert(rc==SQLITE_OK);
		}
	}
	rc=sqlite3_bind_int64(statement, 1, ts);
	assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP2(statement);
	assert(rc==SQLITE_DONE);
	
}


int main() {
	SQLite3DB statsdb;
	statsdb.open((char *)"../src/proxysql_stats.db.2", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	statsdb.execute("PRAGMA synchronous=0");
	int num_vars = sizeof(variable_names)/sizeof(const char *);
	//set<string> varset;
	unordered_map<string,int> varmap;
	for (int i=0; i<num_vars; i++) {
		//varset.insert(variable_names[i]);
		varmap.insert(make_pair(variable_names[i],i+2));
	}
	//for (auto it=varset.begin(); it!=varset.end(); ++it) {
	for (auto it=varmap.begin(); it!=varmap.end(); ++it) {
		cout << it->first << " " << it->second << endl;
	}
	SQLite3_result * timestamps = new SQLite3_result();
	char * error;
	int cols, affected_rows;
	create_table(statsdb);
	statsdb.execute_statement((char *)"SELECT DISTINCT timestamp FROM history_mysql_status_variables", &error, &cols, &affected_rows, &timestamps);
	for (auto it = timestamps->rows.begin() ; it != timestamps->rows.end(); ++it) {
		SQLite3_row *r=*it;
		uint64_t ts = atoll(r->fields[0]);
		//cout << r->fields[0] << endl;
		SQLite3_result * vals_one_time = new SQLite3_result();
		string s = "SELECT variable_name, variable_value FROM history_mysql_status_variables WHERE timestamp = ";
		s += to_string(ts);
		statsdb.execute_statement(s.c_str(), &error, &cols, &affected_rows, &vals_one_time);
		insert_row(statsdb,varmap, vals_one_time, ts);
/*
		for (auto it2 = vals_one_time->rows.begin() ; it2 != vals_one_time->rows.end(); ++it2) {
			SQLite3_row *r=*it2;
			//cout << r->fields[1] << " " << r->fields[2] << endl;
		}
*/
	}
	return EXIT_SUCCESS;
}
