#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include "cpp.h"

#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"

#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=(*proxy_sqlite3_step)(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

extern bool admin_proxysql_mysql_paused;
extern bool admin_proxysql_pgsql_paused;
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication* GloPgAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;
extern PgSQL_Threads_Handler* GloPTH;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern ProxySQL_Cluster *GloProxyCluster;

void ProxySQL_Admin::p_update_metrics() {
	// Update proxysql_uptime
	auto t1 = monotonic_time();
	auto new_uptime = (t1 - GloVars.global.start_time)/1000/1000;
	auto cur_uptime = this->metrics.p_counter_array[p_admin_counter::uptime]->Value();
	this->metrics.p_counter_array[p_admin_counter::uptime]->Increment(new_uptime - cur_uptime);

	// Update memory metrics
	this->p_stats___memory_metrics();
	// Update stmt metrics
	this->p_update_stmt_metrics();

	// updated mysql_listener_paused
	int st = ( admin_proxysql_mysql_paused == true ? 1 : 0);
	this->metrics.p_gauge_array[p_admin_gauge::mysql_listener_paused]->Set(st);

	// updated pgsql_listener_paused
	st = ( admin_proxysql_pgsql_paused == true ? 1 : 0);
	this->metrics.p_gauge_array[p_admin_gauge::pgsql_listener_paused]->Set(st);
}



/**
 * @brief Gets the number of currently opened file descriptors. In case of error '-1' is
 *   returned and error is logged.
 * @return On success, the number of currently opened file descriptors, '-1' otherwise.
 */
int32_t get_open_fds() {
	DIR* dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		proxy_error("'opendir()' failed with error: '%d'\n", errno);
		return -1;
	}

	struct dirent* dp = nullptr;
	int32_t count = -3;

	while ((dp = readdir(dir)) != NULL) {
		count++;
	}

	closedir(dir);

	return count;
}


void ProxySQL_Admin::p_stats___memory_metrics() {
	if (!GloMTH) return;

	// Check that last execution is older than the specified interval
	unsigned long long new_ts = monotonic_time() / 1000 / 1000;
	if (new_ts < last_p_memory_metrics_ts + variables.p_memory_metrics_interval) {
		return;
	}
	// Update the 'memory_metrics' last exec timestamp
	last_p_memory_metrics_ts = new_ts;

	// proxysql_connpool_memory_bytes metric
	const auto connpool_mem = MyHGM->Get_Memory_Stats();
	this->metrics.p_gauge_array[p_admin_gauge::connpool_memory_bytes]->Set(connpool_mem);

	// proxysql_sqlite3_memory_bytes metric
	int highwater = 0;
	int current = 0;
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	this->metrics.p_gauge_array[p_admin_gauge::sqlite3_memory_bytes]->Set(current);

	// proxysql_jemalloc_* memory metrics
	// ===============================================================
	size_t
		allocated = 0,
		resident  = 0,
		active    = 0,
		mapped    = 0,
		metadata  = 0,
		retained  = 0,
		sz        = sizeof(size_t);

#ifndef NOJEM
	mallctl("stats.resident", &resident, &sz, NULL, 0);
	mallctl("stats.active", &active, &sz, NULL, 0);
	mallctl("stats.allocated", &allocated, &sz, NULL, 0);
	mallctl("stats.mapped", &mapped, &sz, NULL, 0);
	mallctl("stats.metadata", &metadata, &sz, NULL, 0);
	mallctl("stats.retained", &retained, &sz, NULL, 0);
#endif // NOJEM

	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_resident]->Set(resident);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_active]->Set(active);
	const auto cur_allocated = this->metrics.p_counter_array[p_admin_counter::jemalloc_allocated]->Value();
	this->metrics.p_counter_array[p_admin_counter::jemalloc_allocated]->Increment(allocated - cur_allocated);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_mapped]->Set(mapped);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_metadata]->Set(metadata);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_retained]->Set(retained);

	// ===============================================================

	// proxysql_auth_memory metric
	unsigned long mu = GloMyAuth->memory_usage();
	this->metrics.p_gauge_array[p_admin_gauge::auth_memory_bytes]->Set(mu);

	// proxysql_query_digest_memory metric
	const auto& query_digest_t_size = GloMyQPro->get_query_digests_total_size();
	this->metrics.p_gauge_array[p_admin_gauge::query_digest_memory_bytes]->Set(query_digest_t_size);

	// mysql_query_rules_memory metric
	const auto& rules_mem_used = GloMyQPro->get_rules_mem_used();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_query_rules_memory_bytes]->Set(rules_mem_used);

	// mysql_firewall_users_table metric
	const auto& firewall_users_table = GloMyQPro->get_firewall_memory_users_table();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_users_table]->Set(firewall_users_table);

	// mysql_firewall_users_config metric
	const auto& firewall_users_config = GloMyQPro->get_firewall_memory_users_config();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_users_config]->Set(firewall_users_config);

	// mysql_firewall_rules_table metric
	const auto& firewall_rules_table = GloMyQPro->get_firewall_memory_rules_table();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_rules_table]->Set(firewall_rules_table);

	// mysql_firewall_rules_table metric
	const auto& firewall_rules_config = GloMyQPro->get_firewall_memory_rules_config();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_rules_config]->Set(firewall_rules_config);

	// proxysql_stack_memory_mysql_threads
	const auto& stack_memory_mysql_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_mysql_threads]->Set(stack_memory_mysql_threads);

	// proxysql_stack_memory_admin_threads
	const auto& stack_memory_admin_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_admin_threads]->Set(stack_memory_admin_threads);

	// proxysql_stack_memory_cluster_threads
	const auto& stack_memory_cluster_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_cluster_threads]->Set(stack_memory_cluster_threads);

	// proxysql_prepare_statement_memory metric
	uint64_t prepare_stmt_metadata_mem_used;
	uint64_t prepare_stmt_backend_mem_used;
	GloMyStmt->get_memory_usage(prepare_stmt_metadata_mem_used, prepare_stmt_backend_mem_used);
	this->metrics.p_gauge_array[p_admin_gauge::prepare_stmt_metadata_memory_bytes]->Set(prepare_stmt_metadata_mem_used);
	this->metrics.p_gauge_array[p_admin_gauge::prepare_stmt_backend_memory_bytes]->Set(prepare_stmt_backend_mem_used);

	// Update opened file descriptors
	int32_t cur_fds = get_open_fds();
	if (cur_fds != -1) {
		this->metrics.p_gauge_array[p_admin_gauge::fds_in_use]->Set(cur_fds);
	}
}


void ProxySQL_Admin::stats___memory_metrics() {
	if (!GloMTH) return;
	SQLite3_result * resultset = NULL;

	int highwater;
	int current;
	char bu[32];
	char *vn=NULL;
	char *query=NULL;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_memory_metrics");
	char *a=(char *)"INSERT INTO stats_memory_metrics VALUES (\"%s\",\"%s\")";
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	vn=(char *)"SQLite3_memory_bytes";
	sprintf(bu,"%d",current);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);
#ifndef NOJEM
	{
		uint64_t epoch = 1;
		size_t allocated = 0, resident = 0, active = 0, mapped = 0 , metadata = 0, retained = 0 , sz = sizeof(size_t);
		mallctl("epoch", &epoch, &sz, &epoch, sz);
		mallctl("stats.resident", &resident, &sz, NULL, 0);
		mallctl("stats.active", &active, &sz, NULL, 0);
		mallctl("stats.allocated", &allocated, &sz, NULL, 0);
		mallctl("stats.mapped", &mapped, &sz, NULL, 0);
		mallctl("stats.metadata", &metadata, &sz, NULL, 0);
		mallctl("stats.retained", &retained, &sz, NULL, 0);
//		float frag_pct = ((float)active / allocated)*100 - 100;
//		size_t frag_bytes = active - allocated;
//		float rss_pct = ((float)resident / allocated)*100 - 100;
//		size_t rss_bytes = resident - allocated;
//		float metadata_pct = ((float)metadata / resident)*100;
		vn=(char *)"jemalloc_resident";
		sprintf(bu,"%lu",resident);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_active";
		sprintf(bu,"%lu",active);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_allocated";
		sprintf(bu,"%lu",allocated);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_mapped";
		sprintf(bu,"%lu",mapped);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_metadata";
		sprintf(bu,"%lu",metadata);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_retained";
		sprintf(bu,"%lu",retained);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
#endif
	{
		if (GloMyAuth) {
			unsigned long mu = GloMyAuth->memory_usage();
			vn=(char *)"Auth_memory";
			sprintf(bu,"%lu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
	}
	{
		if (GloMyQPro) {
			unsigned long long mu = GloMyQPro->get_query_digests_total_size();
			vn=(char *)"mysql_query_digest_memory";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloMyQPro) {
			unsigned long long mu = GloMyQPro->get_rules_mem_used();
			vn=(char *)"mysql_query_rules_memory";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloPgQPro) {
			unsigned long long mu = GloPgQPro->get_query_digests_total_size();
			vn = (char*)"pgsql_query_digest_memory";
			sprintf(bu, "%llu", mu);
			query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
			sprintf(query, a, vn, bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloPgQPro) {
			unsigned long long mu = GloPgQPro->get_rules_mem_used();
			vn = (char*)"pgsql_query_rules_memory";
			sprintf(bu, "%llu", mu);
			query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
			sprintf(query, a, vn, bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloMyStmt) {
			uint64_t prep_stmt_metadata_mem_usage;
			uint64_t prep_stmt_backend_mem_usage;
			GloMyStmt->get_memory_usage(prep_stmt_metadata_mem_usage, prep_stmt_backend_mem_usage);
			vn = (char*)"prepare_statement_metadata_memory";
			sprintf(bu, "%lu", prep_stmt_metadata_mem_usage);
			query=(char*)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query, a, vn, bu);
			statsdb->execute(query);
			free(query);
			vn = (char*)"prepare_statement_backend_memory";
			sprintf(bu, "%lu", prep_stmt_backend_mem_usage);
			query=(char*)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query, a, vn, bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloMyQPro) {
			unsigned long long mu = 0;
			mu = GloMyQPro->get_firewall_memory_users_table();
			vn=(char *)"mysql_firewall_users_table";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloMyQPro->get_firewall_memory_users_config();
			vn=(char *)"mysql_firewall_users_config";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloMyQPro->get_firewall_memory_rules_table();
			vn=(char *)"mysql_firewall_rules_table";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloMyQPro->get_firewall_memory_rules_config();
			vn=(char *)"mysql_firewall_rules_config";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
	}
	{
		unsigned long mu;
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads,0);
		vn=(char *)"stack_memory_mysql_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads,0);
		vn=(char *)"stack_memory_admin_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads,0);
		vn=(char *)"stack_memory_cluster_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
}

void ProxySQL_Admin::p_update_stmt_metrics() {
	if (GloMyStmt) {
		uint64_t stmt_client_active_unique { 0 };
		uint64_t stmt_client_active_total { 0 };
		uint64_t stmt_max_stmt_id { 0 };
		uint64_t stmt_cached { 0 };
		uint64_t stmt_server_active_unique { 0 };
		uint64_t stmt_server_active_total { 0 };
		GloMyStmt->get_metrics(
			&stmt_client_active_unique,
			&stmt_client_active_total,
			&stmt_max_stmt_id,
			&stmt_cached,
			&stmt_server_active_unique,
			&stmt_server_active_total
		);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_client_active_total]->Set(stmt_client_active_total);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_client_active_unique]->Set(stmt_client_active_unique);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_server_active_total]->Set(stmt_server_active_total);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_server_active_unique]->Set(stmt_server_active_unique);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_max_stmt_id]->Set(stmt_max_stmt_id);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_cached]->Set(stmt_cached);
	}
}

void ProxySQL_Admin::stats___mysql_global() {
	if (!GloMTH) return;
	SQLite3_result * resultset=GloMTH->SQL3_GlobalStatus(true);
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_global");
	char *a=(char *)"INSERT INTO stats_mysql_global VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<2; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	delete resultset;
	resultset=NULL;

	resultset=MyHGM->SQL3_Get_ConnPool_Stats();
	if (resultset) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int arg_len=0;
			for (int i=0; i<2; i++) {
				arg_len+=strlen(r->fields[i]);
			}
			char *query=(char *)malloc(strlen(a)+arg_len+32);
			sprintf(query,a,r->fields[0],r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset=NULL;
	}

	int highwater;
	int current;
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	char bu[32];
	char *vn=NULL;
	char *query=NULL;
	vn=(char *)"SQLite3_memory_bytes";
	sprintf(bu,"%d",current);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);

	unsigned long long connpool_mem=MyHGM->Get_Memory_Stats();
	vn=(char *)"ConnPool_memory_bytes";
	sprintf(bu,"%llu",connpool_mem);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);

	if (GloMyStmt) {
		uint64_t stmt_client_active_unique = 0;
		uint64_t stmt_client_active_total = 0;
		uint64_t stmt_max_stmt_id = 0;
		uint64_t stmt_cached = 0;
		uint64_t stmt_server_active_unique = 0;
		uint64_t stmt_server_active_total = 0;
		GloMyStmt->get_metrics(&stmt_client_active_unique,&stmt_client_active_total,&stmt_max_stmt_id,&stmt_cached,&stmt_server_active_unique,&stmt_server_active_total);
		vn=(char *)"Stmt_Client_Active_Total";
		sprintf(bu,"%lu",stmt_client_active_total);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Client_Active_Unique";
		sprintf(bu,"%lu",stmt_client_active_unique);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Server_Active_Total";
		sprintf(bu,"%lu",stmt_server_active_total);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Server_Active_Unique";
		sprintf(bu,"%lu",stmt_server_active_unique);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Max_Stmt_id";
		sprintf(bu,"%lu",stmt_max_stmt_id);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Cached";
		sprintf(bu,"%lu",stmt_cached);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}

	if (GloQC && (resultset=GloQC->SQL3_getStats())) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int arg_len=0;
			for (int i=0; i<2; i++) {
				arg_len+=strlen(r->fields[i]);
			}
			char *query=(char *)malloc(strlen(a)+arg_len+32);
			sprintf(query,a,r->fields[0],r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset=NULL;
	}

	if (GloMyLdapAuth) {
		resultset=GloMyLdapAuth->SQL3_getStats();
		if (resultset) {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int arg_len=0;
				for (int i=0; i<2; i++) {
					arg_len+=strlen(r->fields[i]);
				}
				char *query=(char *)malloc(strlen(a)+arg_len+32);
				sprintf(query,a,r->fields[0],r->fields[1]);
				statsdb->execute(query);
				free(query);
			}
			delete resultset;
			resultset=NULL;
		}
	}

	if (GloMyQPro) {
		unsigned long long mu = GloMyQPro->get_new_req_conns_count();
		vn=(char *)"new_req_conns_count";
		sprintf(bu,"%llu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
	{
		vn=(char *)"mysql_listener_paused";
		sprintf(bu, "%s", ( admin_proxysql_mysql_paused==true ? "true" : "false") );
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
}

void ProxySQL_Admin::stats___pgsql_global() {
	if (!GloPTH) return;
	SQLite3_result* resultset = GloPTH->SQL3_GlobalStatus(true);
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_global");
	char* a = (char*)"INSERT INTO stats_pgsql_global VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		int arg_len = 0;
		for (int i = 0; i < 2; i++) {
			arg_len += strlen(r->fields[i]);
		}
		char* query = (char*)malloc(strlen(a) + arg_len + 32);
		sprintf(query, a, r->fields[0], r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	delete resultset;
	resultset = NULL;

	resultset = PgHGM->SQL3_Get_ConnPool_Stats();
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			int arg_len = 0;
			for (int i = 0; i < 2; i++) {
				arg_len += strlen(r->fields[i]);
			}
			char* query = (char*)malloc(strlen(a) + arg_len + 32);
			sprintf(query, a, r->fields[0], r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset = NULL;
	}

	int highwater;
	int current;
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	char bu[32];
	char* vn = NULL;
	char* query = NULL;
	vn = (char*)"SQLite3_memory_bytes";
	sprintf(bu, "%d", current);
	query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
	sprintf(query, a, vn, bu);
	statsdb->execute(query);
	free(query);

	unsigned long long connpool_mem = PgHGM->Get_Memory_Stats();
	vn = (char*)"ConnPool_memory_bytes";
	sprintf(bu, "%llu", connpool_mem);
	query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
	sprintf(query, a, vn, bu);
	statsdb->execute(query);
	free(query);

	/*if (GloMyStmt) {
		uint64_t stmt_client_active_unique = 0;
		uint64_t stmt_client_active_total = 0;
		uint64_t stmt_max_stmt_id = 0;
		uint64_t stmt_cached = 0;
		uint64_t stmt_server_active_unique = 0;
		uint64_t stmt_server_active_total = 0;
		GloMyStmt->get_metrics(&stmt_client_active_unique, &stmt_client_active_total, &stmt_max_stmt_id, &stmt_cached, &stmt_server_active_unique, &stmt_server_active_total);
		vn = (char*)"Stmt_Client_Active_Total";
		sprintf(bu, "%lu", stmt_client_active_total);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
		vn = (char*)"Stmt_Client_Active_Unique";
		sprintf(bu, "%lu", stmt_client_active_unique);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
		vn = (char*)"Stmt_Server_Active_Total";
		sprintf(bu, "%lu", stmt_server_active_total);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
		vn = (char*)"Stmt_Server_Active_Unique";
		sprintf(bu, "%lu", stmt_server_active_unique);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
		vn = (char*)"Stmt_Max_Stmt_id";
		sprintf(bu, "%lu", stmt_max_stmt_id);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
		vn = (char*)"Stmt_Cached";
		sprintf(bu, "%lu", stmt_cached);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
	}*/

	if (GloQC && (resultset = GloQC->SQL3_getStats())) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			int arg_len = 0;
			for (int i = 0; i < 2; i++) {
				arg_len += strlen(r->fields[i]);
			}
			char* query = (char*)malloc(strlen(a) + arg_len + 32);
			sprintf(query, a, r->fields[0], r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset = NULL;
	}

	/*if (GloMyLdapAuth) {
		resultset = GloMyLdapAuth->SQL3_getStats();
		if (resultset) {
			for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
				SQLite3_row* r = *it;
				int arg_len = 0;
				for (int i = 0; i < 2; i++) {
					arg_len += strlen(r->fields[i]);
				}
				char* query = (char*)malloc(strlen(a) + arg_len + 32);
				sprintf(query, a, r->fields[0], r->fields[1]);
				statsdb->execute(query);
				free(query);
			}
			delete resultset;
			resultset = NULL;
		}
	}*/

	if (GloPgQPro) {
		unsigned long long mu = GloPgQPro->get_new_req_conns_count();
		vn = (char*)"new_req_conns_count";
		sprintf(bu, "%llu", mu);
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
	}
	{
		vn = (char*)"pgsql_listener_paused";
		sprintf(bu, "%s", (admin_proxysql_pgsql_paused == true ? "true" : "false"));
		query = (char*)malloc(strlen(a) + strlen(vn) + strlen(bu) + 16);
		sprintf(query, a, vn, bu);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
}


void ProxySQL_Admin::stats___mysql_processlist() {
	int rc;
	if (!GloMTH) return;
	mysql_thread___show_processlist_extended = variables.mysql_show_processlist_extended;
	SQLite3_result * resultset=GloMTH->SQL3_Processlist();
	if (resultset==NULL) return;

	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";

	query1 = (char *)"INSERT OR IGNORE INTO stats_mysql_processlist VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";
	query32s = "INSERT OR IGNORE INTO stats_mysql_processlist VALUES " + generate_multi_rows_query(32,16);
	query32 = (char *)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

/* for reference
CREATE TABLE stats_mysql_processlist (
    ThreadID INT NOT NULL,
    SessionID INTEGER PRIMARY KEY,
    user VARCHAR,
    db VARCHAR,
    cli_host VARCHAR,
    cli_port INT,
    hostgroup INT,
    l_srv_host VARCHAR,
    l_srv_port INT,
    srv_host VARCHAR,
    srv_port INT,
    command VARCHAR,
    time_ms INT NOT NULL,
    info VARCHAR,
    status_flags INT,
    extended_info VARCHAR)
*/

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_processlist");

	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_processlist() {
	int rc;
	if (!GloPTH) return;
	pgsql_thread___show_processlist_extended = variables.pgsql_show_processlist_extended;
	SQLite3_result* resultset = GloPTH->SQL3_Processlist();
	if (resultset == NULL) return;

	sqlite3_stmt* statement1 = NULL;
	sqlite3_stmt* statement32 = NULL;

	char* query1 = NULL;
	char* query32 = NULL;
	std::string query32s = "";

	query1 = (char*)"INSERT OR IGNORE INTO stats_pgsql_processlist VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";
	query32s = "INSERT OR IGNORE INTO stats_pgsql_processlist VALUES " + generate_multi_rows_query(32, 16);
	query32 = (char*)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_processlist");

	int row_idx = 0;
	int max_bulk_row_idx = resultset->rows_count / 32;
	max_bulk_row_idx = max_bulk_row_idx * 32;
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r1 = *it;
		int idx = row_idx % 32;
		if (row_idx < max_bulk_row_idx) { // bulk
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 16) + 15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 16) + 15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 16) + 16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc = (*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc = (*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc = (*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_connection_pool(bool _reset) {

	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Connection_Pool(_reset);
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_connection_pool");
	char *a=(char *)"INSERT INTO stats_mysql_connection_pool VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<14; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11],r->fields[12],r->fields[13]);
		statsdb->execute(query);
		free(query);
	}
	if (_reset) {
		statsdb->execute("DELETE FROM stats_mysql_connection_pool_reset");
		statsdb->execute("INSERT INTO stats_mysql_connection_pool_reset SELECT * FROM stats_mysql_connection_pool");
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_connection_pool(bool _reset) {
	if (!PgHGM) return;
	SQLite3_result* resultset = PgHGM->SQL3_Connection_Pool(_reset);
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_connection_pool");
	char* a = (char*)"INSERT INTO stats_pgsql_connection_pool VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		int arg_len = 0;
		for (int i = 0; i < 13; i++) {
			arg_len += strlen(r->fields[i]);
		}
		char* query = (char*)malloc(strlen(a) + arg_len + 32);
		sprintf(query, a, r->fields[0], r->fields[1], r->fields[2], r->fields[3], r->fields[4], r->fields[5], r->fields[6], r->fields[7], r->fields[8], r->fields[9], r->fields[10], r->fields[11], r->fields[12]);
		statsdb->execute(query);
		free(query);
	}
	if (_reset) {
		statsdb->execute("DELETE FROM stats_pgsql_connection_pool_reset");
		statsdb->execute("INSERT INTO stats_pgsql_connection_pool_reset SELECT * FROM stats_pgsql_connection_pool");
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_free_connections() {
	int rc;
	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Free_Connections();
	if (resultset==NULL) return;

	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";

	query1 = (char *)"INSERT INTO stats_mysql_free_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	query32s = "INSERT INTO stats_mysql_free_connections VALUES " + generate_multi_rows_query(32,13);
	query32 = (char *)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_free_connections");

	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // autocommit
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+13, r1->fields[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // mysql_info
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement1, 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc=(*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc=(*proxy_sqlite3_bind_text)(statement1, 9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // autocommit
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc=(*proxy_sqlite3_bind_text)(statement1, 13, r1->fields[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // mysql_info
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	statsdb->execute("COMMIT");
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_free_connections() {
	int rc;
	if (!PgHGM) return;
	SQLite3_result* resultset = PgHGM->SQL3_Free_Connections();
	if (resultset == NULL) return;

	sqlite3_stmt* statement1 = NULL;
	sqlite3_stmt* statement32 = NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char* query1 = NULL;
	char* query32 = NULL;
	std::string query32s = "";

	query1 = (char*)"INSERT INTO stats_pgsql_free_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	query32s = "INSERT INTO stats_pgsql_free_connections VALUES " + generate_multi_rows_query(32, 12);
	query32 = (char*)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_free_connections");

	int row_idx = 0;
	int max_bulk_row_idx = resultset->rows_count / 32;
	max_bulk_row_idx = max_bulk_row_idx * 32;
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r1 = *it;
		int idx = row_idx % 32;
		if (row_idx < max_bulk_row_idx) { // bulk
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 12) + 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 12) + 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 12) + 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			}
			else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 12) + 4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 12) + 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			}
			else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx * 12) + 10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 12) + 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // pgsql_info
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		}
		else { // single row
			rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc = (*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc = (*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			}
			else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc = (*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement1, 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc = (*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc = (*proxy_sqlite3_bind_text)(statement1, 9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc = (*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			}
			else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_text)(statement1, 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc = (*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // pgsql_info
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	statsdb->execute("COMMIT");
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	delete resultset;
}


void ProxySQL_Admin::stats___mysql_commands_counters() {
	if (!GloMyQPro) return;
	SQLite3_result * resultset=GloMyQPro->get_stats_commands_counters();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_commands_counters");
	char *a=(char *)"INSERT INTO stats_mysql_commands_counters VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<15; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11],r->fields[12],r->fields[13],r->fields[14]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_commands_counters() {
	if (!GloPgQPro) return;
	SQLite3_result* resultset = GloPgQPro->get_stats_commands_counters();
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_commands_counters");
	char* a = (char*)"INSERT INTO stats_pgsql_commands_counters VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		int arg_len = 0;
		for (int i = 0; i < 15; i++) {
			arg_len += strlen(r->fields[i]);
		}
		char* query = (char*)malloc(strlen(a) + arg_len + 32);
		sprintf(query, a, r->fields[0], r->fields[1], r->fields[2], r->fields[3], r->fields[4], r->fields[5], r->fields[6], r->fields[7], r->fields[8], r->fields[9], r->fields[10], r->fields[11], r->fields[12], r->fields[13], r->fields[14]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_query_rules() {
	if (!GloMyQPro) return;
	SQLite3_result * resultset=GloMyQPro->get_stats_query_rules();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_query_rules");
	char *a=(char *)"INSERT INTO stats_mysql_query_rules VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<2; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_query_rules() {
	if (!GloPgQPro) return;
	SQLite3_result* resultset = GloPgQPro->get_stats_query_rules();
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_pgsql_query_rules");
	char* a = (char*)"INSERT INTO stats_pgsql_query_rules VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		int arg_len = 0;
		for (int i = 0; i < 2; i++) {
			arg_len += strlen(r->fields[i]);
		}
		char* query = (char*)malloc(strlen(a) + arg_len + 32);
		sprintf(query, a, r->fields[0], r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_servers_checksums() {
	// NOTE: This mutex unlock is required due to a race condition created when:
	//  - One Admin session has the following callstack:
	//      + admin_session_handler -> locks on 'sql_query_global_mutex'
	//          | GenericRefreshStatistics
	//          | stats___proxysql_servers_checksums
	//          | get_stats_proxysql_servers_checksums
	//      + stats_proxysql_servers_checksums -> tries to lock on 'ProxySQL_Cluster_Nodes::mutex'
	//  - One ProxySQL_Cluster thread has the following callstack:
	//      + ProxySQL_Cluster::Update_Node_Checksums
	//      + ProxySQL_Cluster_Nodes::Update_Node_Checksums -> locks on 'ProxySQL_Cluster_Nodes::mutex'
	//        | ProxySQL_Node_Entry::set_checksums
	//      + ProxySQL_Cluster::pull_mysql_query_rules_from_peer -> tries to lock on 'sql_query_global_mutex'
	//  Producing a deadlock scenario between the two threads.
	pthread_mutex_unlock(&this->sql_query_global_mutex);
	SQLite3_result* resultset = GloProxyCluster->get_stats_proxysql_servers_checksums();
	pthread_mutex_lock(&this->sql_query_global_mutex);
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_proxysql_servers_checksums");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_checksums VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		(*proxy_sqlite3_finalize)(statement1);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_servers_metrics() {
	//SQLite3_result * resultset=GloProxyCluster->get_stats_proxysql_servers_metrics();
	//if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_proxysql_servers_metrics");
	SQLite3_result *resultset=NULL;
	resultset=GloProxyCluster->get_stats_proxysql_servers_metrics();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_metrics VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		(*proxy_sqlite3_finalize)(statement1);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_message_metrics(bool reset) {
	SQLite3_result* resultset = proxysql_get_message_stats(reset);
	if (resultset == NULL) return;

	statsdb->execute("BEGIN");
	if (reset) {
		statsdb->execute("DELETE FROM stats_proxysql_message_metrics_reset");
	} else {
		statsdb->execute("DELETE FROM stats_proxysql_message_metrics");
	}

	char* query1 = nullptr;
	char* query32 = nullptr;
	std::string query32s = "";

	if (reset) {
		query1=(char*)"INSERT INTO stats_proxysql_message_metrics_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
		query32s = "INSERT INTO stats_proxysql_message_metrics_reset VALUES " + generate_multi_rows_query(32,7);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char*)"INSERT INTO stats_proxysql_message_metrics VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
		query32s = "INSERT INTO stats_proxysql_message_metrics VALUES " + generate_multi_rows_query(32,7);
		query32 = (char *)query32s.c_str();
	}

	sqlite3_stmt* statement1 = nullptr;
	sqlite3_stmt* statement32 = nullptr;
	int rc = 0;

	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	int row_idx = 0;
	int max_bulk_row_idx = resultset->rows_count/32;
	max_bulk_row_idx = max_bulk_row_idx*32;

	for (SQLite3_row* r1 : resultset->rows) {
		int idx=row_idx%32;

		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // message_id
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // filename
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // line
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // func
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+5, atoll(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen

			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // message_id
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // filename
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // line
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // func
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoll(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen

			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);

	statsdb->execute("COMMIT");
	delete resultset;
}

int ProxySQL_Admin::stats___save_mysql_query_digest_to_sqlite(
	const bool reset, const bool copy, const SQLite3_result *resultset, const umap_query_digest *digest_umap,
	const umap_query_digest_text *digest_text_umap
) {
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	statsdb->execute("DELETE FROM stats_mysql_query_digest_reset");
	statsdb->execute("DELETE FROM stats_mysql_query_digest");
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest_reset VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char *)"INSERT INTO stats_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	}

	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int num_rows = resultset ? resultset->rows_count : digest_umap->size();
	int max_bulk_row_idx = num_rows/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	auto it = resultset ? digest_umap->cend() : digest_umap->cbegin();
	int i = 0;

	time_t __now;
	time(&__now);
	unsigned long long curtime=monotonic_time();
	time_t seen_time;

	// If the function do not receives a resultset, it gets the values directly from the digest_umap
	while (resultset ? i != resultset->rows_count : it != digest_umap->end()) {
		QP_query_digest_stats *qds = (QP_query_digest_stats *)(resultset ? NULL : it->second);
		SQLite3_row *row  = resultset ? resultset->rows[i] : NULL;
		char digest_hex_str[20]; // 2+sizeof(unsigned long long)*2+2
		if (!resultset) {
			sprintf(digest_hex_str, "0x%016llX", (long long unsigned int)qds->digest);
		}
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+1, resultset ? atoll(row->fields[11]) : qds->hid); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+2, resultset ? row->fields[0] : qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+3, resultset ? row->fields[1] : qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+4, resultset ? row->fields[2] : qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+5, resultset ? row->fields[3] : digest_hex_str, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+6, resultset ? row->fields[4] : qds->get_digest_text(digest_text_umap), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+7, resultset ? atoll(row->fields[5]) : qds->count_star); ASSERT_SQLITE_OK(rc, statsdb);
			{
				seen_time = qds != nullptr ? __now - curtime/1000000 + qds->first_seen/1000000 : 0;
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+8, resultset ? atoll(row->fields[6]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			{
				seen_time = qds != nullptr ? __now - curtime/1000000 + qds->last_seen/1000000 : 0;
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+9, resultset ? atoll(row->fields[7]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+10, resultset ? atoll(row->fields[8]) : qds->sum_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+11, resultset ? atoll(row->fields[9]) : qds->min_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+12, resultset ? atoll(row->fields[10]) : qds->max_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+13, resultset ? atoll(row->fields[12]) : qds->rows_affected); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+14, resultset ? atoll(row->fields[13]) : qds->rows_sent); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, resultset ? atoll(row->fields[11]) : qds->hid); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, resultset ? row->fields[0] : qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, resultset ? row->fields[1] : qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, resultset ? row->fields[2] : qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, resultset ? row->fields[3] : digest_hex_str, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, resultset ? row->fields[4] : qds->get_digest_text(digest_text_umap), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, resultset ? atoll(row->fields[5]) : qds->count_star); ASSERT_SQLITE_OK(rc, statsdb);
			{
				seen_time = qds != nullptr ? __now - curtime/1000000 + qds->first_seen/1000000 : 0;
				rc=(*proxy_sqlite3_bind_int64)(statement1, 8, resultset ? atoll(row->fields[6]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			{
				seen_time = qds != nullptr ? __now - curtime/1000000 + qds->last_seen/1000000 : 0;
				rc=(*proxy_sqlite3_bind_int64)(statement1, 9, resultset ? atoll(row->fields[7]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, resultset ? atoll(row->fields[8]) : qds->sum_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 11, resultset ? atoll(row->fields[9]) : qds->min_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 12, resultset ? atoll(row->fields[10]) : qds->max_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 13, resultset ? atoll(row->fields[12]) : qds->rows_affected); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement1, 14, resultset ? atoll(row->fields[13]) : qds->rows_sent); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
#ifdef DEBUG
		if (resultset)
			assert(row_idx == i);
#endif
		row_idx++;
		if (resultset)
			i++;
		else
			it++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	if (reset) {
		if (copy) {
			statsdb->execute("INSERT INTO stats_mysql_query_digest SELECT * FROM stats_mysql_query_digest_reset");
		}
	}
	statsdb->execute("COMMIT");

	return row_idx;
}

int ProxySQL_Admin::stats___mysql_query_digests(bool reset, bool copy) {
	if (!GloMyQPro) return 0;
	SQLite3_result * resultset=NULL;
	if (reset==true) {
		resultset=GloMyQPro->get_query_digests_reset();
	} else {
		resultset=GloMyQPro->get_query_digests();
	}
	if (resultset==NULL) return 0;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	// ALWAYS delete from both tables
	//if (reset) {
		statsdb->execute("DELETE FROM stats_mysql_query_digest_reset");
	//} else {
		statsdb->execute("DELETE FROM stats_mysql_query_digest");
	//}
//	char *a=(char *)"INSERT INTO stats_mysql_query_digest VALUES (%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s,%s,%s,%s,%s)";
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest_reset VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char *)"INSERT INTO stats_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	}

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+1, atoll(r1->fields[11])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+2, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+3, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+4, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+5, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+6, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+7, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+8, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+9, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+10, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+11, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+12, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+14, atoll(r1->fields[13])); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[11])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 12, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement1, 14, atoll(r1->fields[13])); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
/*
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[10],r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9]);
		statsdb->execute(query);
		free(query);
	}
*/
	if (reset) {
		if (copy) {
			statsdb->execute("INSERT INTO stats_mysql_query_digest SELECT * FROM stats_mysql_query_digest_reset");
		}
	}
	statsdb->execute("COMMIT");
	delete resultset;

	return row_idx;
}

int ProxySQL_Admin::stats___mysql_query_digests_v2(bool reset, bool copy, bool use_resultset) {
	if (!GloMyQPro) return 0;
	std::pair<SQLite3_result *, int> res;
	if (reset == true) {
		res=GloMyQPro->get_query_digests_reset_v2(copy, use_resultset);
	} else {
		res=GloMyQPro->get_query_digests_v2(use_resultset);
	}

	if (res.first == NULL)
		return res.second;

	int num_rows = GloAdmin->stats___save_mysql_query_digest_to_sqlite(reset, copy, res.first, NULL, NULL);
	delete res.first;

	return num_rows;
}

int ProxySQL_Admin::stats___pgsql_query_digests_v2(bool reset, bool copy, bool use_resultset) {
	if (!GloPgQPro) return 0;
	std::pair<SQLite3_result*, int> res;
	if (reset == true) {
		res = GloPgQPro->get_query_digests_reset_v2(copy, use_resultset);
	} else {
		res = GloPgQPro->get_query_digests_v2(use_resultset);
	}

	if (res.first == NULL)
		return res.second;

	int num_rows = GloAdmin->stats___save_pgsql_query_digest_to_sqlite(reset, copy, res.first, NULL, NULL);
	delete res.first;

	return num_rows;
}

void ProxySQL_Admin::stats___mysql_client_host_cache(bool reset) {
	if (!GloMyQPro) return;

	SQLite3_result* resultset = GloMTH->get_client_host_cache(reset);
	if (resultset==NULL) return;

	statsdb->execute("BEGIN");

	int rc = 0;
	sqlite3_stmt* statement=NULL;
	char* query = NULL;

	if (reset) {
		query=(char*)"INSERT INTO stats_mysql_client_host_cache_reset VALUES (?1, ?2, ?3)";
	} else {
		query=(char*)"INSERT INTO stats_mysql_client_host_cache VALUES (?1, ?2, ?3)";
	}

	statsdb->execute("DELETE FROM stats_mysql_client_host_cache_reset");
	statsdb->execute("DELETE FROM stats_mysql_client_host_cache");

	rc = statsdb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, statsdb);

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *row = *it;

		rc=(*proxy_sqlite3_bind_text)(statement, 1, row->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, atoll(row->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, atoll(row->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement);
		rc=(*proxy_sqlite3_reset)(statement);
	}

	(*proxy_sqlite3_finalize)(statement);

	if (reset) {
		statsdb->execute("INSERT INTO stats_mysql_client_host_cache SELECT * FROM stats_mysql_client_host_cache_reset");
	}

	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_client_host_cache(bool reset) {
	if (!GloPTH) return;

	SQLite3_result* resultset = GloPTH->get_client_host_cache(reset);
	if (resultset == NULL) return;

	statsdb->execute("BEGIN");

	int rc = 0;
	sqlite3_stmt* statement = NULL;
	char* query = NULL;

	if (reset) {
		query = (char*)"INSERT INTO stats_pgsql_client_host_cache_reset VALUES (?1, ?2, ?3)";
	} else {
		query = (char*)"INSERT INTO stats_pgsql_client_host_cache VALUES (?1, ?2, ?3)";
	}

	statsdb->execute("DELETE FROM stats_pgsql_client_host_cache_reset");
	statsdb->execute("DELETE FROM stats_pgsql_client_host_cache");

	rc = statsdb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, statsdb);

	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* row = *it;

		rc = (*proxy_sqlite3_bind_text)(statement, 1, row->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 2, atoll(row->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 3, atoll(row->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);

		SAFE_SQLITE3_STEP2(statement);
		rc = (*proxy_sqlite3_clear_bindings)(statement);
		rc = (*proxy_sqlite3_reset)(statement);
	}

	(*proxy_sqlite3_finalize)(statement);

	if (reset) {
		statsdb->execute("INSERT INTO stats_pgsql_client_host_cache SELECT * FROM stats_pgsql_client_host_cache_reset");
	}

	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_errors(bool reset) {
	if (!GloMyQPro) return;
	SQLite3_result * resultset=NULL;
	if (reset==true) {
		resultset=MyHGM->get_mysql_errors(true);
	} else {
		resultset=MyHGM->get_mysql_errors(false);
	}
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	if (reset) {
		statsdb->execute("DELETE FROM stats_mysql_errors_reset");
	} else {
		statsdb->execute("DELETE FROM stats_mysql_errors");
	}
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_errors_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_mysql_errors_reset VALUES " + generate_multi_rows_query(32,11);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char *)"INSERT INTO stats_mysql_errors VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_mysql_errors VALUES " + generate_multi_rows_query(32,11);
		query32 = (char *)query32s.c_str();
	}

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+8, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___pgsql_errors(bool reset) {
	if (!PgHGM) return;
	SQLite3_result* resultset = PgHGM->get_pgsql_errors(reset);
	if (resultset == NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt* statement1 = NULL;
	sqlite3_stmt* statement32 = NULL;
	char* query1 = NULL;
	char* query32 = NULL;
	std::string query32s = "";
	if (reset) {
		statsdb->execute("DELETE FROM stats_pgsql_errors_reset");
	}
	else {
		statsdb->execute("DELETE FROM stats_pgsql_errors");
	}
	if (reset) {
		query1 = (char*)"INSERT INTO stats_pgsql_errors_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_pgsql_errors_reset VALUES " + generate_multi_rows_query(32, 11);
		query32 = (char*)query32s.c_str();
	}
	else {
		query1 = (char*)"INSERT INTO stats_pgsql_errors VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_pgsql_errors VALUES " + generate_multi_rows_query(32, 11);
		query32 = (char*)query32s.c_str();
	}

	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx = 0;
	int max_bulk_row_idx = resultset->rows_count / 32;
	max_bulk_row_idx = max_bulk_row_idx * 32;
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r1 = *it;
		int idx = row_idx % 32;
		if (row_idx < max_bulk_row_idx) { // bulk
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 1,  atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // hid
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 2,  r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // hostname
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 3,  atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // port
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 4,  r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // username
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 5,  r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // client_address
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 6,  r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 7,  r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sqlstate
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 8,  atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 9,  atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen
			rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // last_error
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
				rc = (*proxy_sqlite3_reset)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc = (*proxy_sqlite3_bind_int64)(statement1, 1,  atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // hid
			rc = (*proxy_sqlite3_bind_text)(statement1,  2,  r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // hostname
			rc = (*proxy_sqlite3_bind_int64)(statement1, 3,  atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // port
			rc = (*proxy_sqlite3_bind_text)(statement1,  4,  r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // username
			rc = (*proxy_sqlite3_bind_text)(statement1,  5,  r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // client_address
			rc = (*proxy_sqlite3_bind_text)(statement1,  6,  r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // database
			rc = (*proxy_sqlite3_bind_text)(statement1,  7,  r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sqlstate
			rc = (*proxy_sqlite3_bind_int64)(statement1, 8,  atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc = (*proxy_sqlite3_bind_int64)(statement1, 9,  atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc = (*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen
			rc = (*proxy_sqlite3_bind_text)(statement1,  11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // last_error
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_users() {
	account_details_t **ads=NULL;
	statsdb->execute("DELETE FROM stats_mysql_users");

	int num_users=GloMyAuth->dump_all_users(&ads, false);
	if (num_users==0) return;

	const char q[] {
		"INSERT INTO stats_mysql_users(username,frontend_connections,frontend_max_connections) VALUES ('%s',%d,%d)"
	};
	char buf[256] = { 0 };

	for (int i=0; i<num_users; i++) {
		account_details_t *ad=ads[i];
		if (ad->default_hostgroup>= 0) { // only not admin/stats
			cfmt_t q_fmt = cstr_format(buf, q, ad->username, ad->num_connections_used, ad->max_connections);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			} else {
				statsdb->execute(buf);
			}
		}
		free(ad->username);
		free(ad);
	}

	if (GloMyLdapAuth) {
		std::unique_ptr<SQLite3_result> ldap_users { GloMyLdapAuth->dump_all_users() };

		for (const SQLite3_row* row : ldap_users->rows) {
			const char* username = row->fields[LDAP_USER_FIELD_IDX::USERNAME];
			int f_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTEND_CONNECTIONS]);
			int f_max_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTED_MAX_CONNECTIONS]);

			cfmt_t q_fmt = cstr_format(buf, q, username, f_conns, f_max_conns);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			} else {
				statsdb->execute(buf);
			}
		}
	}

	free(ads);
}

void ProxySQL_Admin::stats___pgsql_users() {
	pgsql_account_details_t** ads = NULL;
	statsdb->execute("DELETE FROM stats_pgsql_users");

	int num_users = GloPgAuth->dump_all_users(&ads, false);
	if (num_users == 0) return;

	const char q[] = "INSERT INTO stats_pgsql_users(username,frontend_connections,frontend_max_connections) VALUES ('%s',%d,%d)";

	char buf[256] = { 0 };

	for (int i = 0; i < num_users; i++) {
		pgsql_account_details_t* ad = ads[i];
		if (ad->default_hostgroup >= 0) { // only not admin/stats
			cfmt_t q_fmt = cstr_format(buf, q, ad->username, ad->num_connections_used, ad->max_connections);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			}
			else {
				statsdb->execute(buf);
			}
		}
		free(ad->username);
		free(ad);
	}

	/*if (GloMyLdapAuth) {
		std::unique_ptr<SQLite3_result> ldap_users{ GloMyLdapAuth->dump_all_users() };

		for (const SQLite3_row* row : ldap_users->rows) {
			const char* username = row->fields[LDAP_USER_FIELD_IDX::USERNAME];
			int f_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTEND_CONNECTIONS]);
			int f_max_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTED_MAX_CONNECTIONS]);

			cfmt_t q_fmt = cstr_format(buf, q, username, f_conns, f_max_conns);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			}
			else {
				statsdb->execute(buf);
			}
		}
	}*/

	free(ads);
}

void ProxySQL_Admin::stats___mysql_gtid_executed() {
	statsdb->execute("DELETE FROM stats_mysql_gtid_executed");
	SQLite3_result *resultset=NULL;
	resultset = MyHGM->get_stats_mysql_gtid_executed();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		query1=(char *)"INSERT INTO stats_mysql_gtid_executed VALUES (?1, ?2, ?3, ?4)";
		query32s = "INSERT INTO stats_mysql_gtid_executed VALUES " + generate_multi_rows_query(32,4);
		query32 = (char *)query32s.c_str();

		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
		rc = statsdb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, statsdb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
				if (idx==31) {
					SAFE_SQLITE3_STEP(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
				SAFE_SQLITE3_STEP(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
		delete resultset;
		resultset = NULL;
	}
}

void ProxySQL_Admin::stats___mysql_prepared_statements_info() {
	if (!GloMyStmt) return;
	SQLite3_result * resultset=NULL;
	resultset=GloMyStmt->get_prepared_statements_global_infos();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	statsdb->execute("DELETE FROM stats_mysql_prepared_statements_info");
	query1=(char *)"INSERT INTO stats_mysql_prepared_statements_info VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	query32s = "INSERT INTO stats_mysql_prepared_statements_info VALUES " + generate_multi_rows_query(32,9);
	query32 = (char *)query32s.c_str();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	//rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=sqlite3_bind_int64(statement32, (idx*9)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+5, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+6, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+7, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+8, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+9, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=sqlite3_bind_int64(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 5, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 6, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 7, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 8, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 9, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

int ProxySQL_Admin::stats___save_pgsql_query_digest_to_sqlite(
	const bool reset, const bool copy, const SQLite3_result* resultset, const umap_query_digest* digest_umap,
	const umap_query_digest_text* digest_text_umap
) {
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt* statement1 = NULL;
	sqlite3_stmt* statement32 = NULL;
	char* query1 = NULL;
	char* query32 = NULL;
	std::string query32s = "";
	statsdb->execute("DELETE FROM stats_pgsql_query_digest_reset");
	statsdb->execute("DELETE FROM stats_pgsql_query_digest");
	if (reset) {
		query1 = (char*)"INSERT INTO stats_pgsql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_pgsql_query_digest_reset VALUES " + generate_multi_rows_query(32, 14);
		query32 = (char*)query32s.c_str();
	}
	else {
		query1 = (char*)"INSERT INTO stats_pgsql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_pgsql_query_digest VALUES " + generate_multi_rows_query(32, 14);
		query32 = (char*)query32s.c_str();
	}

	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx = 0;
	int num_rows = resultset ? resultset->rows_count : digest_umap->size();
	int max_bulk_row_idx = num_rows / 32;
	max_bulk_row_idx = max_bulk_row_idx * 32;
	auto it = resultset ? digest_umap->cend() : digest_umap->cbegin();
	int i = 0;

	time_t __now;
	time(&__now);
	unsigned long long curtime = monotonic_time();
	time_t seen_time;

	// If the function do not receives a resultset, it gets the values directly from the digest_umap
	while (resultset ? i != resultset->rows_count : it != digest_umap->end()) {
		QP_query_digest_stats* qds = (QP_query_digest_stats*)(resultset ? NULL : it->second);
		SQLite3_row* row = resultset ? resultset->rows[i] : NULL;
		string digest_hex_str;
		if (!resultset) {
			std::ostringstream digest_stream;
			digest_stream << "0x" << std::hex << qds->digest;
			digest_hex_str = digest_stream.str();
		}
		int idx = row_idx % 32;
		if (row_idx < max_bulk_row_idx) { // bulk
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 1, resultset ? atoll(row->fields[11]) : qds->hid); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 14) + 2, resultset ? row->fields[0] : qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 14) + 3, resultset ? row->fields[1] : qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 14) + 4, resultset ? row->fields[2] : qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 14) + 5, resultset ? row->fields[3] : digest_hex_str.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 14) + 6, resultset ? row->fields[4] : qds->get_digest_text(digest_text_umap), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 7, resultset ? atoll(row->fields[5]) : qds->count_star); ASSERT_SQLITE_OK(rc, statsdb);
			{
				seen_time = qds != nullptr ? __now - curtime / 1000000 + qds->first_seen / 1000000 : 0;
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 8, resultset ? atoll(row->fields[6]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			{
				seen_time = qds != nullptr ? __now - curtime / 1000000 + qds->last_seen / 1000000 : 0;
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 9, resultset ? atoll(row->fields[7]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 10, resultset ? atoll(row->fields[8]) : qds->sum_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 11, resultset ? atoll(row->fields[9]) : qds->min_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 12, resultset ? atoll(row->fields[10]) : qds->max_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 13, resultset ? atoll(row->fields[12]) : qds->rows_affected); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 14) + 14, resultset ? atoll(row->fields[13]) : qds->rows_sent); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		}
		else { // single row
			rc = (*proxy_sqlite3_bind_int64)(statement1, 1, resultset ? atoll(row->fields[11]) : qds->hid); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 2, resultset ? row->fields[0] : qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 3, resultset ? row->fields[1] : qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 4, resultset ? row->fields[2] : qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 5, resultset ? row->fields[3] : digest_hex_str.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 6, resultset ? row->fields[4] : qds->get_digest_text(digest_text_umap), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 7, resultset ? atoll(row->fields[5]) : qds->count_star); ASSERT_SQLITE_OK(rc, statsdb);
			{
				seen_time = qds != nullptr ? __now - curtime / 1000000 + qds->first_seen / 1000000 : 0;
				rc = (*proxy_sqlite3_bind_int64)(statement1, 8, resultset ? atoll(row->fields[6]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			{
				seen_time = qds != nullptr ? __now - curtime / 1000000 + qds->last_seen / 1000000 : 0;
				rc = (*proxy_sqlite3_bind_int64)(statement1, 9, resultset ? atoll(row->fields[7]) : seen_time); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc = (*proxy_sqlite3_bind_int64)(statement1, 10, resultset ? atoll(row->fields[8]) : qds->sum_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 11, resultset ? atoll(row->fields[9]) : qds->min_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 12, resultset ? atoll(row->fields[10]) : qds->max_time); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 13, resultset ? atoll(row->fields[12]) : qds->rows_affected); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc = (*proxy_sqlite3_bind_int64)(statement1, 14, resultset ? atoll(row->fields[13]) : qds->rows_sent); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
#ifdef DEBUG
		if (resultset)
			assert(row_idx == i);
#endif
		row_idx++;
		if (resultset)
			i++;
		else
			it++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	if (reset) {
		if (copy) {
			statsdb->execute("INSERT INTO stats_pgsql_query_digest SELECT * FROM stats_pgsql_query_digest_reset");
		}
	}
	statsdb->execute("COMMIT");

	return row_idx;
}
