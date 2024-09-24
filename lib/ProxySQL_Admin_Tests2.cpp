#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>

#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

#include "MySQL_Data_Stream.h"

static int int_cmp(const void *a, const void *b) {
	const unsigned long long *ia = (const unsigned long long *)a;
	const unsigned long long *ib = (const unsigned long long *)b;
	if (*ia < *ib) return -1;
	if (*ia > *ib) return 1;
	return 0;
}

extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern MySQL_Monitor *GloMyMon;
extern MySQL_Threads_Handler *GloMTH;

static pthread_mutex_t test_mysql_firewall_whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::unordered_map<std::string, void *> map_test_mysql_firewall_whitelist_rules;
static char rand_del[6] = {0};

static void init_rand_del() {
	if (rand_del[0] == 0) {
		static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		rand_del[0] = '-';
		for (int i = 1; i < 4; i++) {
			rand_del[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}
		rand_del[4] = '-';
		rand_del[5] = 0;
	}
}

int ProxySQL_Test___GetDigestTable(bool reset, bool use_swap);
bool ProxySQL_Test___Refresh_MySQL_Variables(unsigned int cnt);
template<enum SERVER_TYPE>
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg);
int ProxySQL_Test___GenerateRandomQueryInDigestTable(int n);

void ProxySQL_Admin::map_test_mysql_firewall_whitelist_rules_cleanup() {
	for (std::unordered_map<std::string, void*>::iterator it = map_test_mysql_firewall_whitelist_rules.begin(); it != map_test_mysql_firewall_whitelist_rules.end(); ++it) {
		PtrArray* myptrarray = (PtrArray*)it->second;
		delete myptrarray;
	}
	map_test_mysql_firewall_whitelist_rules.clear();
}

bool ProxySQL_Admin::ProxySQL_Test___Load_MySQL_Whitelist(int *ret1, int *ret2, int cmd, int loops) {
	// cmd == 1 : populate the structure with a global mutex
	// cmd == 2 : perform lookup with a global mutex
	// cmd == 3 : perform lookup with a mutex for each call
	// cmd == 4 : populate the structure with a global mutex , but without cleaning up
	// all accept an extra argument that is the number of loops
	char *q = (char *)"SELECT * FROM mysql_firewall_whitelist_rules ORDER BY RANDOM()";
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	bool ret = true;
	int _ret1 = 0;
	// cleanup
	if (cmd == 1 || cmd == 2 || cmd == 4) {
		pthread_mutex_lock(&test_mysql_firewall_whitelist_mutex);
	}
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	init_rand_del();
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return false;
	} else {
		*ret1 = resultset->rows_count;
		int loop = 0;
		//if (cmd == 1) {
		//	loop = loops -1;
		//}
		for ( ; loop < loops ; loop++) {
			_ret1 = 0;
			if (cmd == 1) {
				for (std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin() ; it != map_test_mysql_firewall_whitelist_rules.end(); ++it) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					delete myptrarray;
				}
				map_test_mysql_firewall_whitelist_rules.clear();
			}
			if (cmd == 4) {
				for (std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin() ; it != map_test_mysql_firewall_whitelist_rules.end(); ++it) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					myptrarray->reset();
				}
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int active = atoi(r->fields[0]);
				if (active == 0) {
					continue;
				}
				char * username = r->fields[1];
				char * client_address = r->fields[2];
				char * schemaname = r->fields[3];
				char * flagIN = r->fields[4];
				char * digest_hex = r->fields[5];
				unsigned long long digest_num = strtoull(digest_hex,NULL,0);
				string s = username;
				s += rand_del;
				s += client_address;
				s += rand_del;
				s += schemaname;
				s += rand_del;
				s += flagIN;
				std::unordered_map<std::string, void *>:: iterator it2;
				if (cmd == 1 || cmd == 4) {
					it2 = map_test_mysql_firewall_whitelist_rules.find(s);
					if (it2 != map_test_mysql_firewall_whitelist_rules.end()) {
						PtrArray * myptrarray = (PtrArray *)it2->second;
						myptrarray->add((void *)digest_num);
					} else {
						PtrArray * myptrarray = new PtrArray();
						myptrarray->add((void *)digest_num);
						map_test_mysql_firewall_whitelist_rules[s] = (void *)myptrarray;
						//proxy_info("Inserted key: %s\n" , s.c_str());
					}
				} else if (cmd == 2 || cmd == 3) {
					if (cmd == 3) {
						pthread_mutex_lock(&test_mysql_firewall_whitelist_mutex);
					}
					it2 = map_test_mysql_firewall_whitelist_rules.find(s);
					if (it2 != map_test_mysql_firewall_whitelist_rules.end()) {
						PtrArray * myptrarray = (PtrArray *)it2->second;
						void * r = bsearch(&digest_num, myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
						if (r) _ret1++;
					} else {
						//proxy_error("Not found: %s %s %s %s\n", username, client_address, schemaname, flagIN);
						proxy_error("Not found: %s\n", s.c_str());
					}
					if (cmd == 3) {
						pthread_mutex_unlock(&test_mysql_firewall_whitelist_mutex);
					}
				}
			}
			if (cmd == 1 || cmd == 4) {
				std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin();
				while (it != map_test_mysql_firewall_whitelist_rules.end()) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					switch (cmd) {
						case 1:
							qsort(myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
							it++;
							break;
						case 4:
							if (myptrarray->len) {
								qsort(myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
								it++;
							} else {
								delete myptrarray;
								it = map_test_mysql_firewall_whitelist_rules.erase(it);
							}
							break;
						default:
							break;
					}
				}
			}
		}
	}
	if (cmd == 2 || cmd == 3) {
		*ret2 = _ret1;
	}
	if (resultset) delete resultset;
	if (cmd == 1 || cmd == 2 || cmd == 4) {
		pthread_mutex_unlock(&test_mysql_firewall_whitelist_mutex);
	}
	return ret;
}

// if dual is not 0 , we call the new search algorithm
bool ProxySQL_Admin::ProxySQL_Test___Verify_mysql_query_rules_fast_routing(
	int *ret1, int *ret2, int cnt, int dual, int ths, bool lock, bool maps_per_thread
) {
	// A thread param of '0' is equivalent to not testing
	if (ths == 0) { ths = 1; }
	char *q = (char *)"SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()";

	bool ret = true;
	int matching_rows = 0;

	SQLite3_result *resultset=NULL;
	{
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);

		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			*ret1 = -1;
			return false;
		}
	}
	*ret2 = resultset->rows_count;

	char *query2=(char *)"SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM main.mysql_query_rules_fast_routing ORDER BY username, schemaname, flagIN";
	SQLite3_result* resultset2 = nullptr;

	if (maps_per_thread) {
		char* error2 = nullptr;
		int cols2 = 0;
		int affected_rows2 = 0;
		admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);

		if (error2) {
			proxy_error("Error on %s : %s\n", query2, error2);
			return false;
		}
	}

	vector<uint32_t> results(ths, 0);
	vector<fast_routing_hashmap_t> th_hashmaps {};

	if (maps_per_thread) {
		for (uint32_t i = 0; i < static_cast<uint32_t>(ths); i++) {
			th_hashmaps.push_back(GloMyQPro->create_fast_routing_hashmap(resultset2));
		}
	}

	const auto perform_searches =
		[&results,&dual](khash_t(khStrInt)* hashmap, SQLite3_result* resultset, uint32_t pos, bool lock) -> void
	{
		uint32_t matching_rows = 0;

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int dest_HG = atoi(r->fields[3]);
			int ret_HG = -1;
			if (dual) {
				ret_HG = GloMyQPro->testing___find_HG_in_mysql_query_rules_fast_routing_dual(
					hashmap, r->fields[0], r->fields[1], atoi(r->fields[2]), lock
				);
			} else {
				ret_HG = GloMyQPro->testing___find_HG_in_mysql_query_rules_fast_routing(
					r->fields[0], r->fields[1], atoi(r->fields[2])
				);
			}

			if (dest_HG == ret_HG) {
				matching_rows++;
			}
		}

		results[pos] = matching_rows;
	};

	proxy_info("Test with params - cnt: %d, threads: %d, lock: %d, maps_per_thread: %d\n", cnt, ths, lock, maps_per_thread);

	unsigned long long curtime1 = monotonic_time() / 1000;
	std::vector<std::thread> workers {};

	for (int i = 0; i < ths; i++) {
		khash_t(khStrInt)* hashmap = maps_per_thread ? th_hashmaps[i].rules_fast_routing : nullptr;
		workers.push_back(std::thread(perform_searches, hashmap, resultset, i, lock));
	}

	for (std::thread& w : workers) {
		w.join();
	}

	matching_rows = results[0];
	if (matching_rows != resultset->rows_count) {
		ret = false;
	}
	*ret1 = matching_rows;

	if (ret == true) {
		if (cnt > 1) {
			for (int i=1 ; i < cnt; i++) {
				std::vector<std::thread> workers {};

				for (int i = 0; i < ths; i++) {
					khash_t(khStrInt)* hashmap = maps_per_thread ? th_hashmaps[i].rules_fast_routing : nullptr;
					workers.push_back(std::thread(perform_searches, hashmap, resultset, i, lock));
				}

				for (std::thread& w : workers) {
					w.join();
				}
			}
		}
	}

	unsigned long long curtime2 = monotonic_time() / 1000;
	uint32_t total_maps_size = 0;

	for (const fast_routing_hashmap_t& hashmap : th_hashmaps) {
		total_maps_size += hashmap.rules_fast_routing___keys_values___size;
		total_maps_size += kh_size(hashmap.rules_fast_routing) * ((sizeof(int) + sizeof(char *) + 4));

		kh_destroy(khStrInt, hashmap.rules_fast_routing);
		free(hashmap.rules_fast_routing___keys_values);
	}

	proxy_info("Test took %llums\n", curtime2 - curtime1);
	proxy_info("Verified rows %d\n", results[0]);
	proxy_info("Total maps size %dkb\n", total_maps_size / 1024);

	if (resultset) delete resultset;
	if (resultset2) delete resultset2;

	return ret;
}

unsigned int ProxySQL_Admin::ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(unsigned int cnt, bool empty) {
	char *a = (char *)"INSERT OR IGNORE INTO mysql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, '')";
	int rc;
	sqlite3_stmt *statement1=NULL;
	rc=admindb->prepare_v2(a, &statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
	char * username_buf = (char *)malloc(128);
	char * schemaname_buf = (char *)malloc(256);
	//ui.username = username_buf;
	//ui.schemaname = schemaname_buf;
	if (empty==false) {
		strcpy(username_buf,"user_name_");
	} else {
		strcpy(username_buf,"");
	}
	strcpy(schemaname_buf,"shard_name_");
	int _k;
	for (unsigned int i=0; i<cnt; i++) {
		_k = fastrand()%117 + 1;
		if (empty == false) {
			for (int _i=0 ; _i<_k ; _i++) {
				int b = fastrand()%10;
				username_buf[10+_i]='0' + b;
			}
			username_buf[10+_k]='\0';
		}
		_k = fastrand()%244+ 1;
		for (int _i=0 ; _i<_k ; _i++) {
			int b = fastrand()%10;
			schemaname_buf[11+_i]='0' + b;
		}
		schemaname_buf[11+_k]='\0';
		int flagIN = fastrand()%20;
		int destHG = fastrand()%100;
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, username_buf, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, schemaname_buf, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, flagIN); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, destHG); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement1);
		if ((*proxy_sqlite3_changes)(admindb->get_db())==0) {
			i--;
		}
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	}
	(*proxy_sqlite3_finalize)(statement1);
	free(username_buf);
	free(schemaname_buf);
	return cnt;
}

void ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters() {
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 10001 AND 20000");
	admindb->execute("DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup BETWEEN 10001 AND 20000");
	char *q1 = (char *)"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (?1, ?2, ?3), (?4, ?5, ?6), (?7, ?8, ?9)";
	char *q2 = (char *)"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup) VALUES (?1, ?2)";
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement2=NULL;
	rc=admindb->prepare_v2(q1, &statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	rc=admindb->prepare_v2(q2, &statement2);
	ASSERT_SQLITE_OK(rc, admindb);
	char hostnamebuf1[32];
	char hostnamebuf2[32];
	char hostnamebuf3[32];
	for (int i=1000; i<2000; i++) {
		sprintf(hostnamebuf1,"hostname%d", i*10+1);
		sprintf(hostnamebuf2,"hostname%d", i*10+2);
		sprintf(hostnamebuf3,"hostname%d", i*10+3);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 1, i*10+1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, hostnamebuf1, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, 3306); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 5, hostnamebuf2, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 6, 3306); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 7, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 8, hostnamebuf3, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 9, 3306); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_bind_int64)(statement2, 1, i*10+1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement2, 2, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement2);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, admindb);
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement2);
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
}
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_read_only_action() {
	// we immediately exit. This is just for developer
	return 0;
	ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters();
	char hostnamebuf1[32];
	char hostnamebuf2[32];
	char hostnamebuf3[32];
	unsigned long long t1 = monotonic_time();
	//for (int j=0 ; j<500; j++) {
	for (int j=0 ; j<1000; j++) {
		for (int i=1000; i<2000; i++) {
			sprintf(hostnamebuf1,"hostname%d", i*10+1);
			sprintf(hostnamebuf2,"hostname%d", i*10+2);
			sprintf(hostnamebuf3,"hostname%d", i*10+3);
			MyHGM->read_only_action_v2( std::list<read_only_server_t> {
										read_only_server_t { std::string(hostnamebuf1), 3306, 0 },
										read_only_server_t { std::string(hostnamebuf2), 3306, 1 },
										read_only_server_t { std::string(hostnamebuf3), 3306, 1 }
										} );
		}
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}

#ifdef DEBUG
// NEVER USED THIS FUNCTION IN PRODUCTION.
// THIS IS FOR TESTING PURPOSE ONLY
// IT ACCESSES MyHGM without lock
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup() {
	// we immediately exit. This is just for developer
	return 0;
	ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters();
	unsigned long long t1 = monotonic_time();
	unsigned int hid = 0;
	MyHGC * myhgc = NULL;
	for (int j=0 ; j<100000; j++) {
		for (unsigned int i=1000; i<2000; i++) {
			// NEVER USED THIS FUNCTION IN PRODUCTION.
			// THIS IS FOR TESTING PURPOSE ONLY
			// IT ACCESSES MyHGM without lock
			hid = i*10+1; // writer hostgroup
			myhgc = MyHGM->MyHGC_lookup(hid);
			assert(myhgc);
			hid++; // reader hostgroup
			myhgc = MyHGM->MyHGC_lookup(hid);
			assert(myhgc);
		}
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}

// NEVER USED THIS FUNCTION IN PRODUCTION.
// THIS IS FOR TESTING PURPOSE ONLY
// IT ACCESSES MyHGM without lock
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_Balancing_HG5211() {
	unsigned long long t1 = monotonic_time();
	const unsigned int NS = 4;
	unsigned int cu[NS] = { 50, 10, 10, 0 };
	MyHGC * myhgc = NULL;
	myhgc = MyHGM->MyHGC_lookup(5211);
	assert(myhgc);
	assert(myhgc->mysrvs->servers->len == NS);
	unsigned int cnt[NS];
	for (unsigned int i=0; i<NS; i++) {
		cnt[i]=0;
	}
	for (unsigned int i=0; i<NS; i++) {
		MySrvC * m = (MySrvC *)myhgc->mysrvs->servers->index(i);
		m->ConnectionsUsed->conns->len=cu[i];
	}
	unsigned int NL = 1000;
	for (unsigned int i=0; i<NL; i++) {
		MySrvC * mysrvc = myhgc->get_random_MySrvC(NULL, 0, -1, NULL);
		assert(mysrvc);
		for (unsigned int k=0; k<NS; k++) {
			MySrvC * m = (MySrvC *)myhgc->mysrvs->servers->index(k);
			if (m == mysrvc)
				cnt[k]++;
		}
	}
	{
		unsigned int tc = 0;
		for (unsigned int k=0; k<NS; k++) {
			tc += cnt[k];
		}
		assert(tc == NL);
	}
	for (unsigned int k=0; k<NS; k++) {
		proxy_info("Balancing_HG5211: server %u, cnt: %u\n", k, cnt[k]);
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}

bool ProxySQL_Admin::ProxySQL_Test___CA_Certificate_Load_And_Verify(uint64_t* duration, int cnt, const char* cacert, const char* capath)
{
	assert(duration);
	assert(cacert || capath);
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	uint64_t t1 = monotonic_time();
	for (int i = 0; i < cnt; i++) {
		if (0 == SSL_CTX_load_verify_locations(ctx, cacert, capath)) {
			proxy_error("Unable to load CA Certificate: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return false;
		}
	}
	uint64_t t2 = monotonic_time();
	SSL_CTX_free(ctx);
	*duration = ((t2/1000) - (t1/1000));
	proxy_info("Duration: %lums\n", *duration);
	return true;
}
#endif //DEBUG


/*
Explicit Instantiation:
If the function template is used with specific template arguments in multiple
source files, we must explicitly instantiate the template for those arguments
in the source file where the function is defined. This ensures that the
compiler generates the necessary code for those template instantiations
*/
template void ProxySQL_Admin::ProxySQL_Test_Handler<MySQL_Session>(ProxySQL_Admin*, MySQL_Session*, char*, bool&);
template void ProxySQL_Admin::ProxySQL_Test_Handler<PgSQL_Session>(ProxySQL_Admin*, PgSQL_Session*, char*, bool&);

template<typename S>
void ProxySQL_Admin::ProxySQL_Test_Handler(ProxySQL_Admin *SPA, S* sess, char *query_no_space, bool& run_query) {
	if constexpr (std::is_same_v<S, MySQL_Session>) {
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
	} else {
		assert(0);
	}
	int test_n = 0;
	int test_arg1 = 0;
	int test_arg2 = 0;
	int test_arg3 = -1;
	int test_arg4 = -1;
	int r1 = 0;
	proxy_warning("Received PROXYSQLTEST command: %s\n", query_no_space);
	char *msg = NULL;
	sscanf(query_no_space+strlen("PROXYSQLTEST "),"%d %d %d %d %d", &test_n, &test_arg1, &test_arg2, &test_arg3, &test_arg4);
	if (test_n) {
		switch (test_n) {
			case 1:
				// generate test_arg1*1000 entries in digest map
				if (test_arg1==0) {
					test_arg1=1;
				}
				r1 = ProxySQL_Test___GenerateRandomQueryInDigestTable(test_arg1);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 2:
				// get all the entries from the digest map, but without writing to DB
				// it uses multiple threads
				r1 = ProxySQL_Test___GetDigestTable(false, false);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 3:
				// get all the entries from the digest map and reset, but without writing to DB
				// it uses multiple threads
				r1 = ProxySQL_Test___GetDigestTable(true, false);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 4:
				// purge the digest map, synchronously, in single thread
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(false, false, NULL);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 5:
				// purge the digest map, synchronously, in multiple threads
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(false, true, NULL);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 6:
				// purge the digest map, asynchronously, in single thread
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(true, false, &msg);
				SPA->send_ok_msg_to_client(sess, msg, r1, query_no_space);
				free(msg);
				run_query=false;
				break;
			case 7:
				// get all the entries from the digest map and reset, but without writing to DB
				// it uses multiple threads
				// it locks for a very short time and doesn't use SQLite3_result, but swap
				r1 = ProxySQL_Test___GetDigestTable(true, true);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 8:
				// get all the entries from the digest map and reset, AND write to DB
				r1 = SPA->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(SPA->statsdb_disk);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 11: // generate username
			case 15: // no username, empty string
				// generate random mysql_query_rules_fast_routing
				if (test_arg1==0) {
					test_arg1=10000;
				}
				if (test_n==15) {
					r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, true);
				} else {
					r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, false);
				}
				SPA->send_ok_msg_to_client(sess, (char *)"Generated new mysql_query_rules_fast_routing table", r1, query_no_space);
				run_query=false;
				break;
			case 12: // generate username
			case 16: // no username, empty string
				// generate random mysql_query_rules_fast_routing and LOAD TO RUNTIME
				if (test_arg1==0) {
					test_arg1=10000;
				}
				if (test_n==16) {
					r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, true);
				} else {
					r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, false);
				}
				msg = SPA->load_mysql_query_rules_to_runtime();
				if (msg==NULL) {
					SPA->send_ok_msg_to_client(sess, (char *)"Generated new mysql_query_rules_fast_routing table and loaded to runtime", r1, query_no_space);
				} else {
					SPA->send_error_msg_to_client(sess, msg);
				}
				run_query=false;
				break;
			case 13:
				// LOAD MYSQL QUERY RULES TO RUNTIME for N times
				if (test_arg1==0) {
					test_arg1=1;
				}
				for (int i=0; i<test_arg1; i++) {
					SPA->load_mysql_query_rules_to_runtime();
				}
				msg = (char *)malloc(128);
				sprintf(msg,"Loaded mysql_query_rules_fast_routing to runtime %d times",test_arg1);
				SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
				run_query=false;
				free(msg);
				break;
			case 14: // old algorithm
			case 17: // perform dual lookup, with and without username
				// Allows to verify and benchmark 'mysql_query_rules_fast_routing'. Every options
				// verifies all 'mysql_query_rules_fast_routing' rules:
				//   - Test num: 14 old algorithm, 17 perform a dual lookup.
				//   - arg1: 1-N Number of times the computation should be repeated.
				//   - arg2: 1-N Number of parallel threads for the test.
				//   - arg3: 1-0 Wether or not to acquire a read_lock before searching in the hashmap.
				//   - arg4: 1-0 Wether or not to create thread specific hashmaps for the search.
				if (test_arg1==0) {
					test_arg1=1;
				}
				// To preserve classic mode
				if (test_arg3 == -1) {
					test_arg3 = 1;
				}
				if (test_arg4 == -1) {
					test_arg4 = 0;
				}
				{
					int ret1, ret2;
					bool bret = SPA->ProxySQL_Test___Verify_mysql_query_rules_fast_routing(
						&ret1, &ret2, test_arg1, (test_n==14 ? 0 : 1), test_arg2, test_arg3, test_arg4
					);
					if (bret) {
						SPA->send_ok_msg_to_client(sess, (char *)"Verified all rules in mysql_query_rules_fast_routing", ret1, query_no_space);
					} else {
						if (ret1==-1) {
							SPA->send_error_msg_to_client(sess, (char *)"Severe error in verifying rules in mysql_query_rules_fast_routing");
						} else {
							msg = (char *)malloc(256);
							sprintf(msg,"Error verifying mysql_query_rules_fast_routing. Found %d rows out of %d", ret1, ret2);
							SPA->send_error_msg_to_client(sess, msg);
							free(msg);
						}
					}
				}
					run_query=false;
				break;
			case 21:
				// refresh mysql variables N*1000 times
				if (test_arg1==0) {
					test_arg1=1;
				}
				test_arg1 *= 1000;
				ProxySQL_Test___Refresh_MySQL_Variables(test_arg1);
				msg = (char *)malloc(128);
				sprintf(msg,"Refreshed MySQL Variables %d times",test_arg1);
				SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
				run_query=false;
				free(msg);
				break;
			case 22:
				// get all the entries from the digest map, but WRITING to DB
				// it uses multiple threads
				// It locks the maps while generating the resultset
				r1 = SPA->stats___mysql_query_digests(false, true);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 23:
				// get all the entries from the digest map, but WRITING to DB
				// it uses multiple threads for creating the resultset
				r1 = SPA->stats___mysql_query_digests_v2(false, false, true);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 24:
				// get all the entries from the digest map, but WRITING to DB
				// Do not create a resultset, uses the digest_umap
				r1 = SPA->stats___mysql_query_digests_v2(false, false, false);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 25:
				// get all the entries from the digest map AND RESET, but WRITING to DB
				// it uses multiple threads
				// It locks the maps while generating the resultset
				r1 = SPA->stats___mysql_query_digests(true, true);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 26:
				// get all the entries from the digest map AND RESET, but WRITING to DB
				// it uses multiple threads for creating the resultset
				r1 = SPA->stats___mysql_query_digests_v2(true, true, true);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 27:
				// get all the entries from the digest map AND RESET, but WRITING to DB
				// Do not create a resultset, uses the digest_umap
				r1 = SPA->stats___mysql_query_digests_v2(true, true, false);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 31:
				{
					if (test_arg1==0) {
						test_arg1=1;
					}
					if (test_arg1 > 4) {
						test_arg1=1;
					}
/*
					if (test_arg1 == 2 || test_arg1 == 3) {
						if (test_arg2 == 0) {
							test_arg2 = 1;
						}
					}
*/
					int ret1;
					int ret2;
					SPA->ProxySQL_Test___Load_MySQL_Whitelist(&ret1, &ret2, test_arg1, test_arg2);
					if (test_arg1==1 || test_arg1==4) {
						SPA->send_ok_msg_to_client(sess, (char *)"Processed all rows from firewall whitelist", ret1, query_no_space);
					} else if (test_arg1==2 || test_arg1==3) {
						if (ret1 == ret2) {
							SPA->send_ok_msg_to_client(sess, (char *)"Verified all rows from firewall whitelist", ret1, query_no_space);
						} else {
							msg = (char *)malloc(256);
							sprintf(msg,"Error verifying firewall whitelist. Found %d entries out of %d", ret2, ret1);
							SPA->send_error_msg_to_client(sess, msg);
							free(msg);
						}
					}
					run_query=false;
				}
				break;
			case 41:
				{
					char msg[256];
					unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_read_only_action();
					sprintf(msg, "Tested in %llums\n", d);
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
					run_query=false;
				}
				break;
#ifdef DEBUG
			case 51:
				{
					char msg[256];
					unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup();
					sprintf(msg, "Tested in %llums\n", d);
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
					run_query=false;
				}
				break;
			case 52:
				{
					char msg[256];
					SPA->mysql_servers_wrlock();
					SPA->admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id=5211");
					SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.2',3306,10000)");
					SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.3',3306,8000)");
					SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.4',3306,8000)");
					SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.5',3306,7000)");
					SPA->load_mysql_servers_to_runtime();
					SPA->mysql_servers_wrunlock();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
					unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_Balancing_HG5211();
					sprintf(msg, "Tested in %llums\n", d);
					SPA->mysql_servers_wrlock();
					SPA->admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id=5211");
					SPA->load_mysql_servers_to_runtime();
					SPA->mysql_servers_wrunlock();
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
					run_query=false;
				}
				break;
			case 53:
				{
					// Test monitor tasks timeout
					// test_arg1: 1 = ON, 0 = OFF
					char msg[256];
					GloMyMon->proxytest_forced_timeout = (test_arg1) ? true : false;
					sprintf(msg, "Monitor task timeout flag is:%s\n", GloMyMon->proxytest_forced_timeout ? "ON" : "OFF");
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
					run_query = false;
				}
				break;
			case 54:
			{
				run_query = false;
				if (test_arg1 == 0) {
					test_arg1 = 1000;
				}
				if (GloMTH->variables.ssl_p2s_ca == NULL &&
					GloMTH->variables.ssl_p2s_capath == NULL) {
					SPA->send_error_msg_to_client(sess, (char *)"'mysql-ssl_p2s_ca' and 'mysql-ssl_p2s_capath' have not been configured");
					break;
				}
				char msg[256];
				uint64_t duration = 0ULL;
				if (SPA->ProxySQL_Test___CA_Certificate_Load_And_Verify(&duration, test_arg1, GloMTH->variables.ssl_p2s_ca,
					GloMTH->variables.ssl_p2s_capath)) {
					sprintf(msg, "Took %lums in loading and verifying CA Certificate for %d times\n", duration, test_arg1);
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
				}
				else {
					SPA->send_error_msg_to_client(sess, (char *)"Unable to verify CA Certificate");
				}
			}
			break;
#endif // DEBUG
			default:
				SPA->send_error_msg_to_client(sess, (char *)"Invalid test");
				run_query=false;
				break;
		}
	} else {
		SPA->send_error_msg_to_client(sess, (char *)"Invalid test");
	}
}
