#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <cstdlib>
#include <cctype>
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include <cstring>

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
extern PgSQL_Threads_Handler* GloPTH;

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
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, time_t last_seen);
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
	auto [rc1, statement1_unique] = admindb->prepare_v2(a);
	ASSERT_SQLITE_OK(rc1, admindb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
	char * username_buf = (char *)malloc(128);
	char * schemaname_buf = (char *)malloc(256);
	//ui.username = username_buf;
	//ui.schemaname = schemaname_buf;
	static const char user_name_prefix[] = "user_name_";
	static const char schema_name_prefix[] = "shard_name_";
	if (empty==false) {
		memcpy(username_buf, user_name_prefix, sizeof(user_name_prefix));
	} else {
		*username_buf = '\0';
	}
	memcpy(schemaname_buf, schema_name_prefix, sizeof(schema_name_prefix));
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
	auto [rc1, statement1_unique] = admindb->prepare_v2(q1);
	ASSERT_SQLITE_OK(rc1, admindb);
	auto [rc2, statement2_unique] = admindb->prepare_v2(q2);
	ASSERT_SQLITE_OK(rc2, admindb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	sqlite3_stmt *statement2 = statement2_unique.get();
	char hostnamebuf1[32];
	char hostnamebuf2[32];
	char hostnamebuf3[32];
	for (int i=1000; i<2000; i++) {
		snprintf(hostnamebuf1, sizeof(hostnamebuf1), "hostname%d", i*10+1);
		snprintf(hostnamebuf2, sizeof(hostnamebuf2), "hostname%d", i*10+2);
		snprintf(hostnamebuf3, sizeof(hostnamebuf3), "hostname%d", i*10+3);
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
			snprintf(hostnamebuf1, sizeof(hostnamebuf1), "hostname%d", i*10+1);
			snprintf(hostnamebuf2, sizeof(hostnamebuf2), "hostname%d", i*10+2);
			snprintf(hostnamebuf3, sizeof(hostnamebuf3), "hostname%d", i*10+3);
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

template<typename ThreadType>
bool RunWatchdogTest(const char* label, ThreadType* worker, unsigned int poll_timeout) {
	if (!worker) return false;

	if (worker->watchdog_test__simulated_delay_ms > 0 ||
		worker->watchdog_test__missed_heartbeats > 0) {
		proxy_error("Watchdog test already running, please wait for it to finish.\n");
		return false;
	}
	if (poll_timeout == 0) {
		proxy_error("Invalid poll_timeout value: %u\n", poll_timeout);
		return false;
	}

	proxy_info("Starting Watchdog test for %s threads (poll timeout:%u ms)...\n", label, poll_timeout);

	const unsigned int target_missed = GloVars.restart_on_missing_heartbeats;
	const unsigned int time_per_miss_ms = poll_timeout + 1000 + 200;
	const unsigned int total_expected_time_ms = target_missed * time_per_miss_ms;

	worker->watchdog_test__simulated_delay_ms = total_expected_time_ms;
	const unsigned int timeout_ms = static_cast<unsigned int>(total_expected_time_ms * 1.25);

	constexpr unsigned int poll_interval_ms = 200;
	unsigned int waited_ms = 0;
	unsigned int last_missed = 0;
	bool success = false;

	while (waited_ms < timeout_ms) {
		std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
		waited_ms += poll_interval_ms;

		unsigned int missed = worker->watchdog_test__missed_heartbeats;
		if (missed != last_missed) {
			last_missed = missed;
			proxy_info("Watchdog test - Missed heartbeats: %u\n", missed);
		}

		if (success == false && missed == target_missed) {
			success = true;
			break;
		}
	}

	// Clean-up
	worker->watchdog_test__simulated_delay_ms = 0;
	worker->watchdog_test__missed_heartbeats = 0;

	usleep(1000000);

	if (worker->watchdog_test__missed_heartbeats != 0) {
		worker->watchdog_test__simulated_delay_ms = 0;
		worker->watchdog_test__missed_heartbeats = 0;
	}

	if (success) {
		proxy_info("Watchdog test passed. Missed heartbeats: %u\n", target_missed);
	} else {
		proxy_error("Watchdog test failed. Timeout hit before reaching %u missed heartbeats (got: %u)\n",
			target_missed, last_missed);
	}

	return success;
}

bool ProxySQL_Admin::ProxySQL_Test___WatchDog(int type) {
	if (GloVars.restart_on_missing_heartbeats <= 0) {
		proxy_error("Watchdog test is disabled (restart_on_missing_heartbeats is 0)\n");
		return false;
	}

	if (type == 0 && GloMTH && GloMTH->num_threads > 0) {
		if (!RunWatchdogTest("MySQL", GloMTH->mysql_threads[0].worker, GloMTH->variables.poll_timeout)) {
			proxy_error("MySQL Watchdog test failed.\n");
			return false;
		}
	} else if (type == 1 && GloPTH && GloPTH->num_threads > 0) {
		if (!RunWatchdogTest("PgSQL", GloPTH->pgsql_threads[0].worker, GloPTH->variables.poll_timeout)) {
			proxy_error("PgSQL Watchdog test failed.\n");
			return false;
		}
	} else {
		proxy_error("Invalid type %d for ProxySQL_Test___WatchDog\n", type);
		return false;
	}

	return true;
}

namespace {

/**
 * @brief Minimal row projection used by Top-K internal verification.
 *
 * The struct mirrors all user-visible fields returned by
 * `Query_Processor::get_query_digests_topk()` so the DEBUG validator can build
 * a reference result from `get_query_digests()` and compare end-to-end output.
 */
struct query_digest_test_row_t {
	int hid {0};
	std::string schemaname {};
	std::string username {};
	std::string client_address {};
	uint64_t digest {0};
	std::string digest_text {};
	uint32_t count_star {0};
	uint64_t first_seen {0};
	uint64_t last_seen {0};
	uint64_t sum_time {0};
	uint64_t min_time {0};
	uint64_t max_time {0};
	uint64_t rows_affected {0};
	uint64_t rows_sent {0};
};

/**
 * @brief Parse an unsigned integer from SQLite result text.
 *
 * @param value NUL-terminated text representation.
 * @return Parsed value, or `0` for null/empty input.
 */
uint64_t parse_u64_or_zero(const char* value) {
	if (!value || value[0] == '\0') {
		return 0;
	}
	return strtoull(value, nullptr, 0);
}

/**
 * @brief Parse an integer from SQLite result text.
 *
 * @param value NUL-terminated text representation.
 * @return Parsed value, or `0` for null/empty input.
 */
int parse_int_or_zero(const char* value) {
	if (!value || value[0] == '\0') {
		return 0;
	}
	return atoi(value);
}

/**
 * @brief Compute the selected primary sort metric for a digest row.
 *
 * @param row Candidate digest row.
 * @param sort_by Requested primary sort mode.
 * @return Metric value used as first ordering key (descending).
 */
uint64_t query_digest_test_sort_metric(const query_digest_test_row_t& row, query_digest_sort_by_t sort_by) {
	switch (sort_by) {
		case query_digest_sort_by_t::avg_time:
			return row.count_star ? (row.sum_time / row.count_star) : 0;
		case query_digest_sort_by_t::sum_time:
			return row.sum_time;
		case query_digest_sort_by_t::max_time:
			return row.max_time;
		case query_digest_sort_by_t::rows_sent:
			return row.rows_sent;
		case query_digest_sort_by_t::count_star:
		default:
			return row.count_star;
	}
}

/**
 * @brief Deterministic ordering predicate matching Top-K implementation.
 *
 * The ordering keys are intentionally identical to the production comparator
 * used by Query Processor Top-K so the reference calculation is equivalent.
 *
 * @param lhs Left candidate row.
 * @param rhs Right candidate row.
 * @param sort_by Primary sort metric selector.
 * @return true if @p lhs ranks before @p rhs.
 */
bool query_digest_test_better(
	const query_digest_test_row_t& lhs,
	const query_digest_test_row_t& rhs,
	query_digest_sort_by_t sort_by
) {
	const uint64_t lhs_sort = query_digest_test_sort_metric(lhs, sort_by);
	const uint64_t rhs_sort = query_digest_test_sort_metric(rhs, sort_by);
	if (lhs_sort != rhs_sort) {
		return lhs_sort > rhs_sort;
	}
	if (lhs.sum_time != rhs.sum_time) {
		return lhs.sum_time > rhs.sum_time;
	}
	if (lhs.count_star != rhs.count_star) {
		return lhs.count_star > rhs.count_star;
	}
	if (lhs.digest != rhs.digest) {
		return lhs.digest < rhs.digest;
	}
	if (lhs.hid != rhs.hid) {
		return lhs.hid < rhs.hid;
	}
	if (lhs.username != rhs.username) {
		return lhs.username < rhs.username;
	}
	if (lhs.schemaname != rhs.schemaname) {
		return lhs.schemaname < rhs.schemaname;
	}
	return lhs.client_address < rhs.client_address;
}

/**
 * @brief Check substring match over digest text for Top-K reference filters.
 *
 * @param digest_text Candidate digest text.
 * @param needle Requested substring.
 * @param case_sensitive Whether match should be case-sensitive.
 * @return true when @p needle occurs in @p digest_text.
 */
bool query_digest_test_text_matches(
	const std::string& digest_text,
	const std::string& needle,
	bool case_sensitive
) {
	if (needle.empty()) {
		return true;
	}
	if (case_sensitive) {
		return digest_text.find(needle) != std::string::npos;
	}
	for (size_t p = 0; p < digest_text.size(); ++p) {
		size_t i = 0;
		while (i < needle.size() && (p + i) < digest_text.size()) {
			const unsigned char lhs = static_cast<unsigned char>(digest_text[p + i]);
			const unsigned char rhs = static_cast<unsigned char>(needle[i]);
			if (std::tolower(lhs) != std::tolower(rhs)) {
				break;
			}
			++i;
		}
		if (i == needle.size()) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Evaluate whether a row satisfies a Top-K filter set.
 *
 * @param row Input row.
 * @param filters Filter configuration.
 * @return true if all active predicates match.
 */
bool query_digest_test_matches(const query_digest_test_row_t& row, const query_digest_filter_opts_t& filters) {
	if (!filters.schemaname.empty() && row.schemaname != filters.schemaname) {
		return false;
	}
	if (!filters.username.empty() && row.username != filters.username) {
		return false;
	}
	if (filters.hostgroup >= 0 && row.hid != filters.hostgroup) {
		return false;
	}
	if (!filters.match_digest_text.empty() &&
		!query_digest_test_text_matches(row.digest_text, filters.match_digest_text, filters.digest_text_case_sensitive)) {
		return false;
	}
	if (filters.has_digest && row.digest != filters.digest) {
		return false;
	}
	if (filters.min_count > 0 && row.count_star < filters.min_count) {
		return false;
	}
	if (filters.min_avg_time_us > 0) {
		const uint64_t avg_time = row.count_star ? (row.sum_time / row.count_star) : 0;
		if (avg_time < filters.min_avg_time_us) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Build a reference Top-K result from a digest snapshot.
 *
 * This helper replays the production semantics used by
 * `Query_Processor::get_query_digests_topk()`:
 * - apply filters,
 * - compute aggregate match counters,
 * - sort deterministically,
 * - retain `min(max_window, limit + offset)` rows,
 * - apply offset/limit pagination.
 *
 * @param snapshot Immutable digest row snapshot.
 * @param filters Filter set.
 * @param sort_by Primary sort mode.
 * @param limit Requested page size.
 * @param offset Requested page offset.
 * @param max_window Maximum retained Top-K window.
 * @param expected Output reference result.
 */
void query_digest_test_compute_expected(
	const std::vector<query_digest_test_row_t>& snapshot,
	const query_digest_filter_opts_t& filters,
	query_digest_sort_by_t sort_by,
	uint32_t limit,
	uint32_t offset,
	uint32_t max_window,
	query_digest_topk_result_t& expected
) {
	expected = {};
	std::vector<query_digest_test_row_t> matched_rows {};
	matched_rows.reserve(snapshot.size());

	for (const auto& row : snapshot) {
		if (!query_digest_test_matches(row, filters)) {
			continue;
		}
		expected.matched_count++;
		expected.matched_total_queries += row.count_star;
		expected.matched_total_time_us += row.sum_time;
		matched_rows.push_back(row);
	}

	std::sort(matched_rows.begin(), matched_rows.end(),
		[&sort_by](const query_digest_test_row_t& lhs, const query_digest_test_row_t& rhs) -> bool {
			return query_digest_test_better(lhs, rhs, sort_by);
		}
	);

	uint32_t retained_window = limit + offset;
	if (max_window > 0 && retained_window > max_window) {
		retained_window = max_window;
	}
	if (matched_rows.size() > retained_window) {
		matched_rows.resize(retained_window);
	}

	if (offset >= matched_rows.size()) {
		return;
	}

	const size_t begin = static_cast<size_t>(offset);
	const size_t end = std::min(matched_rows.size(), begin + static_cast<size_t>(limit));
	expected.rows.reserve(end > begin ? end - begin : 0);
	for (size_t i = begin; i < end; ++i) {
		const auto& src = matched_rows[i];
		query_digest_topk_row_t dst {};
		dst.hid = src.hid;
		dst.schemaname = src.schemaname;
		dst.username = src.username;
		dst.client_address = src.client_address;
		dst.digest = src.digest;
		dst.digest_text = src.digest_text;
		dst.count_star = src.count_star;
		dst.first_seen = src.first_seen;
		dst.last_seen = src.last_seen;
		dst.sum_time = src.sum_time;
		dst.min_time = src.min_time;
		dst.max_time = src.max_time;
		dst.rows_affected = src.rows_affected;
		dst.rows_sent = src.rows_sent;
		expected.rows.push_back(std::move(dst));
	}
}

/**
 * @brief Compare two epoch second values with a small tolerance.
 *
 * The Top-K API computes timestamps relative to current wall clock and
 * monotonic time. A 1-2 second drift can appear between independent snapshots.
 *
 * @param lhs First epoch value.
 * @param rhs Second epoch value.
 * @return true if absolute difference is <= 2 seconds.
 */
bool query_digest_test_epoch_close(uint64_t lhs, uint64_t rhs) {
	if (lhs > rhs) {
		return (lhs - rhs) <= 2;
	}
	return (rhs - lhs) <= 2;
}

/**
 * @brief Compare a reference row against an actual Top-K row.
 *
 * @param expected Reference row.
 * @param actual Actual row returned by production Top-K API.
 * @return true when all relevant fields match.
 */
bool query_digest_test_row_equal(const query_digest_topk_row_t& expected, const query_digest_topk_row_t& actual) {
	return expected.hid == actual.hid &&
		expected.schemaname == actual.schemaname &&
		expected.username == actual.username &&
		expected.client_address == actual.client_address &&
		expected.digest == actual.digest &&
		expected.digest_text == actual.digest_text &&
		expected.count_star == actual.count_star &&
		query_digest_test_epoch_close(expected.first_seen, actual.first_seen) &&
		query_digest_test_epoch_close(expected.last_seen, actual.last_seen) &&
		expected.sum_time == actual.sum_time &&
		expected.min_time == actual.min_time &&
		expected.max_time == actual.max_time &&
		expected.rows_affected == actual.rows_affected &&
		expected.rows_sent == actual.rows_sent;
}

} // namespace

/**
 * @brief DEBUG-only in-process validator for query digest Top-K semantics.
 *
 * The validator snapshots digest rows using `get_query_digests()`, computes a
 * reference result entirely in test code, then compares it against
 * `QueryDigestTopK<SERVER_TYPE_MYSQL>()` across multiple filter/sort/pagination
 * combinations.
 *
 * @param rounds Number of parameter combinations to verify.
 * @param limit_max Maximum generated `limit` value.
 * @param offset_max Maximum generated `offset` value.
 * @param passed Output count of successful rounds.
 * @param failed Output count of failed rounds.
 * @return true if every round passed.
 */
bool ProxySQL_Admin::ProxySQL_Test___Verify_QueryDigestTopK(
	int rounds,
	int limit_max,
	int offset_max,
	int* passed,
	int* failed
) {
	if (!passed || !failed) {
		return false;
	}
	*passed = 0;
	*failed = 0;

	if (!GloMyQPro) {
		proxy_error("ProxySQL_Test___Verify_QueryDigestTopK: MySQL Query Processor not available\n");
		return false;
	}

	if (rounds <= 0) {
		rounds = 16;
	}
	if (limit_max <= 0) {
		limit_max = 200;
	}
	if (offset_max < 0) {
		offset_max = 200;
	}

	std::unique_ptr<SQLite3_result> snapshot_rs(GloMyQPro->get_query_digests());
	if (!snapshot_rs) {
		proxy_error("ProxySQL_Test___Verify_QueryDigestTopK: unable to snapshot digest rows\n");
		return false;
	}

	std::vector<query_digest_test_row_t> snapshot {};
	snapshot.reserve(snapshot_rs->rows_count);
	for (auto* src : snapshot_rs->rows) {
		if (!src || src->cnt < 14) {
			continue;
		}
		query_digest_test_row_t row {};
		row.schemaname = src->fields[0] ? src->fields[0] : "";
		row.username = src->fields[1] ? src->fields[1] : "";
		row.client_address = src->fields[2] ? src->fields[2] : "";
		row.digest = parse_u64_or_zero(src->fields[3]);
		row.digest_text = src->fields[4] ? src->fields[4] : "";
		row.count_star = static_cast<uint32_t>(parse_u64_or_zero(src->fields[5]));
		row.first_seen = parse_u64_or_zero(src->fields[6]);
		row.last_seen = parse_u64_or_zero(src->fields[7]);
		row.sum_time = parse_u64_or_zero(src->fields[8]);
		row.min_time = parse_u64_or_zero(src->fields[9]);
		row.max_time = parse_u64_or_zero(src->fields[10]);
		row.hid = parse_int_or_zero(src->fields[11]);
		row.rows_affected = parse_u64_or_zero(src->fields[12]);
		row.rows_sent = parse_u64_or_zero(src->fields[13]);
		snapshot.push_back(std::move(row));
	}

	/**
	 * Empty digest map is a valid scenario (e.g. startup). Validate that
	 * Top-K also returns an empty result and treat it as a passing round.
	 */
	if (snapshot.empty()) {
		const query_digest_filter_opts_t no_filters {};
		const query_digest_topk_result_t actual = QueryDigestTopK<SERVER_TYPE_MYSQL>(
			no_filters, query_digest_sort_by_t::count_star, 10, 0, 10
		);
		if (actual.rows.empty() && actual.matched_count == 0 && actual.matched_total_queries == 0 && actual.matched_total_time_us == 0) {
			*passed = 1;
			return true;
		}
		*failed = 1;
		return false;
	}

	const query_digest_sort_by_t sort_modes[] = {
		query_digest_sort_by_t::count_star,
		query_digest_sort_by_t::avg_time,
		query_digest_sort_by_t::sum_time,
		query_digest_sort_by_t::max_time,
		query_digest_sort_by_t::rows_sent
	};

	for (int round = 0; round < rounds; ++round) {
		const query_digest_test_row_t& seed = snapshot[static_cast<size_t>((round * 17) % snapshot.size())];
		const query_digest_sort_by_t sort_by = sort_modes[round % 5];

		query_digest_filter_opts_t filters {};
		if (round & 0x1) {
			filters.username = seed.username;
		}
		if (round & 0x2) {
			filters.schemaname = seed.schemaname;
		}
		if (round & 0x4) {
			filters.hostgroup = seed.hid;
		}
		if (round % 3 == 0 && !seed.digest_text.empty()) {
			const size_t match_len = std::min<size_t>(12, seed.digest_text.size());
			filters.match_digest_text = seed.digest_text.substr(0, match_len);
			filters.digest_text_case_sensitive = (round % 2 == 0);
		}
		if (round & 0x8) {
			filters.min_count = std::max<uint32_t>(1, seed.count_star / 2);
		}
		if (round & 0x10) {
			filters.min_avg_time_us = seed.count_star ? (seed.sum_time / seed.count_star) : 0;
		}
		if (round % 5 == 0) {
			filters.has_digest = true;
			filters.digest = seed.digest;
		}

		const uint32_t limit = static_cast<uint32_t>((round * 31) % (limit_max + 1));
		const uint32_t offset = static_cast<uint32_t>((round * 43) % (offset_max + 1));
		const uint32_t requested_window = limit + offset;
		uint32_t max_window = 0;
		switch (round % 4) {
			case 0:
				max_window = requested_window;
				break;
			case 1:
				max_window = requested_window > 0 ? requested_window - 1 : 0;
				break;
			case 2:
				max_window = requested_window + 5;
				break;
			case 3:
			default:
				max_window = static_cast<uint32_t>(std::max(1, limit_max / 2));
				break;
		}

		query_digest_topk_result_t expected {};
		query_digest_test_compute_expected(snapshot, filters, sort_by, limit, offset, max_window, expected);

		const query_digest_topk_result_t actual = QueryDigestTopK<SERVER_TYPE_MYSQL>(
			filters, sort_by, limit, offset, max_window
		);

		bool round_ok = true;
		round_ok = round_ok && (expected.matched_count == actual.matched_count);
		round_ok = round_ok && (expected.matched_total_queries == actual.matched_total_queries);
		round_ok = round_ok && (expected.matched_total_time_us == actual.matched_total_time_us);
		round_ok = round_ok && (expected.rows.size() == actual.rows.size());

		const size_t rows_to_check = std::min(expected.rows.size(), actual.rows.size());
		for (size_t i = 0; i < rows_to_check && round_ok; ++i) {
			if (!query_digest_test_row_equal(expected.rows[i], actual.rows[i])) {
				round_ok = false;
			}
		}

		if (round_ok) {
			(*passed)++;
		} else {
			(*failed)++;
			proxy_error(
				"ProxySQL_Test___Verify_QueryDigestTopK failed at round=%d "
				"(sort=%d limit=%u offset=%u max_window=%u expected_rows=%zu actual_rows=%zu)\n",
				round, static_cast<int>(sort_by), limit, offset, max_window, expected.rows.size(), actual.rows.size()
			);
		}
	}

	return (*failed == 0);
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
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(false, false, test_arg1);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 5:
				// purge the digest map, synchronously, in multiple threads
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(false, true, test_arg1);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
				run_query=false;
				break;
			case 6:
				// purge the digest map, asynchronously, in single thread
				r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(true, false, test_arg1);
				SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
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
					snprintf(msg, sizeof(msg), "Tested in %llums\n", d);
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
					run_query=false;
				}
				break;
#ifdef DEBUG
			case 51:
				{
					char msg[256];
					unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup();
					snprintf(msg, sizeof(msg), "Tested in %llums\n", d);
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
					snprintf(msg, sizeof(msg), "Tested in %llums\n", d);
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
					snprintf(msg, sizeof(msg), "Monitor task timeout flag is:%s\n", GloMyMon->proxytest_forced_timeout ? "ON" : "OFF");
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
					snprintf(msg, sizeof(msg), "Took %llums in loading and verifying CA Certificate for %d times\n", static_cast<unsigned long long>(duration), test_arg1);
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
				}
				else {
					SPA->send_error_msg_to_client(sess, (char *)"Unable to verify CA Certificate");
				}
			}
			break;
			case 55:
				// test_arg1: 1 = POSTGRESQL, 0 = MYSQL
				if (SPA->ProxySQL_Test___WatchDog(test_arg1)) {
					SPA->send_ok_msg_to_client(sess, msg, 0, query_no_space);
				} else {
					SPA->send_error_msg_to_client(sess, (char*)"WatchDog test failed");
				}
				run_query = false;
				break;
			case 56:
				{
					/**
					 * Internal validator for in-memory QueryDigestTopK implementation.
					 * Args:
					 *   - test_arg1: rounds (default 16)
					 *   - test_arg2: limit max (default 200)
					 *   - test_arg3: offset max (default 200)
					 */
					if (test_arg1 <= 0) {
						test_arg1 = 16;
					}
					if (test_arg2 <= 0) {
						test_arg2 = 200;
					}
					if (test_arg3 < 0) {
						test_arg3 = 200;
					}

					int passed = 0;
					int failed = 0;
					const bool ok = SPA->ProxySQL_Test___Verify_QueryDigestTopK(
						test_arg1, test_arg2, test_arg3, &passed, &failed
					);

					char test_msg[256];
					snprintf(
						test_msg, sizeof(test_msg),
						"QueryDigestTopK internal test rounds=%d passed=%d failed=%d",
						test_arg1, passed, failed
					);

					if (ok) {
						SPA->send_ok_msg_to_client(sess, test_msg, passed, query_no_space);
					} else {
						SPA->send_error_msg_to_client(sess, test_msg);
					}
					run_query = false;
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
