#include "MySQL_HostGroups_Manager.h"

#ifdef TEST_AURORA
static unsigned long long array_mysrvc_total = 0;
static unsigned long long array_mysrvc_cands = 0;
#endif // TEST_AURORA

extern MySQL_Threads_Handler *GloMTH;

MyHGC::MyHGC(int _hid) {
	hid=_hid;
	mysrvs=new MySrvList(this);
	current_time_now = 0;
	new_connections_now = 0;
	attributes.initialized = false;
	reset_attributes();
	// Uninitialized server defaults. Should later be initialized via 'mysql_hostgroup_attributes'.
	servers_defaults.weight = -1;
	servers_defaults.max_connections = -1;
	servers_defaults.use_ssl = -1;
	num_online_servers.store(0, std::memory_order_relaxed);;
	last_log_time_num_online_servers = 0;
}
	
void MyHGC::reset_attributes() {
	if (attributes.initialized == false) {
		attributes.init_connect = NULL;
		attributes.comment = NULL;
		attributes.ignore_session_variables_text = NULL;
	}
	attributes.initialized = true;
	attributes.configured = false;
	attributes.max_num_online_servers = 1000000;
	attributes.throttle_connections_per_sec = 1000000;
	attributes.autocommit = -1;
	attributes.free_connections_pct = 10;
	attributes.handle_warnings = -1;
	attributes.monitor_slave_lag_when_null = -1;
	attributes.multiplex = true;
	attributes.connection_warming = false;
	free(attributes.init_connect);
	attributes.init_connect = NULL;
	free(attributes.comment);
	attributes.comment = NULL;
	free(attributes.ignore_session_variables_text);
	attributes.ignore_session_variables_text = NULL;
	attributes.ignore_session_variables_json = json();
}
	
MyHGC::~MyHGC() {
	reset_attributes(); // free all memory
	delete mysrvs;
}

MySrvC *MyHGC::get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, MySQL_Session *sess) {
	MySrvC *mysrvc=NULL;
	unsigned int j;
	unsigned int sum=0;
	unsigned int TotalUsedConn=0;
	unsigned int l=mysrvs->cnt();
	static time_t last_hg_log = 0;
#ifdef TEST_AURORA
	unsigned long long a1 = array_mysrvc_total/10000;
	array_mysrvc_total += l;
	unsigned long long a2 = array_mysrvc_total/10000;
	if (a2 > a1) {
		fprintf(stderr, "Total: %llu, Candidates: %llu\n", array_mysrvc_total-l, array_mysrvc_cands);
	}
#endif // TEST_AURORA
	MySrvC *mysrvcCandidates_static[32];
	MySrvC **mysrvcCandidates = mysrvcCandidates_static;
	unsigned int num_candidates = 0;
	bool max_connections_reached = false;
	if (l>32) {
		mysrvcCandidates = (MySrvC **)malloc(sizeof(MySrvC *)*l);
	}
	if (l) {
		//int j=0;
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->myhgc->num_online_servers.load(std::memory_order_relaxed) <= mysrvc->myhgc->attributes.max_num_online_servers) { // number of online servers in HG is within configured range
					if (mysrvc->ConnectionsUsed->conns_length() < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
						if (mysrvc->current_latency_us < (mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000)) { // consider the host only if not too far
							if (gtid_trxid) {
								if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							} else {
								if (max_lag_ms >= 0) {
									if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us / 1000) {
										sum+=mysrvc->weight;
										TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
										mysrvcCandidates[num_candidates]=mysrvc;
										num_candidates++;
									} else {
										sess->thread->status_variables.stvar[st_var_aws_aurora_replicas_skipped_during_query]++;
									}
								} else {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							}
						}
					} else {
						max_connections_reached = true;
					}
				} else {
					mysrvc->myhgc->log_num_online_server_count_error();
				}
			} else {
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED) {
					// try to recover shunned servers
					if (mysrvc->shunned_automatic && mysql_thread___shun_recovery_time_sec) {
						time_t t;
						t=time(NULL);
						// we do all these changes without locking . We assume the server is not used from long
						// even if the server is still in used and any of the follow command fails it is not critical
						// because this is only an attempt to recover a server that is probably dead anyway

						// the next few lines of code try to solve issue #530
						int max_wait_sec = ( mysql_thread___shun_recovery_time_sec * 1000 >= mysql_thread___connect_timeout_server_max ? mysql_thread___connect_timeout_server_max/1000 - 1 : mysql_thread___shun_recovery_time_sec );
						if (max_wait_sec < 1) { // min wait time should be at least 1 second
							max_wait_sec = 1;
						}
						if (t > mysrvc->time_last_detected_error && (t - mysrvc->time_last_detected_error) > max_wait_sec) {
							if (
								(mysrvc->shunned_and_kill_all_connections==false) // it is safe to bring it back online
								||
								(mysrvc->shunned_and_kill_all_connections==true && mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) // if shunned_and_kill_all_connections is set, ensure all connections are already dropped
							) {
#ifdef DEBUG
								if (GloMTH->variables.hostgroup_manager_verbose >= 3) {
									proxy_info("Unshunning server %s:%d.\n", mysrvc->address, mysrvc->port);
								}
#endif
								mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
								mysrvc->shunned_automatic=false;
								mysrvc->shunned_and_kill_all_connections=false;
								mysrvc->connect_ERR_at_time_last_detected_error=0;
								mysrvc->time_last_detected_error=0;
								// note: the following function scans all the hostgroups.
								// This is ok for now because we only have a global mutex.
								// If one day we implement a mutex per hostgroup (unlikely,
								// but possible), this must be taken into consideration
								if (mysql_thread___unshun_algorithm == 1) {
									MyHGM->unshun_server_all_hostgroups(mysrvc->address, mysrvc->port, t, max_wait_sec, &mysrvc->myhgc->hid);
								}
								// if a server is taken back online, consider it immediately
								if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
									if (gtid_trxid) {
										if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
										}
									} else {
										if (max_lag_ms >= 0) {
											if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
												sum+=mysrvc->weight;
												TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
												mysrvcCandidates[num_candidates]=mysrvc;
												num_candidates++;
											}
										} else {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if (max_lag_ms > 0) { // we are using AWS Aurora, as this logic is implemented only here
			unsigned int min_num_replicas = sess->thread->variables.aurora_max_lag_ms_only_read_from_replicas;
			if (min_num_replicas) {
				if (num_candidates >= min_num_replicas) { // there are at least N replicas
					// we try to remove the writer
					unsigned int total_aws_aurora_current_lag_us=0;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						total_aws_aurora_current_lag_us += mysrvc->aws_aurora_current_lag_us;
					}
					if (total_aws_aurora_current_lag_us) { // we are just double checking that we don't have all servers with aws_aurora_current_lag_us==0
						for (j=0; j<num_candidates; j++) {
							mysrvc = mysrvcCandidates[j];
							if (mysrvc->aws_aurora_current_lag_us==0) {
								sum-=mysrvc->weight;
								TotalUsedConn-=mysrvc->ConnectionsUsed->conns_length();
								if (j < num_candidates-1) {
									mysrvcCandidates[j]=mysrvcCandidates[num_candidates-1];
								}
								num_candidates--;
							}
						}
					}
				}
			}
		}
		if (sum==0) {
			// per issue #531 , we try a desperate attempt to bring back online any shunned server
			// we do this lowering the maximum wait time to 10%
			// most of the follow code is copied from few lines above
			time_t t;
			t=time(NULL);
			int max_wait_sec = ( mysql_thread___shun_recovery_time_sec * 1000 >= mysql_thread___connect_timeout_server_max ? mysql_thread___connect_timeout_server_max/10000 - 1 : mysql_thread___shun_recovery_time_sec/10 );
			if (max_wait_sec < 1) { // min wait time should be at least 1 second
				max_wait_sec = 1;
			}
			if (t - last_hg_log > 1) { // log this at most once per second to avoid spamming the logs
				last_hg_log = time(NULL);

				if (gtid_trxid) {
					proxy_error("Hostgroup %u has no servers ready for GTID '%s:%ld'. Waiting for replication...\n", hid, gtid_uuid, gtid_trxid);
				} else {
					proxy_error("Hostgroup %u has no servers available%s! Checking servers shunned for more than %u second%s\n", hid,
						(max_connections_reached ? " or max_connections reached for all servers" : ""), max_wait_sec, max_wait_sec == 1 ? "" : "s");
				}
			}
			for (j=0; j<l; j++) {
				mysrvc=mysrvs->idx(j);
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED && mysrvc->shunned_automatic == true) {
					if ((t - mysrvc->time_last_detected_error) > max_wait_sec) {
						mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
						mysrvc->shunned_automatic=false;
						mysrvc->connect_ERR_at_time_last_detected_error=0;
						mysrvc->time_last_detected_error=0;
						// if a server is taken back online, consider it immediately
						if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
							if (gtid_trxid) {
								if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							} else {
								if (max_lag_ms >= 0) {
									if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
										sum+=mysrvc->weight;
										TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
										mysrvcCandidates[num_candidates]=mysrvc;
										num_candidates++;
									}
								} else {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							}
						}
					}
				}
			}
		}
		if (sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
			if (l>32) {
				free(mysrvcCandidates);
			}
#ifdef TEST_AURORA
			array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
			return NULL; // if we reach here, we couldn't find any target
		}

/*
		unsigned int New_sum=0;
		unsigned int New_TotalUsedConn=0;
		// we will now scan again to ignore overloaded servers
		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
			unsigned int len=mysrvc->ConnectionsUsed->conns_length();
			if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {

				New_sum+=mysrvc->weight;
				New_TotalUsedConn+=len;
			} else {
				// remove the candidate
				if (j+1 < num_candidates) {
					mysrvcCandidates[j] = mysrvcCandidates[num_candidates-1];
				}
				j--;
				num_candidates--;
			}
		}
*/

		unsigned int New_sum=sum;

		if (New_sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
			if (l>32) {
				free(mysrvcCandidates);
			}
#ifdef TEST_AURORA
			array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
			return NULL; // if we reach here, we couldn't find any target
		}

		// latency awareness algorithm is enabled only when compiled with USE_MYSRVC_ARRAY
		if (sess && sess->thread->variables.min_num_servers_lantency_awareness) {
			if ((int) num_candidates >= sess->thread->variables.min_num_servers_lantency_awareness) {
				unsigned int servers_with_latency = 0;
				unsigned int total_latency_us = 0;
				// scan and verify that all servers have some latency
				for (j=0; j<num_candidates; j++) {
					mysrvc = mysrvcCandidates[j];
					if (mysrvc->current_latency_us) {
						servers_with_latency++;
						total_latency_us += mysrvc->current_latency_us;
					}
				}
				if (servers_with_latency == num_candidates) {
					// all servers have some latency.
					// That is good. If any server have no latency, something is wrong
					// and we will skip this algorithm
					sess->thread->status_variables.stvar[st_var_ConnPool_get_conn_latency_awareness]++;
					unsigned int avg_latency_us = 0;
					avg_latency_us = total_latency_us/num_candidates;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						if (mysrvc->current_latency_us > avg_latency_us) {
							// remove the candidate
							if (j+1 < num_candidates) {
								mysrvcCandidates[j] = mysrvcCandidates[num_candidates-1];
							}
							j--;
							num_candidates--;
						}
					}
					// we scan again to adjust weight
					New_sum = 0;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						New_sum+=mysrvc->weight;
					}
				}
			}
		}


		unsigned int k;
		if (New_sum > 32768) {
			k=rand()%New_sum;
		} else {
			k=fastrand()%New_sum;
		}
		k++;
		New_sum=0;

		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
			New_sum+=mysrvc->weight;
			if (k<=New_sum) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
				if (l>32) {
					free(mysrvcCandidates);
				}
#ifdef TEST_AURORA
				array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
				return mysrvc;
			}
		}
	} else {
		time_t t = time(NULL);

		if (t - last_hg_log > 1) {
			last_hg_log = time(NULL);
			proxy_error("Hostgroup %u has no servers available!\n", hid);
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL\n");
	if (l>32) {
		free(mysrvcCandidates);
	}
#ifdef TEST_AURORA
	array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
	return NULL; // if we reach here, we couldn't find any target
}

void MyHGC::refresh_online_server_count() {
	if (__sync_fetch_and_add(&glovars.shutdown, 0) != 0)
		return;
#ifdef DEBUG
	assert(MyHGM->is_locked);
#endif
	unsigned int online_servers_count = 0;
	for (unsigned int i = 0; i < mysrvs->servers->len; i++) {
		MySrvC* mysrvc = (MySrvC*)mysrvs->servers->index(i);
		if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
			online_servers_count++;
		}
	}
	num_online_servers.store(online_servers_count, std::memory_order_relaxed);
}

void MyHGC::log_num_online_server_count_error() {
	const time_t curtime = time(NULL);
	// if this is the first time the method is called or if more than 10 seconds have passed since the last log
	if (last_log_time_num_online_servers == 0 ||
		((curtime - last_log_time_num_online_servers) > 10)) {
		last_log_time_num_online_servers = curtime;
		proxy_error(
			"Number of online servers detected in a hostgroup exceeds the configured maximum online servers. hostgroup:%u, num_online_servers:%u, max_online_servers:%u\n",
			hid, num_online_servers.load(std::memory_order_relaxed), attributes.max_num_online_servers);
	}
}
