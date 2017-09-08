#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_CLUSTER_VERSION "0.1.0702" DEB


#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=sqlite3_step(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(10);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)



static char *NODE_COMPUTE_DELIMITER=(char *)"-gtyw23a-"; // a random string used for hashing

extern ProxySQL_Cluster * GloProxyCluster;

extern ProxySQL_Admin *GloAdmin;

typedef struct _proxy_node_address_t {
	pthread_t thrid;
	uint64_t hash; // unused for now
	char *hostname;
	uint16_t port;
} proxy_node_address_t;


void * ProxySQL_Cluster_Monitor_thread(void *args) {

	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads,tmp_stack_size);
		}
	}

	proxy_node_address_t * node = (proxy_node_address_t *)args;
	mysql_thread_init();
	pthread_detach(pthread_self());

	proxy_info("Cluster: starting thread for peer %s:%d\n", node->hostname, node->port);
	char *query1 = (char *)"SELECT GLOBAL_CHECKSUM()"; // in future this will be used for "light check"
	char *query2 = (char *)"SELECT * FROM stats_mysql_global ORDER BY Variable_Name";
	char *query3 = (char *)"SELECT * FROM runtime_checksums_values ORDER BY name";
	char *username = NULL;
	char *password = NULL;
	bool rc_bool = true;
	int cluster_check_status_frequency_count = 0;
	MYSQL *conn = mysql_init(NULL);
//		goto __exit_monitor_thread;
	if (conn==NULL) {
		proxy_error("Unable to run mysql_init()\n");
		goto __exit_monitor_thread;
	}
	while (glovars.shutdown == 0 && rc_bool == true) {
		MYSQL * rc_conn = NULL;
		int rc_query = 0;
		bool update_checksum = false;
		if (username) { free(username); }
		if (password) { free(password); }
		GloProxyCluster->get_credentials(&username, &password);
		// TODO: add options, like timeout
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			//rc_conn = mysql_real_connect(conn, node->hostname, username, password, NULL, node->port, NULL, CLIENT_COMPRESS); // FIXME: add optional support for compression
			rc_conn = mysql_real_connect(conn, node->hostname, username, password, NULL, node->port, NULL, 0);
			//char *query = query1;
			if (rc_conn) {
				while ( glovars.shutdown == 0 && rc_query == 0 && rc_bool == true) {
					unsigned long long start_time=monotonic_time();
					//unsigned long long before_query_time=monotonic_time();
					rc_query = mysql_query(conn,query1);
					if ( rc_query == 0 ) {
						MYSQL_RES *result = mysql_store_result(conn);
						//unsigned long long after_query_time=monotonic_time();
						//unsigned long long elapsed_time_us = (after_query_time - before_query_time);
						update_checksum = GloProxyCluster->Update_Global_Checksum(node->hostname, node->port, result);
						mysql_free_result(result);
						// FIXME: update metrics are not updated for now. We only check checksum
						//rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, result, elapsed_time_us); 
						//unsigned long long elapsed_time_ms = elapsed_time_us / 1000;
/*
						int e_ms = (int)elapsed_time_ms;
						//fprintf(stderr,"Elapsed time = %d ms\n", e_ms);
						int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
						if (ci > e_ms) {
							if (rc_bool) {
								usleep((ci-e_ms)*1000); // remember, usleep is in us
							}
						}
*/
						//query = query3;
						//unsigned long long before_query_time2=monotonic_time();
						if (update_checksum) {
							rc_query = mysql_query(conn,query3);
							if ( rc_query == 0 ) {
								MYSQL_RES *result = mysql_store_result(conn);
								//unsigned long long after_query_time2=monotonic_time();
								//unsigned long long elapsed_time_us2 = (after_query_time2 - before_query_time2);
								rc_bool = GloProxyCluster->Update_Node_Checksums(node->hostname, node->port, result);
								mysql_free_result(result);
								//unsigned long long elapsed_time_ms2 = elapsed_time_us2 / 1000;
								//int e_ms = (int)elapsed_time_ms + int(elapsed_time_ms2);
								//fprintf(stderr,"Elapsed time = %d ms\n", e_ms);
								//int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
								//if (ci > e_ms) {
								//	if (rc_bool) {
								//		tts = 1;
								//		//usleep((ci-e_ms)*1000); // remember, usleep is in us
								//	}
								//}
							}
						} else {
							GloProxyCluster->Update_Node_Checksums(node->hostname, node->port);
							//int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
							//if (ci > elapsed_time_ms) {
							//	if (rc_bool) {
							//		usleep((ci-elapsed_time_ms)*1000); // remember, usleep is in us
							//	}
							//}
						}
						if (rc_query == 0) {
							cluster_check_status_frequency_count++;
							int freq = __sync_fetch_and_add(&GloProxyCluster->cluster_check_status_frequency,0);
							if (freq && cluster_check_status_frequency_count >= freq) {
								cluster_check_status_frequency_count = 0;
								unsigned long long before_query_time=monotonic_time();
								rc_query = mysql_query(conn,query2);
								if ( rc_query == 0 ) {
									MYSQL_RES *result = mysql_store_result(conn);
									unsigned long long after_query_time=monotonic_time();
									unsigned long long elapsed_time_us = (after_query_time - before_query_time);
									rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, result, elapsed_time_us); 
									mysql_free_result(result);
								}
							}
						}
					}
					unsigned long long end_time=monotonic_time();
					if (rc_query == 0) {
						unsigned long long elapsed_time = (end_time - start_time);
						unsigned long long e_ms = elapsed_time / 1000;
						int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
						if ((unsigned) ci > e_ms) {
							usleep((ci-e_ms)*1000); // remember, usleep is in us
						}
					}
				}
				if (glovars.shutdown == 0) {
					// we arent' shutting down, but the query failed
				}
				if (conn->net.vio) { 
					mysql_close(conn);
				}
			} else {
				proxy_warning("Cluster: unable to connect to peer %s:%d . Error: %s\n", node->hostname, node->port, mysql_error(conn));
				mysql_close(conn);
				conn = mysql_init(NULL);
				int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
				usleep((ci)*1000); // remember, usleep is in us
			}
		} else {
			sleep(1);	// do not monitor if the username is empty
		}
	}
__exit_monitor_thread:
	//if (conn) {
	if (conn->net.vio) {
		mysql_close(conn);
	}
	proxy_info("Cluster: closing thread for peer %s:%d\n", node->hostname, node->port);
	free(node->hostname);
	free(node);
	//pthread_exit(0);
	mysql_thread_end();
	//GloProxyCluster->thread_ending(node->thrid);

	__sync_fetch_and_sub(&GloVars.statuses.stack_memory_cluster_threads,tmp_stack_size);

	return NULL;
}


static uint64_t generate_hash_proxysql_node(char *_hostname, uint16_t _port) {
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(21,12); // rand
	myhash.Update(_hostname, strlen(_hostname));
	myhash.Update(NODE_COMPUTE_DELIMITER, strlen(NODE_COMPUTE_DELIMITER));
	myhash.Update(&_port, sizeof(_port));
	myhash.Final(&hash1,&hash2);
	return hash1;
}


void ProxySQL_Node_Metrics::reset() {
	memset(this, 0, sizeof(ProxySQL_Node_Metrics));
}


ProxySQL_Node_Entry::ProxySQL_Node_Entry(char *_hostname, uint16_t _port, uint64_t _weight, char * _comment) {
	hash = 0;
	global_checksum = 0;
	hostname = NULL;
	if (_hostname) {
		hostname = strdup(_hostname);
	}
	port = _port;
	weight = _weight;
	if (_comment == NULL) {
		comment = strdup((char *)"");
	} else {
		comment = strdup(_comment);
	}
	active = false;
	hash = generate_hash_proxysql_node(_hostname, _port);
	metrics_idx = 0;
	metrics = (ProxySQL_Node_Metrics **)malloc(sizeof(ProxySQL_Node_Metrics *)*PROXYSQL_NODE_METRICS_LEN);
	for (int i = 0; i < PROXYSQL_NODE_METRICS_LEN ; i++) {
		metrics[i] = new ProxySQL_Node_Metrics();
	}
	proxy_info("Created new Cluster Node Entry for host %s:%d\n",hostname,port);
}

ProxySQL_Node_Entry::~ProxySQL_Node_Entry() {
	proxy_info("Destroyed Cluster Node Entry for host %s:%d\n",hostname,port);
	if (hostname) {
		free(hostname);
		hostname = NULL;
	}
	if (comment) {
		free(comment);
		comment = NULL;
	}
	for (int i = 0; i < PROXYSQL_NODE_METRICS_LEN ; i++) {
		delete metrics[i];
		metrics[i] = NULL;
	}
	free(metrics);
	metrics = NULL;
}

bool ProxySQL_Node_Entry::get_active() {
	return active;
}

void ProxySQL_Node_Entry::set_active(bool a) {
	active = a;
}

uint64_t ProxySQL_Node_Entry::get_weight() {
	return weight;
}

void ProxySQL_Node_Entry::set_weight(uint64_t w) {
	weight = w;
}

void ProxySQL_Node_Entry::set_comment(char *s) {
	if (comment) {
		free(comment);
	}
	if (s==NULL) {
		comment = strdup((char *)"");
	} else {
		comment = strdup(s);
	}
}

ProxySQL_Node_Metrics * ProxySQL_Node_Entry::get_metrics_curr() {
	ProxySQL_Node_Metrics *m = metrics[metrics_idx];
	return m;
}

ProxySQL_Node_Metrics * ProxySQL_Node_Entry::get_metrics_prev() {
	ProxySQL_Node_Metrics *m = metrics[metrics_idx_prev];
	return m;
}

void ProxySQL_Node_Entry::set_checksums(MYSQL_RES *_r) {
	MYSQL_ROW row;
	time_t now = time(NULL);
	pthread_mutex_lock(&GloVars.checksum_mutex);
	while ( _r && (row = mysql_fetch_row(_r))) {
		if (strcmp(row[0],"admin_variables")==0) {
			checksums_values.admin_variables.version = atoll(row[1]);
			checksums_values.admin_variables.epoch = atoll(row[2]);
			checksums_values.admin_variables.last_updated = now;
			if (strcmp(checksums_values.admin_variables.checksum, row[3])) {
				strcpy(checksums_values.admin_variables.checksum, row[3]);
				checksums_values.admin_variables.last_changed = now;
				checksums_values.admin_variables.diff_check = 1;
			} else {
				checksums_values.admin_variables.diff_check++;
			}
			if (strcmp(checksums_values.admin_variables.checksum, GloVars.checksums_values.admin_variables.checksum) == 0) {
				checksums_values.admin_variables.diff_check = 0;
			}
			continue;
		}
		if (strcmp(row[0],"mysql_query_rules")==0) {
			checksums_values.mysql_query_rules.version = atoll(row[1]);
			checksums_values.mysql_query_rules.epoch = atoll(row[2]);
			checksums_values.mysql_query_rules.last_updated = now;
			if (strcmp(checksums_values.mysql_query_rules.checksum, row[3])) {
				strcpy(checksums_values.mysql_query_rules.checksum, row[3]);
				checksums_values.mysql_query_rules.last_changed = now;
				checksums_values.mysql_query_rules.diff_check = 1;
				proxy_info("Cluster: detected a new checksum for mysql_query_rules from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.mysql_query_rules.version, checksums_values.mysql_query_rules.epoch, checksums_values.mysql_query_rules.checksum);
				if (strcmp(checksums_values.mysql_query_rules.checksum, GloVars.checksums_values.mysql_query_rules.checksum) == 0) {
					proxy_info("Cluster: checksum for mysql_query_rules from peer %s:%d matches with local checksum %s , we won't sync.\n", hostname, port, GloVars.checksums_values.mysql_query_rules.checksum);
				}
			} else {
				checksums_values.mysql_query_rules.diff_check++;
			}
			if (strcmp(checksums_values.mysql_query_rules.checksum, GloVars.checksums_values.mysql_query_rules.checksum) == 0) {
				checksums_values.mysql_query_rules.diff_check = 0;
			}
			continue;
		}
		if (strcmp(row[0],"mysql_servers")==0) {
			checksums_values.mysql_servers.version = atoll(row[1]);
			checksums_values.mysql_servers.epoch = atoll(row[2]);
			checksums_values.mysql_servers.last_updated = now;
			if (strcmp(checksums_values.mysql_servers.checksum, row[3])) {
				strcpy(checksums_values.mysql_servers.checksum, row[3]);
				checksums_values.mysql_servers.last_changed = now;
				checksums_values.mysql_servers.diff_check = 1;
				proxy_info("Cluster: detected a new checksum for mysql_servers from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.mysql_servers.version, checksums_values.mysql_servers.epoch, checksums_values.mysql_servers.checksum);
				if (strcmp(checksums_values.mysql_servers.checksum, GloVars.checksums_values.mysql_servers.checksum) == 0) {
					proxy_info("Cluster: checksum for mysql_servers from peer %s:%d matches with local checksum %s , we won't sync.\n", hostname, port, GloVars.checksums_values.mysql_servers.checksum);
				}
			} else {
				checksums_values.mysql_servers.diff_check++;
			}
			if (strcmp(checksums_values.mysql_servers.checksum, GloVars.checksums_values.mysql_servers.checksum) == 0) {
				checksums_values.mysql_servers.diff_check = 0;
			}
			continue;
		}
		if (strcmp(row[0],"mysql_users")==0) {
			checksums_values.mysql_users.version = atoll(row[1]);
			checksums_values.mysql_users.epoch = atoll(row[2]);
			checksums_values.mysql_users.last_updated = now;
			if (strcmp(checksums_values.mysql_users.checksum, row[3])) {
				strcpy(checksums_values.mysql_users.checksum, row[3]);
				checksums_values.mysql_users.last_changed = now;
				checksums_values.mysql_users.diff_check = 1;
				proxy_info("Cluster: detected a new checksum for mysql_users from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.mysql_users.version, checksums_values.mysql_users.epoch, checksums_values.mysql_users.checksum);
				if (strcmp(checksums_values.mysql_users.checksum, GloVars.checksums_values.mysql_users.checksum) == 0) {
					proxy_info("Cluster: checksum for mysql_users from peer %s:%d matches with local checksum %s , we won't sync.\n", hostname, port, GloVars.checksums_values.mysql_users.checksum);
				}
			} else {
				checksums_values.mysql_users.diff_check++;
			}
			if (strcmp(checksums_values.mysql_users.checksum, GloVars.checksums_values.mysql_users.checksum) == 0) {
				checksums_values.mysql_users.diff_check = 0;
			}
			continue;
		}
		if (strcmp(row[0],"mysql_variables")==0) {
			checksums_values.mysql_variables.version = atoll(row[1]);
			checksums_values.mysql_variables.epoch = atoll(row[2]);
			checksums_values.mysql_variables.last_updated = now;
			if (strcmp(checksums_values.mysql_variables.checksum, row[3])) {
				strcpy(checksums_values.mysql_variables.checksum, row[3]);
				checksums_values.mysql_variables.last_changed = now;
				checksums_values.mysql_variables.diff_check = 1;
			} else {
				checksums_values.mysql_variables.diff_check++;
			}
			if (strcmp(checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.checksum) == 0) {
				checksums_values.mysql_variables.diff_check = 0;
			}
			continue;
		}
		if (strcmp(row[0],"proxysql_servers")==0) {
			checksums_values.proxysql_servers.version = atoll(row[1]);
			checksums_values.proxysql_servers.epoch = atoll(row[2]);
			checksums_values.proxysql_servers.last_updated = now;
			if (strcmp(checksums_values.proxysql_servers.checksum, row[3])) {
				strcpy(checksums_values.proxysql_servers.checksum, row[3]);
				checksums_values.proxysql_servers.last_changed = now;
				checksums_values.proxysql_servers.diff_check = 1;
				proxy_info("Cluster: detected a new checksum for proxysql_servers from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.proxysql_servers.version, checksums_values.proxysql_servers.epoch, checksums_values.proxysql_servers.checksum);
				if (strcmp(checksums_values.proxysql_servers.checksum, GloVars.checksums_values.proxysql_servers.checksum) == 0) {
					proxy_info("Cluster: checksum for proxysql_servers from peer %s:%d matches with local checksum %s , we won't sync.\n", hostname, port, GloVars.checksums_values.proxysql_servers.checksum);
				}
			} else {
				checksums_values.proxysql_servers.diff_check++;
			}
			if (strcmp(checksums_values.proxysql_servers.checksum, GloVars.checksums_values.proxysql_servers.checksum) == 0) {
				checksums_values.proxysql_servers.diff_check = 0;
			}
			continue;
		}
	}
	if (_r == NULL) {
		ProxySQL_Checksum_Value_2 *v = NULL;
		v = &checksums_values.admin_variables;
		v->last_updated = now;
		if (v->diff_check)
			v->diff_check++;
		v = &checksums_values.mysql_query_rules;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.mysql_query_rules.checksum) == 0) {
			v->diff_check = 0;
		}
		if (v->diff_check)
			v->diff_check++;
		v = &checksums_values.mysql_servers;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.mysql_servers.checksum) == 0) {
			v->diff_check = 0;
		}
		if (v->diff_check)
			v->diff_check++;
		v = &checksums_values.mysql_users;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.mysql_users.checksum) == 0) {
			v->diff_check = 0;
		}
		if (v->diff_check)
			v->diff_check++;
		v = &checksums_values.mysql_variables;
		v->last_updated = now;
		if (v->diff_check)
			v->diff_check++;
		v = &checksums_values.proxysql_servers;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.proxysql_servers.checksum) == 0) {
			v->diff_check = 0;
		}
		if (v->diff_check)
			v->diff_check++;
	}
	pthread_mutex_unlock(&GloVars.checksum_mutex);
	// we now do a series of checks, and we take action
	// note that this is done outside the critical section
	// as mutex on GloVars.checksum_mutex is already released
	unsigned int diff_mqr = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_query_rules_diffs_before_sync,0);
	unsigned int diff_ms = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync,0);
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_users_diffs_before_sync,0);
	unsigned int diff_ps = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_proxysql_servers_diffs_before_sync,0);
	ProxySQL_Checksum_Value_2 *v = NULL;
	if (diff_mqr) {
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.epoch,0);
		v = &checksums_values.mysql_query_rules;
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mqr) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_query_rules_from_peer();
				}
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mqr*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL QUERY RULES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mqr*10));
			}
		}
	}
	if (diff_ms) {
		v = &checksums_values.mysql_servers;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.epoch,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ms) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_servers_from_peer();
				}
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ms*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms*10));
			}
		}
	}
	if (diff_mu) {
		v = &checksums_values.mysql_users;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.epoch,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mu) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_users_from_peer();
				}
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mu*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL USERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mu*10));
			}
		}
	}
	if (diff_ps) {
		v = &checksums_values.proxysql_servers;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.epoch,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ps) {
					proxy_info("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_proxysql_servers_from_peer();
				}
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ms*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %llu. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD PROXYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ps*10));
			}
		}
	}
}

void ProxySQL_Cluster::pull_mysql_query_rules_from_peer() {
	char * hostname = NULL;
	uint16_t port = 0;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_query_rules_mutex);
	nodes.get_peer_to_sync_mysql_query_rules(&hostname, &port);
	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		// bool rc_bool = true;
		MYSQL *rc_conn;
		int rc_query;
		int rc;
		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_query_rules_from_peer;
		}
		GloProxyCluster->get_credentials(&username, &password);
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				rc_query = mysql_query(conn,"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, comment FROM runtime_mysql_query_rules");
				if ( rc_query == 0 ) {
					MYSQL_RES *result = mysql_store_result(conn);
					GloAdmin->admindb->execute("DELETE FROM mysql_query_rules");
					MYSQL_ROW row;
					char *q = (char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, comment) VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31)";
					sqlite3_stmt *statement1 = NULL;
					sqlite3 *mydb3 = GloAdmin->admindb->get_db();
					rc=sqlite3_prepare_v2(mydb3, q, -1, &statement1, 0);
					assert(rc==SQLITE_OK);
					while ((row = mysql_fetch_row(result))) {
						rc=sqlite3_bind_int64(statement1, 1, atoll(row[0])); assert(rc==SQLITE_OK); // rule_id
						rc=sqlite3_bind_int64(statement1, 2, 1); assert(rc==SQLITE_OK); // active
						rc=sqlite3_bind_text(statement1, 3, row[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // username
						rc=sqlite3_bind_text(statement1, 4, row[2], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // schemaname
						rc=sqlite3_bind_text(statement1, 5, row[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // flagIN
						rc=sqlite3_bind_text(statement1, 6, row[4], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // client_addr
						rc=sqlite3_bind_text(statement1, 7, row[5], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // proxy_addr
						rc=sqlite3_bind_text(statement1, 8, row[6], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // proxy_port
						rc=sqlite3_bind_text(statement1, 9, row[7], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // digest
						rc=sqlite3_bind_text(statement1, 10, row[8], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // match_digest
						rc=sqlite3_bind_text(statement1, 11, row[9], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // match_pattern
						rc=sqlite3_bind_text(statement1, 12, row[10], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // negate_match_pattern
						rc=sqlite3_bind_text(statement1, 13, row[11], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // re_modifiers
						rc=sqlite3_bind_text(statement1, 14, row[12], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // flagOUT
						rc=sqlite3_bind_text(statement1, 15, row[13], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // replace_pattern
						rc=sqlite3_bind_text(statement1, 16, row[14], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // destination_hostgroup
						rc=sqlite3_bind_text(statement1, 17, row[15], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // cache_ttl
						rc=sqlite3_bind_text(statement1, 18, row[16], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // reconnect
						rc=sqlite3_bind_text(statement1, 19, row[17], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // timeout
						rc=sqlite3_bind_text(statement1, 20, row[18], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // retries
						rc=sqlite3_bind_text(statement1, 21, row[19], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // delay
						rc=sqlite3_bind_text(statement1, 22, row[20], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // next_query_flagIN
						rc=sqlite3_bind_text(statement1, 23, row[21], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // mirror_flagOUT
						rc=sqlite3_bind_text(statement1, 24, row[22], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // mirror_hostgroup
						rc=sqlite3_bind_text(statement1, 25, row[23], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // error_msg
						rc=sqlite3_bind_text(statement1, 26, row[24], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // OK_msg
						rc=sqlite3_bind_text(statement1, 27, row[25], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // sticky_conn
						rc=sqlite3_bind_text(statement1, 28, row[26], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // multiplex
						rc=sqlite3_bind_text(statement1, 29, row[27], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // log
						rc=sqlite3_bind_text(statement1, 30, row[28], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // apply
						rc=sqlite3_bind_text(statement1, 31, row[29], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // comment
						SAFE_SQLITE3_STEP(statement1);
						rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
						rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
					}
					mysql_free_result(result);
					proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d completed\n", hostname, port);
					proxy_info("Cluster: Loading to runtime MySQL Query Rules from peer %s:%d\n", hostname, port);
					GloAdmin->load_mysql_query_rules_to_runtime();
					if (GloProxyCluster->cluster_mysql_query_rules_save_to_disk == true) {
						proxy_info("Cluster: Saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
						GloAdmin->flush_mysql_query_rules__from_memory_to_disk();
					}
				} else {
					proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				}
			} else {
				proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
			}
		}
__exit_pull_mysql_query_rules_from_peer:
		if (conn) {
			if (conn->net.vio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_query_rules_mutex);
}

void ProxySQL_Cluster::pull_mysql_users_from_peer() {
	char * hostname = NULL;
	uint16_t port = 0;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_users_mutex);
	nodes.get_peer_to_sync_mysql_users(&hostname, &port);
	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		// bool rc_bool = true;
		MYSQL *rc_conn;
		int rc_query;
		int rc;
		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_users_from_peer;
		}
		GloProxyCluster->get_credentials(&username, &password);
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			proxy_info("Cluster: Fetching MySQL Users from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				rc_query = mysql_query(conn, "SELECT username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections FROM runtime_mysql_users");
				if ( rc_query == 0 ) {
					MYSQL_RES *result = mysql_store_result(conn);
					GloAdmin->admindb->execute("DELETE FROM mysql_users");
					MYSQL_ROW row;
					char *q = (char *)"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections) VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
					sqlite3_stmt *statement1 = NULL;
					sqlite3 *mydb3 = GloAdmin->admindb->get_db();
					rc=sqlite3_prepare_v2(mydb3, q, -1, &statement1, 0);
					assert(rc==SQLITE_OK);
					while ((row = mysql_fetch_row(result))) {
						rc=sqlite3_bind_text(statement1, 1, row[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // username
						rc=sqlite3_bind_text(statement1, 2, row[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // password
						rc=sqlite3_bind_int64(statement1, 3, atoll(row[2])); assert(rc==SQLITE_OK); // active
						rc=sqlite3_bind_int64(statement1, 4, atoll(row[3])); assert(rc==SQLITE_OK); // use_ssl
						rc=sqlite3_bind_int64(statement1, 5, atoll(row[4])); assert(rc==SQLITE_OK); // default_hostgroup
						rc=sqlite3_bind_text(statement1, 6, row[5], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK); // default_schema
						rc=sqlite3_bind_int64(statement1, 7, atoll(row[6])); assert(rc==SQLITE_OK); // schema_locked
						rc=sqlite3_bind_int64(statement1, 8, atoll(row[7])); assert(rc==SQLITE_OK); // transaction_persistent
						rc=sqlite3_bind_int64(statement1, 9, atoll(row[8])); assert(rc==SQLITE_OK); // fast_forward
						rc=sqlite3_bind_int64(statement1, 10, atoll(row[9])); assert(rc==SQLITE_OK); // backend
						rc=sqlite3_bind_int64(statement1, 11, atoll(row[10])); assert(rc==SQLITE_OK); // frontend
						rc=sqlite3_bind_int64(statement1, 12, atoll(row[11])); assert(rc==SQLITE_OK); // max_connection

						SAFE_SQLITE3_STEP(statement1);
						rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
						rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
					}
					mysql_free_result(result);
					proxy_info("Cluster: Fetching MySQL Users from peer %s:%d completed\n", hostname, port);
					proxy_info("Cluster: Loading to runtime MySQL Users from peer %s:%d\n", hostname, port);
					GloAdmin->init_users();
					if (GloProxyCluster->cluster_mysql_query_rules_save_to_disk == true) {
						proxy_info("Cluster: Saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
						GloAdmin->flush_mysql_users__from_memory_to_disk();
					}
				} else {
					proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				}
			} else {
				proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
			}
		}
__exit_pull_mysql_users_from_peer:
		if (conn) {
			if (conn->net.vio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_users_mutex);
}

void ProxySQL_Cluster::pull_mysql_servers_from_peer() {
	char * hostname = NULL;
	uint16_t port = 0;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_servers_mutex);
	nodes.get_peer_to_sync_mysql_servers(&hostname, &port);
	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		// bool rc_bool = true;
		MYSQL *rc_conn;
		int rc_query;
		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_servers_from_peer;
		}
		GloProxyCluster->get_credentials(&username, &password);
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				GloAdmin->mysql_servers_wrlock();
				rc_query = mysql_query(conn,"SELECT hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_mysql_servers WHERE status<>'OFFLINE_HARD'");
				if ( rc_query == 0 ) {
					MYSQL_RES *result = mysql_store_result(conn);
					GloAdmin->admindb->execute("DELETE FROM mysql_servers");
					MYSQL_ROW row;
					char *q=(char *)"INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (%s, \"%s\", %s, \"%s\", %s, %s, %s, %s, %s, %s, '%s')";
					while ((row = mysql_fetch_row(result))) {
						int i;
						int l=0;
						for (i=0; i<10; i++) {
							l+=strlen(row[i]);
						}
						char *o=escape_string_single_quotes(row[10],false);
						char *query = (char *)malloc(strlen(q)+i+strlen(o)+64);

						sprintf(query,q,row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],o);
						if (o!=row[10]) { // there was a copy
							free(o);
						}
						GloAdmin->admindb->execute(query);
						free(query);
					}
					mysql_free_result(result);

					rc_query = mysql_query(conn,"SELECT writer_hostgroup, reader_hostgroup, comment FROM runtime_mysql_replication_hostgroups");
					if ( rc_query == 0 ) {
						MYSQL_RES *result = mysql_store_result(conn);
						GloAdmin->admindb->execute("DELETE FROM mysql_replication_hostgroups");
						MYSQL_ROW row;
						char *q=(char *)"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment) VALUES (%s, %s, '%s')";
						while ((row = mysql_fetch_row(result))) {
							int i;
							int l=0;
							for (i=0; i<2; i++) {
								l+=strlen(row[i]);
							}
							char *o=escape_string_single_quotes(row[2],false);
							char *query = (char *)malloc(strlen(q)+i+strlen(o)+64);

							sprintf(query,q,row[0],row[1],o);
							if (o!=row[2]) { // there was a copy
								free(o);
							}
							GloAdmin->admindb->execute(query);
							free(query);
						}
						mysql_free_result(result);
						proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d completed\n", hostname, port);
						proxy_info("Cluster: Loading to runtime MySQL Servers from peer %s:%d\n", hostname, port);
						GloAdmin->load_mysql_servers_to_runtime();
						if (GloProxyCluster->cluster_mysql_servers_save_to_disk == true) {
							proxy_info("Cluster: Saving to disk MySQL Servers from peer %s:%d\n", hostname, port);
							GloAdmin->flush_mysql_servers__from_memory_to_disk();
						}
					} else {
						proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					}
				} else {
					proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				}
				GloAdmin->mysql_servers_wrunlock();
			} else {
				proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
			}
		}
__exit_pull_mysql_servers_from_peer:
		if (conn) {
			if (conn->net.vio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_servers_mutex);
}

void ProxySQL_Cluster::pull_proxysql_servers_from_peer() {
	char * hostname = NULL;
	uint16_t port = 0;
	pthread_mutex_lock(&GloProxyCluster->update_proxysql_servers_mutex);
	nodes.get_peer_to_sync_proxysql_servers(&hostname, &port);
	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		// bool rc_bool = true;
		MYSQL *rc_conn;
		int rc_query;
		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_proxysql_servers_from_peer;
		}
		GloProxyCluster->get_credentials(&username, &password);
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				rc_query = mysql_query(conn,"SELECT hostname, port, weight, comment FROM runtime_proxysql_servers");
				if ( rc_query == 0 ) {
					MYSQL_RES *result = mysql_store_result(conn);
					GloAdmin->admindb->execute("DELETE FROM proxysql_servers");
					MYSQL_ROW row;
					char *q=(char *)"INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES (\"%s\", %s, %s, '%s')";
					while ((row = mysql_fetch_row(result))) {
						int i;
						int l=0;
						for (i=0; i<3; i++) {
							l+=strlen(row[i]);
						}
						char *o=escape_string_single_quotes(row[3],false);
						char *query = (char *)malloc(strlen(q)+i+strlen(o)+64);

						sprintf(query,q,row[0],row[1],row[2],o);
						if (o!=row[3]) { // there was a copy
							free(o);
						}
						GloAdmin->admindb->execute(query);
						free(query);
					}
					mysql_free_result(result);
					proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d completed\n", hostname, port);
					proxy_info("Cluster: Loading to runtime ProxySQL Servers from peer %s:%d\n", hostname, port);
					GloAdmin->load_proxysql_servers_to_runtime(false);
					if (GloProxyCluster->cluster_proxysql_servers_save_to_disk == true) {
						proxy_info("Cluster: Saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
						GloAdmin->flush_proxysql_servers__from_memory_to_disk();
					}
				} else {
					proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				}
			} else {
				proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
			}
		}
__exit_pull_proxysql_servers_from_peer:
		if (conn) {
			if (conn->net.vio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_proxysql_servers_mutex);
}

void ProxySQL_Node_Entry::set_metrics(MYSQL_RES *_r, unsigned long long _response_time) {
	MYSQL_ROW row;
	metrics_idx_prev = metrics_idx;	
	metrics_idx++;
	if (metrics_idx == PROXYSQL_NODE_METRICS_LEN) {
		metrics_idx = 0;
	}
	ProxySQL_Node_Metrics *m = metrics[metrics_idx];
	m->reset();
	m->read_time_us = monotonic_time();
	m->response_time_us = _response_time;
	while ((row = mysql_fetch_row(_r))) {
		char c = row[0][0];
		switch (c) {
			case 'C':
				if (strcmp(row[0],"Client_Connections_connected")==0) {
					m->Client_Connections_connected = atoll(row[1]);
					break;
				}
				if (strcmp(row[0],"Client_Connections_created")==0) {
					m->Client_Connections_created = atoll(row[1]);
					break;
				}
				break;
			case 'P':
				if (strcmp(row[0],"ProxySQL_Uptime")==0) {
					m->ProxySQL_Uptime = atoll(row[1]);
				}
				break;
			case 'Q':
				if (strcmp(row[0],"Questions")==0) {
					m->Questions = atoll(row[1]);
				}
				break;
			case 'S':
				if (strcmp(row[0],"Servers_table_version")==0) {
					m->Servers_table_version = atoll(row[1]);
				}
				break;
			default:
				break;
		}
	}
}

ProxySQL_Cluster_Nodes::ProxySQL_Cluster_Nodes() {
	pthread_mutex_init(&mutex,NULL);
}

void ProxySQL_Cluster_Nodes::set_all_inactive() {
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {	
		ProxySQL_Node_Entry *node = it->second;
		node->set_active(false);
		it++;
	}
}

void ProxySQL_Cluster_Nodes::remove_inactives() {
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {	
		ProxySQL_Node_Entry *node = it->second;
		if (node->get_active() == false) {
			delete node;
			it = umap_proxy_nodes.erase(it);
		} else {
			it++;
		}
	}
}

ProxySQL_Cluster_Nodes::~ProxySQL_Cluster_Nodes() {
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {	
		ProxySQL_Node_Entry *node = it->second;
		delete node;
		it = umap_proxy_nodes.erase(it);
	}
}

uint64_t ProxySQL_Cluster_Nodes::generate_hash(char *_hostname, uint16_t _port) {
	uint64_t hash_ = generate_hash_proxysql_node(_hostname, _port);
	return hash_;
}

void ProxySQL_Cluster_Nodes::load_servers_list(SQLite3_result *resultset, bool _lock) {
	if (_lock)
		pthread_mutex_lock(&mutex);
	set_all_inactive();
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		ProxySQL_Node_Entry *node = NULL;
		char * h_ = r->fields[0];
		uint16_t p_ = atoi(r->fields[1]);
		uint64_t w_ = atoi(r->fields[2]);
		char * c_ = r->fields[3];
		uint64_t hash_ = generate_hash(h_, p_);
		std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator ite = umap_proxy_nodes.find(hash_);
		if (ite == umap_proxy_nodes.end()) {
			node = new ProxySQL_Node_Entry(h_, p_, w_ , c_);
			node->set_active(true);
			umap_proxy_nodes.insert(std::make_pair(hash_, node));
			proxy_node_address_t * a = (proxy_node_address_t *)malloc(sizeof(proxy_node_address_t));
			a->hash = 0; // usused for now
			a->hostname = strdup(h_);
			a->port = p_;
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_create(&a->thrid, &attr, ProxySQL_Cluster_Monitor_thread, (void *)a);
			//pthread_create(&a->thrid, NULL, ProxySQL_Cluster_Monitor_thread, (void *)a);
			//pthread_detach(a->thrid);
		} else {
			node = ite->second;
			node->set_active(true);
			node->set_weight(w_);
			node->set_comment(c_);
		}
	}
	remove_inactives();
	if (_lock)
		pthread_mutex_unlock(&mutex);
}

// if it returns false , the node doesn't exist anymore and the monitor should stop
bool ProxySQL_Cluster_Nodes::Update_Node_Checksums(char * _h, uint16_t _p, MYSQL_RES *_r) {
	bool ret = false;
	uint64_t hash_ = generate_hash(_h, _p);
	pthread_mutex_lock(&mutex);
	std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator ite = umap_proxy_nodes.find(hash_);
	if (ite != umap_proxy_nodes.end()) {
		ProxySQL_Node_Entry * node = ite->second;
		node->set_checksums(_r);
		ret = true;
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}
// if it returns true , the checksum changed
bool ProxySQL_Cluster_Nodes::Update_Global_Checksum(char * _h, uint16_t _p, MYSQL_RES *_r) {
	bool ret = true;
	uint64_t hash_ = generate_hash(_h, _p);
	pthread_mutex_lock(&mutex);
	std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator ite = umap_proxy_nodes.find(hash_);
	if (ite != umap_proxy_nodes.end()) {
		ProxySQL_Node_Entry * node = ite->second;
		MYSQL_ROW row;
		//time_t now = time(NULL);
		//pthread_mutex_lock(&GloVars.checksum_mutex);
		while ((row = mysql_fetch_row(_r))) {
			unsigned long long v = atoll(row[0]);
			if (v == node->global_checksum) {
				ret = false;
			} else {
				node->global_checksum = v;
			}
		}
		//pthread_mutex_unlock(&GloVars.checksum_mutex);
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}

// if it returns false , the node doesn't exist anymore and the monitor should stop
bool ProxySQL_Cluster_Nodes::Update_Node_Metrics(char * _h, uint16_t _p, MYSQL_RES *_r, unsigned long long _response_time) {
	bool ret = false;
	uint64_t hash_ = generate_hash(_h, _p);
	pthread_mutex_lock(&mutex);
	std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator ite = umap_proxy_nodes.find(hash_);
	if (ite != umap_proxy_nodes.end()) {
		ProxySQL_Node_Entry * node = ite->second;
		node->set_metrics(_r, _response_time);
		ret = true;
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_query_rules(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_query_rules;
		if (v->version > 1) {
			if ( v->epoch > epoch && v->diff_check > 3) {
				epoch = v->epoch;
				version = v->version;
				if (hostname) {
					free(hostname);
				}
				hostname=strdup(node->get_hostname());
				p = node->get_port();
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_query_rules version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_servers(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_servers;
		if (v->version > 1) {
			if ( v->epoch > epoch && v->diff_check > 3) {
				epoch = v->epoch;
				version = v->version;
				if (hostname) {
					free(hostname);
				}
				hostname=strdup(node->get_hostname());
				p = node->get_port();
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_servers version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_users(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_users;
		if (v->version > 1) {
			if ( v->epoch > epoch && v->diff_check > 3) {
				epoch = v->epoch;
				version = v->version;
				if (hostname) {
					free(hostname);
				}
				hostname=strdup(node->get_hostname());
				p = node->get_port();
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_users version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_proxysql_servers(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.proxysql_servers;
		if (v->version > 1) {
			if ( v->epoch > epoch && v->diff_check > 3) {
				epoch = v->epoch;
				version = v->version;
				if (hostname) {
					free(hostname);
				}
				hostname=strdup(node->get_hostname());
				p = node->get_port();
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with proxysql_servers version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

SQLite3_result * ProxySQL_Cluster_Nodes::stats_proxysql_servers_checksums() {
	const int colnum=9;
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"name");
	result->add_column_definition(SQLITE_TEXT,"version");
	result->add_column_definition(SQLITE_TEXT,"epoch");
	result->add_column_definition(SQLITE_TEXT,"checksum");
	result->add_column_definition(SQLITE_TEXT,"last_changed");
	result->add_column_definition(SQLITE_TEXT,"last_updated");
	result->add_column_definition(SQLITE_TEXT,"diff_check");

	char buf[32];
	int k;
	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * vals[6];
		vals[0] = &node->checksums_values.admin_variables;
		vals[1] = &node->checksums_values.mysql_query_rules;
		vals[2] = &node->checksums_values.mysql_servers;
		vals[3] = &node->checksums_values.mysql_users;
		vals[4] = &node->checksums_values.mysql_variables;
		vals[5] = &node->checksums_values.proxysql_servers;
		for (int i=0; i<6 ; i++) {
			ProxySQL_Checksum_Value_2 *v = vals[i];
			char **pta=(char **)malloc(sizeof(char *)*colnum);
			pta[0]=strdup(node->get_hostname());
			sprintf(buf,"%d", node->get_port());
			pta[1]=strdup(buf);

			switch (i) {
				case 0:
					pta[2]=strdup((char *)"admin_variables");
					break;
				case 1:
					pta[2]=strdup((char *)"mysql_query_rules");
					break;
				case 2:
					pta[2]=strdup((char *)"mysql_servers");
					break;
				case 3:
					pta[2]=strdup((char *)"mysql_users");
					break;
				case 4:
					pta[2]=strdup((char *)"mysql_variables");
					break;
				case 5:
					pta[2]=strdup((char *)"proxysql_servers");
					break;
				default:
					break;
			}
			sprintf(buf,"%llu", v->version);
			pta[3]=strdup(buf);
			sprintf(buf,"%llu", v->epoch);
			pta[4]=strdup(buf);
			pta[5]=strdup(v->checksum);
			sprintf(buf,"%ld", v->last_changed);
			pta[6]=strdup(buf);
			sprintf(buf,"%ld", v->last_updated);
			pta[7]=strdup(buf);
			sprintf(buf,"%u", v->diff_check);
			pta[8]=strdup(buf);


			result->add_row(pta);
			for (k=0; k<colnum; k++) {
				if (pta[k])
					free(pta[k]);
				}
			free(pta);
		}
		it++;
	}
	pthread_mutex_unlock(&mutex);
	return result;
}

SQLite3_result * ProxySQL_Cluster_Nodes::stats_proxysql_servers_metrics() {
	const int colnum=10;
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"weight");
	result->add_column_definition(SQLITE_TEXT,"comment");
	result->add_column_definition(SQLITE_TEXT,"response_time_ms");
	result->add_column_definition(SQLITE_TEXT,"uptime_s");
	result->add_column_definition(SQLITE_TEXT,"last_check_ms");
	result->add_column_definition(SQLITE_TEXT,"Queries");
	result->add_column_definition(SQLITE_TEXT,"Client_Connections_connected");
	result->add_column_definition(SQLITE_TEXT,"Client_Connections_created");

	char buf[32];
	int k;
	pthread_mutex_lock(&mutex);
	unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		char **pta=(char **)malloc(sizeof(char *)*colnum);
		pta[0]=strdup(node->get_hostname());
		sprintf(buf,"%d", node->get_port());
		pta[1]=strdup(buf);
		sprintf(buf,"%lu", node->get_weight());
		pta[2]=strdup(buf);
		pta[3]=strdup(node->get_comment());
		ProxySQL_Node_Metrics *curr = node->get_metrics_curr();
		// ProxySQL_Node_Metrics *prev = node->get_metrics_prev();
		sprintf(buf,"%llu", curr->response_time_us/1000);
		pta[4]=strdup(buf);
		sprintf(buf,"%llu", curr->ProxySQL_Uptime);
		pta[5]=strdup(buf);
		sprintf(buf,"%llu", (curtime - curr->read_time_us)/1000);
		pta[6]=strdup(buf);
		sprintf(buf,"%llu", curr->Questions);
		pta[7]=strdup(buf);
		sprintf(buf,"%llu", curr->Client_Connections_connected);
		pta[8]=strdup(buf);
		sprintf(buf,"%llu", curr->Client_Connections_created);
		pta[9]=strdup(buf);

		result->add_row(pta);
		for (k=0; k<colnum; k++) {
		if (pta[k])
			free(pta[k]);
		}
		free(pta);
		it++;
	}
	pthread_mutex_unlock(&mutex);
	return result;
}

SQLite3_result * ProxySQL_Cluster_Nodes::dump_table_proxysql_servers() {
	const int colnum=4;
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"weight");
	result->add_column_definition(SQLITE_TEXT,"comment");
	char buf[32];
	int k;
	pthread_mutex_lock(&mutex);
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {	
		ProxySQL_Node_Entry * node = it->second;
		char **pta=(char **)malloc(sizeof(char *)*colnum);
		pta[0]=strdup(node->get_hostname());
		sprintf(buf,"%d", node->get_port());
		pta[1]=strdup(buf);
		sprintf(buf,"%lu", node->get_weight());
		pta[2]=strdup(buf);
		pta[3]=strdup(node->get_comment());
		result->add_row(pta);
		for (k=0; k<colnum; k++) {
		if (pta[k])
			free(pta[k]);
		}
		free(pta);
		it++;
	}
	pthread_mutex_unlock(&mutex);
	return result;
}

ProxySQL_Cluster::ProxySQL_Cluster() {
	pthread_mutex_init(&mutex,NULL);
	pthread_mutex_init(&update_mysql_query_rules_mutex,NULL);
	pthread_mutex_init(&update_mysql_servers_mutex,NULL);
	pthread_mutex_init(&update_mysql_users_mutex,NULL);
	pthread_mutex_init(&update_proxysql_servers_mutex,NULL);
	cluster_username = strdup((char *)"");
	cluster_password = strdup((char *)"");
	cluster_check_interval_ms = 1000;
	cluster_check_status_frequency = 10;
	cluster_mysql_query_rules_diffs_before_sync = 3;
	cluster_mysql_servers_diffs_before_sync = 3;
	cluster_mysql_users_diffs_before_sync = 3;
	cluster_proxysql_servers_diffs_before_sync = 3;
	cluster_mysql_query_rules_save_to_disk = true;
	cluster_mysql_servers_save_to_disk = true;
	cluster_mysql_users_save_to_disk = true;
	cluster_proxysql_servers_save_to_disk = true;
}

ProxySQL_Cluster::~ProxySQL_Cluster() {
	if (cluster_username) {
		free(cluster_username);
		cluster_username = NULL;
	}
	if (cluster_password) {
		free(cluster_password);
		cluster_password = NULL;
	}
}

// this function returns credentials to the caller, used by monitoring threads
void ProxySQL_Cluster::get_credentials(char **username, char **password) {
	pthread_mutex_lock(&mutex);
	*username = strdup(cluster_username);
	*password = strdup(cluster_password);
	pthread_mutex_unlock(&mutex);
}

void ProxySQL_Cluster::set_username(char *_username) {
	pthread_mutex_lock(&mutex);
	free(cluster_username);
	cluster_username=strdup(_username);
	pthread_mutex_unlock(&mutex);
}

void ProxySQL_Cluster::set_password(char *_password) {
	pthread_mutex_lock(&mutex);
	free(cluster_password);
	cluster_password=strdup(_password);
	pthread_mutex_unlock(&mutex);
}

void ProxySQL_Cluster::print_version() {
  fprintf(stderr,"Standard ProxySQL Cluster rev. %s -- %s -- %s\n", PROXYSQL_CLUSTER_VERSION, __FILE__, __TIMESTAMP__);
};

void ProxySQL_Cluster::thread_ending(pthread_t _t) {
	pthread_mutex_lock(&mutex);
	term_threads.push_back(_t);
	pthread_mutex_unlock(&mutex);
}

void ProxySQL_Cluster::join_term_thread() {
	pthread_mutex_lock(&mutex);
	while (!term_threads.empty()) {
		pthread_t t = term_threads.back();
		term_threads.pop_back();
		pthread_join(t,NULL);
	}
	pthread_mutex_unlock(&mutex);
}
