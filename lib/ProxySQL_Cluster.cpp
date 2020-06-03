#include "proxysql.h"
#include "proxysql_utils.h"
#include "cpp.h"
#include "SpookyV2.h"
#include "prometheus_helpers.h"

#include "ProxySQL_Cluster.hpp"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_CLUSTER_VERSION "0.4.0906" DEB

#define QUERY_ERROR_RATE 20

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=(*proxy_sqlite3_step)(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(10);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

#define SAFE_SQLITE3_STEP2(_stmt) do {\
        do {\
                rc=(*proxy_sqlite3_step)(_stmt);\
                if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
                        usleep(100);\
                }\
        } while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
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
	int query_error_counter = 0;
	char *query_error = NULL;
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
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			if (conn == NULL) {
				conn = mysql_init(NULL);
				if (conn==NULL) {
					proxy_error("Unable to run mysql_init()\n");
					goto __exit_monitor_thread;
				}
			}
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
			//rc_conn = mysql_real_connect(conn, node->hostname, username, password, NULL, node->port, NULL, CLIENT_COMPRESS); // FIXME: add optional support for compression
			rc_conn = mysql_real_connect(conn, node->hostname, username, password, NULL, node->port, NULL, 0);
//			if (rc_conn) {
//			}
			//char *query = query1;
			if (rc_conn) {
				rc_query = mysql_query(conn,(char *)"SELECT @@version");
				if (rc_query == 0) {
					query_error = NULL;
					query_error_counter = 0;
					MYSQL_RES *result = mysql_store_result(conn);
					MYSQL_ROW row;
					bool same_version = false;
					while ((row = mysql_fetch_row(result))) {
						if (row[0]) {
							if (strcmp(row[0], PROXYSQL_VERSION)==0) {
								proxy_info("Cluster: clustering with peer %s:%d . Remote version: %s . Self version: %s\n", node->hostname, node->port, row[0], PROXYSQL_VERSION);
								same_version = true;
							} else {
								proxy_warning("Cluster: different ProxySQL version with peer %s:%d . Remote: %s . Self: %s\n", node->hostname, node->port, row[0], PROXYSQL_VERSION);
							}
						}
					}
					mysql_free_result(result);
					if (same_version == false) {
						mysql_close(conn);
						conn = mysql_init(NULL);
						int exit_after_N_seconds = 30; // hardcoded sleep time
						while (glovars.shutdown == 0 && exit_after_N_seconds) {
							sleep(1);
							exit_after_N_seconds--;
						}
						rc_query = 1;
					}
				}
				while ( glovars.shutdown == 0 && rc_query == 0 && rc_bool == true) {
					unsigned long long start_time=monotonic_time();
					//unsigned long long before_query_time=monotonic_time();
					rc_query = mysql_query(conn,query1);
					if ( rc_query == 0 ) {
						query_error = NULL;
						query_error_counter = 0;
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
								query_error = NULL;
								query_error_counter = 0;
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
							} else {
								query_error = query3;
								if (query_error_counter == 0) {
									proxy_error("Cluster: unable to run query on %s:%d using user %s : %s\n", node->hostname, node->port , username, query_error);
								}
								if (++query_error_counter == QUERY_ERROR_RATE) query_error_counter = 0;
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
									query_error = NULL;
									query_error_counter = 0;
									MYSQL_RES *result = mysql_store_result(conn);
									unsigned long long after_query_time=monotonic_time();
									unsigned long long elapsed_time_us = (after_query_time - before_query_time);
									rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, result, elapsed_time_us);
									mysql_free_result(result);
								} else {
									query_error = query2;
									if (query_error_counter == 0) {
										proxy_error("Cluster: unable to run query on %s:%d using user %s : %s\n", node->hostname, node->port , username, query_error);
									}
									if (++query_error_counter == QUERY_ERROR_RATE) query_error_counter = 0;
								}
							}
						}
					} else {
						query_error = query1;
						if (query_error_counter == 0) {
							proxy_error("Cluster: unable to run query on %s:%d using user %s : %s\n", node->hostname, node->port , username, query_error);
						}
						if (++query_error_counter == QUERY_ERROR_RATE) query_error_counter = 0;
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
				if (conn->net.pvio) {
					mysql_close(conn);
					conn = NULL;
					int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
					usleep((ci)*1000); // remember, usleep is in us
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
		rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, NULL, 0); // added extra check, see #1323
	}
__exit_monitor_thread:
	if (conn)
	if (conn->net.pvio) {
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
				proxy_info("Cluster: detected a new checksum for admin_variables from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.admin_variables.version, checksums_values.admin_variables.epoch, checksums_values.admin_variables.checksum);
			} else {
				proxy_info("Cluster: checksum for admin_variables from peer %s:%d matches with local checksum %s, we won't sync.\n", hostname, port, GloVars.checksums_values.admin_variables.checksum);
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
				proxy_info("Cluster: detected a new checksum for mysql_variables from peer %s:%d, version %llu, epoch %llu, checksum %s . Not syncing yet ...\n", hostname, port, checksums_values.mysql_variables.version, checksums_values.mysql_variables.epoch, checksums_values.mysql_variables.checksum);
				if (strcmp(checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.checksum) == 0) {
					proxy_info("Cluster: checksum for mysql_variables from peer %s:%d matches with local checksum %s , we won't sync.\n", hostname, port, GloVars.checksums_values.mysql_variables.checksum);
				}
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
		if (strcmp(v->checksum, GloVars.checksums_values.admin_variables.checksum) == 0) {
			v->diff_check = 0;
		}
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
		if (strcmp(v->checksum, GloVars.checksums_values.mysql_variables.checksum) == 0) {
			v->diff_check = 0;
		}
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
	unsigned int diff_mv = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync,0);
	unsigned int diff_av = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_admin_variables_diffs_before_sync,0);
	ProxySQL_Checksum_Value_2 *v = NULL;
	if (diff_mqr) {
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.checksum,0);
		v = &checksums_values.mysql_query_rules;
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mqr) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_query_rules_from_peer();
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mqr*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mqr*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_query_rules_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mqr*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL QUERY RULES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mqr*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_query_rules_version_one]->Increment();
			}
		}
	}
	if (diff_ms) {
		v = &checksums_values.mysql_servers;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.checksum,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ms) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_servers_from_peer();
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_ms*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ms*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_servers_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ms*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_servers_version_one]->Increment();
			}
		}
	}
	if (diff_mu) {
		v = &checksums_values.mysql_users;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.checksum,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mu) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_users_from_peer();
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mu*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mu*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_users_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mu*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL USERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mu*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_users_version_one]->Increment();
			}
		}
	}
	if (diff_ps) {
		v = &checksums_values.proxysql_servers;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.checksum,0);
		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ps) {
					proxy_info("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_proxysql_servers_from_peer();
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_ps*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ps*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_proxysql_servers_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ps*10)) == 0) {
					proxy_warning("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD PROXYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ps*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_proxysql_servers_version_one]->Increment();
			}
		}
	}
	if (diff_mv) {
		v = &checksums_values.mysql_variables;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.version, 0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.epoch, 0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.checksum, 0);

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mv) {
					proxy_info("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_global_variables_from_peer("mysql");
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mv*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_variables_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mv*10)) == 0) {
				proxy_warning("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_variables_version_one]->Increment();
			}
		}
	}
	if (diff_av) {
		v = &checksums_values.admin_variables;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.version, 0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.epoch, 0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.checksum, 0);

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_av) {
					proxy_info("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_global_variables_from_peer("admin");
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_av*10)) == 0)) {
				proxy_error("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %llu checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_av*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_admin_variables_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_av*10)) == 0) {
				proxy_warning("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %llu checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_av*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_admin_variables_version_one]->Increment();
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
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
			proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				MYSQL_RES *result1 = NULL;
				MYSQL_RES *result2 = NULL;
				rc_query = mysql_query(conn,"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM runtime_mysql_query_rules");
				if ( rc_query == 0 ) {
					MYSQL_RES *result1 = mysql_store_result(conn);
					rc_query = mysql_query(conn,"SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM runtime_mysql_query_rules_fast_routing");
					if ( rc_query == 0) {
						result2 = mysql_store_result(conn);
						proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d completed\n", hostname, port);
						proxy_info("Cluster: Loading to runtime MySQL Query Rules from peer %s:%d\n", hostname, port);
						GloAdmin->admindb->execute("DELETE FROM mysql_query_rules");
						GloAdmin->admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
						MYSQL_ROW row;
						char *q = (char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34)";
						sqlite3_stmt *statement1 = NULL;
						//sqlite3 *mydb3 = GloAdmin->admindb->get_db();
						//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q, -1, &statement1, 0);
						rc = GloAdmin->admindb->prepare_v2(q, &statement1);
						ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						while ((row = mysql_fetch_row(result1))) {
							rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(row[0])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // rule_id
							rc=(*proxy_sqlite3_bind_int64)(statement1, 2, 1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // active
							rc=(*proxy_sqlite3_bind_text)(statement1, 3, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
							rc=(*proxy_sqlite3_bind_text)(statement1, 4, row[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // schemaname
							rc=(*proxy_sqlite3_bind_text)(statement1, 5, row[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // flagIN
							rc=(*proxy_sqlite3_bind_text)(statement1, 6, row[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // client_addr
							rc=(*proxy_sqlite3_bind_text)(statement1, 7, row[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // proxy_addr
							rc=(*proxy_sqlite3_bind_text)(statement1, 8, row[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // proxy_port
							rc=(*proxy_sqlite3_bind_text)(statement1, 9, row[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // digest
							rc=(*proxy_sqlite3_bind_text)(statement1, 10, row[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // match_digest
							rc=(*proxy_sqlite3_bind_text)(statement1, 11, row[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // match_pattern
							rc=(*proxy_sqlite3_bind_text)(statement1, 12, row[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // negate_match_pattern
							rc=(*proxy_sqlite3_bind_text)(statement1, 13, row[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // re_modifiers
							rc=(*proxy_sqlite3_bind_text)(statement1, 14, row[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // flagOUT
							rc=(*proxy_sqlite3_bind_text)(statement1, 15, row[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // replace_pattern
							rc=(*proxy_sqlite3_bind_text)(statement1, 16, row[14], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // destination_hostgroup
							rc=(*proxy_sqlite3_bind_text)(statement1, 17, row[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // cache_ttl
							rc=(*proxy_sqlite3_bind_text)(statement1, 18, row[16], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // cache_empty_result
							rc=(*proxy_sqlite3_bind_text)(statement1, 19, row[17], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // cache_timeout
							rc=(*proxy_sqlite3_bind_text)(statement1, 20, row[18], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // reconnect
							rc=(*proxy_sqlite3_bind_text)(statement1, 21, row[19], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // timeout
							rc=(*proxy_sqlite3_bind_text)(statement1, 22, row[20], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // retries
							rc=(*proxy_sqlite3_bind_text)(statement1, 23, row[21], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // delay
							rc=(*proxy_sqlite3_bind_text)(statement1, 24, row[22], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // next_query_flagIN
							rc=(*proxy_sqlite3_bind_text)(statement1, 25, row[23], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // mirror_flagOUT
							rc=(*proxy_sqlite3_bind_text)(statement1, 26, row[24], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // mirror_hostgroup
							rc=(*proxy_sqlite3_bind_text)(statement1, 27, row[25], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // error_msg
							rc=(*proxy_sqlite3_bind_text)(statement1, 28, row[26], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // OK_msg
							rc=(*proxy_sqlite3_bind_text)(statement1, 29, row[27], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // sticky_conn
							rc=(*proxy_sqlite3_bind_text)(statement1, 30, row[28], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // multiplex
							rc=(*proxy_sqlite3_bind_text)(statement1, 31, row[29], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // gtid_from_hostgroup
							rc=(*proxy_sqlite3_bind_text)(statement1, 32, row[30], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // log
							rc=(*proxy_sqlite3_bind_text)(statement1, 33, row[31], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // apply
							rc=(*proxy_sqlite3_bind_text)(statement1, 34, row[32], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
							SAFE_SQLITE3_STEP2(statement1);
							rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
							rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						}
						char *q1fr = (char *)"INSERT INTO mysql_query_rules_fast_routing(username, schemaname, flagIN, destination_hostgroup, comment) VALUES (?1, ?2, ?3, ?4, ?5)";
						char *q32fr = (char *)"INSERT INTO mysql_query_rules_fast_routing(username, schemaname, flagIN, destination_hostgroup, comment) VALUES (?1, ?2, ?3, ?4, ?5), (?6, ?7, ?8, ?9, ?10), (?11, ?12, ?13, ?14, ?15), (?16, ?17, ?18, ?19, ?20), (?21, ?22, ?23, ?24, ?25), (?26, ?27, ?28, ?29, ?30), (?31, ?32, ?33, ?34, ?35), (?36, ?37, ?38, ?39, ?40), (?41, ?42, ?43, ?44, ?45), (?46, ?47, ?48, ?49, ?50), (?51, ?52, ?53, ?54, ?55), (?56, ?57, ?58, ?59, ?60), (?61, ?62, ?63, ?64, ?65), (?66, ?67, ?68, ?69, ?70), (?71, ?72, ?73, ?74, ?75), (?76, ?77, ?78, ?79, ?80), (?81, ?82, ?83, ?84, ?85), (?86, ?87, ?88, ?89, ?90), (?91, ?92, ?93, ?94, ?95), (?96, ?97, ?98, ?99, ?100), (?101, ?102, ?103, ?104, ?105), (?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115), (?116, ?117, ?118, ?119, ?120), (?121, ?122, ?123, ?124, ?125), (?126, ?127, ?128, ?129, ?130), (?131, ?132, ?133, ?134, ?135), (?136, ?137, ?138, ?139, ?140), (?141, ?142, ?143, ?144, ?145), (?146, ?147, ?148, ?149, ?150), (?151, ?152, ?153, ?154, ?155), (?156, ?157, ?158, ?159, ?160)";
						sqlite3_stmt *statement1fr = NULL;
						sqlite3_stmt *statement32fr = NULL;
						//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q1fr, -1, &statement1fr, 0);
						rc = GloAdmin->admindb->prepare_v2(q1fr, &statement1fr);
						ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q32fr, -1, &statement32fr, 0);
						rc = GloAdmin->admindb->prepare_v2(q32fr, &statement32fr);
						ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						int row_idx=0;
						int max_bulk_row_idx=mysql_num_rows(result2)/32;
						max_bulk_row_idx=max_bulk_row_idx*32;
						while ((row = mysql_fetch_row(result2))) {
							int idx=row_idx%32;
							if (row_idx<max_bulk_row_idx) { // bulk
								rc=(*proxy_sqlite3_bind_text)(statement32fr, (idx*5)+1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
								rc=(*proxy_sqlite3_bind_text)(statement32fr, (idx*5)+2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // schemaname
								rc=(*proxy_sqlite3_bind_int64)(statement32fr, (idx*5)+3, atoll(row[2])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // flagIN
								rc=(*proxy_sqlite3_bind_int64)(statement32fr, (idx*5)+4, atoll(row[3])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // destination_hostgroup
								rc=(*proxy_sqlite3_bind_text)(statement32fr, (idx*5)+5, row[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
								if (idx==31) {
									SAFE_SQLITE3_STEP2(statement32fr);
									rc=(*proxy_sqlite3_clear_bindings)(statement32fr); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
									rc=(*proxy_sqlite3_reset)(statement32fr); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
								}
							} else { // single row
								rc=(*proxy_sqlite3_bind_text)(statement1fr, 1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
								rc=(*proxy_sqlite3_bind_text)(statement1fr, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // schemaname
								rc=(*proxy_sqlite3_bind_int64)(statement1fr, 3, atoll(row[2])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // flagIN
								rc=(*proxy_sqlite3_bind_int64)(statement1fr, 4, atoll(row[3])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // destination_hostgroup
								rc=(*proxy_sqlite3_bind_text)(statement1fr, 5, row[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
								SAFE_SQLITE3_STEP2(statement1fr);
								rc=(*proxy_sqlite3_clear_bindings)(statement1fr); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
								rc=(*proxy_sqlite3_reset)(statement1fr); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
							}
							row_idx++;
						}
						GloAdmin->load_mysql_query_rules_to_runtime();
						if (GloProxyCluster->cluster_mysql_query_rules_save_to_disk == true) {
							proxy_info("Cluster: Saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
							GloAdmin->flush_mysql_query_rules__from_memory_to_disk();
						} else {
							proxy_info("Cluster: NOT saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
						}
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_success]->Increment();
					} else {
						proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
					}
				} else {
					proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
				}
				if (result1) {
					mysql_free_result(result1);
				}
				if (result2) {
					mysql_free_result(result2);
				}
			} else {
				proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
			}
		}
__exit_pull_mysql_query_rules_from_peer:
		if (conn) {
			if (conn->net.pvio) {
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
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
			proxy_info("Cluster: Fetching MySQL Users from peer %s:%d started\n", hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				rc_query = mysql_query(conn, "SELECT username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, comment FROM runtime_mysql_users");
				if ( rc_query == 0 ) {
					MYSQL_RES *result = mysql_store_result(conn);
					GloAdmin->admindb->execute("DELETE FROM mysql_users");
					MYSQL_ROW row;
					char *q = (char *)"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, comment) VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
					sqlite3_stmt *statement1 = NULL;
					//sqlite3 *mydb3 = GloAdmin->admindb->get_db();
					//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q, -1, &statement1, 0);
					rc = GloAdmin->admindb->prepare_v2(q, &statement1);
					ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
					while ((row = mysql_fetch_row(result))) {
						rc=(*proxy_sqlite3_bind_text)(statement1, 1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
						rc=(*proxy_sqlite3_bind_text)(statement1, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // password
						rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoll(row[2])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // active
						rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(row[3])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // use_ssl
						rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoll(row[4])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // default_hostgroup
						rc=(*proxy_sqlite3_bind_text)(statement1, 6, row[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // default_schema
						rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(row[6])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // schema_locked
						rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(row[7])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // transaction_persistent
						rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(row[8])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // fast_forward
						rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(row[9])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // backend
						rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(row[10])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // frontend
						rc=(*proxy_sqlite3_bind_int64)(statement1, 12, atoll(row[11])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // max_connection
						rc=(*proxy_sqlite3_bind_text)(statement1, 13, row[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment

						SAFE_SQLITE3_STEP2(statement1);
						rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
					}
					mysql_free_result(result);
					proxy_info("Cluster: Fetching MySQL Users from peer %s:%d completed\n", hostname, port);
					proxy_info("Cluster: Loading to runtime MySQL Users from peer %s:%d\n", hostname, port);
					GloAdmin->init_users();
					if (GloProxyCluster->cluster_mysql_query_rules_save_to_disk == true) {
						proxy_info("Cluster: Saving to disk MySQL Users from peer %s:%d\n", hostname, port);
						GloAdmin->flush_mysql_users__from_memory_to_disk();
					} else {
						proxy_info("Cluster: Saving to disk MySQL Users Rules from peer %s:%d\n", hostname, port);
					}
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_success]->Increment();
				} else {
					proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_failure]->Increment();
				}
			} else {
				proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_failure]->Increment();
			}
		}
__exit_pull_mysql_users_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_users_mutex);
}

/**
 * @brief Makes a query with the supplied connection and stores the result in the
 *  'MYSQL_RES' passed as a parameter.
 *
 * @param conn The MYSQL connectionn in which to perform the queries.
 * @param f_query A struct holding the query, three messages and the counters to update
 *  case of success, and in case of error:
 *   1. Message to display before performing the query.
 *   2. Message to display when the operation is complete.
 *   3. Message to display in case the query fails to be executed.
 * @param result The result of the executed query.
 * @return int The errno in case fo the query execution not being successful,
 *  zero otherwise.
 */
int ProxySQL_Cluster::fetch_and_store(MYSQL* conn, const fetch_query& f_query, MYSQL_RES** result) {
	const auto& msgs = f_query.msgs;
	const auto& query = f_query.query;

	// report operation to be performed
	if (!msgs[0].empty()) {
		proxy_info("%s", msgs[0].c_str());
	}

	int query_res = mysql_query(conn, query);

	if (query_res == 0) {
		*result = mysql_store_result(conn);
		query_res = mysql_errno(conn);
	} else {
		// report error
		if (!msgs[2].empty()) {
			std::string f_err = msgs[2] + mysql_error(conn);
			proxy_info("%s", f_err.c_str());
		}
		if (f_query.failure_counter != p_cluster_counter::metric(-1)) {
			metrics.p_counter_array[f_query.failure_counter]->Increment();
		}
	}

	// report finish msg
	if (query_res == 0 && !msgs[1].empty()) {
		proxy_info("%s", msgs[1].c_str());
	}

	if (f_query.success_counter != p_cluster_counter::metric(-1)) {
		metrics.p_counter_array[f_query.success_counter]->Increment();
	}

	return query_res;
}

void ProxySQL_Cluster::pull_mysql_servers_from_peer() {
	char * hostname = NULL;
	uint16_t port = 0;
	char * peer_checksum = NULL;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_servers_mutex);
	nodes.get_peer_to_sync_mysql_servers(&hostname, &port, &peer_checksum);
	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		// bool rc_bool = true;
		MYSQL *rc_conn;
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
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
			proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d started. Expected checksum %s\n", hostname, port, peer_checksum);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);
			if (rc_conn) {
				GloAdmin->mysql_servers_wrlock();
				std::vector<MYSQL_RES*> results {};

				// Server query messages
				std::string fetch_servers_done = "";
				string_format("Cluster: Fetching MySQL Servers from peer %s:%d completed\n", fetch_servers_done, hostname, port);
				std::string fetch_servers_err = "";
				string_format("Cluster: Fetching MySQL Servers from peer %s:%d failed: \n", fetch_servers_err, hostname, port);

				// group_replication_hostgroups query and messages
				const char* CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS =
					"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
					"max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_group_replication_hostgroups";
				std::string fetch_group_replication_hostgroups = "";
				string_format("Cluster: Fetching 'MySQL Group Replication Hostgroups' from peer %s:%d\n", fetch_group_replication_hostgroups, hostname, port);
				std::string fetch_group_replication_hostgroups_err = "";
				string_format("Cluster: Fetching 'MySQL Group Replication Hostgroups' from peer %s:%d failed: \n", fetch_group_replication_hostgroups_err, hostname, port);

				// AWS Aurora query and messages
				const char* CLUSTER_QUERY_MYSQL_AWS_AURORA =
					"SELECT writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
					"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment FROM runtime_mysql_aws_aurora_hostgroups";
				std::string fetch_aws_aurora_start = "";
				string_format("Cluster: Fetching 'MySQL Aurora Hostgroups' from peer %s:%d\n", fetch_aws_aurora_start, hostname, port);
				std::string fetch_aws_aurora_err = "";
				string_format("Cluster: Fetching 'MySQL Aurora Hostgroups' from peer %s:%d failed: \n", fetch_aws_aurora_err, hostname, port);

				// Galera query and messages
				const char* CLUSTER_QUERY_MYSQL_GALERA =
					"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
					"max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_galera_hostgroups";
				std::string fetch_galera_start = "";
				string_format("Cluster: Fetching 'MySQL Galera Hostgroups' from peer %s:%d\n", fetch_galera_start, hostname, port);
				std::string fetch_galera_err = "";
				string_format("Cluster: Fetching 'MySQL Galera Hostgroups' from peer %s:%d failed: \n", fetch_galera_err, hostname, port);

				// Checksums query and messages
				const char* CLUSTER_QUERY_RUNTIME_CHECKS = "SELECT * FROM runtime_checksums_values WHERE name='mysql_servers' LIMIT 1";
				std::string fetch_checksums_start = "";
				string_format("Cluster: Fetching checksum for MySQL Servers from peer %s:%d before proceessing\n", fetch_checksums_start, hostname, port);
				std::string fetch_checksums_err = "";
				string_format("Cluster: Fetching checksum for MySQL Servers from peer %s:%d failed: \n", fetch_checksums_err, hostname, port);

				// Create fetching queries
				fetch_query queries[] = {
					{
						CLUSTER_QUERY_MYSQL_SERVERS,
						p_cluster_counter::pulled_mysql_servers_success,
						p_cluster_counter::pulled_mysql_servers_failure,
						{ "", fetch_servers_done, fetch_servers_err }
					},
					{
						CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS,
						p_cluster_counter::pulled_mysql_servers_replication_hostgroups_success,
						p_cluster_counter::pulled_mysql_servers_replication_hostgroups_failure,
						{ "", "", fetch_servers_err }
					},
					{
						CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS,
						p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_success,
						p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_failure,
						{ fetch_group_replication_hostgroups, "", fetch_group_replication_hostgroups_err }
					},
					{
						CLUSTER_QUERY_MYSQL_GALERA,
						p_cluster_counter::pulled_mysql_servers_galera_hostgroups_success,
						p_cluster_counter::pulled_mysql_servers_galera_hostgroups_failure,
						{ fetch_galera_start, "", fetch_galera_err } },
					{
						CLUSTER_QUERY_MYSQL_AWS_AURORA,
						p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_success,
						p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_failure,
						{ fetch_aws_aurora_start, "", fetch_aws_aurora_err }
					},
					{
						CLUSTER_QUERY_RUNTIME_CHECKS,
						p_cluster_counter::pulled_mysql_servers_runtime_checks_success,
						p_cluster_counter::pulled_mysql_servers_runtime_checks_failure,
						{ fetch_checksums_start, "", fetch_checksums_err }
					}
				};

				bool fetching_error = false;
				for (size_t i = 0; i < sizeof(queries) / sizeof(fetch_query); i++) {
					MYSQL_RES* fetch_res = nullptr;
					int it_err = fetch_and_store(conn, queries[i], &fetch_res);

					if (it_err == 0) {
						results.push_back(fetch_res);
					} else {
						fetching_error = true;
						break;
					}
				}

				if (fetching_error == false) {
					MYSQL_ROW row;
					char *checks = NULL;
					while ((row = mysql_fetch_row(results[5]))) {
						if (checks) { // health check
							free(checks);
							checks = NULL;
						}
						if (row[3]) {
							checks = strdup(row[3]); // checksum
						}
					}
					if (checks && strcmp(checks,peer_checksum)==0) {
						// we are OK to sync!
						proxy_info("Cluster: Fetching checksum for MySQL Servers from peer %s:%d successful. Checksum: %s\n", hostname, port, checks);
						// sync mysql_servers
						proxy_info("Cluster: Writing mysql_servers table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_servers");
						MYSQL_ROW row;
						char *q=(char *)"INSERT INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (%s, \"%s\", %s, %s, %s, \"%s\", %s, %s, %s, %s, %s, '%s')";
						while ((row = mysql_fetch_row(results[0]))) {
							int i;
							int l=0;
							for (i=0; i<11; i++) {
								l+=strlen(row[i]);
							}
							char *o=escape_string_single_quotes(row[11],false);
							char *query = (char *)malloc(strlen(q)+i+strlen(o)+64);

							sprintf(query,q,row[0],row[1],row[2],row[3], row[4], ( strcmp(row[5],"SHUNNED")==0 ? "ONLINE" : row[5] ), row[6],row[7],row[8],row[9],row[10],o);
							if (o!=row[11]) { // there was a copy
								free(o);
							}
							GloAdmin->admindb->execute(query);
							free(query);
						}

						// sync mysql_replication_hostgroups
						proxy_info("Cluster: Writing mysql_replication_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_replication_hostgroups");
						q=(char *)"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment) VALUES (%s, %s, '%s', '%s')";
						while ((row = mysql_fetch_row(results[1]))) {
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

						// sync mysql_group_replication_hostgroups
						proxy_info("Cluster: Writing mysql_group_replication_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_group_replication_hostgroups");
						q=(char*)"INSERT INTO mysql_group_replication_hostgroups ( "
							"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
							"max_writers, writer_is_also_reader, max_transactions_behind, comment) ";
						char *error = NULL;
						int cols = 0;
						int affected_rows = 0;
						SQLite3_result *resultset = NULL;
						while ((row = mysql_fetch_row(results[2]))) {
							int i;
							int l = 0;
							for (i = 0; i < 8; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[8] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[8], false);
								query = (char *)malloc(strlen(fqs.c_str()) + i + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
								// free in case of 'o' being a copy
								if (o != row[8]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char *)malloc(strlen(fqs.c_str()) + strlen("NULL") + i + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_info("Dumping fetched 'mysql_group_replication_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char *)"SELECT * FROM mysql_group_replication_hostgroups", &error , &cols , &affected_rows , &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_galera_hostgroups
						proxy_info("Cluster: Writing mysql_galera_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_galera_hostgroups");
						q=(char *)"INSERT INTO mysql_galera_hostgroups ( "
							"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
							"max_writers, writer_is_also_reader, max_transactions_behind, comment) ";
						while ((row = mysql_fetch_row(results[3]))) {
							int i;
							int l = 0;
							for (i = 0; i < 8; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[8] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[8], false);
								query = (char *)malloc(strlen(fqs.c_str()) + i + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
								// free in case of 'o' being a copy
								if (o != row[8]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char *)malloc(strlen(fqs.c_str()) + i + strlen("NULL") + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_info("Dumping fetched 'mysql_galera_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char *)"SELECT * FROM mysql_galera_hostgroups", &error , &cols , &affected_rows , &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_aws_aurora_hostgroups
						proxy_info("Cluster: Writing mysql_aws_aurora_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_aws_aurora_hostgroups");
						q=(char *)"INSERT INTO mysql_aws_aurora_hostgroups ( "
							"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
							"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) ";
						while ((row = mysql_fetch_row(results[4]))) {
							int i;
							int l = 0;
							for (i = 0; i < 13; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[13] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, '%s', %s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[13], false);
								query = (char *)malloc(strlen(fqs.c_str()) + i + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], o);
								// free in case of 'o' being a copy
								if (o != row[13]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, '%s', %s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char *)malloc(strlen(fqs.c_str()) + i + strlen("NULL") + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_info("Dumping fetched 'mysql_aws_aurora_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char *)"SELECT * FROM mysql_aws_aurora_hostgroups", &error , &cols , &affected_rows , &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						proxy_info("Cluster: Loading to runtime MySQL Servers from peer %s:%d\n", hostname, port);
						GloAdmin->load_mysql_servers_to_runtime();
						if (GloProxyCluster->cluster_mysql_servers_save_to_disk == true) {
							proxy_info("Cluster: Saving to disk MySQL Servers from peer %s:%d\n", hostname, port);
							GloAdmin->flush_mysql_servers__from_memory_to_disk();
						} else {
							proxy_info("Cluster: Not saving to disk MySQL Servers from peer %s:%d failed.\n", hostname, port);
						}
					}

					// free results
					for (MYSQL_RES* result : results) {
						mysql_free_result(result);
					}

					metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_success]->Increment();
				}
				GloAdmin->mysql_servers_wrunlock();
			} else {
				proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_failure]->Increment();
			}
		}
__exit_pull_mysql_servers_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_servers_mutex);
}

void ProxySQL_Cluster::pull_global_variables_from_peer(const std::string& var_type) {
	char * hostname = NULL;
	uint16_t port = 0;
	char* vars_type_str = nullptr;
	p_cluster_counter::metric success_metric = p_cluster_counter::metric(-1);
	p_cluster_counter::metric failure_metric = p_cluster_counter::metric(-1);

	if (var_type == "mysql") {
		vars_type_str = const_cast<char*>("MySQL");
		success_metric = p_cluster_counter::pulled_mysql_variables_success;
		failure_metric = p_cluster_counter::pulled_mysql_variables_failure;
	} else if (var_type == "admin") {
		vars_type_str = const_cast<char*>("Admin");
		success_metric = p_cluster_counter::pulled_admin_variables_success;
		failure_metric = p_cluster_counter::pulled_admin_variables_failure;
	} else {
		proxy_error("Invalid parameter supplied to 'pull_global_variables_from_peer': var_type=%s", var_type.c_str());
		assert(0);
	}

	pthread_mutex_lock(&GloProxyCluster->update_mysql_variables_mutex);
	if (var_type == "mysql") {
		nodes.get_peer_to_sync_mysql_variables(&hostname, &port);
	} else {
		nodes.get_peer_to_sync_admin_variables(&hostname, &port);
	}

	if (hostname) {
		char *username = NULL;
		char *password = NULL;
		MYSQL *rc_conn = nullptr;
		int rc_query = 0;
		int rc = 0;
		MYSQL *conn = mysql_init(NULL);

		if (conn == NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_variables_from_peer;
		}

		GloProxyCluster->get_credentials(&username, &password);
		if (strlen(username)) { // do not monitor if the username is empty
			unsigned int timeout = 1;
			unsigned int timeout_long = 60;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout_long);
			mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
			proxy_info("Cluster: Fetching %s variables from peer %s:%d started\n", vars_type_str, hostname, port);
			rc_conn = mysql_real_connect(conn, hostname, username, password, NULL, port, NULL, 0);

			if (rc_conn) {
				std::string s_query = "";
				string_format("SELECT * FROM runtime_global_variables WHERE variable_name LIKE '%s-%%'", s_query, var_type.c_str());
				mysql_query(conn, s_query.c_str());

				if (rc_query == 0) {
					MYSQL_RES *result = mysql_store_result(conn);
					std::string d_query = "";
					string_format("DELETE FROM runtime_global_variables WHERE variable_name LIKE '%s-%%'", d_query, var_type.c_str());
					GloAdmin->admindb->execute(d_query.c_str());

					MYSQL_ROW row;
					char *q = (char *)"INSERT OR REPLACE INTO global_variables (variable_name, variable_value) VALUES (?1 , ?2)";
					sqlite3_stmt *statement1 = NULL;
					rc = GloAdmin->admindb->prepare_v2(q, &statement1);
					ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

					while ((row = mysql_fetch_row(result))) {
						rc=(*proxy_sqlite3_bind_text)(statement1, 1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // variable_name
						rc=(*proxy_sqlite3_bind_text)(statement1, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // variable_value

						SAFE_SQLITE3_STEP2(statement1);
						rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
					}

					mysql_free_result(result);
					proxy_info("Cluster: Fetching %s Variables from peer %s:%d completed\n", vars_type_str, hostname, port);
					proxy_info("Cluster: Loading to runtime %s Variables from peer %s:%d\n", vars_type_str, hostname, port);

					if (var_type == "mysql") {
						GloAdmin->load_mysql_variables_to_runtime();

						if (GloProxyCluster->cluster_mysql_variables_save_to_disk == true) {
							proxy_info("Cluster: Saving to disk MySQL Variables from peer %s:%d\n", hostname, port);
							GloAdmin->flush_mysql_variables__from_memory_to_disk();
						}
					} else {
						GloAdmin->load_admin_variables_to_runtime();

						if (GloProxyCluster->cluster_admin_variables_save_to_disk == true) {
							proxy_info("Cluster: Saving to disk Admin Variables from peer %s:%d\n", hostname, port);
							GloAdmin->flush_admin_variables__from_memory_to_disk();
						}
					}
					metrics.p_counter_array[success_metric]->Increment();
				} else {
					proxy_info("Cluster: Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
					metrics.p_counter_array[failure_metric]->Increment();
				}
			} else {
				proxy_info("Cluster: Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
				metrics.p_counter_array[failure_metric]->Increment();
			}
		}
__exit_pull_mysql_variables_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_variables_mutex);
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
			{ unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val); }
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
					} else {
						proxy_info("Cluster: NOT saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
					}
					metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_success]->Increment();
				} else {
					proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_failure]->Increment();
				}
			} else {
				proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_failure]->Increment();
			}
		}
__exit_pull_proxysql_servers_from_peer:
		if (conn) {
			if (conn->net.pvio) {
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
			if (pthread_create(&a->thrid, &attr, ProxySQL_Cluster_Monitor_thread, (void *)a) != 0) {
				proxy_error("Thread creation\n");
				assert(0);
			}
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
		if (_r) {
			node->set_metrics(_r, _response_time);
		} else {
			// if _r is NULL, this function is being called only to verify if
			// the node should still be checked or not
			// see bug #1323
		}
		ret = true;
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_query_rules(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	unsigned int diff_mqr = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_query_rules_diffs_before_sync,0);
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_query_rules;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_mqr) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with mysql_query_rules epoch %llu , but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_query_rules version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_servers(char **host, uint16_t *port, char **peer_checksum) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
	char *pc = NULL;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	unsigned int diff_ms = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync,0);
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_servers;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_ms) {
					epoch = v->epoch;
					version = v->version;
					if (pc) {
						free(pc);
					}
					if (hostname) {
						free(hostname);
					}
					pc = strdup(v->checksum);
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with mysql_servers epoch %llu , but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
			if (pc) {
				free(pc);
				pc = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_servers version %llu, epoch %llu\n", hostname, p, version, epoch);
		*peer_checksum = pc;
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_users(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_users_diffs_before_sync,0);
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_users;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with mysql_users epoch %llu , but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_users version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_variables(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync,0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end();) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_variables;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with mysql_variables epoch %llu, but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with mysql_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}


void ProxySQL_Cluster_Nodes::get_peer_to_sync_admin_variables(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_admin_variables_diffs_before_sync,0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end();) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.admin_variables;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with admin_variables epoch %llu, but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		proxy_info("Cluster: detected peer %s:%d with admin_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_proxysql_servers(char **host, uint16_t *port) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	uint16_t p = 0;
//	pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	unsigned int diff_ps = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_proxysql_servers_diffs_before_sync,0);
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.proxysql_servers;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check > diff_ps) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					hostname=strdup(node->get_hostname());
					p = node->get_port();
				}
			}
		}
		it++;
	}
//	pthread_mutex_unlock(&mutex);
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with proxysql_servers epoch %llu , but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
		}
	}
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

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using cluster_counter_tuple =
	std::tuple<
		p_cluster_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_gauge_tuple =
	std::tuple<
		p_cluster_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_counter_vector = std::vector<cluster_counter_tuple>;
using cluster_gauge_vector = std::vector<cluster_gauge_tuple>;

const std::tuple<cluster_counter_vector, cluster_gauge_vector>
cluster_metrics_map = std::make_tuple(
	cluster_counter_vector {
		// mysql_query_rules
		std::make_tuple (
			p_cluster_counter::pulled_mysql_query_rules_success,
			"pulled_mysql_query_rules",
			"Number of times 'mysql_query_rules' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_query_rules_failure,
			"pulled_mysql_query_rules",
			"Number of times 'mysql_query_rules' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// mysql_servers_*
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_success,
			"pulled_mysql_servers",
			"Number of times 'mysql_servers' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_failure,
			"pulled_mysql_servers",
			"Number of times 'mysql_servers' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_replication_hostgroups_success,
			"pulled_mysql_servers_replication_hostgroups",
			"Number of times 'mysql_servers_replication_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "successs" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_replication_hostgroups_failure,
			"pulled_mysql_servers_replication_hostgroups",
			"Number of times 'mysql_servers_replication_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_success,
			"pulled_mysql_servers_group_replication_hostgroups",
			"Number of times 'mysql_servers_group_replication_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_failure,
			"pulled_mysql_servers_group_replication_hostgroups",
			"Number of times 'mysql_servers_group_replication_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_galera_hostgroups_success,
			"pulled_mysql_servers_galera_hostgroups",
			"Number of times 'mysql_servers_galera_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_galera_hostgroups_failure,
			"pulled_mysql_servers_galera_hostgroups",
			"Number of times 'mysql_servers_galera_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_success,
			"pulled_mysql_servers_aws_aurora_hostgroups",
			"Number of times 'mysql_servers_aws_aurora_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_failure,
			"pulled_mysql_servers_aws_aurora_hostgroups",
			"Number of times 'mysql_servers_aws_aurora_hostgroups' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_runtime_checks_success,
			"pulled_mysql_servers_runtime_checks",
			"Number of times '' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_runtime_checks_failure,
			"pulled_mysql_servers_runtime_checks",
			"Number of times 'mysql_servers_runtime_checks' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// mysql_users_*
		std::make_tuple (
			p_cluster_counter::pulled_mysql_users_success,
			"pulled_mysql_users",
			"Number of times 'mysql_users' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_users_failure,
			"pulled_mysql_users",
			"Number of times 'mysql_users' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// proxysql_servers_*
		std::make_tuple (
			p_cluster_counter::pulled_proxysql_servers_success,
			"pulled_proxysql_servers",
			"Number of times 'mysql_proxysql_servers' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_proxysql_servers_failure,
			"pulled_proxysql_servers",
			"Number of times 'mysql_proxysql_servers' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// mysql_variables_*
		std::make_tuple (
			p_cluster_counter::pulled_mysql_variables_success,
			"pulled_mysql_variables",
			"Number of times 'mysql_variables' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_variables_failure,
			"pulled_mysql_variables",
			"Number of times 'mysql_variables' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// admin_variables_*
		std::make_tuple (
			p_cluster_counter::pulled_admin_variables_success,
			"pulled_admin_variables",
			"Number of times 'admin_variables' have been pulled from a peer.",
			metric_tags { { "status", "success" } }
		),
		std::make_tuple (
			p_cluster_counter::pulled_admin_variables_failure,
			"pulled_admin_variables",
			"Number of times 'admin_variables' have been pulled from a peer.",
			metric_tags { { "status", "failure" } }
		),

		// sync_conflict same epoch
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_query_rules_share_epoch,
			"sync_conflict_mysql_query_rules_share_epoch",
			"Number of times 'mysql_query_rules' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_servers_share_epoch,
			"sync_conflict_mysql_servers_share_epoch",
			"Number of times 'mysql_servers' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_proxysql_servers_share_epoch,
			"sync_conflict_proxysql_servers_share_epoch",
			"Number of times 'proxysql_servers' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_users_share_epoch,
			"sync_conflict_mysql_users_share_epoch",
			"Number of times 'mysql_users' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_variables_share_epoch,
			"sync_conflict_mysql_variables_share_epoch",
			"Number of times 'mysql_variables' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_admin_variables_share_epoch,
			"sync_conflict_admin_variables_share_epoch",
			"Number of times 'admin_variables' has not been synced because they share the same epoch.",
			metric_tags { { "type", "error" } }
		),

		// sync_delayed due to version one
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_query_rules_version_one,
			"sync_delayed_mysql_query_rules_version_one",
			"Number of times 'mysql_query_rules' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_servers_version_one,
			"sync_delayed_mysql_servers_version_one",
			"Number of times 'mysql_servers' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_users_version_one,
			"sync_delayed_mysql_users_version_one",
			"Number of times 'mysql_users' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_proxysql_servers_version_one,
			"sync_delayed_proxysql_servers_version_one",
			"Number of times 'proxysql_servers' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_variables_version_one,
			"sync_delayed_mysql_variables_version_one",
			"Number of times 'mysql_variables' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_admin_variables_version_one,
			"sync_delayed_admin_variables_version_one",
			"Number of times 'admin_variables' has not been synced because version one doesn't allow sync.",
			metric_tags { { "type", "warning" } }
		),

	},
	cluster_gauge_vector {}
);

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
	init_prometheus_counter_array<cluster_metrics_map_idx, p_cluster_counter>(cluster_metrics_map, this->metrics.p_counter_array);
	init_prometheus_gauge_array<cluster_metrics_map_idx, p_cluster_gauge>(cluster_metrics_map, this->metrics.p_gauge_array);
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
