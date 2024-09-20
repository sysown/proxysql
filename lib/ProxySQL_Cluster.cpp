#include <utility>

#include "proxysql.h"
#include "proxysql_utils.h"
#include "cpp.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "prometheus_helpers.h"

#include "ProxySQL_Cluster.hpp"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"

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

using std::vector;
using std::pair;
using std::string;

static char *NODE_COMPUTE_DELIMITER=(char *)"-gtyw23a-"; // a random string used for hashing

extern ProxySQL_Cluster * GloProxyCluster;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_LDAP_Authentication* GloMyLdapAuth;
extern MySQL_Authentication* GloMyAuth;

void * ProxySQL_Cluster_Monitor_thread(void *args) {
	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	set_thread_name("ClusterMonitor");
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads,tmp_stack_size);
		}
	}

	ProxySQL_Node_Address * node = (ProxySQL_Node_Address *)args;
	mysql_thread_init();
	pthread_detach(pthread_self());

	proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Thread started for peer %s:%d\n", node->hostname, node->port);

	proxy_info("Cluster: starting thread for peer %s:%d\n", node->hostname, node->port);
	char *query1 = (char *)"SELECT GLOBAL_CHECKSUM()"; // in future this will be used for "light check"
	char *query2 = (char *)"SELECT * FROM stats_mysql_global ORDER BY Variable_Name";
	char *query3 = (char *)"SELECT * FROM runtime_checksums_values ORDER BY name";
	bool rc_bool = true;
	int query_error_counter = 0;
	char *query_error = NULL;
	int cluster_check_status_frequency_count = 0;
	MYSQL *conn = mysql_init(NULL);

	if (conn==NULL) {
		proxy_error("Unable to run mysql_init()\n");
		goto __exit_monitor_thread;
	}
	while (glovars.shutdown == 0 && rc_bool == true) {
		cluster_creds_t creds(GloProxyCluster->get_credentials());

		if (creds.user.size()) { // do not monitor if the username is empty
			if (conn == NULL) {
				conn = mysql_init(NULL);
				if (conn==NULL) {
					proxy_error("Unable to run mysql_init()\n");
					goto __exit_monitor_thread;
				}
			}
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			// FIXME: add optional support for compression
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Connecting to peer %s:%d\n", node->hostname, node->port);
			MYSQL* rc_conn = mysql_real_connect(conn, node->get_host_address(), creds.user.c_str(), creds.pass.c_str(), NULL, node->port, NULL, 0);

			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				int rc_query = mysql_query(conn,(char *)"SELECT @@version");
				if (rc_query == 0) {
					query_error = NULL;
					query_error_counter = 0;
					MYSQL_RES *result = mysql_store_result(conn);
					MYSQL_ROW row;
					bool same_version = false;
					while ((row = mysql_fetch_row(result))) {
						if (row[0]) {
							const char* PROXYSQL_VERSION_ = GloMyLdapAuth == nullptr ? PROXYSQL_VERSION : PROXYSQL_VERSION"-Enterprise";
							if (strcmp(row[0], PROXYSQL_VERSION_)==0) {
								proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Clustering with peer %s:%d . Remote version: %s . Self version: %s\n", node->hostname, node->port, row[0], PROXYSQL_VERSION_);
								proxy_info("Cluster: clustering with peer %s:%d . Remote version: %s . Self version: %s\n", node->hostname, node->port, row[0], PROXYSQL_VERSION_);
								same_version = true;
								std::string q = "PROXYSQL CLUSTER_NODE_UUID ";
								q += GloVars.uuid;
								q += " ";
								pthread_mutex_lock(&GloProxyCluster->admin_mysql_ifaces_mutex);
								q += GloProxyCluster->admin_mysql_ifaces;
								pthread_mutex_unlock(&GloProxyCluster->admin_mysql_ifaces_mutex);
								proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Sending CLUSTER_NODE_UUID %s to peer %s:%d\n", GloVars.uuid, node->hostname, node->port);
								proxy_info("Cluster: sending CLUSTER_NODE_UUID %s to peer %s:%d\n", GloVars.uuid, node->hostname, node->port);
								rc_query = mysql_query(conn, q.c_str());
							} else {
								proxy_warning("Cluster: different ProxySQL version with peer %s:%d . Remote: %s . Self: %s\n", node->hostname, node->port, row[0], PROXYSQL_VERSION_);
							}
						}
					}
					mysql_free_result(result);
					if (same_version == false) {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Remote peer %s:%d proxysql version is different. Closing connection\n", node->hostname, node->port);
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

					rc_query = mysql_query(conn,query1);
					if ( rc_query == 0 ) {
						query_error = NULL;
						query_error_counter = 0;
						MYSQL_RES *result = mysql_store_result(conn);
						//unsigned long long after_query_time=monotonic_time();
						//unsigned long long elapsed_time_us = (after_query_time - before_query_time);
						bool update_checksum = GloProxyCluster->Update_Global_Checksum(node->hostname, node->port, result);
						mysql_free_result(result);
						// FIXME: update metrics are not updated for now. We only check checksum
						//rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, result, elapsed_time_us);

						if (update_checksum) {
							unsigned long long before_query_time=monotonic_time();
							rc_query = mysql_query(conn,query3);
							if ( rc_query == 0 ) {
								query_error = NULL;
								query_error_counter = 0;
								MYSQL_RES *result = mysql_store_result(conn);
								rc_bool = GloProxyCluster->Update_Node_Checksums(node->hostname, node->port, result);
								mysql_free_result(result);
							} else {
								query_error = query3;
								if (query_error_counter == 0) {
									unsigned long long after_query_time=monotonic_time();
									unsigned long long elapsed_time_us = (after_query_time - before_query_time);
									proxy_error(
										"Cluster: unable to run query on %s:%d using user %s after %llums : %s . Error: %s\n",
										node->hostname, node->port, creds.user.c_str(), elapsed_time_us/1000, query_error, mysql_error(conn)
									);
								}
								if (++query_error_counter == QUERY_ERROR_RATE) query_error_counter = 0;
							}
						} else {
							GloProxyCluster->Update_Node_Checksums(node->hostname, node->port);
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
										unsigned long long after_query_time=monotonic_time();
										unsigned long long elapsed_time_us = (after_query_time - before_query_time);
										proxy_error(
											"Cluster: unable to run query on %s:%d using user %s after %llums : %s . Error: %s\n",
											node->hostname, node->port, creds.user.c_str(), elapsed_time_us/1000, query_error, mysql_error(conn)
										);
									}
									if (++query_error_counter == QUERY_ERROR_RATE) query_error_counter = 0;
								}
							}
						}
					} else {
						query_error = query1;
						if (query_error_counter == 0) {
							unsigned long long after_query_time=monotonic_time();
							unsigned long long elapsed_time_us = (after_query_time - start_time);
							proxy_error(
								"Cluster: unable to run query on %s:%d using user %s after %llums : %s . Error: %s\n",
								node->hostname, node->port, creds.user.c_str(), elapsed_time_us/1000, query_error, mysql_error(conn)
							);
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
				node->resolve_hostname();
				mysql_close(conn);
				conn = mysql_init(NULL);
				int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
				usleep((ci)*1000); // remember, usleep is in us
				sleep(1); // sleep for longer
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
	delete node;
	mysql_thread_end();

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

ProxySQL_Node_Entry::ProxySQL_Node_Entry(char *_hostname, uint16_t _port, uint64_t _weight, char * _comment) : 
	ProxySQL_Node_Entry(_hostname, _port, _weight, _comment, NULL) {
	// resolving DNS if available in Cache
	resolve_hostname();
}

ProxySQL_Node_Entry::ProxySQL_Node_Entry(char* _hostname, uint16_t _port, uint64_t _weight, char* _comment, char* ip) {
	hash = 0;
	global_checksum = 0;
	ip_addr = NULL;
	hostname = NULL;
	if (_hostname) {
		hostname = strdup(_hostname);
	}
	port = _port;
	weight = _weight;
	if (_comment == NULL) {
		comment = strdup((char*)"");
	} else {
		comment = strdup(_comment);
	}

	if (ip) {
		ip_addr = strdup(ip);
	}

	active = false;
	hash = generate_hash_proxysql_node(_hostname, _port);
	metrics_idx = 0;
	metrics = (ProxySQL_Node_Metrics**)malloc(sizeof(ProxySQL_Node_Metrics*) * PROXYSQL_NODE_METRICS_LEN);
	for (int i = 0; i < PROXYSQL_NODE_METRICS_LEN; i++) {
		metrics[i] = new ProxySQL_Node_Metrics();
	}
	proxy_info("Created new Cluster Node Entry for host %s:%d\n", hostname, port);
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
	if (ip_addr) {
		free(ip_addr);
		ip_addr = NULL;
	}
	for (int i = 0; i < PROXYSQL_NODE_METRICS_LEN ; i++) {
		delete metrics[i];
		metrics[i] = NULL;
	}
	free(metrics);
	metrics = NULL;
}

void ProxySQL_Node_Entry::resolve_hostname() {
	if (ip_addr) {
		free(ip_addr);
		ip_addr = NULL;
	}
	if (hostname && port) {
		size_t ip_count = 0;
		const std::string& ip = MySQL_Monitor::dns_lookup(hostname, false, &ip_count);

		if (ip_count > 1) {
			proxy_warning("ProxySQL Cluster node '%s' has more than one (%ld) mapped IP address: under some circumstances this may lead to undefined behavior. It is recommended to provide IP address or hostname with only one resolvable IP.\n",
				hostname, ip_count);
		}

		if (ip.empty() == false) {
			ip_addr = strdup(ip.c_str());
		}
	}
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

	// Fetch the cluster_*_diffs_before_sync variables to ensure consistency at local scope
	unsigned int diff_av = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_admin_variables_diffs_before_sync,0);
	unsigned int diff_mqr = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_query_rules_diffs_before_sync,0);
	unsigned int diff_ms = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync,0);
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_users_diffs_before_sync,0);
	unsigned int diff_ps = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_proxysql_servers_diffs_before_sync,0);
	unsigned int diff_mv = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync,0);
	unsigned int diff_lv = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_ldap_variables_diffs_before_sync,0);

	pthread_mutex_lock(&GloVars.checksum_mutex);

	while ( _r && (row = mysql_fetch_row(_r))) {
		if (strcmp(row[0],"admin_variables")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.admin_variables;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.admin_variables;
			checksums_values.admin_variables.version = atoll(row[1]);
			checksums_values.admin_variables.epoch = atoll(row[2]);
			checksums_values.admin_variables.last_updated = now;
			if (strcmp(checksums_values.admin_variables.checksum, row[3])) {
				strcpy(checksums_values.admin_variables.checksum, row[3]);
				checksums_values.admin_variables.last_changed = now;
				checksums_values.admin_variables.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_av) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_admin_variables_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.admin_variables.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for admin_variables from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.admin_variables.version, checksums_values.admin_variables.epoch,
					checksums_values.admin_variables.checksum, GloVars.checksums_values.admin_variables.checksum, checksums_values.admin_variables.diff_check);
			}
			if (strcmp(checksums_values.admin_variables.checksum, GloVars.checksums_values.admin_variables.checksum) == 0) {
				checksums_values.admin_variables.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for admin_variables from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.admin_variables.checksum);
			}
			continue;
		}
		if (strcmp(row[0],"mysql_query_rules")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.mysql_query_rules;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.mysql_query_rules;
			checksums_values.mysql_query_rules.version = atoll(row[1]);
			checksums_values.mysql_query_rules.epoch = atoll(row[2]);
			checksums_values.mysql_query_rules.last_updated = now;
			if (strcmp(checksums_values.mysql_query_rules.checksum, row[3])) {
				strcpy(checksums_values.mysql_query_rules.checksum, row[3]);
				checksums_values.mysql_query_rules.last_changed = now;
				checksums_values.mysql_query_rules.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_mqr) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_mysql_query_rules_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.mysql_query_rules.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_query_rules from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.mysql_query_rules.version, checksums_values.mysql_query_rules.epoch,
					checksums_values.mysql_query_rules.checksum, GloVars.checksums_values.mysql_query_rules.checksum, checksums_values.mysql_query_rules.diff_check);
			}
			if (strcmp(checksums_values.mysql_query_rules.checksum, GloVars.checksums_values.mysql_query_rules.checksum) == 0) {
				checksums_values.mysql_query_rules.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_query_rules from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.mysql_query_rules.checksum);
			}
			continue;
		}
		if (strcmp(row[0],"mysql_servers")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.mysql_servers;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.mysql_servers;
			checksums_values.mysql_servers.version = atoll(row[1]);
			checksums_values.mysql_servers.epoch = atoll(row[2]);
			checksums_values.mysql_servers.last_updated = now;
			if (strcmp(checksums_values.mysql_servers.checksum, row[3])) {
				strcpy(checksums_values.mysql_servers.checksum, row[3]);
				checksums_values.mysql_servers.last_changed = now;
				checksums_values.mysql_servers.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_ms) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_mysql_servers_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.mysql_servers.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_servers from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.mysql_servers.version, checksums_values.mysql_servers.epoch,
					checksums_values.mysql_servers.checksum, GloVars.checksums_values.mysql_servers.checksum, checksums_values.mysql_servers.diff_check);
			}
			if (strcmp(checksums_values.mysql_servers.checksum, GloVars.checksums_values.mysql_servers.checksum) == 0) {
				checksums_values.mysql_servers.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_servers from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.mysql_servers.checksum);
			}
			continue;
		}
		if (strcmp(row[0], "mysql_servers_v2")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.mysql_servers_v2;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.mysql_servers_v2;
			checksums_values.mysql_servers_v2.version = atoll(row[1]);
			checksums_values.mysql_servers_v2.epoch = atoll(row[2]);
			checksums_values.mysql_servers_v2.last_updated = now;
			if (strcmp(checksums_values.mysql_servers_v2.checksum, row[3])) {
				strcpy(checksums_values.mysql_servers_v2.checksum, row[3]);
				checksums_values.mysql_servers_v2.last_changed = now;
				checksums_values.mysql_servers_v2.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_ms) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_mysql_servers_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.mysql_servers_v2.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_servers_v2 from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.mysql_servers_v2.version, checksums_values.mysql_servers_v2.epoch,
					checksums_values.mysql_servers_v2.checksum, GloVars.checksums_values.mysql_servers_v2.checksum, checksums_values.mysql_servers_v2.diff_check);
			}
			if (strcmp(checksums_values.mysql_servers_v2.checksum, GloVars.checksums_values.mysql_servers_v2.checksum) == 0) {
				checksums_values.mysql_servers_v2.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_servers_v2 from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.mysql_servers.checksum);
			}
			continue;
		}
		if (strcmp(row[0],"mysql_users")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.mysql_users;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.mysql_users;
			checksums_values.mysql_users.version = atoll(row[1]);
			checksums_values.mysql_users.epoch = atoll(row[2]);
			checksums_values.mysql_users.last_updated = now;
			if (strcmp(checksums_values.mysql_users.checksum, row[3])) {
				strcpy(checksums_values.mysql_users.checksum, row[3]);
				checksums_values.mysql_users.last_changed = now;
				checksums_values.mysql_users.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_mu) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_mysql_users_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.mysql_users.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_users from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.mysql_users.version, checksums_values.mysql_users.epoch,
					checksums_values.mysql_users.checksum, GloVars.checksums_values.mysql_users.checksum, checksums_values.mysql_users.diff_check);
			}
			if (strcmp(checksums_values.mysql_users.checksum, GloVars.checksums_values.mysql_users.checksum) == 0) {
				checksums_values.mysql_users.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_users from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.mysql_users.checksum);
			}
			continue;
		}
		if (strcmp(row[0],"mysql_variables")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.mysql_variables;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.mysql_variables;
			checksums_values.mysql_variables.version = atoll(row[1]);
			checksums_values.mysql_variables.epoch = atoll(row[2]);
			checksums_values.mysql_variables.last_updated = now;
			if (strcmp(checksums_values.mysql_variables.checksum, row[3])) {
				strcpy(checksums_values.mysql_variables.checksum, row[3]);
				checksums_values.mysql_variables.last_changed = now;
				checksums_values.mysql_variables.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_mv) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_mysql_variables_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.mysql_variables.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_variables from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.mysql_variables.version, checksums_values.mysql_variables.epoch,
					checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.checksum, checksums_values.mysql_variables.diff_check);
			}
			if (strcmp(checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.checksum) == 0) {
				checksums_values.mysql_variables.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for mysql_variables from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.mysql_variables.checksum);
			}
			continue;
		}
		if (strcmp(row[0],"proxysql_servers")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.proxysql_servers;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.proxysql_servers;
			checksums_values.proxysql_servers.version = atoll(row[1]);
			checksums_values.proxysql_servers.epoch = atoll(row[2]);
			checksums_values.proxysql_servers.last_updated = now;
			if (strcmp(checksums_values.proxysql_servers.checksum, row[3])) {
				strcpy(checksums_values.proxysql_servers.checksum, row[3]);
				checksums_values.proxysql_servers.last_changed = now;
				checksums_values.proxysql_servers.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_ps) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_proxysql_servers_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.proxysql_servers.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for proxysql_servers from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.proxysql_servers.version, checksums_values.proxysql_servers.epoch,
					checksums_values.proxysql_servers.checksum, GloVars.checksums_values.proxysql_servers.checksum, checksums_values.proxysql_servers.diff_check);
			}
			if (strcmp(checksums_values.proxysql_servers.checksum, GloVars.checksums_values.proxysql_servers.checksum) == 0) {
				checksums_values.proxysql_servers.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for proxysql_servers from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.proxysql_servers.checksum);
			}
			continue;
		}
		if (GloMyLdapAuth && strcmp(row[0],"ldap_variables")==0) {
			ProxySQL_Checksum_Value_2& checksum = checksums_values.ldap_variables;
			ProxySQL_Checksum_Value& global_checksum = GloVars.checksums_values.ldap_variables;
			checksums_values.ldap_variables.version = atoll(row[1]);
			checksums_values.ldap_variables.epoch = atoll(row[2]);
			checksums_values.ldap_variables.last_updated = now;
			if (strcmp(checksums_values.ldap_variables.checksum, row[3])) {
				strcpy(checksums_values.ldap_variables.checksum, row[3]);
				checksums_values.ldap_variables.last_changed = now;
				checksums_values.ldap_variables.diff_check = 1;
				const char* no_sync_message = NULL;

				if (diff_lv) {
					no_sync_message = "Not syncing yet ...\n";
				} else {
					no_sync_message = "Not syncing due to 'admin-cluster_ldap_variables_diffs_before_sync=0'.\n";
				}

				proxy_info(
					"Cluster: detected a new checksum for %s from peer %s:%d, version %llu, epoch %llu, checksum %s . %s",
					row[0], hostname, port, checksum.version, checksum.epoch, checksum.checksum, no_sync_message
				);

				if (strcmp(checksum.checksum, global_checksum.checksum) == 0) {
					proxy_info(
						"Cluster: checksum for %s from peer %s:%d matches with local checksum %s , we won't sync.\n",
						row[0], hostname, port, global_checksum.checksum
					);
				}
			} else {
				checksums_values.ldap_variables.diff_check++;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for ldap_variables from peer %s:%d, version %llu, epoch %llu, checksum %s is different from local checksum %s. Incremented diff_check %d ...\n", hostname, port, checksums_values.ldap_variables.version, checksums_values.ldap_variables.epoch,
					checksums_values.ldap_variables.checksum, GloVars.checksums_values.ldap_variables.checksum, checksums_values.ldap_variables.diff_check);
			}
			if (strcmp(checksums_values.ldap_variables.checksum, GloVars.checksums_values.ldap_variables.checksum) == 0) {
				checksums_values.ldap_variables.diff_check = 0;
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Checksum for ldap_variables from peer %s:%d matches with local checksum %s, reset diff_check to 0.\n", hostname, port, GloVars.checksums_values.ldap_variables.checksum);
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
		v = &checksums_values.mysql_servers_v2;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.mysql_servers_v2.checksum) == 0) {
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
		v = &checksums_values.ldap_variables;
		v->last_updated = now;
		if (strcmp(v->checksum, GloVars.checksums_values.ldap_variables.checksum) == 0) {
			v->diff_check = 0;
		}
		if (v->diff_check)
			v->diff_check++;
	}
	pthread_mutex_unlock(&GloVars.checksum_mutex);
	// we now do a series of checks, and we take action
	// note that this is done outside the critical section
	// as mutex on GloVars.checksum_mutex is already released
	ProxySQL_Checksum_Value_2 *v = NULL;
	if (diff_av) {
		v = &checksums_values.admin_variables;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.version, 0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.epoch, 0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.admin_variables.checksum, 0);
		const string expected_checksum { v->checksum };

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_av) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_global_variables_from_peer("admin", expected_checksum, v->epoch);
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_av*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_av * 10));
				proxy_error("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_av*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_admin_variables_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_av*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_av * 10));
				proxy_warning("Cluster: detected a peer %s:%d with admin_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD ADMIN VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_av*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_admin_variables_version_one]->Increment();
			}
		}
	}
	if (diff_mqr) {
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_query_rules.checksum,0);
		v = &checksums_values.mysql_query_rules;
		const std::string v_exp_checksum { v->checksum };

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mqr) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_query_rules_from_peer(v_exp_checksum, v->epoch);
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mqr*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mqr * 10));
				proxy_error("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mqr*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_query_rules_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mqr*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL QUERY RULES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mqr * 10));
				proxy_warning("Cluster: detected a peer %s:%d with mysql_query_rules version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL QUERY RULES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mqr*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_query_rules_version_one]->Increment();
			}
		}
	}
	if (diff_ms) {
		mysql_servers_sync_algorithm mysql_server_sync_algo = (mysql_servers_sync_algorithm)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_servers_sync_algorithm, 0);

		if (mysql_server_sync_algo == mysql_servers_sync_algorithm::auto_select) {
			mysql_server_sync_algo = (GloVars.global.monitor == false) ? 
				mysql_servers_sync_algorithm::runtime_mysql_servers_and_mysql_servers_v2 : mysql_servers_sync_algorithm::mysql_servers_v2;
		}

		v = &checksums_values.mysql_servers_v2;
		const unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers_v2.version, 0);
		const unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers_v2.epoch, 0);
		const char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers_v2.checksum, 0);
		bool runtime_mysql_servers_already_loaded = false;

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ms) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers_v2 version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with mysql_servers_v2 version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);

					ProxySQL_Checksum_Value_2* runtime_mysql_server_checksum = &checksums_values.mysql_servers;

					const bool fetch_runtime = (mysql_server_sync_algo == mysql_servers_sync_algorithm::runtime_mysql_servers_and_mysql_servers_v2);

					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetch mysql_servers_v2:'YES', mysql_servers:'%s' from peer %s:%d\n", (fetch_runtime ? "YES" : "NO"),
						hostname, port);
					proxy_info("Cluster: Fetch mysql_servers_v2:'YES', mysql_servers:'%s' from peer %s:%d\n", (fetch_runtime ? "YES" : "NO"),
						hostname, port);

					GloProxyCluster->pull_mysql_servers_v2_from_peer({ v->checksum, static_cast<time_t>(v->epoch) },
							{ runtime_mysql_server_checksum->checksum, static_cast<time_t>(runtime_mysql_server_checksum->epoch) }, fetch_runtime);

					runtime_mysql_servers_already_loaded = fetch_runtime;
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_ms * 10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers_v2 version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ms * 10));
				proxy_error("Cluster: detected a peer %s:%d with mysql_servers_v2 version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ms * 10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_servers_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ms * 10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms * 10));
				proxy_warning("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms * 10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_servers_version_one]->Increment();
			}
		}

		if (mysql_server_sync_algo == mysql_servers_sync_algorithm::runtime_mysql_servers_and_mysql_servers_v2 && 
			runtime_mysql_servers_already_loaded == false) {
			v = &checksums_values.mysql_servers;
			unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.version, 0);
			unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.epoch, 0);
			char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_servers.checksum, 0);

			if (v->version > 1) {
				if (
					(own_version == 1) // we just booted
					||
					(v->epoch > own_epoch) // epoch is newer
				) {
					if (v->diff_check >= diff_ms) {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
						proxy_info("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
						GloProxyCluster->pull_runtime_mysql_servers_from_peer({ v->checksum, static_cast<time_t>(v->epoch) });
					}
				}
				if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_ms * 10)) == 0)) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ms * 10));
					proxy_error("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ms * 10));
					GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_servers_share_epoch]->Increment();
				}
			} else {
				if (v->diff_check && (v->diff_check % (diff_ms * 10)) == 0) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms * 10));
					proxy_warning("Cluster: detected a peer %s:%d with mysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ms * 10));
					GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_servers_version_one]->Increment();
				}
			}
		} 
	}
	if (diff_mu) {
		v = &checksums_values.mysql_users;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_users.checksum,0);
		const std::string v_exp_checksum { v->checksum };

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mu) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_mysql_users_from_peer(v_exp_checksum, v->epoch);
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mu*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mu * 10));
				proxy_error("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mu*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_users_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mu*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL USERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mu * 10));
				proxy_warning("Cluster: detected a peer %s:%d with mysql_users version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL USERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mu*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_users_version_one]->Increment();
			}
		}
	}
	if (diff_mv) {
		v = &checksums_values.mysql_variables;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.version, 0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.epoch, 0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.mysql_variables.checksum, 0);
		const string expected_checksum { v->checksum };

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_mv) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_global_variables_from_peer("mysql", expected_checksum, v->epoch);
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_mv*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mv * 10));
				proxy_error("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_mv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_mysql_variables_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_mv*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mv * 10));
				proxy_warning("Cluster: detected a peer %s:%d with mysql_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_mv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_mysql_variables_version_one]->Increment();
			}
		}
	}
	if (GloMyLdapAuth && diff_lv) {
		v = &checksums_values.ldap_variables;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.ldap_variables.version, 0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.ldap_variables.epoch, 0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.ldap_variables.checksum, 0);
		const string expected_checksum { v->checksum };

		if (v->version > 1) {
			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_lv) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_global_variables_from_peer("ldap", expected_checksum, v->epoch);
				}
			}
			if ((v->epoch == own_epoch) && v->diff_check && ((v->diff_check % (diff_lv*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD LDAP VARIABLES is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_lv * 10));
				proxy_error("Cluster: detected a peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD LDAP VARIABLES is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_lv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_ldap_variables_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_lv*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD LDAP VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_lv * 10));
				proxy_warning("Cluster: detected a peer %s:%d with ldap_variables version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD LDAP VARIABLES TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_lv*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_ldap_variables_version_one]->Increment();
			}
		}
	}
	// IMPORTANT-NOTE: This action should ALWAYS be performed the last, since the 'checksums_values' gets
	// invalidated by 'pull_proxysql_servers_from_peer' and further memory accesses would be invalid.
	if (diff_ps) {
		v = &checksums_values.proxysql_servers;
		unsigned long long own_version = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.version,0);
		unsigned long long own_epoch = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.epoch,0);
		char* own_checksum = __sync_fetch_and_add(&GloVars.checksums_values.proxysql_servers.checksum,0);
		if (v->version > 1) {
			// NOTE: Backup values: 'v' gets invalidated by 'pull_proxysql_servers_from_peer()'
			unsigned long long v_epoch = v->epoch;
			unsigned long long v_version = v->version;
			unsigned int v_diff_check = v->diff_check;
			const string v_exp_checksum { v->checksum };

			if (
				(own_version == 1) // we just booted
				||
				(v->epoch > own_epoch) // epoch is newer
			) {
				if (v->diff_check >= diff_ps) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					proxy_info("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. Proceeding with remote sync\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch);
					GloProxyCluster->pull_proxysql_servers_from_peer(v_exp_checksum, v->epoch);
				}
			}
			if ((v_epoch == own_epoch) && v_diff_check && ((v_diff_check % (diff_ps*10)) == 0)) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v_version, v_epoch, v_diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ps * 10));
				proxy_error("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u, checksum %s. Own version: %llu, epoch: %llu, checksum %s. Sync conflict, epoch times are EQUAL, can't determine which server holds the latest config, we won't sync. This message will be repeated every %u checks until LOAD MYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v_version, v_epoch, v_diff_check, v->checksum, own_version, own_epoch, own_checksum, (diff_ps*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_conflict_proxysql_servers_share_epoch]->Increment();
			}
		} else {
			if (v->diff_check && (v->diff_check % (diff_ps*10)) == 0) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD PROXYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ps * 10));
				proxy_warning("Cluster: detected a peer %s:%d with proxysql_servers version %llu, epoch %llu, diff_check %u. Own version: %llu, epoch: %llu. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every %u checks until LOAD PROXYSQL SERVERS TO RUNTIME is executed on candidate master.\n", hostname, port, v->version, v->epoch, v->diff_check, own_version, own_epoch, (diff_ps*10));
				GloProxyCluster->metrics.p_counter_array[p_cluster_counter::sync_delayed_proxysql_servers_version_one]->Increment();
			}
		}
	}
}

/**
 * @brief Computes the checksum from a MySQL resultset in the same we already do in 'SQLite3_result::raw_checksum'.
 * @details For each received column computing the field length via 'strlen' is required, this is because we
 *  hardcode the fields length in 'MySQL_Session::SQLite3_to_MySQL'.
 * @param resultset The resulset which checksum needs to be computed.
 * @return The hash resulting from the checksum computation.
 */
uint64_t mysql_raw_checksum(MYSQL_RES* resultset) {
	if (resultset == nullptr) { return 0; }

	uint64_t num_rows = mysql_num_rows(resultset);
	if (num_rows == 0) { return 0; }

	uint32_t num_fields = mysql_num_fields(resultset);
	SpookyHash myhash {};
	myhash.Init(19, 3);

	while (MYSQL_ROW row = mysql_fetch_row(resultset)) {
		for (uint32_t i = 0; i < num_fields; i++) {
			if (row[i]) {
				// computing 'strlen' is required see @details
				myhash.Update(row[i], strlen(row[i]));
			} else {
				myhash.Update("", 0);
			}
		}
	}

	// restore the initial resulset index
	mysql_data_seek(resultset, 0);

	uint64_t res_hash = 0, hash2 = 0;
	myhash.Final(&res_hash, &hash2);

	return res_hash;
}

void ProxySQL_Cluster::pull_mysql_query_rules_from_peer(const string& expected_checksum, const time_t epoch) {
	char * hostname = NULL;
	char * ip_address = NULL;
	uint16_t port = 0;
	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_query_rules_mutex);
	nodes.get_peer_to_sync_mysql_query_rules(&hostname, &port, &ip_address);
	if (hostname) {
		cluster_creds_t creds {};

		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_query_rules_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d started. Expected checksum: %s\n", hostname, port, expected_checksum.c_str());
			proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d started. Expected checksum: %s\n", hostname, port, expected_checksum.c_str());
			MYSQL* rc_conn = mysql_real_connect(
				conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0
			);
			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				MYSQL_RES *result1 = NULL;
				MYSQL_RES *result2 = NULL;
				//rc_query = mysql_query(conn,"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment FROM runtime_mysql_query_rules");
				int rc_query = mysql_query(conn,CLUSTER_QUERY_MYSQL_QUERY_RULES);
				if ( rc_query == 0 ) {
					result1 = mysql_store_result(conn);
					rc_query = mysql_query(conn,CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING);
					if ( rc_query == 0) {
						result2 = mysql_store_result(conn);
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d completed\n", hostname, port);
						proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d completed\n", hostname, port);

						std::unique_ptr<SQLite3_result> SQLite3_query_rules_resultset { get_SQLite3_resulset(result1) };
						std::unique_ptr<SQLite3_result> SQLite3_query_rules_fast_routing_resultset { get_SQLite3_resulset(result2) };

						const uint64_t query_rules_hash =
							SQLite3_query_rules_resultset->raw_checksum() + SQLite3_query_rules_fast_routing_resultset->raw_checksum();
						const string computed_checksum { get_checksum_from_hash(query_rules_hash) };
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for MySQL Query Rules from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());
						proxy_info("Cluster: Computed checksum for MySQL Query Rules from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());

						if (expected_checksum == computed_checksum) {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime MySQL Query Rules from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: Loading to runtime MySQL Query Rules from peer %s:%d\n", hostname, port);
						pthread_mutex_lock(&GloAdmin->sql_query_global_mutex);
						//GloAdmin->admindb->execute("PRAGMA quick_check");
						GloAdmin->admindb->execute("DELETE FROM mysql_query_rules");
						GloAdmin->admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
						MYSQL_ROW row;
						char *q = (char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment) VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35)";
						sqlite3_stmt *statement1 = NULL;
						//sqlite3 *mydb3 = GloAdmin->admindb->get_db();
						//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q, -1, &statement1, 0);
						int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
						ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						GloAdmin->admindb->execute("BEGIN TRANSACTION");
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
							rc=(*proxy_sqlite3_bind_text)(statement1, 34, row[32], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // attributes
							rc=(*proxy_sqlite3_bind_text)(statement1, 35, row[33], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
							SAFE_SQLITE3_STEP2(statement1);
							rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
							rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						}
						(*proxy_sqlite3_finalize)(statement1);
						GloAdmin->admindb->execute("COMMIT");


						std::string query32frs = "INSERT INTO mysql_query_rules_fast_routing(username, schemaname, flagIN, destination_hostgroup, comment) VALUES " + generate_multi_rows_query(32,5);
						char *q1fr = (char *)"INSERT INTO mysql_query_rules_fast_routing(username, schemaname, flagIN, destination_hostgroup, comment) VALUES (?1, ?2, ?3, ?4, ?5)";
						char *q32fr = (char *)query32frs.c_str();
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
						GloAdmin->admindb->execute("BEGIN TRANSACTION");
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
						(*proxy_sqlite3_finalize)(statement1fr);
						(*proxy_sqlite3_finalize)(statement32fr);
						//GloAdmin->admindb->execute("PRAGMA integrity_check");
						GloAdmin->admindb->execute("COMMIT");

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading MySQL Query Rules to Runtime from peer %s:%d\n", hostname, port);
						// We release the ownership of the memory for 'SQLite3' resultsets here since now it's no longer
						// our responsability to free the memory, they should be directly passed to the 'Query Processor'
						GloAdmin->load_mysql_query_rules_to_runtime(
							SQLite3_query_rules_resultset.release(), SQLite3_query_rules_fast_routing_resultset.release(), expected_checksum, epoch
						);
						if (GloProxyCluster->cluster_mysql_query_rules_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
							GloAdmin->flush_GENERIC__from_to("mysql_query_rules", "memory_to_disk");
						} else {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "NOT saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: NOT saving to disk MySQL Query Rules from peer %s:%d\n", hostname, port);
						}
						pthread_mutex_unlock(&GloAdmin->sql_query_global_mutex);
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_success]->Increment();

						} else {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d failed because of mismatching checksum. Expected: %s , Computed: %s\n",
								hostname, port, expected_checksum.c_str(), computed_checksum.c_str());
							proxy_info(
								"Cluster: Fetching MySQL Query Rules from peer %s:%d failed because of mismatching checksum. Expected: %s , Computed: %s\n",
								hostname, port, expected_checksum.c_str(), computed_checksum.c_str()
							);
							metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
							fetch_failed = true;
						}
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
						proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
						fetch_failed = true;
					}
				} else {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
					fetch_failed = true;
				}
				if (result1) {
					mysql_free_result(result1);
				}
				if (result2) {
					mysql_free_result(result2);
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching MySQL Query Rules from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_query_rules_failure]->Increment();
				fetch_failed = true;
			}
		}
__exit_pull_mysql_query_rules_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (ip_address)
			free(ip_address);
	} else {
		proxy_info("No hostname found\n");
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_query_rules_mutex);
	if (fetch_failed == true) sleep(1);
}

uint64_t get_mysql_users_checksum(
	MYSQL_RES* resultset, MYSQL_RES* ldap_resultset, unique_ptr<SQLite3_result>& all_users
) {
	uint64_t raw_users_checksum = GloMyAuth->get_runtime_checksum(resultset, all_users);

	if (GloMyLdapAuth) {
		raw_users_checksum += mysql_raw_checksum(ldap_resultset);
	}

	return raw_users_checksum;
}

void update_mysql_users(MYSQL_RES* result) {
	GloAdmin->admindb->execute("DELETE FROM mysql_users");
	char* q = (char *)"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, default_schema,"
		" schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment)"
		" VALUES (?1 , ?2 , ?3 , ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";

	sqlite3_stmt *statement1 = NULL;
	int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
	ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // password
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, 1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // active
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(row[2])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // use_ssl
		rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoll(row[3])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // default_hostgroup
		rc=(*proxy_sqlite3_bind_text)(statement1, 6, row[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // default_schema
		rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(row[5])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // schema_locked
		rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(row[6])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // transaction_persistent
		rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(row[7])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // fast_forward
		rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(row[8])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // backend
		rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(row[9])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // frontend
		rc=(*proxy_sqlite3_bind_int64)(statement1, 12, atoll(row[10])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // max_connection
		rc=(*proxy_sqlite3_bind_text)(statement1, 13, row[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // attributes
		rc=(*proxy_sqlite3_bind_text)(statement1, 14, row[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment

		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
	}
}

void update_ldap_mappings(MYSQL_RES* result) {
	GloAdmin->admindb->execute("DELETE FROM mysql_ldap_mapping");
	char* q = const_cast<char*>(
		"INSERT INTO mysql_ldap_mapping (priority, frontend_entity, backend_entity, comment)"
		" VALUES (?1 , ?2 , ?3 , ?4)"
	);

	sqlite3_stmt *statement1 = NULL;
	int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
	ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(row[0])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // priority
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // frontend_entity
		rc=(*proxy_sqlite3_bind_text)(statement1, 3, row[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // backend_entity
		rc=(*proxy_sqlite3_bind_text)(statement1, 4, row[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment

		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
	}
}

void ProxySQL_Cluster::pull_mysql_users_from_peer(const string& expected_checksum, const time_t epoch) {
	char * hostname = NULL;
	char * ip_address = NULL;
	uint16_t port = 0;
	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_users_mutex);
	nodes.get_peer_to_sync_mysql_users(&hostname, &port, &ip_address);
	if (hostname) {
		cluster_creds_t creds {};

		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_users_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Users from peer %s:%d started. Expected checksum: %s\n", hostname, port, expected_checksum.c_str());
			proxy_info("Cluster: Fetching MySQL Users from peer %s:%d started. Expected checksum: %s\n", hostname, port, expected_checksum.c_str());

			MYSQL* rc_conn = mysql_real_connect(conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0);
			if (rc_conn == nullptr) {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_failure]->Increment();
				fetch_failed = true;

				if (GloMyLdapAuth) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					proxy_info("Cluster: Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_ldap_mapping_failure]->Increment();
					fetch_failed = true;
				}

				goto __exit_pull_mysql_users_from_peer;
			}

			MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

			int rc_query = mysql_query(conn, CLUSTER_QUERY_MYSQL_USERS);
			if (rc_query == 0) {
				MYSQL_RES* mysql_users_result = mysql_store_result(conn);
				MYSQL_RES* ldap_mapping_result = nullptr;

				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Users from peer %s:%d completed\n", hostname, port);
				proxy_info("Cluster: Fetching MySQL Users from peer %s:%d completed\n", hostname, port);

				if (GloMyLdapAuth) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching LDAP Mappings from peer %s:%d.\n", hostname, port);
					proxy_info("Cluster: Fetching LDAP Mappings from peer %s:%d.\n", hostname, port);

					rc_query = mysql_query(
						conn, "SELECT priority, frontend_entity, backend_entity, comment FROM mysql_ldap_mapping ORDER BY priority"
					);

					if (rc_query == 0) {
						ldap_mapping_result = mysql_store_result(conn);
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching LDAP Mappings from peer %s:%d completed\n", hostname, port);
						proxy_info("Cluster: Fetching LDAP Mappings from peer %s:%d completed\n", hostname, port);
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
						proxy_info("Cluster: Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_ldap_mapping_failure]->Increment();
						fetch_failed = true;
					}
				}

				unique_ptr<SQLite3_result> mysql_users_resultset { nullptr };
				const uint64_t users_raw_checksum =
					get_mysql_users_checksum(mysql_users_result, ldap_mapping_result, mysql_users_resultset);
				const string computed_checksum { get_checksum_from_hash(users_raw_checksum) };
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for MySQL Users from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());
				proxy_info("Cluster: Computed checksum for MySQL Users from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());

				if (expected_checksum == computed_checksum) {
					update_mysql_users(mysql_users_result);
					mysql_free_result(mysql_users_result);

					if (GloMyLdapAuth) {
						update_ldap_mappings(ldap_mapping_result);
						mysql_free_result(ldap_mapping_result);
					}

					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime MySQL Users from peer %s:%d\n", hostname, port);
					proxy_info("Cluster: Loading to runtime MySQL Users from peer %s:%d\n", hostname, port);
					if (GloMyLdapAuth) {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime LDAP Mappings from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: Loading to runtime LDAP Mappings from peer %s:%d\n", hostname, port);
					}

					GloAdmin->init_users(std::move(mysql_users_resultset), expected_checksum, epoch);
					if (GloProxyCluster->cluster_mysql_users_save_to_disk == true) {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk MySQL Users from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: Saving to disk MySQL Users from peer %s:%d\n", hostname, port);
						if (GloMyLdapAuth) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk LDAP Mappings from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk LDAP Mappings from peer %s:%d\n", hostname, port);
						}

						GloAdmin->flush_mysql_users__from_memory_to_disk();
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "NOT saving to disk MySQL Users from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: NOT saving to disk MySQL Users from peer %s:%d\n", hostname, port);
						if (GloMyLdapAuth) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "NOT Saving to disk LDAP Mappings from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: NOT Saving to disk LDAP Mappings from peer %s:%d\n", hostname, port);
						}
					}

					metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_success]->Increment();

					if (GloMyLdapAuth) {
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_ldap_mapping_success]->Increment();
					}
				} else {
					if (mysql_users_result) {
						mysql_free_result(mysql_users_result);
					}
					if (ldap_mapping_result) {
						mysql_free_result(ldap_mapping_result);
					}

					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Users from peer %s:%d failed: Checksum changed from %s to %s\n",
						hostname, port, expected_checksum.c_str(), computed_checksum.c_str());
					proxy_info(
						"Cluster: Fetching MySQL Users from peer %s:%d failed: Checksum changed from %s to %s\n",
						hostname, port, expected_checksum.c_str(), computed_checksum.c_str()
					);
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_failure]->Increment();
					fetch_failed = true;

					if (GloMyLdapAuth) {
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_ldap_mapping_failure]->Increment();
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching MySQL Users from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_users_failure]->Increment();
				fetch_failed = true;

				if (GloMyLdapAuth) {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					proxy_info("Cluster: Fetching LDAP Mappings from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_mysql_ldap_mapping_failure]->Increment();
				}
			}
		}
__exit_pull_mysql_users_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (ip_address)
			free(ip_address);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_users_mutex);
	if (fetch_failed == true) sleep(1);
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

/**
 * @brief Generates a hash from the received resultsets from executing the following queries in the specified
 *   order:
 *   - CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS.
 *   - CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS.
 *   - CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS.
 *   - CLUSTER_QUERY_MYSQL_GALERA.
 *   - CLUSTER_QUERY_MYSQL_AWS_AURORA.
 *   - CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES.
 *
 *  IMPORTANT: It's assumed that the previous queries were successful and that the resultsets are received in
 *  the specified order.
 * @param results The resultsets from whose to compute the checksum. Previous described order is required.
 * @return Zero if the received resultset were empty, the computed hash otherwise.
 */
uint64_t compute_servers_tables_raw_checksum(const vector<MYSQL_RES*>& results, size_t size) {
	bool init = false;
	SpookyHash myhash {};

	for (size_t i = 0; i < size; i++) {
		uint64_t raw_hash = mysql_raw_checksum(results[i]);

		if (raw_hash != 0) {
			if (init == false) {
				init = true;
				myhash.Init(19, 3);
			}

			myhash.Update(&raw_hash, sizeof(raw_hash));
		}
	}

	uint64_t servers_hash = 0, _hash2 = 0;
	if (init) {
		myhash.Final(&servers_hash, &_hash2);
	}

	return servers_hash;
}

incoming_servers_t convert_mysql_servers_resultsets(const std::vector<MYSQL_RES*>& results) {
	if (results.size() != sizeof(incoming_servers_t) / sizeof(void*)) {
		return incoming_servers_t {};
	} else {
		return incoming_servers_t {
			get_SQLite3_resulset(results[0]).release(),
			get_SQLite3_resulset(results[1]).release(),
			get_SQLite3_resulset(results[2]).release(),
			get_SQLite3_resulset(results[3]).release(),
			get_SQLite3_resulset(results[4]).release(),
			get_SQLite3_resulset(results[5]).release(),
			get_SQLite3_resulset(results[6]).release(),
			get_SQLite3_resulset(results[7]).release(),
		};
	}
}

/**
 * @brief mysql_servers records will be fetched from remote peer and saved locally.
 *
 * @details This method involves fetching the mysql_servers records (also referred to as runtime_mysql_servers) from a remote peer 
 *    and comparing their checksum to the remote peer's checksum. If the checksums match, the local mysql_servers (i.e., runtime_mysql_servers)
 *    will be updated and saved to disk, but only if the cluster_mysql_servers_save_to_disk variable is set to true.
 * 
 *    It's important to note that the runtime_mysql_servers module is distinct from the mysql_servers_v2 module. It has 
 *    its own independent checksum (does not have dependent modules) and represents the current runtime state of the mysql_servers.
 * 
 * @param peer_runtime_mysql_server checksum and epoch of mysql_servers from remote peer 
 */
void ProxySQL_Cluster::pull_runtime_mysql_servers_from_peer(const runtime_mysql_servers_checksum_t& peer_runtime_mysql_server) {
	char * hostname = NULL;
	char * ip_address = NULL;
	uint16_t port = 0;
	char * peer_checksum = NULL;
	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_runtime_mysql_servers_mutex);
	nodes.get_peer_to_sync_runtime_mysql_servers(&hostname, &port, &peer_checksum, &ip_address);
	if (hostname) {
		cluster_creds_t creds {};

		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_servers_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching 'MySQL Servers' from peer %s:%d started. Expected checksum %s\n", hostname, port, peer_checksum);
			proxy_info("Cluster: Fetching 'MySQL Servers' from peer %s:%d started. Expected checksum %s\n", hostname, port, peer_checksum);
			MYSQL* rc_conn = mysql_real_connect(
				conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0
			);
			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				// servers messages
				std::string fetch_servers_done;
				string_format("Cluster: Fetching 'MySQL Servers' from peer %s:%d completed\n", fetch_servers_done, hostname, port);
				std::string fetch_servers_err;
				string_format("Cluster: Fetching 'MySQL Servers' from peer %s:%d failed: \n", fetch_servers_err, hostname, port);

				// Create fetching query
				fetch_query query = {
					CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS,
					p_cluster_counter::pulled_mysql_servers_success,
					p_cluster_counter::pulled_mysql_servers_failure,
					{ "", fetch_servers_done, fetch_servers_err }
				};

				MYSQL_RES* result = nullptr;

				if (fetch_and_store(conn, query, &result) != 0) {
					if (result) {
						mysql_free_result(result);
						result = nullptr;
					}
				}

				if (result != nullptr) {
					const uint64_t servers_hash = mysql_raw_checksum(result);
					const string computed_checksum{ get_checksum_from_hash(servers_hash) };
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for MySQL Servers from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());
					proxy_info("Cluster: Computed checksum for MySQL Servers from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());

					if (computed_checksum == peer_checksum) {
						GloAdmin->mysql_servers_wrlock();
						std::unique_ptr<SQLite3_result> runtime_mysql_servers_resultset = get_SQLite3_resulset(result);
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading runtime_mysql_servers from peer %s:%d into mysql_servers_incoming", hostname, port);
						MyHGM->servers_add(runtime_mysql_servers_resultset.get());
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Updating runtime_mysql_servers from peer %s:%d", hostname, port);
						MyHGM->commit(
							{ runtime_mysql_servers_resultset.release(), peer_runtime_mysql_server },
							{ nullptr, {} }, true, true
						);

						if (GloProxyCluster->cluster_mysql_servers_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving Runtime MySQL Servers to Database\n");
							GloAdmin->save_mysql_servers_runtime_to_database(false);
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk MySQL Servers v2 from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk MySQL Servers v2 from peer %s:%d\n", hostname, port);
							GloAdmin->flush_GENERIC__from_to("mysql_servers", "memory_to_disk");
						}
						GloAdmin->mysql_servers_wrunlock();

						// free result
						mysql_free_result(result);

						metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_success]->Increment();
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_failure]->Increment();
				fetch_failed = true;
			}
		}
__exit_pull_mysql_servers_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (peer_checksum)
			free(peer_checksum);

		if (ip_address)
			free(ip_address);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_runtime_mysql_servers_mutex);
	if (fetch_failed == true) sleep(1);
}

/**
 * @brief mysql_servers_v2 records will be fetched from remote peer. mysql_servers records will be fetched if 
 *    fetch_runtime_mysql_servers flag is true.
 * 
 * @details The previous implementation of the "pull_mysql_servers_from_peer" method fetched data from "mysql_servers" (equivalent to runtime mysql_servers) 
 *    and other dependent modules like "mysql_replication_hostgroups", "mysql_group_replication_hostgroups", "mysql_galera_hostgroups", 
 *    "mysql_aws_aurora_hostgroups", and "mysql_hostgroup_attributes". It then computed an accumulated checksum and compares it with the 
 *    peer checksum. If they matched, the configuration was loaded and saved to disk if "cluster_mysql_servers_save_to_disk" was set to true.
 *
 *    The new implementation, "pull_mysql_servers_v2_from_peer", instead fetches data from "mysql_servers_v2" (equivalent to admin mysql_servers) 
 *    and the same dependent modules. It then computes an accumulated checksum and compares it with the peer checksum. If they matched, the 
 *    configuration was loaded and saved to disk if "cluster_mysql_servers_save_to_disk" was set to true. Additionally, if the "fetch_runtime_mysql_servers" 
 *    option is enabled (if cluster_mysql_servers_sync_algorithm value is set to 1), the "mysql_servers" table will also be fetched and its checksum will be 
 *    computed and matched with the peer checksum. If they match, the configuration will be loaded and saved to disk if the "cluster_mysql_servers_save_to_disk" 
 *    option is true.
 *
 *    Apart from separately fetching the runtime mysql_servers, the primary distinction between the previous and new implementations lies in the 
 *    fetching of different tables (mysql_servers vs mysql_servers_v2) and computing of checksum. In the previous version, 
 *    the checksum for "mysql_servers" was computed and added to the checksums of other dependent modules. In contrast, the new version 
 *    calculates the checksum for "mysql_servers_v2" and combines it with the checksums of other dependent modules.
 *
 *    IMPORTANT: This function performs both the fetching of config, and conditionally the 'runtime_mysql_servers', in
 *    order to avoid extra transitory states and checksums that would result if this operation was performed in multiple
 *    steps. When required by the sync algorithm ('mysql_servers_sync_algorithm'), these two fetches and configuration
 *    promotion should be performed in a single 'atomic' operation.
 * 
 * @param peer_mysql_server_v2 checksum and epoch of mysql_servers_v2 from remote peer
 * @param peer_runtime_mysql_server checksum and epoch of mysql_servers from remote peer
 * @param fetch_runtime_mysql_servers fetch mysql_servers records if value is true
 * 
 * NOTE: pull_mysql_servers_v2_from_peer will always be called irrespective of cluster_mysql_servers_sync_algorithm value.
 */
void ProxySQL_Cluster::pull_mysql_servers_v2_from_peer(const mysql_servers_v2_checksum_t& peer_mysql_server_v2,
	const runtime_mysql_servers_checksum_t& peer_runtime_mysql_server, bool fetch_runtime_mysql_servers) {
	char* hostname = NULL;
	char* ip_address = NULL;
	uint16_t port = 0;
	char* peer_mysql_servers_v2_checksum = NULL;
	char* peer_runtime_mysql_servers_checksum = NULL;
	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_servers_v2_mutex);
	nodes.get_peer_to_sync_mysql_servers_v2(&hostname, &port, &peer_mysql_servers_v2_checksum, 
		&peer_runtime_mysql_servers_checksum, &ip_address);
	if (hostname) {
		cluster_creds_t creds {};

		MYSQL* conn = mysql_init(NULL);
		if (conn == NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_servers_v2_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Servers v2 from peer %s:%d started. Expected checksum %s\n", hostname, port, peer_mysql_servers_v2_checksum);
			proxy_info("Cluster: Fetching MySQL Servers v2 from peer %s:%d started. Expected checksum %s\n", hostname, port, peer_mysql_servers_v2_checksum);
			MYSQL* rc_conn = mysql_real_connect(
				conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0
			);
			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				std::vector<MYSQL_RES*> results(8,nullptr);

				// servers messages
				std::string fetch_servers_done = "";
				string_format("Cluster: Fetching 'MySQL Servers v2' from peer %s:%d completed\n", fetch_servers_done, hostname, port);
				std::string fetch_servers_err = "";
				string_format("Cluster: Fetching 'MySQL Servers v2' from peer %s:%d failed: \n", fetch_servers_err, hostname, port);

				// group_replication_hostgroups messages
				std::string fetch_group_replication_hostgroups = "";
				string_format("Cluster: Fetching 'MySQL Group Replication Hostgroups' from peer %s:%d\n", fetch_group_replication_hostgroups, hostname, port);
				std::string fetch_group_replication_hostgroups_err = "";
				string_format("Cluster: Fetching 'MySQL Group Replication Hostgroups' from peer %s:%d failed: \n", fetch_group_replication_hostgroups_err, hostname, port);

				// AWS Aurora messages
				std::string fetch_aws_aurora_start = "";
				string_format("Cluster: Fetching 'MySQL Aurora Hostgroups' from peer %s:%d\n", fetch_aws_aurora_start, hostname, port);
				std::string fetch_aws_aurora_err = "";
				string_format("Cluster: Fetching 'MySQL Aurora Hostgroups' from peer %s:%d failed: \n", fetch_aws_aurora_err, hostname, port);

				// Galera messages
				std::string fetch_galera_start = "";
				string_format("Cluster: Fetching 'MySQL Galera Hostgroups' from peer %s:%d\n", fetch_galera_start, hostname, port);
				std::string fetch_galera_err = "";
				string_format("Cluster: Fetching 'MySQL Galera Hostgroups' from peer %s:%d failed: \n", fetch_galera_err, hostname, port);

				// hostgroup attributes messages
				std::string fetch_hostgroup_attributes_start = "";
				string_format("Cluster: Fetching 'MySQL Hostgroup Attributes' from peer %s:%d\n", fetch_hostgroup_attributes_start, hostname, port);
				std::string fetch_hostgroup_attributes_err = "";
				string_format("Cluster: Fetching 'MySQL Hostgroup Attributes' from peer %s:%d failed: \n", fetch_hostgroup_attributes_err, hostname, port);

				// mysql servers ssl params messages
				std::string fetch_mysql_servers_ssl_params_start = "";
				string_format("Cluster: Fetching 'MySQL Servers SSL Params' from peer %s:%d\n", fetch_mysql_servers_ssl_params_start, hostname, port);
				std::string fetch_mysql_servers_ssl_params_err = "";
				string_format("Cluster: Fetching 'MySQL Servers SSL Params' from peer %s:%d failed: \n", fetch_mysql_servers_ssl_params_err, hostname, port);

				// Create fetching queries

				/**
				 * @brief Array of queries definitions used to fetch data from a peer.
				 * @details All the queries defined here require to be updated if their target table definition is
				 *  changed. More details on 'CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS' definition.
				 */
				fetch_query queries[] = {
					{
						CLUSTER_QUERY_MYSQL_SERVERS_V2,
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
						CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES,
						p_cluster_counter::pulled_mysql_servers_hostgroup_attributes_success,
						p_cluster_counter::pulled_mysql_servers_hostgroup_attributes_failure,
						{ fetch_hostgroup_attributes_start, "", fetch_hostgroup_attributes_err }
					},
					{
						CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS,
						p_cluster_counter::pulled_mysql_servers_ssl_params_success,
						p_cluster_counter::pulled_mysql_servers_ssl_params_failure,
						{ fetch_mysql_servers_ssl_params_start, "", fetch_mysql_servers_ssl_params_err }
					}
				};

				bool fetching_error = false;
				for (size_t i = 0; i < sizeof(queries) / sizeof(fetch_query); i++) {
					MYSQL_RES* fetch_res = nullptr;
					int it_err = fetch_and_store(conn, queries[i], &fetch_res);

					if (it_err == 0) {
						results[i] = fetch_res;
					} else {
						fetching_error = true;
						fetch_failed = true;
						break;
					}
				}

				// fetch_runtime_mysql_servers value depends on 'cluster_mysql_servers_sync_algorithm'
				if (fetch_runtime_mysql_servers == true) {
					// Fetching runtime mysql servers (mysql_servers) configuration from remote peer
					std::string fetch_runtime_servers_done = "";
					string_format("Cluster: Fetching 'MySQL Servers' from peer %s:%d completed\n", fetch_runtime_servers_done, hostname, port);
					std::string fetch_runtime_servers_err = "";
					string_format("Cluster: Fetching 'MySQL Servers' from peer %s:%d failed: \n", fetch_runtime_servers_err, hostname, port);

					// Query definition used to fetch data from a peer.
					fetch_query query = {
						CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS,
						p_cluster_counter::pulled_mysql_servers_success,
						p_cluster_counter::pulled_mysql_servers_failure,
						{ "", fetch_runtime_servers_done, fetch_runtime_servers_err }
					};

					MYSQL_RES* fetch_res = nullptr;
					if (fetch_and_store(conn, query, &fetch_res) == 0) {
						results[7] = fetch_res;
					} else {
						fetching_error = true;
					}
				}

				if (fetching_error == false) {
					const uint64_t servers_hash = compute_servers_tables_raw_checksum(results, 7); // ignore runtime_mysql_servers in checksum calculation
					const string computed_checksum{ get_checksum_from_hash(servers_hash) };
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for MySQL Servers v2 from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());
					proxy_info("Cluster: Computed checksum for MySQL Servers v2 from peer %s:%d : %s\n", hostname, port, computed_checksum.c_str());

					bool runtime_checksum_matches = true;

					if (results[7]) {
						const uint64_t runtime_mysql_server_hash = mysql_raw_checksum(results[7]);
						const std::string runtime_mysql_server_computed_checksum = get_checksum_from_hash(runtime_mysql_server_hash);
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for MySQL Servers from peer %s:%d : %s\n", hostname, port, runtime_mysql_server_computed_checksum.c_str());
						proxy_info("Cluster: Computed checksum for MySQL Servers from peer %s:%d : %s\n", hostname, port, runtime_mysql_server_computed_checksum.c_str());
						runtime_checksum_matches = (runtime_mysql_server_computed_checksum == peer_runtime_mysql_servers_checksum);
					}

					if (computed_checksum == peer_mysql_servers_v2_checksum && runtime_checksum_matches == true) {
						// No need to perform the conversion if checksums don't match
						const incoming_servers_t incoming_servers{ convert_mysql_servers_resultsets(results) };
						// we are OK to sync!
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching checksum for 'MySQL Servers' from peer %s:%d successful. Checksum: %s\n", hostname, port, computed_checksum.c_str());
						proxy_info("Cluster: Fetching checksum for 'MySQL Servers' from peer %s:%d successful. Checksum: %s\n", hostname, port, computed_checksum.c_str());
						// sync mysql_servers
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_servers table\n");
						proxy_info("Cluster: Writing mysql_servers table\n");
						GloAdmin->mysql_servers_wrlock();
						GloAdmin->admindb->execute("DELETE FROM mysql_servers");
						MYSQL_ROW row;
						char* q = (char*)"INSERT INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (%s, \"%s\", %s, %s, \"%s\", %s, %s, %s, %s, %s, %s, '%s')";
						while ((row = mysql_fetch_row(results[0]))) {
							int l = 0;
							for (int i = 0; i < 11; i++) {
								l += strlen(row[i]);
							}
							char* o = escape_string_single_quotes(row[11], false);
							char* query = (char*)malloc(strlen(q) + l + strlen(o) + 64);

							sprintf(query, q, row[0], row[1], row[2], row[3], (strcmp(row[4], "SHUNNED") == 0 ? "ONLINE" : row[4]), row[5], row[6], row[7], row[8], row[9], row[10], o);
							if (o != row[11]) { // there was a copy
								free(o);
							}
							GloAdmin->admindb->execute(query);
							free(query);
						}

						// sync mysql_replication_hostgroups
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_replication_hostgroups table\n");
						proxy_info("Cluster: Writing mysql_replication_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_replication_hostgroups");
						q = (char*)"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment) VALUES (%s, %s, '%s', '%s')";
						while ((row = mysql_fetch_row(results[1]))) {
							int l = 0;
							for (int i = 0; i < 3; i++) {
								l += strlen(row[i]);
							}
							char* o = escape_string_single_quotes(row[3], false);
							char* query = (char*)malloc(strlen(q) + l + strlen(o) + 64);
							sprintf(query, q, row[0], row[1], row[2], o);
							if (o != row[3]) { // there was a copy
								free(o);
							}
							GloAdmin->admindb->execute(query);
							free(query);
						}

						// sync mysql_group_replication_hostgroups
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_group_replication_hostgroups table\n");
						proxy_info("Cluster: Writing mysql_group_replication_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_group_replication_hostgroups");
						q = (char*)"INSERT INTO mysql_group_replication_hostgroups ( "
							"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
							"max_writers, writer_is_also_reader, max_transactions_behind, comment) ";
						char* error = NULL;
						int cols = 0;
						int affected_rows = 0;
						SQLite3_result* resultset = NULL;
						while ((row = mysql_fetch_row(results[2]))) {
							int l = 0;
							for (int i = 0; i < 8; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[8] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[8], false);
								query = (char*)malloc(strlen(fqs.c_str()) + l + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
								// free in case of 'o' being a copy
								if (o != row[8]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char*)malloc(strlen(fqs.c_str()) + strlen("NULL") + l + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'mysql_group_replication_hostgroups'\n");
						proxy_info("Dumping fetched 'mysql_group_replication_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char*)"SELECT * FROM mysql_group_replication_hostgroups", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_galera_hostgroups
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_galera_hostgroups table\n");
						proxy_info("Cluster: Writing mysql_galera_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_galera_hostgroups");
						q = (char*)"INSERT INTO mysql_galera_hostgroups ( "
							"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, "
							"max_writers, writer_is_also_reader, max_transactions_behind, comment) ";
						while ((row = mysql_fetch_row(results[3]))) {
							int l = 0;
							for (int i = 0; i < 8; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[8] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[8], false);
								query = (char*)malloc(strlen(fqs.c_str()) + l + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
								// free in case of 'o' being a copy
								if (o != row[8]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char*)malloc(strlen(fqs.c_str()) + l + strlen("NULL") + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'mysql_galera_hostgroups'\n");
						proxy_info("Dumping fetched 'mysql_galera_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char*)"SELECT * FROM mysql_galera_hostgroups", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_aws_aurora_hostgroups
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_aws_aurora_hostgroups table\n");
						proxy_info("Cluster: Writing mysql_aws_aurora_hostgroups table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_aws_aurora_hostgroups");
						q = (char*)"INSERT INTO mysql_aws_aurora_hostgroups ( "
							"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
							"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) ";
						while ((row = mysql_fetch_row(results[4]))) {
							int l = 0;
							for (int i = 0; i < 13; i++) {
								l += strlen(row[i]);
							}
							char* o = nullptr;
							char* query = nullptr;
							std::string fqs = q;

							if (row[13] != nullptr) {
								fqs += "VALUES (%s, %s, %s, %s, '%s', %s, %s, %s, %s, %s, %s, %s, %s, '%s')";
								o = escape_string_single_quotes(row[13], false);
								query = (char*)malloc(strlen(fqs.c_str()) + l + strlen(o) + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], o);
								// free in case of 'o' being a copy
								if (o != row[13]) {
									free(o);
								}
							} else {
								// In case of comment being null, placeholder must not have ''
								fqs += "VALUES (%s, %s, %s, %s, '%s', %s, %s, %s, %s, %s, %s, %s, %s, %s)";
								o = const_cast<char*>("NULL");
								query = (char*)malloc(strlen(fqs.c_str()) + l + strlen("NULL") + 64);
								sprintf(query, fqs.c_str(), row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], o);
							}

							GloAdmin->admindb->execute(query);
							free(query);
						}
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'mysql_aws_aurora_hostgroups'\n");
						proxy_info("Dumping fetched 'mysql_aws_aurora_hostgroups'\n");
						GloAdmin->admindb->execute_statement((char*)"SELECT * FROM mysql_aws_aurora_hostgroups", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_hostgroup_attributes
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_hostgroup_attributes table\n");
						proxy_info("Cluster: Writing mysql_hostgroup_attributes table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_hostgroup_attributes");
						{
							const char* q = (const char*)"INSERT INTO mysql_hostgroup_attributes ( "
								"hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, "
								"init_connect, multiplex, connection_warming, throttle_connections_per_sec, "
								"ignore_session_variables, hostgroup_settings, servers_defaults, comment) VALUES "
								"(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
							sqlite3_stmt *statement1 = NULL;
							int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
							ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

							while ((row = mysql_fetch_row(results[5]))) {
								rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atol(row[0])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // hostgroup_id
								rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atol(row[1])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // max_num_online_servers
								rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atol(row[2])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // autocommit
								rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atol(row[3])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // free_connections_pct
								rc=(*proxy_sqlite3_bind_text)(statement1, 5, row[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // variable_name
								rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atol(row[5])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // multiplex
								rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atol(row[6])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // connection_warming
								rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atol(row[7])); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // throttle_connections_per_sec
								rc=(*proxy_sqlite3_bind_text)(statement1, 9, row[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ignore_session_variables
								rc=(*proxy_sqlite3_bind_text)(statement1, 10,row[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // hostgroup_settings
								rc=(*proxy_sqlite3_bind_text)(statement1, 11, row[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // servers_defaults
								rc=(*proxy_sqlite3_bind_text)(statement1, 12, row[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
								SAFE_SQLITE3_STEP2(statement1);
								rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
								rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
							}
							(*proxy_sqlite3_finalize)(statement1);
						}

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'mysql_hostgroup_attributes'\n");
						proxy_info("Dumping fetched 'mysql_hostgroup_attributes'\n");
						GloAdmin->admindb->execute_statement((char*)"SELECT * FROM mysql_hostgroup_attributes", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						// sync mysql_servers_ssl_params
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Writing mysql_servers_ssl_params table\n");
						proxy_info("Cluster: Writing mysql_servers_ssl_params table\n");
						GloAdmin->admindb->execute("DELETE FROM mysql_servers_ssl_params");
						{
							const char* q = (const char*)"INSERT INTO mysql_servers_ssl_params (hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
							sqlite3_stmt *statement1 = NULL;
							int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
							ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

							while ((row = mysql_fetch_row(results[6]))) {
								rc=(*proxy_sqlite3_bind_text)(statement1,  1,  row[0],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // hostname
								rc=(*proxy_sqlite3_bind_int64)(statement1, 2,  atol(row[1]));                  ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // port
								rc=(*proxy_sqlite3_bind_text)(statement1,  3,  row[2],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // username
								rc=(*proxy_sqlite3_bind_text)(statement1,  4,  row[3],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_ca
								rc=(*proxy_sqlite3_bind_text)(statement1,  5,  row[4],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_cert
								rc=(*proxy_sqlite3_bind_text)(statement1,  6,  row[5],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_key
								rc=(*proxy_sqlite3_bind_text)(statement1,  7,  row[6],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_capath
								rc=(*proxy_sqlite3_bind_text)(statement1,  8,  row[7],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_crl
								rc=(*proxy_sqlite3_bind_text)(statement1,  9,  row[8],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_crlpath
								rc=(*proxy_sqlite3_bind_text)(statement1,  10, row[9],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // ssl_cipher
								rc=(*proxy_sqlite3_bind_text)(statement1,  11, row[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // tls_version
								rc=(*proxy_sqlite3_bind_text)(statement1,  12, row[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // comment
								SAFE_SQLITE3_STEP2(statement1);
								rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
								rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
							}
							(*proxy_sqlite3_finalize)(statement1);
						}

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'mysql_servers_ssl_params'\n");
						proxy_info("Dumping fetched 'mysql_servers_ssl_params'\n");
						GloAdmin->admindb->execute_statement((char*)"SELECT * FROM mysql_servers_ssl_params", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime MySQL Servers v2 from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: Loading to runtime MySQL Servers v2 from peer %s:%d\n", hostname, port);
						GloAdmin->load_mysql_servers_to_runtime(incoming_servers, peer_runtime_mysql_server, peer_mysql_server_v2);

						if (GloProxyCluster->cluster_mysql_servers_save_to_disk == true) {
							if (fetch_runtime_mysql_servers == true) {
								proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving Runtime MySQL Servers to Database\n");
								GloAdmin->save_mysql_servers_runtime_to_database(false);
                            }
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk MySQL Servers v2 from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk MySQL Servers v2 from peer %s:%d\n", hostname, port);
							GloAdmin->flush_GENERIC__from_to("mysql_servers", "memory_to_disk");
						} else {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Not saving to disk MySQL Servers from peer %s:%d failed.\n", hostname, port);
							proxy_info("Cluster: Not saving to disk MySQL Servers from peer %s:%d failed.\n", hostname, port);
						}
						GloAdmin->mysql_servers_wrunlock();
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Servers v2 from peer %s:%d failed: Checksum changed from %s to %s\n",
							hostname, port, peer_mysql_servers_v2_checksum, computed_checksum.c_str());
						proxy_info(
							"Cluster: Fetching MySQL Servers v2 from peer %s:%d failed: Checksum changed from %s to %s\n",
							hostname, port, peer_mysql_servers_v2_checksum, computed_checksum.c_str()
						);
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_variables_failure]->Increment();
						fetch_failed = true;
					}

					// free results
					for (MYSQL_RES* result : results) {
						mysql_free_result(result);
					}

					metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_success]->Increment();
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching MySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_mysql_servers_failure]->Increment();
				fetch_failed = true;
			}
		}
	__exit_pull_mysql_servers_v2_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (ip_address)
			free(ip_address);

		if (peer_mysql_servers_v2_checksum)
			free (peer_mysql_servers_v2_checksum);

		if (peer_runtime_mysql_servers_checksum)
			free(peer_runtime_mysql_servers_checksum);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_servers_v2_mutex);
	if (fetch_failed == true) sleep(1);
}

void ProxySQL_Cluster::pull_global_variables_from_peer(const string& var_type, const string& expected_checksum, const time_t epoch) {
	char * hostname = NULL;
	char * ip_address = NULL;
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
	} else if (var_type == "ldap") {
		vars_type_str = const_cast<char*>("LDAP");
		success_metric = p_cluster_counter::pulled_ldap_variables_success;
		failure_metric = p_cluster_counter::pulled_ldap_variables_failure;
	} else {
		proxy_error("Invalid parameter supplied to 'pull_global_variables_from_peer': var_type=%s\n", var_type.c_str());
		assert(0);
	}

	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_mysql_variables_mutex);
	if (var_type == "mysql") {
		nodes.get_peer_to_sync_mysql_variables(&hostname, &port, &ip_address);
	} else if (var_type == "admin") {
		nodes.get_peer_to_sync_admin_variables(&hostname, &port, &ip_address);
	} else if (var_type == "ldap"){
		nodes.get_peer_to_sync_ldap_variables(&hostname, &port, &ip_address);
	} else {
		proxy_error("Invalid parameter supplied to 'pull_global_variables_from_peer': var_type=%s\n", var_type.c_str());
		assert(0);
	}

	if (hostname) {
		cluster_creds_t creds {};

		MYSQL *conn = mysql_init(NULL);
		if (conn == NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_mysql_variables_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_info("Cluster: Fetching %s variables from peer %s:%d started\n", vars_type_str, hostname, port);
			MYSQL* rc_conn = mysql_real_connect(
				conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0
			);

			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				std::string s_query = "";
				string_format("SELECT * FROM runtime_global_variables WHERE variable_name LIKE '%s-%%'", s_query, var_type.c_str());
				if (var_type == "mysql") {
					s_query += " AND variable_name NOT IN ('mysql-threads')";
				}
				if (GloVars.cluster_sync_interfaces == false) {
					if (var_type == "admin") {
						s_query += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_ADMIN);
					} else if (var_type == "mysql") {
						s_query += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_MYSQL);
					}
				}
				s_query += " ORDER BY variable_name";
				int rc_query = mysql_query(conn, s_query.c_str());

				if (rc_query == 0) {
					MYSQL_RES *result = mysql_store_result(conn);
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching %s Variables from peer %s:%d completed\n", vars_type_str, hostname, port);
					proxy_info("Cluster: Fetching %s Variables from peer %s:%d completed\n", vars_type_str, hostname, port);

					uint64_t glovars_hash = mysql_raw_checksum(result);
					string computed_checksum { get_checksum_from_hash(glovars_hash) };
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Computed checksum for %s Variables from peer %s:%d : %s\n", vars_type_str, hostname, port, computed_checksum.c_str());
					proxy_info("Cluster: Computed checksum for %s Variables from peer %s:%d : %s\n", vars_type_str, hostname, port, computed_checksum.c_str());

					if (expected_checksum == computed_checksum) {

					std::string d_query = "";
					// remember that we read from runtime_global_variables but write into global_variables
					string_format("DELETE FROM global_variables WHERE variable_name LIKE '%s-%%'", d_query, var_type.c_str());
					if (var_type == "mysql") {
						s_query += " AND variable_name NOT IN ('mysql-threads')";
					}
					if (GloVars.cluster_sync_interfaces == false) {
						if (var_type == "admin") {
							d_query += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_ADMIN);
						} else if (var_type == "mysql") {
							d_query += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_MYSQL);
						}
					}
					GloAdmin->admindb->execute(d_query.c_str());

					MYSQL_ROW row;
					char *q = (char *)"INSERT OR REPLACE INTO global_variables (variable_name, variable_value) VALUES (?1 , ?2)";
					sqlite3_stmt *statement1 = NULL;
					int rc = GloAdmin->admindb->prepare_v2(q, &statement1);
					ASSERT_SQLITE_OK(rc, GloAdmin->admindb);

					while ((row = mysql_fetch_row(result))) {
						rc=(*proxy_sqlite3_bind_text)(statement1, 1, row[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // variable_name
						rc=(*proxy_sqlite3_bind_text)(statement1, 2, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, GloAdmin->admindb); // variable_value

						SAFE_SQLITE3_STEP2(statement1);
						rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
						rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, GloAdmin->admindb);
					}

					mysql_free_result(result);
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime %s Variables from peer %s:%d\n", vars_type_str, hostname, port);
					proxy_info("Cluster: Loading to runtime %s Variables from peer %s:%d\n", vars_type_str, hostname, port);

					if (var_type == "mysql") {
						GloAdmin->load_mysql_variables_to_runtime(expected_checksum, epoch);

						if (GloProxyCluster->cluster_mysql_variables_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk MySQL Variables from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk MySQL Variables from peer %s:%d\n", hostname, port);
							GloAdmin->flush_mysql_variables__from_memory_to_disk();
						}
					} else if (var_type == "admin") {
						GloAdmin->load_admin_variables_to_runtime(expected_checksum, epoch, false);

						if (GloProxyCluster->cluster_admin_variables_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk Admin Variables from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk Admin Variables from peer %s:%d\n", hostname, port);
							GloAdmin->flush_admin_variables__from_memory_to_disk();
						}

					} else if (var_type == "ldap") {
						GloAdmin->load_ldap_variables_to_runtime(expected_checksum, epoch);

						if (GloProxyCluster->cluster_ldap_variables_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk LDAP Variables from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk LDAP Variables from peer %s:%d\n", hostname, port);
							GloAdmin->flush_ldap_variables__from_memory_to_disk();
						}
					} else {
						proxy_error("Invalid parameter supplied to 'pull_global_variables_from_peer': var_type=%s\n", var_type.c_str());
						assert(0);
					}
					metrics.p_counter_array[success_metric]->Increment();
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching %s Variables from peer %s:%d failed: Checksum changed from %s to %s\n",
							vars_type_str, hostname, port, expected_checksum.c_str(), computed_checksum.c_str());
						proxy_info(
							"Cluster: Fetching %s Variables from peer %s:%d failed: Checksum changed from %s to %s\n",
							vars_type_str, hostname, port, expected_checksum.c_str(), computed_checksum.c_str()
						);
						metrics.p_counter_array[p_cluster_counter::pulled_mysql_variables_failure]->Increment();
						fetch_failed = true;
					}
				} else {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
					proxy_info("Cluster: Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
					metrics.p_counter_array[failure_metric]->Increment();
					fetch_failed = true;
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching %s Variables from peer %s:%d failed: %s\n", vars_type_str, hostname, port, mysql_error(conn));
				metrics.p_counter_array[failure_metric]->Increment();
				fetch_failed = true;
			}
		}
__exit_pull_mysql_variables_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (ip_address)
			free(ip_address);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_mysql_variables_mutex);
	if (fetch_failed == true) sleep(1);
}

void ProxySQL_Cluster::pull_proxysql_servers_from_peer(const std::string& expected_checksum, const time_t epoch) {
	char * hostname = NULL;
	char * ip_address = NULL;
	uint16_t port = 0;
	bool fetch_failed = false;
	pthread_mutex_lock(&GloProxyCluster->update_proxysql_servers_mutex);
	nodes.get_peer_to_sync_proxysql_servers(&hostname, &port, &ip_address);
	if (hostname) {
		cluster_creds_t creds {};

		MYSQL *conn = mysql_init(NULL);
		if (conn==NULL) {
			proxy_error("Unable to run mysql_init()\n");
			goto __exit_pull_proxysql_servers_from_peer;
		}

		creds = GloProxyCluster->get_credentials();
		if (creds.user.size()) { // do not monitor if the username is empty
			// READ/WRITE timeouts were enforced as an attempt to prevent deadlocks in the original
			// implementation. They were proven unnecessary, leaving only 'CONNECT_TIMEOUT'.
			unsigned int timeout = 1;
			mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
			{
				unsigned char val = 1; mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
				mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
			}
			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching ProxySQL Servers from peer %s:%d started. Expected checksum: %s\n",
				hostname, port, expected_checksum.c_str());
			proxy_info(
				"Cluster: Fetching ProxySQL Servers from peer %s:%d started. Expected checksum: %s\n",
				hostname, port, expected_checksum.c_str()
			);
			MYSQL* rc_conn = mysql_real_connect(
				conn, ip_address ? ip_address : hostname, creds.user.c_str(), creds.pass.c_str(), NULL, port, NULL, 0
			);
			if (rc_conn) {
				MySQL_Monitor::update_dns_cache_from_mysql_conn(conn);

				int rc_query = mysql_query(conn,"SELECT hostname, port, weight, comment FROM runtime_proxysql_servers ORDER BY hostname, port");
				if ( rc_query == 0 ) {
					MYSQL_RES* result = mysql_store_result(conn);
					uint64_t proxy_servers_hash = mysql_raw_checksum(result);
					const string computed_cks { get_checksum_from_hash(proxy_servers_hash) };
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching ProxySQL Servers from peer %s:%d completed. Computed checksum: %s\n", hostname, port, computed_cks.c_str());
					proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d completed. Computed checksum: %s\n", hostname, port, computed_cks.c_str());

					if (computed_cks == expected_checksum) {
						mysql_data_seek(result,0);
						GloAdmin->admindb->execute("DELETE FROM proxysql_servers");
						char *q=(char *)"INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES (\"%s\", %s, %s, '%s')";
						while (MYSQL_ROW row = mysql_fetch_row(result)) {
							int l=0;
							for (int i=0; i<3; i++) {
								l+=strlen(row[i]);
							}
							char *o=escape_string_single_quotes(row[3],false);
							char *query = (char *)malloc(strlen(q)+l+strlen(o)+64);
							sprintf(query,q,row[0],row[1],row[2],o);
							if (o!=row[3]) { // there was a copy
								free(o);
							}
							GloAdmin->admindb->execute(query);
							free(query);
						}

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Dumping fetched 'proxysql_servers'\n");
						proxy_info("Dumping fetched 'proxysql_servers'\n");
						char *error = NULL;
						int cols = 0;
						int affected_rows = 0;
						SQLite3_result *resultset = NULL;
						GloAdmin->admindb->execute_statement((char *)"SELECT * FROM proxysql_servers", &error, &cols, &affected_rows, &resultset);
						resultset->dump_to_stderr();
						delete resultset;

						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Loading to runtime ProxySQL Servers from peer %s:%d\n", hostname, port);
						proxy_info("Cluster: Loading to runtime ProxySQL Servers from peer %s:%d\n", hostname, port);
						GloAdmin->load_proxysql_servers_to_runtime(false, expected_checksum, epoch);
						if (GloProxyCluster->cluster_proxysql_servers_save_to_disk == true) {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: Saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
							GloAdmin->flush_GENERIC__from_to("proxysql_servers","memory_to_disk");
						} else {
							proxy_debug(PROXY_DEBUG_CLUSTER, 5, "NOT saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
							proxy_info("Cluster: NOT saving to disk ProxySQL Servers from peer %s:%d\n", hostname, port);
						}
						metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_success]->Increment();
					} else {
						proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching ProxySQL Servers from peer %s:%d failed: Checksum changed from %s to %s\n",
							hostname, port, expected_checksum.c_str(), computed_cks.c_str());
						proxy_info(
							"Cluster: Fetching ProxySQL Servers from peer %s:%d failed: Checksum changed from %s to %s\n",
							hostname, port, expected_checksum.c_str(), computed_cks.c_str()
						);
						metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_failure]->Increment();
						fetch_failed = true;
					}
					mysql_free_result(result);
				} else {
					proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
					metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_failure]->Increment();
					fetch_failed = true;
				}
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				proxy_info("Cluster: Fetching ProxySQL Servers from peer %s:%d failed: %s\n", hostname, port, mysql_error(conn));
				metrics.p_counter_array[p_cluster_counter::pulled_proxysql_servers_failure]->Increment();
				fetch_failed = true;
			}
		}
__exit_pull_proxysql_servers_from_peer:
		if (conn) {
			if (conn->net.pvio) {
				mysql_close(conn);
			}
		}
		free(hostname);

		if (ip_address)
			free(ip_address);
	}
	pthread_mutex_unlock(&GloProxyCluster->update_proxysql_servers_mutex);
	if (fetch_failed == true) sleep(1);
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

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using cluster_nodes_counter_tuple =
	std::tuple<
		p_cluster_nodes_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_nodes_gauge_tuple =
	std::tuple<
		p_cluster_nodes_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_nodes_dyn_counter_tuple =
	std::tuple<
		p_cluster_nodes_dyn_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_nodes_dyn_gauge_tuple =
	std::tuple<
		p_cluster_nodes_dyn_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using cluster_nodes_counter_vector = std::vector<cluster_nodes_counter_tuple>;
using cluster_nodes_gauge_vector = std::vector<cluster_nodes_gauge_tuple>;
using cluster_nodes_dyn_counter_vector = std::vector<cluster_nodes_dyn_counter_tuple>;
using cluster_nodes_dyn_gauge_vector = std::vector<cluster_nodes_dyn_gauge_tuple>;

const std::tuple<
	cluster_nodes_counter_vector,
	cluster_nodes_gauge_vector,
	cluster_nodes_dyn_counter_vector,
	cluster_nodes_dyn_gauge_vector
>
cluster_nodes_metrics_map = std::make_tuple(
	cluster_nodes_counter_vector{},
	cluster_nodes_gauge_vector {},
	cluster_nodes_dyn_counter_vector {
		std::make_tuple (
			p_cluster_nodes_dyn_counter::proxysql_servers_checksums_version_total,
			"proxysql_servers_checksums_version_total",
			"Number of times the configuration has been loaded locally.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_counter::proxysql_servers_metrics_uptime_s,
			"proxysql_servers_metrics_uptime_s_total",
			"Current uptime of the Cluster node, in seconds.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_counter::proxysql_servers_metrics_queries,
			"proxysql_servers_metrics_queries_total",
			"Number of queries the Cluster node has processed.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_counter::proxysql_servers_metrics_client_conns_created,
			"proxysql_servers_metrics_client_conns_created_total",
			"Number of frontend client connections created over time on the Cluster node.",
			metric_tags {}
		),
	},
	cluster_nodes_dyn_gauge_vector {
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_checksums_epoch,
			"proxysql_servers_checksums_epoch",
			"Time at which this configuration was created (locally or imported).",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_checksums_changed_at,
			"proxysql_servers_checksums_changed_at",
			"Time at which this configuration was loaded locally.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_checksums_updated_at,
			"proxysql_servers_checksums_updated_at",
			"Last time local ProxySQL checked the checksum of a remote instance.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_checksums_diff_check,
			"proxysql_servers_checksums_diff_check",
			"Number of checks in a row in which it was detected that remote conf is different than local one.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_metrics_weight,
			"proxysql_servers_metrics_weight",
			"Weight of the Cluster node, defined in the proxysql_servers table",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_metrics_response_time_ms,
			"proxysql_servers_metrics_response_time_ms",
			"Latest time to respond to Cluster checks, in milliseconds.",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_metrics_last_check_ms,
			"proxysql_servers_metrics_last_check_ms",
			"Latest time to process Cluster checks, in milliseconds",
			metric_tags {}
		),
		std::make_tuple (
			p_cluster_nodes_dyn_gauge::proxysql_servers_metrics_client_conns_connected,
			"proxysql_servers_metrics_client_conns_connected_total",
			"Number of frontend client connections currently open on the Cluster node.",
			metric_tags {}
		),
	}
);

ProxySQL_Cluster_Nodes::ProxySQL_Cluster_Nodes() {
	pthread_mutex_init(&mutex,NULL);

	init_prometheus_dyn_counter_array<cluster_nodes_metrics_map_idx, p_cluster_nodes_dyn_counter>(
		cluster_nodes_metrics_map, this->metrics.p_dyn_counter_array
	);
	init_prometheus_dyn_gauge_array<cluster_nodes_metrics_map_idx, p_cluster_nodes_dyn_gauge>(
		cluster_nodes_metrics_map, this->metrics.p_dyn_gauge_array
	);
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

			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Added new peer %s:%d\n", h_, p_);

			ProxySQL_Node_Address * a = new ProxySQL_Node_Address(h_, p_, node->get_ipaddress());
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			if (pthread_create(&a->thrid, &attr, ProxySQL_Cluster_Monitor_thread, (void *)a) != 0) {
				// LCOV_EXCL_START
				proxy_error("Thread creation\n");
				assert(0);
				// LCOV_EXCL_STOP
			}
			//pthread_create(&a->thrid, NULL, ProxySQL_Cluster_Monitor_thread, (void *)a);
			//pthread_detach(a->thrid);
		} else {
			node = ite->second;
			node->resolve_hostname();
			node->set_active(true);
			node->set_weight(w_);
			node->set_comment(c_);

			proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Peer %s:%d already exists. Updating it\n", h_, p_);
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
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Global checksum 0x%llX for peer %s:%d matches\n", v, node->get_hostname(), node->get_port());
				ret = false;
			} else {
				proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Global checksum for peer %s:%d is different from fetched one. Local checksum:[0x%lX] Fetched checksum:[0x%llX]\n", node->get_hostname(), node->get_port(), node->global_checksum, v);
				node->global_checksum = v;
			}
		}
		//pthread_mutex_unlock(&GloVars.checksum_mutex);
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}

void ProxySQL_Cluster_Nodes::Reset_Global_Checksums(bool lock) {
	if (lock) {
		pthread_mutex_lock(&mutex);
	}

	for (auto& proxy_node_entry : umap_proxy_nodes) {
		proxy_node_entry.second->global_checksum = 0;
	}

	if (lock) {
		pthread_mutex_unlock(&mutex);
	}
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

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_query_rules(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char *ip_addr = NULL;
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
				if (v->diff_check >= diff_mqr) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());

					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr= strdup(ip);

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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_query_rules version %llu, epoch %llu\n", hostname, p, version, epoch);
		proxy_info("Cluster: detected peer %s:%d with mysql_query_rules version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_runtime_mysql_servers(char **host, uint16_t *port, char **peer_checksum, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char *ip_addr = NULL;
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
				if (v->diff_check >= diff_ms) {
					epoch = v->epoch;
					version = v->version;
					if (pc) {
						free(pc);
					}
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					pc = strdup(v->checksum);
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr=strdup(ip);
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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		*peer_checksum = pc;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers version %llu, epoch %llu, checksum %s\n", hostname, p, version, epoch, pc);
		proxy_info("Cluster: detected peer %s:%d with mysql_servers version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_servers_v2(char** host, uint16_t* port, 
	char** peer_mysql_servers_v2_checksum, char** peer_runtime_mysql_servers_checksum, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char* hostname = NULL;
	char* ip_addr = NULL;
	uint16_t p = 0;
	char* mysql_servers_v2_checksum = NULL;
	char* runtime_mysql_servers_checksum = NULL;
	//pthread_mutex_lock(&mutex);
	//unsigned long long curtime = monotonic_time();
	unsigned int diff_ms = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync, 0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry*>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry* node = it->second;
		ProxySQL_Checksum_Value_2* v = &node->checksums_values.mysql_servers_v2;
		if (v->version > 1) {
			if (v->epoch > epoch) {
				max_epoch = v->epoch;
				if (v->diff_check >= diff_ms) {
					epoch = v->epoch;
					version = v->version;
					if (mysql_servers_v2_checksum) {
						free(mysql_servers_v2_checksum);
					}
					if (runtime_mysql_servers_checksum) {
						free(runtime_mysql_servers_checksum);
					}
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					mysql_servers_v2_checksum = strdup(v->checksum);
					runtime_mysql_servers_checksum = strdup(node->checksums_values.mysql_servers.checksum);
					hostname = strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
					p = node->get_port();
				}
			}
		}
		it++;
	}
	//	pthread_mutex_unlock(&mutex);
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with mysql_servers_v2 epoch %llu , but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
			if (mysql_servers_v2_checksum) {
				free(mysql_servers_v2_checksum);
				mysql_servers_v2_checksum = NULL;
			}
			if (runtime_mysql_servers_checksum) {
				free(runtime_mysql_servers_checksum);
				runtime_mysql_servers_checksum = NULL;
			}
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		*peer_mysql_servers_v2_checksum = mysql_servers_v2_checksum;
		*peer_runtime_mysql_servers_checksum = runtime_mysql_servers_checksum;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_servers_v2 version %llu, epoch %llu, mysql_servers_v2 checksum %s, runtime_mysql_servers %s\n", hostname, p, version, epoch, mysql_servers_v2_checksum, runtime_mysql_servers_checksum);
		proxy_info("Cluster: detected peer %s:%d with mysql_servers_v2 version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_users(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char *ip_addr = NULL;
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
				if (v->diff_check >= diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_users version %llu, epoch %llu\n", hostname, p, version, epoch);
		proxy_info("Cluster: detected peer %s:%d with mysql_users version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_mysql_variables(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char* ip_addr = NULL;
	uint16_t p = 0;
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync,0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end();) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.mysql_variables;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check >= diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with mysql_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
		proxy_info("Cluster: detected peer %s:%d with mysql_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}


void ProxySQL_Cluster_Nodes::get_peer_to_sync_admin_variables(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char *ip_addr = NULL;
	uint16_t p = 0;
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_admin_variables_diffs_before_sync,0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end();) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.admin_variables;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check >= diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with admin_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
		proxy_info("Cluster: detected peer %s:%d with admin_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_ldap_variables(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char* ip_addr = NULL;
	uint16_t p = 0;
	unsigned int diff_mu = (unsigned int)__sync_fetch_and_add(&GloProxyCluster->cluster_ldap_variables_diffs_before_sync,0);
	for (std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end();) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value_2 * v = &node->checksums_values.ldap_variables;
		if (v->version > 1) {
			if ( v->epoch > epoch ) {
				max_epoch = v->epoch;
				if (v->diff_check >= diff_mu) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
					p = node->get_port();
				}
			}
		}
		it++;
	}
	if (epoch) {
		if (max_epoch > epoch) {
			proxy_warning("Cluster: detected a peer with ldap_variables epoch %llu, but not enough diff_check. We won't sync from epoch %llu: temporarily skipping sync\n", max_epoch, epoch);
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with ldap_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
		proxy_info("Cluster: detected peer %s:%d with ldap_variables version %llu, epoch %llu\n", hostname, p, version, epoch);
	}
}

void ProxySQL_Cluster_Nodes::get_peer_to_sync_proxysql_servers(char **host, uint16_t *port, char** ip_address) {
	unsigned long long version = 0;
	unsigned long long epoch = 0;
	unsigned long long max_epoch = 0;
	char *hostname = NULL;
	char *ip_addr = NULL;
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
				if (v->diff_check >= diff_ps) {
					epoch = v->epoch;
					version = v->version;
					if (hostname) {
						free(hostname);
					}
					if (ip_addr) {
						free(ip_addr);
					}
					hostname=strdup(node->get_hostname());
					const char* ip = node->get_ipaddress();
					if (ip)
						ip_addr = strdup(ip);
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
			if (ip_addr) {
				free(ip_addr);
				ip_addr = NULL;
			}
		}
	}
	if (hostname) {
		*host = hostname;
		*port = p;
		*ip_address = ip_addr;
		proxy_debug(PROXY_DEBUG_CLUSTER, 5, "Detected peer %s:%d with proxysql_servers version %llu, epoch %llu\n", hostname, p, version, epoch);
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
		ProxySQL_Checksum_Value_2 * vals[7];
		vals[0] = &node->checksums_values.admin_variables;
		vals[1] = &node->checksums_values.mysql_query_rules;
		vals[2] = &node->checksums_values.mysql_servers;
		vals[3] = &node->checksums_values.mysql_users;
		vals[4] = &node->checksums_values.mysql_variables;
		vals[5] = &node->checksums_values.proxysql_servers;
		vals[6] = &node->checksums_values.mysql_servers_v2;
		for (int i=0; i<7 ; i++) {
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
				case 6:
					pta[2]=strdup((char*)"mysql_servers_v2");
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

vector<pair<string, ProxySQL_Checksum_Value_2*>> get_module_checksums(ProxySQL_Node_Entry* entry) {
	if (entry == nullptr) { return {}; }

	vector<pair<string, ProxySQL_Checksum_Value_2*>> res {};
	res.push_back({"admin_variables", &entry->checksums_values.admin_variables});
	res.push_back({"mysql_query_rules", &entry->checksums_values.mysql_query_rules});
	res.push_back({"mysql_servers", &entry->checksums_values.mysql_servers});
	res.push_back({"mysql_users", &entry->checksums_values.mysql_users});
	res.push_back({"mysql_variables", &entry->checksums_values.mysql_variables});
	res.push_back({"proxysql_servers", &entry->checksums_values.proxysql_servers});
	res.push_back({"mysql_servers_v2", &entry->checksums_values.mysql_servers_v2});

	return res;
}

void ProxySQL_Cluster_Nodes::update_prometheus_nodes_metrics() {
	using dyn_gauge = p_cluster_nodes_dyn_gauge;
	using dyn_counter = p_cluster_nodes_dyn_counter;

	pthread_mutex_lock(&mutex);

	vector<string> cur_node_metrics {};
	vector<string> cur_node_checksums {};

	// Update metrics for both 'servers_checksums' and 'servers_metrics'
	for (const auto& node_entry : umap_proxy_nodes) {
		const string hostname { node_entry.second->get_hostname() };
		const string port { std::to_string(node_entry.second->get_port()) };
		const vector<pair<string,ProxySQL_Checksum_Value_2*>> modules_name_checksum { get_module_checksums(node_entry.second) };

		const string m_node_metrics_id { hostname + ":" + port };
		const std::map<string, string> m_common_labels { { "hostname", hostname }, { "port", port } };

		// Update the current nodes metric list
		cur_node_metrics.push_back(m_node_metrics_id);

		for (const std::pair<string,ProxySQL_Checksum_Value_2*>& module_name_checksum : modules_name_checksum) {
			const string module_name { module_name_checksum.first };
			const ProxySQL_Checksum_Value_2* module_checksum { module_name_checksum.second };

			std::map<string, string> m_module_labels { m_common_labels.begin(), m_common_labels.end() };
			m_module_labels.insert({ "name", module_name });

			// Update the current nodes checksum list
			const string m_node_checksum_id { hostname + ":" + port + ":" + module_name_checksum.first };
			cur_node_checksums.push_back(m_node_checksum_id);

			// proxysql_servers_checksum
			p_update_map_counter(
				this->metrics.p_proxysql_servers_checksum_version,
				this->metrics.p_dyn_counter_array[p_cluster_nodes_dyn_counter::proxysql_servers_checksums_version_total],
				m_node_checksum_id, m_module_labels, module_name_checksum.second->version
			);

			vector<tuple<map<string,prometheus::Gauge*>&,p_cluster_nodes_dyn_gauge::metric,double>> checksum_gauges {
				std::make_tuple(std::ref(this->metrics.p_proxysql_servers_checksums_epoch), dyn_gauge::proxysql_servers_checksums_epoch, module_checksum->epoch),
				std::make_tuple(std::ref(this->metrics.p_proxysql_servers_checksums_updated_at), dyn_gauge::proxysql_servers_checksums_updated_at, module_checksum->last_updated),
				std::make_tuple(std::ref(this->metrics.p_proxysql_servers_checksums_changed_at), dyn_gauge::proxysql_servers_checksums_changed_at, module_checksum->last_changed),
				std::make_tuple(std::ref(this->metrics.p_proxysql_servers_checksums_diff_check), dyn_gauge::proxysql_servers_checksums_diff_check, module_checksum->diff_check)
			};

			for (const auto& checksum_gauge : checksum_gauges) {
				p_update_map_gauge(
					std::get<0>(checksum_gauge), this->metrics.p_dyn_gauge_array[std::get<1>(checksum_gauge)],
					m_node_checksum_id, m_module_labels, std::get<2>(checksum_gauge)
				);
			}
		}

		const ProxySQL_Node_Metrics* node_metrics = node_entry.second->get_metrics_curr();
		const double conns_created = node_metrics->Client_Connections_created;

		vector<tuple<map<string,prometheus::Counter*>&, p_cluster_nodes_dyn_counter::metric, double>> metric_counters {
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_queries), dyn_counter::proxysql_servers_metrics_queries, node_metrics->Questions),
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_client_conns_created), dyn_counter::proxysql_servers_metrics_client_conns_created, conns_created),
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_uptime_s), dyn_counter::proxysql_servers_metrics_uptime_s, node_metrics->ProxySQL_Uptime)
		};

		const uint64_t curtime = monotonic_time();
		const uint64_t read_time_us = node_entry.second->get_metrics_curr()->read_time_us;
		const double last_check_ms = (curtime - read_time_us) / 1000.0;
		const double response_time_ms = node_metrics->response_time_us / 1000.0;
		const double conns_connected = node_metrics->Client_Connections_connected;

		vector<tuple<map<string,prometheus::Gauge*>&, dyn_gauge::metric, double>> metric_gauges {
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_last_check_ms), dyn_gauge::proxysql_servers_metrics_last_check_ms, last_check_ms),
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_response_time_ms), dyn_gauge::proxysql_servers_metrics_response_time_ms, response_time_ms),
			std::make_tuple(std::ref(this->metrics.p_proxysql_servers_metrics_client_conns_connected), dyn_gauge::proxysql_servers_metrics_client_conns_connected, conns_connected),
		};

		for (const auto& metric_gauge : metric_gauges) {
			p_update_map_gauge(
				std::get<0>(metric_gauge), this->metrics.p_dyn_gauge_array[std::get<1>(metric_gauge)],
				m_node_metrics_id, m_common_labels, std::get<2>(metric_gauge)
			);
		}

		for (const auto& metric_counter : metric_counters) {
			p_update_map_counter(
				std::get<0>(metric_counter), this->metrics.p_dyn_counter_array[std::get<1>(metric_counter)],
				m_node_metrics_id, m_common_labels, std::get<2>(metric_counter)
			);
		}
	}

	// Remove no longer present nodes
	vector<string> missing_server_metrics_keys {};
	vector<string> missing_server_checksums_keys {};

	for (const auto& key : metrics.p_proxysql_servers_metrics_uptime_s) {
		if (std::find(cur_node_metrics.begin(), cur_node_metrics.end(), key.first) == cur_node_metrics.end()) {
			missing_server_metrics_keys.push_back(key.first);
		}
	}
	for (const auto& key : metrics.p_proxysql_servers_checksum_version) {
		if (std::find(cur_node_checksums.begin(), cur_node_checksums.end(), key.first) == cur_node_checksums.end()) {
			missing_server_checksums_keys.push_back(key.first);
		}
	}

	vector<pair<map<string, prometheus::Counter*>&, p_cluster_nodes_dyn_counter::metric>> counter_maps {
		{ metrics.p_proxysql_servers_metrics_uptime_s, dyn_counter::proxysql_servers_metrics_uptime_s },
		{ metrics.p_proxysql_servers_metrics_queries, dyn_counter::proxysql_servers_metrics_queries },
		{ metrics.p_proxysql_servers_metrics_client_conns_created, dyn_counter::proxysql_servers_metrics_client_conns_created },

		{ metrics.p_proxysql_servers_checksum_version, dyn_counter::proxysql_servers_checksums_version_total },
	};
	vector<pair<map<string, prometheus::Gauge*>&, p_cluster_nodes_dyn_gauge::metric>> gauge_maps {
		{ metrics.p_proxysql_servers_metrics_weight, dyn_gauge::proxysql_servers_metrics_weight },
		{ metrics.p_proxysql_servers_metrics_response_time_ms, dyn_gauge::proxysql_servers_metrics_response_time_ms },
		{ metrics.p_proxysql_servers_metrics_last_check_ms, dyn_gauge::proxysql_servers_metrics_last_check_ms },
		{ metrics.p_proxysql_servers_metrics_client_conns_connected, dyn_gauge::proxysql_servers_metrics_client_conns_connected },

		{ metrics.p_proxysql_servers_checksums_epoch, dyn_gauge::proxysql_servers_checksums_epoch },
		{ metrics.p_proxysql_servers_checksums_updated_at, dyn_gauge::proxysql_servers_checksums_updated_at },
		{ metrics.p_proxysql_servers_checksums_changed_at, dyn_gauge::proxysql_servers_checksums_changed_at },
		{ metrics.p_proxysql_servers_checksums_diff_check, dyn_gauge::proxysql_servers_checksums_diff_check },
	};

	const auto delete_metric_counter =
		[this](const string& key, map<string, prometheus::Counter*>& m_map, dyn_counter::metric m_val) {
			auto counter = m_map.find(key);
			if (counter != m_map.end()) {
				metrics.p_dyn_counter_array[m_val]->Remove(counter->second);
				m_map.erase(counter);
			}
		};
	const auto delete_metric_gauge =
		[this](const string& key, map<string, prometheus::Gauge*>& m_map, dyn_gauge::metric m_val) {
			auto counter = m_map.find(key);
			if (counter != m_map.end()) {
				metrics.p_dyn_gauge_array[m_val]->Remove(counter->second);
				m_map.erase(counter);
			}
		};

	for (const auto& key : missing_server_metrics_keys) {
		for (const auto& counter_map : counter_maps) {
			delete_metric_counter(key, counter_map.first, counter_map.second);
		}
		for (const auto& gauge_map : gauge_maps) {
			delete_metric_gauge(key, gauge_map.first, gauge_map.second);
		}
	}

	for (const auto& key : missing_server_checksums_keys) {
		for (const auto& counter_map : counter_maps) {
			delete_metric_counter(key, counter_map.first, counter_map.second);
		}
		for (const auto& gauge_map : gauge_maps) {
			delete_metric_gauge(key, gauge_map.first, gauge_map.second);
		}
	}

	pthread_mutex_unlock(&mutex);
}

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

/**
 * @brief Metrics map holding the metrics for the 'ProxySQL_Cluster' module.
 *
 * @note Many metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<cluster_counter_vector, cluster_gauge_vector>
cluster_metrics_map = std::make_tuple(
	cluster_counter_vector {
		// mysql_query_rules

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_query_rules_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_query_rules" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_query_rules_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_query_rules" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// mysql_servers_*

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_replication_hostgroups_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_replication_hostgroups" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_replication_hostgroups_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_replication_hostgroups" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_group_replication_hostgroups" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_group_replication_hostgroups_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_group_replication_hostgroups" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_galera_hostgroups_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_galera_hostgroups" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_galera_hostgroups_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_galera_hostgroups" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_aws_aurora_hostgroups" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_aws_aurora_hostgroups_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_aws_aurora_hostgroups" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_hostgroup_attributes_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_hostgroup_attributes" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_hostgroup_attributes_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_hostgroup_attributes" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_ssl_params_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_ssl_params" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_ssl_params_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_ssl_params" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_runtime_checks_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_runtime_checks" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_servers_runtime_checks_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_servers_runtime_checks" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// mysql_users_*

		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_mysql_users_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_users" },
				{ "status", "success" }
			}

		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_users_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_users" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// proxysql_servers_*
		// ====================================================================
		std::make_tuple (
			p_cluster_counter::pulled_proxysql_servers_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "proxysql_servers" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_proxysql_servers_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "proxysql_servers" },
				{ "status", "failure" }
			}
		),
		// ====================================================================

		// mysql_variables_*
		std::make_tuple (
			p_cluster_counter::pulled_mysql_variables_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_variables" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_variables_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_variables" },
				{ "status", "failure" }
			}
		),

		// admin_variables_*
		std::make_tuple (
			p_cluster_counter::pulled_admin_variables_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "admin_variables" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_admin_variables_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "admin_variables" },
				{ "status", "failure" }
			}
		),

		// ldap_variables_*
		std::make_tuple (
			p_cluster_counter::pulled_ldap_variables_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "ldap_variables" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_ldap_variables_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "ldap_variables" },
				{ "status", "failure" }
			}
		),

		// mysql_ldap_mappings_*
		std::make_tuple (
			p_cluster_counter::pulled_mysql_ldap_mapping_success,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_ldap_mapping" },
				{ "status", "success" }
			}
		),
		std::make_tuple (
			p_cluster_counter::pulled_mysql_ldap_mapping_failure,
			"proxysql_cluster_pulled_total",
			"Number of times a 'module' have been pulled from a peer.",
			metric_tags {
				{ "module_name", "mysql_ldap_mapping" },
				{ "status", "failure" }
			}
		),

		// sync_conflict same epoch
		// ====================================================================
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_query_rules_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_query_rules" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_servers_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_servers" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_proxysql_servers_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "proxysql_servers" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_users_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_users" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_mysql_variables_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_variables" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_admin_variables_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "admin_variables" },
				{ "reason", "servers_share_epoch" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_conflict_ldap_variables_share_epoch,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "ldap_variables" },
				{ "reason", "servers_share_epoch" }
			}
		),
		// ====================================================================

		// sync_delayed due to version one
		// ====================================================================
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_query_rules_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_query_rules" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_servers_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_servers" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_users_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_users" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_proxysql_servers_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "proxysql_servers" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_mysql_variables_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "mysql_variables" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_admin_variables_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "admin_variables" },
				{ "reason", "version_one" }
			}
		),
		std::make_tuple (
			p_cluster_counter::sync_delayed_ldap_variables_version_one,
			"proxysql_cluster_syn_conflict_total",
			"Number of times a 'module' has not been able to be synced.",
			metric_tags {
				{ "module_name", "ldap_variables" },
				{ "reason", "version_one" }
			}
		),
		// ====================================================================
	},
	cluster_gauge_vector {}
);

ProxySQL_Cluster::ProxySQL_Cluster() : proxysql_servers_to_monitor(NULL) {
	pthread_mutex_init(&mutex,NULL);
	pthread_mutex_init(&update_mysql_query_rules_mutex,NULL);
	pthread_mutex_init(&update_runtime_mysql_servers_mutex,NULL);
	pthread_mutex_init(&update_mysql_servers_v2_mutex, NULL);
	pthread_mutex_init(&update_mysql_users_mutex,NULL);
	pthread_mutex_init(&update_proxysql_servers_mutex,NULL);
	pthread_mutex_init(&update_mysql_variables_mutex,NULL);
	pthread_mutex_init(&admin_mysql_ifaces_mutex,NULL);
	admin_mysql_ifaces = strdup((char *)""); // always initialized
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
	cluster_mysql_servers_sync_algorithm = 1;
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
	if (admin_mysql_ifaces) {
		free(admin_mysql_ifaces);
		admin_mysql_ifaces = NULL;
	}
}

void ProxySQL_Cluster::p_update_metrics() {
	this->nodes.update_prometheus_nodes_metrics();
};

// this function returns credentials to the caller, used by monitoring threads
cluster_creds_t ProxySQL_Cluster::get_credentials() {
	pthread_mutex_lock(&mutex);
	const string user { cluster_username };
	const string pass { cluster_password };
	pthread_mutex_unlock(&mutex);

	return { user, pass };
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

void ProxySQL_Cluster::set_admin_mysql_ifaces(char *value) {
	pthread_mutex_lock(&admin_mysql_ifaces_mutex);
	free(admin_mysql_ifaces);
	admin_mysql_ifaces=strdup(value);
	pthread_mutex_unlock(&admin_mysql_ifaces_mutex);
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

ProxySQL_Node_Address::ProxySQL_Node_Address(char* h, uint16_t p) : ProxySQL_Node_Address(h, p, NULL) {
	// resolving DNS if available in Cache
	resolve_hostname();
}
ProxySQL_Node_Address::ProxySQL_Node_Address(char* h, uint16_t p, char* ip) {
	hostname = strdup(h);
	ip_addr = NULL;
	if (ip) {
		ip_addr = strdup(ip);
	}
	admin_mysql_ifaces = NULL;
	port = p;
	uuid = NULL;
	hash = 0;
}
ProxySQL_Node_Address::~ProxySQL_Node_Address() {
	if (hostname) free(hostname);
	if (uuid) free(uuid);
	if (admin_mysql_ifaces) free(admin_mysql_ifaces);
	if (ip_addr) free(ip_addr);
}
const char* ProxySQL_Node_Address::get_host_address() const {
	const char* host_address = hostname;

	if (ip_addr)
		host_address = ip_addr;

	return host_address;
}
void ProxySQL_Node_Address::resolve_hostname() {
	if (ip_addr) {
		free(ip_addr);
		ip_addr = NULL;
	}
	if (hostname && port) {
		size_t ip_count = 0;
		const std::string& ip = MySQL_Monitor::dns_lookup(hostname, false, &ip_count);

		if (ip_count > 1) {
			proxy_error("Proxy cluster node '%s' has more than one ('%ld') mapped IP address. It is recommended to provide IP address or domain with one resolvable IP address.\n",
				hostname, ip_count);
		}

		if (ip.empty() == false) {
			ip_addr = strdup(ip.c_str());
		}
	}
}
