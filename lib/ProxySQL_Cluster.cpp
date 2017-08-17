#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_CLUSTER_VERSION "0.1.0702" DEB

static char *NODE_COMPUTE_DELIMITER=(char *)"-gtyw23a-"; // a random string used for hashing

extern ProxySQL_Cluster * GloProxyCluster;

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

	//char *query1 = (char *)"SELECT 1"; // in future this will be used for "light check"
	char *query2 = (char *)"SELECT * FROM stats_mysql_global ORDER BY Variable_Name";
	char *query3 = (char *)"SELECT * FROM runtime_checksums_values ORDER BY name";
	char *username = NULL;
	char *password = NULL;
	bool rc_bool = true;
	MYSQL *conn = mysql_init(NULL);
//		goto __exit_monitor_thread;
	if (conn==NULL) {
		proxy_error("Unable to run mysql_init()\n");
		goto __exit_monitor_thread;
	}
	while (glovars.shutdown == 0 && rc_bool == true) {
		MYSQL * rc_conn = NULL;
		int rc_query = 0;
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
			rc_conn = mysql_real_connect(conn, node->hostname, username, password, NULL, node->port, NULL, 0); 
			char *query = query2;
			if (rc_conn) {
				while ( glovars.shutdown == 0 && rc_query == 0 && rc_bool == true) {
					unsigned long long before_query_time=monotonic_time();
					rc_query = mysql_query(conn,query);
					if ( rc_query == 0 ) {
						MYSQL_RES *result = mysql_store_result(conn);
						unsigned long long after_query_time=monotonic_time();
						unsigned long long elapsed_time_us = (after_query_time - before_query_time);
						rc_bool = GloProxyCluster->Update_Node_Metrics(node->hostname, node->port, result, elapsed_time_us); 
						mysql_free_result(result);
						unsigned long long elapsed_time_ms = elapsed_time_us / 1000;
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
						query = query3;
						unsigned long long before_query_time2=monotonic_time();
						rc_query = mysql_query(conn,query);
						if ( rc_query == 0 ) {
							MYSQL_RES *result = mysql_store_result(conn);
							unsigned long long after_query_time2=monotonic_time();
							unsigned long long elapsed_time_us2 = (after_query_time2 - before_query_time2);
							rc_bool = GloProxyCluster->Update_Node_Checksums(node->hostname, node->port, result);
							mysql_free_result(result);
							unsigned long long elapsed_time_ms2 = elapsed_time_us2 / 1000;
							int e_ms = (int)elapsed_time_ms + int(elapsed_time_ms2);
							//fprintf(stderr,"Elapsed time = %d ms\n", e_ms);
							int ci = __sync_fetch_and_add(&GloProxyCluster->cluster_check_interval_ms,0);
							if (ci > e_ms) {
								if (rc_bool) {
									usleep((ci-e_ms)*1000); // remember, usleep is in us
								}
							}
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
}

ProxySQL_Node_Entry::~ProxySQL_Node_Entry() {
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
	while ((row = mysql_fetch_row(_r))) {
		if (strcmp(row[0],"admin_variables")==0) {
			checksums_values.admin_variables.version = atoll(row[1]);
			checksums_values.admin_variables.epoch = atoll(row[2]);
			strcpy(checksums_values.admin_variables.checksum, row[3]);
			continue;
		}
		if (strcmp(row[0],"mysql_query_rules")==0) {
			checksums_values.mysql_query_rules.version = atoll(row[1]);
			checksums_values.mysql_query_rules.epoch = atoll(row[2]);
			strcpy(checksums_values.mysql_query_rules.checksum, row[3]);
			continue;
		}
		if (strcmp(row[0],"mysql_servers")==0) {
			checksums_values.mysql_servers.version = atoll(row[1]);
			checksums_values.mysql_servers.epoch = atoll(row[2]);
			strcpy(checksums_values.mysql_servers.checksum, row[3]);
			continue;
		}
		if (strcmp(row[0],"mysql_users")==0) {
			checksums_values.mysql_users.version = atoll(row[1]);
			checksums_values.mysql_users.epoch = atoll(row[2]);
			strcpy(checksums_values.mysql_users.checksum, row[3]);
			continue;
		}
		if (strcmp(row[0],"mysql_variables")==0) {
			checksums_values.mysql_variables.version = atoll(row[1]);
			checksums_values.mysql_variables.epoch = atoll(row[2]);
			strcpy(checksums_values.mysql_variables.checksum, row[3]);
			continue;
		}
		if (strcmp(row[0],"proxysql_servers")==0) {
			checksums_values.proxysql_servers.version = atoll(row[1]);
			checksums_values.proxysql_servers.epoch = atoll(row[2]);
			strcpy(checksums_values.proxysql_servers.checksum, row[3]);
			continue;
		}
	}
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

void ProxySQL_Cluster_Nodes::load_servers_list(SQLite3_result *resultset) {
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

SQLite3_result * ProxySQL_Cluster_Nodes::stats_proxysql_servers_checksums() {
	const int colnum=6;
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"name");
	result->add_column_definition(SQLITE_TEXT,"version");
	result->add_column_definition(SQLITE_TEXT,"epoch");
	result->add_column_definition(SQLITE_TEXT,"checksum");

	char buf[32];
	int k;
	pthread_mutex_lock(&mutex);
	unsigned long long curtime = monotonic_time();
	for( std::unordered_map<uint64_t, ProxySQL_Node_Entry *>::iterator it = umap_proxy_nodes.begin(); it != umap_proxy_nodes.end(); ) {
		ProxySQL_Node_Entry * node = it->second;
		ProxySQL_Checksum_Value * vals[6];
		vals[0] = &node->checksums_values.admin_variables;
		vals[1] = &node->checksums_values.mysql_query_rules;
		vals[2] = &node->checksums_values.mysql_servers;
		vals[3] = &node->checksums_values.mysql_users;
		vals[4] = &node->checksums_values.mysql_variables;
		vals[5] = &node->checksums_values.proxysql_servers;
		for (int i=0; i<6 ; i++) {
			ProxySQL_Checksum_Value *v = vals[i];
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
	cluster_username = strdup((char *)"");
	cluster_password = strdup((char *)"");
	cluster_check_interval_ms = 1000;
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
