#ifndef CLASS_PROXYSQL_CLUSTER_H
#define CLASS_PROXYSQL_CLUSTER_H
#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"
#include <vector>

#define PROXYSQL_NODE_METRICS_LEN	5


class ProxySQL_Node_Metrics {
	public:
	unsigned long long read_time_us;
	unsigned long long response_time_us;
	unsigned long long ProxySQL_Uptime;
	unsigned long long Questions;
	unsigned long long Client_Connections_created;
	unsigned long long Client_Connections_connected;
	unsigned long long Servers_table_version;
	void reset();
	ProxySQL_Node_Metrics() {
		reset();
	}
	~ProxySQL_Node_Metrics() {
		reset();
	}
};

class ProxySQL_Node_Entry {
	private:
	uint64_t hash;
	char *hostname;
	uint16_t port;
	uint64_t weight;
	char *comment;
	uint64_t generate_hash();
	bool active;
	int metrics_idx_prev;
	int metrics_idx;
	ProxySQL_Node_Metrics **metrics;
	public:
	uint64_t get_hash();
	ProxySQL_Node_Entry(char *_hostname, uint16_t _port, uint64_t _weight, char *_comment);
	~ProxySQL_Node_Entry();
	bool get_active();
	void set_active(bool a);
	uint64_t get_weight();
	void set_weight(uint64_t a);
	char * get_comment() { // note, NO strdup()
		return comment;
	}
	void set_comment(char *a); // note, this is strdup()
	void set_metrics(MYSQL_RES *_r, unsigned long long _response_time);
	char *get_hostname() { // note, NO strdup()
		return hostname;
	}
	uint16_t get_port() {
		return port;
	}
	ProxySQL_Node_Metrics * get_metrics_curr();
	ProxySQL_Node_Metrics * get_metrics_prev();
};

class ProxySQL_Cluster_Nodes {
	private:
	pthread_mutex_t mutex;
	std::unordered_map<uint64_t, ProxySQL_Node_Entry *> umap_proxy_nodes;
	void set_all_inactive();
	void remove_inactives();
	uint64_t generate_hash(char *_hostname, uint16_t _port);
	public:
	ProxySQL_Cluster_Nodes();
	~ProxySQL_Cluster_Nodes();
	void load_servers_list(SQLite3_result *);
	bool Update_Node_Metrics(char * _h, uint16_t _p, MYSQL_RES *_r, unsigned long long _response_time);
	SQLite3_result * dump_table_proxysql_servers();
	SQLite3_result * stats_proxysql_servers_metrics();
};


class ProxySQL_Cluster {
	private:
	pthread_mutex_t mutex;
	std::vector<pthread_t> term_threads;
	ProxySQL_Cluster_Nodes nodes;
	char *cluster_username;
	char *cluster_password;
	public:
	int cluster_check_interval_ms;
	ProxySQL_Cluster();
	~ProxySQL_Cluster();
	void init() {};
	void print_version();
	void load_servers_list(SQLite3_result *r) {
		nodes.load_servers_list(r);
	}
	void get_credentials(char **, char **);
	void set_username(char *);
	void set_password(char *);
	bool Update_Node_Metrics(char * _h, uint16_t _p, MYSQL_RES *_r, unsigned long long _response_time) {
		return nodes.Update_Node_Metrics(_h, _p, _r, _response_time);
	}
	SQLite3_result *dump_table_proxysql_servers() {
		return nodes.dump_table_proxysql_servers();
	}
	SQLite3_result * get_stats_proxysql_servers_metrics() {
		return nodes.stats_proxysql_servers_metrics();
	}
	void thread_ending(pthread_t);
	void join_term_thread();
};
#endif /* CLASS_PROXYSQL_CLUSTER_H */
