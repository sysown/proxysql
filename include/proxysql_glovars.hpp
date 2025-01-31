#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H

#define CLUSTER_SYNC_INTERFACES_ADMIN "('admin-mysql_ifaces','admin-restapi_port','admin-telnet_admin_ifaces','admin-telnet_stats_ifaces','admin-web_port')"
#define CLUSTER_SYNC_INTERFACES_MYSQL "('mysql-interfaces')"

#include <memory>
#include <string.h>
#include "prometheus/registry.h"

#include "configfile.hpp"
#include "proxy_defines.h"
#include "proxysql_utils.h"

namespace ez {
class ezOptionParser;
};

#ifndef ProxySQL_Checksum_Value_LENGTH
#define ProxySQL_Checksum_Value_LENGTH 20
#endif
class ProxySQL_Checksum_Value {
	public:
	char *checksum;
	unsigned long long version;
	unsigned long long epoch;
	bool in_shutdown;
	ProxySQL_Checksum_Value() {
		checksum = (char *)malloc(ProxySQL_Checksum_Value_LENGTH);
		memset(checksum,0,ProxySQL_Checksum_Value_LENGTH);
		version = 0;
		epoch = 0;
		in_shutdown = false;
	}
	void set_checksum(char *c) {
		memset(checksum,0,ProxySQL_Checksum_Value_LENGTH);
		strncpy(checksum,c,ProxySQL_Checksum_Value_LENGTH);
		replace_checksum_zeros(checksum);
	}
	~ProxySQL_Checksum_Value() {
		if (in_shutdown == false) {
			/**
			 * @brief the in_shutdown flag is false by default, but set to true
			 * in the destructor of ProxySQL_GlobalVariables.
			 * See comments there for futher details.
			 */
			free(checksum);
			checksum = NULL;
		}
	}
};

class ProxySQL_GlobalVariables {
	public:
	ez::ezOptionParser *opt;
	ProxySQL_ConfigFile *confFile;
	bool configfile_open;
	char *__cmd_proxysql_config_file;
	char *__cmd_proxysql_datadir;
	char *__cmd_proxysql_uuid;
	int __cmd_proxysql_nostart;
	int __cmd_proxysql_foreground;
	int __cmd_proxysql_gdbg;
	bool __cmd_proxysql_initial;
	bool __cmd_proxysql_reload;
	bool cluster_sync_interfaces; // If true, also mysql-interfaces and admin-mysql_ifaces are synced. false by default
	char *__cmd_proxysql_admin_socket;
	char *config_file;
	char *datadir;
	char *uuid;
	char *admindb;
	char *statsdb_disk;
	char *sqlite3serverdb;
	char *errorlog;
	char *pid;
	int restart_on_missing_heartbeats;
    int console_logging_verbosity_level;
	char * execute_on_exit_failure;
	char * sqlite3_plugin;
	char * web_interface_plugin;
	char * ldap_auth_plugin;
	SSL_CTX *get_SSL_ctx();
	SSL *get_SSL_new();
	void get_SSL_pem_mem(char **key, char **cert);
	std::shared_ptr<prometheus::Registry> prometheus_registry { nullptr };
	struct  {
		unsigned long long start_time;
		bool gdbg;
		bool nostart;
		bool monitor;
		bool version_check;
#ifdef SO_REUSEPORT
		bool reuseport;
#endif /* SO_REUSEPORT */
#ifdef IDLE_THREADS
		bool idle_threads;
#endif /* IDLE_THREADS */
		pthread_mutex_t start_mutex;
		bool foreground;
#ifdef DEBUG
		int gdb;
		debug_level *gdbg_lvl;
#endif
		int backlog;
		int stack_size;
		char *pidfile;
		bool restart_on_error;
		int restart_delay;
		std::mutex ssl_mutex;
		SSL_CTX *ssl_ctx;	
		SSL_CTX *tmp_ssl_ctx;
		// these two buffers are used for the web interface
		char * ssl_key_pem_mem;
		char * ssl_cert_pem_mem;
		bool sqlite3_server;
		int data_packets_history_size;
#ifdef PROXYSQLCLICKHOUSE
		bool clickhouse_server;
#endif /* PROXYSQLCLICKHOUSE */
		int gr_bootstrap_mode;
		char* gr_bootstrap_uri;
		char* gr_bootstrap_account;
		char* gr_bootstrap_account_create;
		char* gr_bootstrap_account_host;
		uint64_t gr_bootstrap_password_retries;
		char* gr_bootstrap_conf_bind_address;
		uint64_t gr_bootstrap_conf_base_port;
		bool gr_bootstrap_conf_use_sockets;
		bool gr_bootstrap_conf_skip_tcp;
		char* gr_bootstrap_ssl_ca;
		char* gr_bootstrap_ssl_capath;
		char* gr_bootstrap_ssl_cert;
		char* gr_bootstrap_ssl_cipher;
		char* gr_bootstrap_ssl_crl;
		char* gr_bootstrap_ssl_crlpath;
		char* gr_bootstrap_ssl_key;
		char* gr_bootstrap_ssl_mode;
		pthread_mutex_t ext_glomth_mutex;

		bool ssl_keylog_enabled;
	} global;
	struct mysql {
		char *server_version;
		int poll_timeout;
	};
	struct {
		unsigned long stack_memory_mysql_threads;
		unsigned long stack_memory_admin_threads;
		unsigned long stack_memory_cluster_threads;
	} statuses;
	pthread_mutex_t checksum_mutex;
	time_t epoch_version;
	struct {
		ProxySQL_Checksum_Value admin_variables;
		ProxySQL_Checksum_Value mysql_query_rules;
		ProxySQL_Checksum_Value mysql_servers;
		ProxySQL_Checksum_Value mysql_users;
		ProxySQL_Checksum_Value mysql_variables;
		ProxySQL_Checksum_Value ldap_variables;
		ProxySQL_Checksum_Value proxysql_servers;
		ProxySQL_Checksum_Value mysql_servers_v2;
		uint64_t global_checksum;
		unsigned long long updates_cnt;
		unsigned long long dumped_at;
	} checksums_values;
	uint64_t generate_global_checksum();
	ProxySQL_GlobalVariables();
	~ProxySQL_GlobalVariables();
	void process_opts_pre();
	void process_opts_post();
	void parse(int argc, const char * argv[]);
	void install_signal_handler();
};

/*
#ifndef PROXYSQL_EXTERN
#define EXTERN extern
#else
#define EXTERN
#endif // PROXYSQL_EXTERN
EXTERN ProxySQL_GlobalVariables GloVars;
*/
#endif /* __CLASS_PROXYSQL_GLOVARS_H */
