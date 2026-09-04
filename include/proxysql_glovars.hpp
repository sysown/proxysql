#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H

#define CLUSTER_SYNC_INTERFACES_ADMIN "('admin-mysql_ifaces','admin-restapi_port','admin-telnet_admin_ifaces','admin-telnet_stats_ifaces','admin-web_port','admin-pgsql_ifaces')"
#define CLUSTER_SYNC_INTERFACES_MYSQL "('mysql-interfaces')"
#define CLUSTER_SYNC_INTERFACES_PGSQL "('pgsql-interfaces')"

#include <memory>
#include <vector>
#include <string.h>
#include "prometheus/registry.h"

#include "configfile.hpp"
#include "proxy_defines.h"
#include "proxysql_utils.h"
#include <openssl/ssl.h>

#ifdef DEBUG
// `debug_level` is fully defined in proxysql_structs.h which itself
// #include's this header at the bottom (circular chain -- structs.h
// defines debug_level, then includes glovars.hpp to declare GloVars,
// then glovars.hpp needs debug_level as a member pointer type).  Any
// caller that #include's proxysql_structs.h gets the full definition
// transitively; callers that #include glovars.hpp directly (e.g. the
// plugin unit tests, which only need the GloVars layout) need this
// forward decl so a pointer-typed member compiles.
struct _debug_level;
typedef struct _debug_level debug_level;
#endif /* DEBUG */

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
	void set_checksum(const char *c) {
		memset(checksum,0,ProxySQL_Checksum_Value_LENGTH);
		if (c) {
			const size_t length = strnlen(c, ProxySQL_Checksum_Value_LENGTH);
			memcpy(checksum, c, length);
		}
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
	bool set_thread_name = true;
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
	char * execute_on_exit_failure;
	char * sqlite3_plugin;
	char * web_interface_plugin;
	char * ldap_auth_plugin;
#ifdef PROXYSQL40
	// Loadable plugin modules (chassis only -- v3.x has no plugin loader).
	std::vector<std::string> plugin_modules;
	// Operator kill switch. When set (via --no-plugins CLI flag or
	// PROXYSQL_NO_PLUGINS=1 env var), the plugin chassis is bypassed
	// entirely: LoadConfiguredPlugins / InitConfiguredPlugins /
	// StartConfiguredPlugins become no-ops, and the chassis-aware
	// admin command dispatcher refuses plugin commands. Lets an
	// operator disable a misbehaving plugin without editing the config
	// file or downgrading. CLI takes priority over env, env over config.
	bool no_plugins;
#endif /* PROXYSQL40 */
	SSL_CTX *get_SSL_ctx();
	SSL *get_SSL_new();
	SSL *get_admin_SSL_new();
	bool is_admin_SSL_enabled();
	void set_admin_SSL_ctx(SSL_CTX *ctx, bool enabled);
	void get_SSL_pem_mem(char **key, char **cert);
	std::shared_ptr<prometheus::Registry> prometheus_registry { nullptr };
	struct  {
		unsigned long long start_time;
		bool gdbg;
		bool nostart;
		bool my_monitor;
		bool pg_monitor;
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
		std::mutex admin_ssl_mutex;
		SSL_CTX *admin_ssl_ctx;
		bool admin_ssl_enabled;
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
		pthread_mutex_t ext_glopth_mutex;
		bool ssl_keylog_enabled;
		uint64_t tls_load_count;
		time_t tls_last_load_timestamp;
		bool tls_last_load_ok;
		char *tls_cert_file;
		char *tls_ca_file;
		char *tls_key_file;
	} global;
	struct mysql {
		char *server_version;
		int poll_timeout;
	};
	struct {
		unsigned long stack_memory_mysql_threads;
		unsigned long stack_memory_pgsql_threads;
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
		ProxySQL_Checksum_Value pgsql_query_rules;
		ProxySQL_Checksum_Value pgsql_servers;
		ProxySQL_Checksum_Value pgsql_users;
		ProxySQL_Checksum_Value pgsql_variables;
		ProxySQL_Checksum_Value pgsql_servers_v2;
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

#ifdef PROXYSQL40
void proxysql_load_plugin_modules_from_config(
	const Setting& root,
	std::vector<std::string>& plugin_modules
);
#endif /* PROXYSQL40 */

/*
#ifndef PROXYSQL_EXTERN
#define EXTERN extern
#else
#define EXTERN
#endif // PROXYSQL_EXTERN
EXTERN ProxySQL_GlobalVariables GloVars;
*/
#endif /* __CLASS_PROXYSQL_GLOVARS_H */
