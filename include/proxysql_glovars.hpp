#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H

#include "configfile.hpp"
#include "proxy_defines.h"

namespace ez {
class ezOptionParser;
};

class ProxySQL_Checksum_Value {
	public:
	char *checksum;
	unsigned long long version;
	unsigned long long epoch;
	ProxySQL_Checksum_Value() {
		checksum = (char *)malloc(20);
		memset(checksum,0,20);
		version = 0;
		epoch = 0;
	}
	void set_checksum(char *c) {
		memset(checksum,0,20);
		strncpy(checksum,c,18);
		for (int i=2; i<18; i++) {
			if (checksum[i]==' ' || checksum[i]==0) {
				checksum[i]='0';
			}
		}

	}
	~ProxySQL_Checksum_Value() {
		free(checksum);
		checksum = NULL;
	}
};

class ProxySQL_GlobalVariables {
	public:
	ez::ezOptionParser *opt;
	ProxySQL_ConfigFile *confFile;
	bool configfile_open;
	char *__cmd_proxysql_config_file;
	char *__cmd_proxysql_datadir;
	int __cmd_proxysql_nostart;
	int __cmd_proxysql_foreground;
	int __cmd_proxysql_gdbg;
	bool __cmd_proxysql_initial;
	bool __cmd_proxysql_reload;
	char *__cmd_proxysql_admin_socket;
	char *config_file;
	char *datadir;
	char *admindb;
	char *errorlog;
	char *pid;
	struct  {
		unsigned long long start_time;
		bool gdbg;
		bool nostart;
		bool monitor;
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
		SSL_CTX *ssl_ctx;	
		bool sqlite3_server;
#ifdef PROXYSQLCLICKHOUSE
		bool clickhouse_server;
#endif /* PROXYSQLCLICKHOUSE */
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
		ProxySQL_Checksum_Value proxysql_servers;
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
