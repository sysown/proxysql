#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H

#include "configfile.hpp"
#include "proxy_defines.h"

namespace ez {
class ezOptionParser;
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
               bool linger;
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
	} global;
	struct mysql {
		char *server_version;
		int poll_timeout;
	};
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
