#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H
//#include "proxysql.h"
//#include "cpp.h"

//#include "ezOptionParser.hpp"
#include "configfile.hpp"

namespace ez {
class ezOptionParser;
};

class ProxySQL_GlobalVariables {
	public:
	ez::ezOptionParser *opt;
	//ezOptionParser *opt;
	ProxySQL_ConfigFile *confFile;
	bool configfile_open;
	char *__cmd_proxysql_config_file;
	char *__cmd_proxysql_datadir;
	//char *__cmd_proxysql_admin_pathdb;
//	bool __cmd_proxysql_print_version=false;
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
		bool use_proxysql_mem;
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
	//MySQL_HostGroups *MyHostGroups;
	//std::vector<MySQL_Hostgroup *> MyHostGroups;
	ProxySQL_GlobalVariables();
	~ProxySQL_GlobalVariables();
	void process_opts_pre();
	void process_opts_post();
	void parse(int argc, const char * argv[]);
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
