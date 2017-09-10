#include "ezOptionParser.hpp"
#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <sys/utsname.h>
#include "SpookyV2.h"

static void term_handler(int sig) {
  proxy_warning("Received TERM signal: shutdown in progress...\n");
#ifdef DEBUG
#endif
  __sync_bool_compare_and_swap(&glovars.shutdown,0,1);
}

void crash_handler(int sig) {
#ifdef DEBUG
//	malloc_stats_print(NULL, NULL, "");
#endif
#ifdef __GLIBC__
	void *arr[20];
	size_t s;

	s = backtrace(arr, 20);

	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(arr, s, STDERR_FILENO);
#endif /* __GLIBC__ */
	// try to generate a core dump signaling again the thread
	signal(sig, SIG_DFL);
	pthread_kill(pthread_self(), sig);
}

ProxySQL_GlobalVariables::~ProxySQL_GlobalVariables() {
	opt->reset();
	delete opt;
	delete confFile;
};

ProxySQL_GlobalVariables::ProxySQL_GlobalVariables() {
	confFile=NULL;
	__cmd_proxysql_config_file=NULL;
	__cmd_proxysql_datadir=NULL;

	config_file=NULL;
	datadir=NULL;
	configfile_open=false;

	__cmd_proxysql_initial=false;
	__cmd_proxysql_reload=false;

	statuses.stack_memory_mysql_threads = 0;
	statuses.stack_memory_admin_threads = 0;
	statuses.stack_memory_cluster_threads = 0;


	global.gdbg=false;
	global.nostart=false;
	global.foreground=false;
	global.monitor=true;
#ifdef IDLE_THREADS
	global.idle_threads=false;
#endif /* IDLE_THREADS */
#ifdef SO_REUSEPORT
	global.reuseport=false;
#endif /* SO_REUSEPORT */
//	global.use_proxysql_mem=false;
	pthread_mutex_init(&global.start_mutex,NULL);
	pthread_mutex_init(&checksum_mutex,NULL);
	epoch_version = 0;
	checksums_values.updates_cnt = 0;
	checksums_values.dumped_at = 0;
	checksums_values.global_checksum = 0;
#ifdef DEBUG
	global.gdb=0;
#endif

	global.sqlite3_server=false;
#ifdef PROXYSQLCLICKHOUSE
	global.clickhouse_server=false;
#endif /* PROXYSQLCLICKHOUSE */
	opt=new ez::ezOptionParser();
	opt->overview="High Performance Advanced Proxy for MySQL";
	opt->syntax="proxysql [OPTIONS]";
	std::string s = "\n\nProxySQL " ;
	s = s + "rev. " + PROXYSQL_VERSION + " -- " + __TIMESTAMP__ + "\nCopyright (C) 2013-2017 René Cannaò\nThis program is free and without warranty\n";
	opt->footer =s.c_str();

	opt->add((const char *)"",0,0,0,(const char *)"Display usage instructions.",(const char *)"-h",(const char *)"-help",(const char *)"--help",(const char *)"--usage");
	opt->add((const char *)"",0,0,0,(const char *)"Print version",(const char *)"-V",(const char *)"--version");
#ifdef DEBUG
	opt->add((const char *)"",0,1,0,(const char *)"Enable debugging messages with specific verbosity",(const char *)"-d",(const char *)"--debug");
#endif /* DEBUG */
	opt->add((const char *)"",0,0,0,(const char *)"Starts only the admin service",(const char *)"-n",(const char *)"--no-start");
	opt->add((const char *)"",0,0,0,(const char *)"Do not start Monitor Module",(const char *)"-M",(const char *)"--no-monitor");
	opt->add((const char *)"",0,0,0,(const char *)"Run in foreground",(const char *)"-f",(const char *)"--foreground");
#ifdef SO_REUSEPORT
	opt->add((const char *)"",0,0,0,(const char *)"Use SO_REUSEPORT",(const char *)"-r",(const char *)"--reuseport");
#endif /* SO_REUSEPORT */
	opt->add((const char *)"",0,0,0,(const char *)"Do not restart ProxySQL if crashes",(const char *)"-e",(const char *)"--exit-on-error");
	opt->add((const char *)"~/proxysql.cnf",0,1,0,(const char *)"Configuraton file",(const char *)"-c",(const char *)"--config");
	opt->add((const char *)"",0,1,0,(const char *)"Datadir",(const char *)"-D",(const char *)"--datadir");
	opt->add((const char *)"",0,0,0,(const char *)"Rename/empty database file",(const char *)"--initial");
	opt->add((const char *)"",0,0,0,(const char *)"Merge config file into database file",(const char *)"--reload");
#ifdef IDLE_THREADS
	opt->add((const char *)"",0,0,0,(const char *)"Create auxiliary threads to handle idle connections",(const char *)"--idle-threads");
#endif /* IDLE_THREADS */
	opt->add((const char *)"",0,1,0,(const char *)"Administration Unix Socket",(const char *)"-S",(const char *)"--admin-socket");

	opt->add((const char *)"",0,0,0,(const char *)"Enable SQLite3 Server",(const char *)"--sqlite3-server");
#ifdef PROXYSQLCLICKHOUSE
	opt->add((const char *)"",0,0,0,(const char *)"Enable ClickHouse Server",(const char *)"--clickhouse-server");
#endif /* PROXYSQLCLICKHOUSE */

	confFile=new ProxySQL_ConfigFile();
};

void ProxySQL_GlobalVariables::install_signal_handler() {
	signal(SIGTERM, term_handler);
	signal(SIGSEGV, crash_handler);
	signal(SIGABRT, crash_handler);
	signal(SIGPIPE, SIG_IGN);
}

void ProxySQL_GlobalVariables::parse(int argc, const char * argv[]) {
	opt->parse(argc, argv);
};

void ProxySQL_GlobalVariables::process_opts_pre() {
	if (opt->isSet("-h")) {
		std::string usage;
		opt->getUsage(usage);
		std::cout << usage;
		exit(EXIT_SUCCESS);
	}

	if (opt->isSet("-V")) {
		fprintf(stderr,"ProxySQL version %s, codename %s\n", PROXYSQL_VERSION, PROXYSQL_CODENAME);
		exit(EXIT_SUCCESS);
	}

	if (opt->isSet("-d")) {
		opt->get("-d")->getInt(GloVars.__cmd_proxysql_gdbg);	
		global.gdbg=true;
	}

	if (opt->isSet("-e")) {
		glovars.proxy_restart_on_error=false;
	} else {
		glovars.proxy_restart_on_error=true;
		glovars.proxy_restart_delay=1;
	}

	if (opt->isSet("-c")) {
		std::string configfile;
		opt->get("-c")->getString(configfile);
		GloVars.__cmd_proxysql_config_file=strdup(configfile.c_str());
	}

	if (opt->isSet("-D")) {
		std::string datadir;
		opt->get("-D")->getString(datadir);
		if (GloVars.__cmd_proxysql_datadir) free(GloVars.__cmd_proxysql_datadir);
		GloVars.__cmd_proxysql_datadir=strdup(datadir.c_str());
	}

	if (opt->isSet("--initial")) {
		__cmd_proxysql_initial=true;
	}

	if (opt->isSet("--reload")) {
		__cmd_proxysql_reload=true;
	}

#ifdef IDLE_THREADS
	if (opt->isSet("--idle-threads")) {
		global.idle_threads=true;
	}
#endif /* IDLE_THREADS */

	if (opt->isSet("--sqlite3-server")) {
		global.sqlite3_server=true;
	}
#ifdef PROXYSQLCLICKHOUSE
	if (opt->isSet("--clickhouse-server")) {
		global.clickhouse_server=true;
	}
#endif /* PROXYSQLCLICKHOUSE */


	config_file=GloVars.__cmd_proxysql_config_file;

	if (config_file==NULL) {
		config_file=(char *)"proxysql.cnf";
		if (Proxy_file_regular(config_file)==false) {
			config_file=(char *)"proxysql.cfg";
			if (Proxy_file_regular(config_file)==false) {
				config_file=(char *)"/etc/proxysql.cnf";
				if (Proxy_file_regular(config_file)==false) {
					config_file=(char *)"/etc/proxysql.cfg";
				}
			}
		}
	}
#ifdef DEBUG
	init_debug_struct();
#endif

};

void ProxySQL_GlobalVariables::process_opts_post() {

	if (opt->isSet("-n")) {
		//global.nostart=true;
		GloVars.global.nostart=true;
		GloVars.__cmd_proxysql_nostart=1;
	}

	if (opt->isSet("-f")) {
		global.foreground=true;
#ifdef __APPLE__
	} else {
		proxy_warning("ProxySQL does not support daemonize in Darwin: running in foreground\n");
		global.foreground=true;
#endif
	}

	if (opt->isSet("-M")) {
		global.monitor=false;
	}

#ifdef SO_REUSEPORT
	{
		struct utsname unameData;
		int rc;
		rc=uname(&unameData);
		if (rc==0) {
			if (strcmp(unameData.sysname,"Linux")==0) {
				int major=0, minor=0, revision=0;
				sscanf(unameData.release, "%d.%d.%d", &major, &minor, &revision);
				//fprintf(stderr,"%d %d %d\n",major,minor,revision);
				if (
					(major > 3)
					||
					(major == 3 && minor >= 9)
				) {
					global.reuseport=true;
				}
			}
		}
	}
#endif /* SO_REUSEPORT */
#ifdef SO_REUSEPORT
	if (opt->isSet("-r")) {
		global.reuseport=true;
	}
#endif /* SO_REUSEPORT */

	if (opt->isSet("-S")) {
		std::string admin_socket;
		opt->get("-S")->getString(admin_socket);
		if (GloVars.__cmd_proxysql_admin_socket) free(GloVars.__cmd_proxysql_admin_socket);
		GloVars.__cmd_proxysql_admin_socket=strdup(admin_socket.c_str());
	}

	proxy_debug(PROXY_DEBUG_GENERIC, 4, "processing opts\n");

  // apply settings from cmdline, that have priority over config file
#ifdef DEBUG
	init_debug_struct_from_cmdline();
#endif

	if (GloVars.__cmd_proxysql_nostart>=0) { glovars.nostart=GloVars.__cmd_proxysql_nostart; }
	if (GloVars.__cmd_proxysql_datadir) {
		free(glovars.proxy_datadir);
		glovars.proxy_datadir=strdup(GloVars.__cmd_proxysql_datadir);
	}
	if (GloVars.__cmd_proxysql_admin_socket) {
		free(glovars.proxy_admin_socket);
		glovars.proxy_admin_socket=strdup(GloVars.__cmd_proxysql_admin_socket);
	}

#ifdef DEBUG
	if (GloVars.global.gdbg) {
		fprintf(stderr,"ProxySQL version %s, codename %s\n", PROXYSQL_VERSION, PROXYSQL_CODENAME);
		fprintf(stderr,"Options:\n  gdbg:         %d\n  foreground:   %d\n  no-start:     %d\n  config:       %s\n  datadir:      %s\n  admin_pathdb: %s\n  admin_socket: %s\n", GloVars.global.gdbg, GloVars.global.foreground, glovars.nostart, glovars.proxy_configfile, glovars.proxy_datadir, glovars.proxy_admin_pathdb, glovars.proxy_admin_socket);
  }
#endif
};


uint64_t ProxySQL_GlobalVariables::generate_global_checksum() {
	SpookyHash myhash;
	myhash.Init(9,5);
	ProxySQL_Checksum_Value *v = NULL;
	v = &checksums_values.admin_variables;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	v = &checksums_values.mysql_query_rules;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	v = &checksums_values.mysql_servers;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	v = &checksums_values.mysql_users;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	v = &checksums_values.mysql_variables;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	v = &checksums_values.proxysql_servers;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	uint64_t h1, h2;
	myhash.Final(&h1, &h2);
	h1 = h1/2; // ugly way to make it signed within LLONG_MAX
	checksums_values.global_checksum = h1;
	return h1;
}
