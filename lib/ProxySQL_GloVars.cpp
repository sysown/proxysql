#include "ezOptionParser.hpp"
#include "proxysql.h"
#include "cpp.h"
#include <string>



static void term_handler(int sig) {
  proxy_error("Received TERM signal: shutdown in progress...\n");
#ifdef DEBUG
#endif
  __sync_bool_compare_and_swap(&glovars.shutdown,0,1);
//  sleep(5);
//  exit(0);
}


ProxySQL_GlobalVariables::~ProxySQL_GlobalVariables() {
	opt->reset();
	//opt->footer.clear();
	delete opt;
	delete confFile;
//	for (std::vector<MySQL_Hostgroup *>::iterator it = MyHostGroups.begin(); it != MyHostGroups.end(); ++it) {
//		MySQL_Hostgroup *myhg=*it;
//		delete myhg;
//	}
};

ProxySQL_GlobalVariables::ProxySQL_GlobalVariables() {
	confFile=NULL;
	__cmd_proxysql_config_file=NULL;
	__cmd_proxysql_datadir=NULL;
	__cmd_proxysql_admin_pathdb=NULL;

	global.gdbg=false;
	global.nostart=false;
	global.foreground=false;
	global.use_proxysql_mem=false;
	pthread_mutex_init(&global.start_mutex,NULL);
#ifdef DEBUG
	global.gdb=0;
#endif
	opt=new ez::ezOptionParser();
	opt->overview="High Performance Advanced Proxy for MySQL";
	opt->syntax="proxysql [OPTIONS]";
	std::string s = "\n\nProxySQL " ;
	s = s + "rev. " + PROXYSQL_VERSION + " -- " + __TIMESTAMP__ + "\nCopyright (C) 2013-2014 René Cannaò\nThis program is free and without warranty\n";
	opt->footer =s.c_str();

/*
opt.add(
		"", // Default.
		0, // Required?
		0, // Number of args expected.
		0, // Delimiter if expecting multiple args.
		"Display usage instructions.", // Help description.
		"-h",     // Flag token. 
		"-help",  // Flag token.
		"--help", // Flag token.
		"--usage" // Flag token.
	);
*/
	opt->add((const char *)"",0,0,0,(const char *)"Display usage instructions.",(const char *)"-h",(const char *)"-help",(const char *)"--help",(const char *)"--usage");
	opt->add((const char *)"",0,0,0,(const char *)"Print version",(const char *)"-V",(const char *)"--version");
	opt->add((const char *)"",0,1,0,(const char *)"Enable debugging messages with specific verbosity",(const char *)"-d",(const char *)"--debug");
	opt->add((const char *)"",0,0,0,(const char *)"Starts only the admin service",(const char *)"-n",(const char *)"--no-start");
	opt->add((const char *)"",0,0,0,(const char *)"Run in foreground",(const char *)"-f",(const char *)"--foreground");
	opt->add((const char *)"~/proxysql.cnf",0,1,0,(const char *)"Configuraton file",(const char *)"-c",(const char *)"--config");
	opt->add((const char *)"",0,1,0,(const char *)"Disable custom memory allocator",(const char *)"-m",(const char *)"--no-memory");
	opt->add((const char *)"",0,1,0,(const char *)"Datadir",(const char *)"-D",(const char *)"--datadir");
	opt->add((const char *)"",0,1,0,(const char *)"Configuration DB path",(const char *)"-a",(const char *)"--admin-pathdb");
	opt->add((const char *)"",0,1,0,(const char *)"Administration Unix Socket",(const char *)"-S",(const char *)"--admin-socket");
//	opt.add("",0,0,0,"","-d","--debug");
//	opt.add("",0,0,0,"","-d","--debug");

	confFile=new ProxySQL_ConfigFile();
	signal(SIGTERM, term_handler);

	//MyHostGroups=new MySQL_HostGroups();

};


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

	if (opt->isSet("-m")) {
		global.use_proxysql_mem=true;
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
	}

	if (opt->isSet("-D")) {
		std::string datadir;
		opt->get("-D")->getString(datadir);
		if (GloVars.__cmd_proxysql_datadir) free(GloVars.__cmd_proxysql_datadir);
		GloVars.__cmd_proxysql_datadir=strdup(datadir.c_str());
	}

	if (opt->isSet("-a")) {
		std::string admindb_path;
		opt->get("-a")->getString(admindb_path);
		if (GloVars.__cmd_proxysql_admin_pathdb) free(GloVars.__cmd_proxysql_admin_pathdb);
		GloVars.__cmd_proxysql_admin_pathdb=strdup(admindb_path.c_str());
	}

	if (opt->isSet("-S")) {
		std::string admin_socket;
		opt->get("-S")->getString(admin_socket);
		if (GloVars.__cmd_proxysql_admin_socket) free(GloVars.__cmd_proxysql_admin_socket);
		GloVars.__cmd_proxysql_admin_socket=strdup(admin_socket.c_str());
	}

	proxy_debug(PROXY_DEBUG_GENERIC, 4, "processing opts\n");

  //gchar *config_file=*config_file_ptr;
	char *config_file=GloVars.__cmd_proxysql_config_file;

	if (config_file==NULL) {
		config_file=(char *)"proxysql.cnf";
		//if (!g_file_test(config_file,(GFileTest)(G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR))) {
		if (Proxy_file_regular(config_file)==false) {
			config_file=(char *)"/etc/proxysql.cnf";
		}
	}

//	rc=config_file_is_readable(config_file);
//	if (rc==0) {
//		proxy_error("Config file does not exist, using defaults\n");
//		init_global_variables(keyfile, 0);
//    exit(EXIT_FAILURE);
//	} else {
//		// FIXME: process config file
//	}

  // apply settings from cmdline, that have priority over config file
#ifdef DEBUG
//	if (GloVars.__cmd_proxysql_gdbg>0) { GloVars.global.gdbg=true; }
	init_debug_struct_from_cmdline();
#endif

//	if (GloVars.__cmd_proxysql_foreground>=0) { foreground=GloVars.__cmd_proxysql_foreground; }
	if (GloVars.__cmd_proxysql_nostart>=0) { glovars.nostart=GloVars.__cmd_proxysql_nostart; }
	if (GloVars.__cmd_proxysql_datadir) {
		free(glovars.proxy_datadir);
		glovars.proxy_datadir=strdup(GloVars.__cmd_proxysql_datadir);
	}
	if (GloVars.__cmd_proxysql_admin_pathdb) {
		free(glovars.proxy_admin_pathdb);
		glovars.proxy_admin_pathdb=strdup(GloVars.__cmd_proxysql_admin_pathdb);
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
