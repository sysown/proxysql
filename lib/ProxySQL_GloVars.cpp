#include "ezOptionParser.hpp"
#include "proxysql.h"
#include "cpp.h"
#include <string>
#include <sys/utsname.h>
#include "prometheus/registry.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <cxxabi.h>
#include <uuid/uuid.h>

#include "MySQL_LDAP_Authentication.hpp"

extern MySQL_LDAP_Authentication* GloMyLdapAuth;

void (*flush_logs_function)() = NULL;

/*
Support system logging facilities sending SIGUSR1 to do log rotation
*/
static void log_handler(int sig) {
	proxy_info("Received SIGUSR1 signal: flushing logs...\n");
	if (flush_logs_function != NULL) {
		flush_logs_function();
	}
}

static void term_handler(int sig) {
	proxy_warning("Received TERM signal: shutdown in progress...\n");
/*
In ProxySQL 2.1 we replace PROXYSQL SHUTDOWN with PROXYSQL SHUTDOWN SLOW , and the former command now perform a "fast shutdown".
The same is now implemented for TERM signal handler.
*/
#ifdef DEBUG
	// Note: in DEBUG built we will still perform a slow shutdown.
	// DEBUG built is not meant for production use.
	__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
#else
	exit(EXIT_SUCCESS);
#endif
}

void crash_handler(int sig) {
#ifdef DEBUG
//	malloc_stats_print(NULL, NULL, "");
#endif
#ifdef __GLIBC__
#define DEBUG_MSG_MAXSIZE	1024
	char debugbuff[DEBUG_MSG_MAXSIZE];
	void *arr[20];
	size_t s;

	s = backtrace(arr, 20);

	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(arr, s, STDERR_FILENO);

	char **strings;
	strings=backtrace_symbols(arr,s);
	if (strings == NULL) {
		perror("backtrace_symbols failed!");
	} else {
		for (unsigned int i=0; i<s; i++) {
			debugbuff[0]=0;
			sscanf(strings[i], "%*[^(](%100[^+]", debugbuff);
			int status;
			char *realname=NULL;
			realname=abi::__cxa_demangle(debugbuff, 0, 0, &status);
			if (realname) {
				fprintf(stderr," ---- %s : %s\n", strings[i], realname);
			}
		}
		//free(strings); // we don't free, we are crashing anyway
	}
	fprintf(stderr, "To report a crashing bug visit: https://github.com/sysown/proxysql/issues\n");
	fprintf(stderr, "For support visit: https://proxysql.com/services/support/\n");


#endif /* __GLIBC__ */
	// try to generate a core dump signaling again the thread
	signal(sig, SIG_DFL);
	pthread_kill(pthread_self(), sig);
}

ProxySQL_GlobalVariables::~ProxySQL_GlobalVariables() {
	opt->reset();
	delete opt;
	delete confFile;
	if (execute_on_exit_failure) {
		free(execute_on_exit_failure);
		execute_on_exit_failure = NULL;
	}
	if (ldap_auth_plugin) {
		free(ldap_auth_plugin);
		ldap_auth_plugin = NULL;
	}
	/**
	 * @brief set in_shutdown flag just the member 'checksums_values'.
	 * @details This is performed to prevent the free() inside the 'ProxySQL_Checksum_Value' destructor for
	 *  'checksums_values' members. These checksums memory is never freed during ProxySQL execution
	 *  lifetime (only reused during update operations), and they are concurrently access by multiple threads,
	 *  including during shutdown phase. Since 'GloVars' (unique instance of this class) is declared global,
	 *  it's impossible to control de destruction order with respect to the other modules. To avoid invalid
	 *  memory accesses during shutdown, we avoid calling free() inside the destructor of the members.
	 */
	checksums_values.admin_variables.in_shutdown = true;
	checksums_values.mysql_query_rules.in_shutdown = true;
	checksums_values.mysql_servers.in_shutdown = true;
	checksums_values.mysql_servers_v2.in_shutdown = true;
	checksums_values.mysql_users.in_shutdown = true;
	checksums_values.mysql_variables.in_shutdown = true;
	checksums_values.ldap_variables.in_shutdown = true;
	checksums_values.proxysql_servers.in_shutdown = true;
	checksums_values.pgsql_query_rules.in_shutdown = true;
	checksums_values.pgsql_servers.in_shutdown = true;
	checksums_values.pgsql_users.in_shutdown = true;
	checksums_values.pgsql_variables.in_shutdown = true;
	if (global.gr_bootstrap_uri) {
		free(global.gr_bootstrap_uri);
		global.gr_bootstrap_uri = nullptr;
	}
	if (global.gr_bootstrap_account) {
		free(global.gr_bootstrap_account);
		global.gr_bootstrap_account = nullptr;
	}
	if (global.gr_bootstrap_account_create) {
		free(global.gr_bootstrap_account_create);
		global.gr_bootstrap_account_create = nullptr;
	}
	if (global.gr_bootstrap_account_host) {
		free(global.gr_bootstrap_account_host);
		global.gr_bootstrap_account_host = nullptr;
	}
	if (global.gr_bootstrap_conf_bind_address) {
		free(global.gr_bootstrap_conf_bind_address);
		global.gr_bootstrap_conf_bind_address = nullptr;
	}
	if (global.gr_bootstrap_ssl_ca) {
		free(global.gr_bootstrap_ssl_ca);
		global.gr_bootstrap_ssl_ca = nullptr;
	}
	if (global.gr_bootstrap_ssl_capath) {
		free(global.gr_bootstrap_ssl_capath);
		global.gr_bootstrap_ssl_capath = nullptr;
	}
	if (global.gr_bootstrap_ssl_cert) {
		free(global.gr_bootstrap_ssl_cert);
		global.gr_bootstrap_ssl_cert = nullptr;
	}
	if (global.gr_bootstrap_ssl_cipher) {
		free(global.gr_bootstrap_ssl_cipher);
		global.gr_bootstrap_ssl_cipher = nullptr;
	}
	if (global.gr_bootstrap_ssl_crl) {
		free(global.gr_bootstrap_ssl_crl);
		global.gr_bootstrap_ssl_crl = nullptr;
	}
	if (global.gr_bootstrap_ssl_crlpath) {
		free(global.gr_bootstrap_ssl_crlpath);
		global.gr_bootstrap_ssl_crlpath = nullptr;
	}
	if (global.gr_bootstrap_ssl_key) {
		free(global.gr_bootstrap_ssl_key);
		global.gr_bootstrap_ssl_key = nullptr;
	}
	if (global.gr_bootstrap_ssl_mode) {
		free(global.gr_bootstrap_ssl_mode);
		global.gr_bootstrap_ssl_mode = nullptr;
	}
};

ProxySQL_GlobalVariables::ProxySQL_GlobalVariables() :
	prometheus_registry(std::make_shared<prometheus::Registry>())
{
	confFile=NULL;
	__cmd_proxysql_config_file=NULL;
	__cmd_proxysql_datadir=NULL;
	__cmd_proxysql_uuid=NULL;

	config_file=NULL;
	datadir=NULL;
	uuid=NULL;
	configfile_open=false;

	__cmd_proxysql_initial=false;
	__cmd_proxysql_reload=false;
	cluster_sync_interfaces=false;

	statuses.stack_memory_mysql_threads = 0;
	statuses.stack_memory_admin_threads = 0;
	statuses.stack_memory_cluster_threads = 0;

	global.version_check = true;
	global.gdbg=false;
	global.nostart=false;
	global.foreground=false;
	global.my_monitor=true;
	global.pg_monitor=true;
#ifdef IDLE_THREADS
	global.idle_threads=false;
#endif /* IDLE_THREADS */
#ifdef SO_REUSEPORT
	global.reuseport=false;
#endif /* SO_REUSEPORT */
//	global.use_proxysql_mem=false;
	pthread_mutex_init(&global.start_mutex,NULL);
	pthread_mutex_init(&checksum_mutex,NULL);
	pthread_mutex_init(&global.ext_glomth_mutex,NULL);
	epoch_version = 0;
	checksums_values.updates_cnt = 0;
	checksums_values.dumped_at = 0;
	checksums_values.global_checksum = 0;
	execute_on_exit_failure = NULL;
	ldap_auth_plugin = NULL;
	web_interface_plugin = NULL;
	sqlite3_plugin = NULL;
#ifdef DEBUG
	global.gdb=0;
#endif

	global.sqlite3_server=false;
	global.data_packets_history_size=0;
#ifdef PROXYSQLCLICKHOUSE
	global.clickhouse_server=false;
#endif /* PROXYSQLCLICKHOUSE */
	global.gr_bootstrap_mode = 0;
	global.gr_bootstrap_uri = nullptr;
	global.gr_bootstrap_account = nullptr;
	global.gr_bootstrap_account_create = nullptr;
	global.gr_bootstrap_account_host = nullptr;
	global.gr_bootstrap_password_retries = 20;
	global.gr_bootstrap_conf_bind_address = nullptr;
	global.gr_bootstrap_conf_base_port = 0;
	global.gr_bootstrap_conf_use_sockets = false;
	global.gr_bootstrap_conf_skip_tcp = false;
	global.gr_bootstrap_ssl_ca = nullptr;
	global.gr_bootstrap_ssl_capath = nullptr;
	global.gr_bootstrap_ssl_cert = nullptr;
	global.gr_bootstrap_ssl_cipher = nullptr;
	global.gr_bootstrap_ssl_crl = nullptr;
	global.gr_bootstrap_ssl_crlpath = nullptr;
	global.gr_bootstrap_ssl_key = nullptr;
	global.gr_bootstrap_ssl_mode = nullptr;
	global.ssl_keylog_enabled = false;
	opt = new ez::ezOptionParser();
	opt->overview = "High Performance Advanced Proxy for MySQL";
	opt->syntax = "proxysql [OPTIONS]";
	std::string s = "\n\nProxySQL " ;
	const char *build_year = &__DATE__[7];
	s = s + "rev. " + PROXYSQL_VERSION + " -- " + __TIMESTAMP__ + "\nCopyright (C) 2013-" + string(build_year) + " ProxySQL LLC\nThis program is free and without warranty\n";
	opt->footer = s.c_str();

	opt->add((const char *)"",0,0,0,(const char *)"Display usage instructions.",(const char *)"-h",(const char *)"-help",(const char *)"--help",(const char *)"--usage");
	opt->add((const char *)"",0,0,0,(const char *)"Print version",(const char *)"-V",(const char *)"--version");
#ifdef DEBUG
	// NOTE: Temporal change for full 'bootstrap' compatibility, only '--debug' is allowed, '-d' is an alias for '-D'
	opt->add((const char *)"",0,1,0,(const char *)"Enable debugging messages with specific verbosity",(const char *)"--debug");
#endif /* DEBUG */
	opt->add((const char *)"",0,0,0,(const char *)"Starts only the admin service",(const char *)"-n",(const char *)"--no-start");
	opt->add((const char *)"",0,0,0,(const char *)"Do not start Monitor Module",(const char *)"-M",(const char *)"--no-monitor");
	opt->add((const char *)"",0,0,0,(const char *)"Run in foreground",(const char *)"-f",(const char *)"--foreground");
#ifdef SO_REUSEPORT
	opt->add((const char *)"",0,0,0,(const char *)"Use SO_REUSEPORT",(const char *)"-r",(const char *)"--reuseport");
#endif /* SO_REUSEPORT */
	opt->add((const char *)"",0,0,0,(const char *)"Do not restart ProxySQL if crashes",(const char *)"-e",(const char *)"--exit-on-error");
	opt->add((const char *)"~/proxysql.cnf",0,1,0,(const char *)"Configuration file",(const char *)"-c",(const char *)"--config");
	opt->add((const char *)"",0,1,0,(const char *)"Datadir",(const char *)"-D",(const char *)"--datadir");
	// NOTE: Duplicated option for 'bootstrap' compatibility
	opt->add((const char *)"",0,1,0,(const char *)"Datadir",(const char *)"-d",(const char *)"--directory");
	opt->add((const char *)"",0,1,0,(const char *)"UUID",(const char *)"-U",(const char *)"--uuid");
	opt->add((const char *)"",0,0,0,(const char *)"Rename/empty database file",(const char *)"--initial");
	opt->add((const char *)"",0,0,0,(const char *)"Merge config file into database file",(const char *)"--reload");
#ifdef IDLE_THREADS
	opt->add((const char *)"",0,0,0,(const char *)"Create auxiliary threads to handle idle connections",(const char *)"--idle-threads");
#endif /* IDLE_THREADS */
	opt->add((const char *)"",0,0,0,(const char *)"Do not check for the latest version of ProxySQL",(const char *)"--no-version-check");
	opt->add((const char *)"",0,1,0,(const char *)"Administration Unix Socket",(const char *)"-S",(const char *)"--admin-socket");

	opt->add((const char *)"",0,0,0,(const char *)"Enable SQLite3 Server",(const char *)"--sqlite3-server");
	// Bootstrap General options
	opt->add((const char *)"",0,1,0,(const char *)"Start ProxySQL in Group Replication bootstrap mode."
		" An URI needs to be specified for creating a connection to the bootstrap server, if no URI is provided,"
		" a connection to the default local socket will be attempted.",(const char *)"-B", (const char *)"--bootstrap");
	opt->add((const char *)"",0,1,0, (const char *)"Account to use by monitoring after bootstrap, either reuses a specify account or creates a new one;"
		" this behavior is controlled by related option '--acount-create'. When used, a password must be provided." ,(const char *)"--account");
	opt->add((const char *)"",0,1,0,(const char *)"Account creation policy for bootstrap. Possible values are:\n"
		"- if-not-exists (default): If the account doesn't exist, create it, otherwise reuse it.\n"
		"- always: Only bootstrap if the account isn't present and can be created.\n"
		"- never: Only bootstrap if the account is already present.",(const char *)"--account-create");
	opt->add((const char *)"",0,1,0,(const char *)"Host pattern to be used for accounts created during bootstrap",(const char *)"--account-host");
	opt->add((const char *)"",0,1,0,(const char *)"Number of attempts for generating a password when creating an account during bootstrap",(const char *)"--password-retries");
	opt->add((const char *)"",0,1,0,(const char *)"Sets the default base port ('mysql-interfaces') for the default R/W split port based configuration",(const char *)"--conf-base-port");
	opt->add((const char *)"",0,1,0,(const char *)"Sets the default bind address ('mysql-interfaces'). Used in combination with '--conf-bind-port'",(const char *)"--conf-bind-address");
	// TODO: We should make query rules compatible with Unix socket domain addresses for routing
	opt->add((const char *)"",0,1,0,(const char *)"bootstrap option, configures two Unix sockets with names 'mysql.sock' and 'mysqlro.sock'",(const char *)"--conf-use-sockets");
	opt->add((const char *)"",0,1,0,(const char *)"Sets the default base port for the default R/W split port based configuration",(const char *)"--conf-skip-tcp");
	// Bootstrap SSL options
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the Certificate Authority (CA) certificate file. Must specify the same certificate used by the server",(const char *)"--ssl-ca");
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the directory that contains trusted SSL CA certificate files",(const char *)"--ssl-capath");
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the client public key certificate file",(const char *)"--ssl-cert");
	opt->add((const char *)"",0,1,0,(const char *)"The list of permissible ciphers for SSL encryption",(const char *)"--ssl-cipher");
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the file containing certificate revocation lists",(const char *)"--ssl-crl");
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the directory that contains certificate revocation list files",(const char *)"--ssl-crlpath");
	opt->add((const char *)"",0,1,0,(const char *)"The path name of the client private key file",(const char *)"--ssl-key");
	// TODO: Complete information about this mode and it's relation with 'ssl-ca'. E.g: For 'VERIFY_CA' mode,
	// MariaDB connector related options. Not direct option 'MYSQL_OPT_SSL_MODE'.
	opt->add((const char *)"",0,1,0,(const char *)"SSL connection mode for using during bootstrap during normal operation with the backend servers. Only PREFERRED, and DISABLED are supported.",(const char *)"--ssl-mode");
#ifdef PROXYSQLCLICKHOUSE
	opt->add((const char *)"",0,0,0,(const char *)"Enable ClickHouse Server",(const char *)"--clickhouse-server");
#endif /* PROXYSQLCLICKHOUSE */

	confFile=new ProxySQL_ConfigFile();
};

void ProxySQL_GlobalVariables::install_signal_handler() {
	signal(SIGUSR1, log_handler);
	signal(SIGTERM, term_handler);
	signal(SIGSEGV, crash_handler);
	signal(SIGABRT, crash_handler);
	signal(SIGFPE, crash_handler);
	signal(SIGPIPE, SIG_IGN);
}

void ProxySQL_GlobalVariables::parse(int argc, const char * argv[]) {
	opt->parse(argc, argv);
};

void update_string_var_if_set(char** cur_val, ez::ezOptionParser* opt, const char* cmd_opt) {
	if (opt->isSet(cmd_opt)) {
		std::string val {};
		opt->get(cmd_opt)->getString(val);
		if (*cur_val) { free(*cur_val); }
		*cur_val = strdup(val.c_str());
	}
}

void update_ulong_var_if_set(uint64_t& cur_val, ez::ezOptionParser* opt, const char* cmd_opt) {
	if (opt->isSet(cmd_opt)) {
		opt->get(cmd_opt)->getULong(cur_val);
	}
}

void ProxySQL_GlobalVariables::process_opts_pre() {
	if (opt->isSet("-h")) {
		std::string usage;
		opt->getUsage(usage);
		std::cout << usage;
		exit(EXIT_SUCCESS);
	}

	if (opt->isSet("-V")) {
		fprintf(stdout,"ProxySQL version %s, codename %s\n", PROXYSQL_VERSION, PROXYSQL_CODENAME);
		exit(EXIT_SUCCESS);
	}

	if (opt->isSet("--debug")) {
		opt->get("--debug")->getInt(GloVars.__cmd_proxysql_gdbg);
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

	update_string_var_if_set(&GloVars.__cmd_proxysql_datadir, opt, "-d");

	if (opt->isSet("-U")) {
		std::string uuid;
		opt->get("-U")->getString(uuid);
		uuid_t uu;
		if (uuid_parse(uuid.c_str(), uu)==0) {
			// we successfully parsed an UUID
			if (GloVars.__cmd_proxysql_uuid) free(GloVars.__cmd_proxysql_uuid);
			GloVars.__cmd_proxysql_uuid=strdup(uuid.c_str());
		} else {
			fprintf(stderr,"The UUID specified in the command line is invalid, ignoring it: %s\n", uuid.c_str());
		}
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
		glovars.idle_threads=true;
	}
#endif /* IDLE_THREADS */

	if (opt->isSet("--no-version-check")) {
		global.version_check=false;
		glovars.version_check=false;
	}
	if (opt->isSet("--sqlite3-server")) {
		global.sqlite3_server=true;
	}
#ifdef PROXYSQLCLICKHOUSE
	if (opt->isSet("--clickhouse-server")) {
		global.clickhouse_server=true;
	}
#endif /* PROXYSQLCLICKHOUSE */
	update_string_var_if_set(&global.gr_bootstrap_uri, opt, "--bootstrap");
	global.gr_bootstrap_mode = opt->isSet("--bootstrap");
	update_ulong_var_if_set(global.gr_bootstrap_conf_base_port, opt, "--conf-base-port");
	update_string_var_if_set(&global.gr_bootstrap_conf_bind_address, opt, "--conf-bind-address");
	global.gr_bootstrap_conf_use_sockets = opt->isSet("--conf-use-sockets");
	global.gr_bootstrap_conf_skip_tcp = opt->isSet("--conf-skip-tcp");
	update_string_var_if_set(&global.gr_bootstrap_account, opt, "--account");
	update_string_var_if_set(&global.gr_bootstrap_account_create, opt, "--account-create");
	update_string_var_if_set(&global.gr_bootstrap_account_host, opt, "--account-host");
	update_ulong_var_if_set(global.gr_bootstrap_password_retries, opt, "--password-retries");
	update_string_var_if_set(&global.gr_bootstrap_ssl_ca, opt, "--ssl-ca");
	update_string_var_if_set(&global.gr_bootstrap_ssl_capath, opt, "--ssl-capath");
	update_string_var_if_set(&global.gr_bootstrap_ssl_cert, opt, "--ssl-cert");
	update_string_var_if_set(&global.gr_bootstrap_ssl_cipher, opt, "--ssl-cipher");
	update_string_var_if_set(&global.gr_bootstrap_ssl_crl, opt, "--ssl-crl");
	update_string_var_if_set(&global.gr_bootstrap_ssl_crlpath, opt, "--ssl-crlpath");
	update_string_var_if_set(&global.gr_bootstrap_ssl_key, opt, "--ssl-key");
	update_string_var_if_set(&global.gr_bootstrap_ssl_mode, opt, "--ssl-mode");

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
	init_coredump_struct();

	proxysql_keylog_init();
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
		global.my_monitor=false;
		global.pg_monitor=false;
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
	if (GloVars.__cmd_proxysql_uuid) {
		free(GloVars.uuid);
		GloVars.uuid=strdup(GloVars.__cmd_proxysql_uuid);
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
	v = &checksums_values.mysql_servers_v2;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
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
	v = &checksums_values.pgsql_query_rules;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
	}
	v = &checksums_values.pgsql_servers;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
	}
	v = &checksums_values.pgsql_servers_v2;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
	}
	v = &checksums_values.pgsql_users;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
	}
	v = &checksums_values.pgsql_variables;
	if (v->version) {
		myhash.Update(v->checksum, strlen(v->checksum));
		myhash.Update(&v->version, sizeof(v->version));
	}
	v = &checksums_values.proxysql_servers;
	if (v->version) {
		myhash.Update(v->checksum,strlen(v->checksum));
		myhash.Update(&v->version,sizeof(v->version));
	}
	if (GloMyLdapAuth) {
		v = &checksums_values.ldap_variables;
		if (v->version) {
			myhash.Update(v->checksum,strlen(v->checksum));
			myhash.Update(&v->version,sizeof(v->version));
		}
	}
	uint64_t h1, h2;
	myhash.Final(&h1, &h2);
	h1 = h1/2; // ugly way to make it signed within LLONG_MAX
	checksums_values.global_checksum = h1;
	return h1;
}
