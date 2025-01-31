#define MAIN_PROXY_SQLITE3
#include <iostream>
#include <thread>
#include "btree_map.h"
#include "proxysql.h"

#include <random>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define PROXYSQL_EXTERN
#include "cpp.h"

#include "mysqld_error.h"

#include "ProxySQL_Statistics.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "MySQL_Logger.hpp"
#include "SQLite3_Server.h"
#include "query_processor.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "proxysql_restapi.h"
#include "Web_Interface.hpp"
#include "proxysql_utils.h"

#include "libdaemon/dfork.h"
#include "libdaemon/dsignal.h"
#include "libdaemon/dlog.h"
#include "libdaemon/dpid.h"
#include "libdaemon/dexec.h"
#include "ev.h"

#include "curl/curl.h"

#include "openssl/x509v3.h"

#include <sys/mman.h>

#include <uuid/uuid.h>

#ifdef DEBUG
#include "proxy_protocol_info.h"
#endif // DEBUG


/*
extern "C" MySQL_LDAP_Authentication * create_MySQL_LDAP_Authentication_func() {
	return NULL;
}
*/


using std::map;
using std::string;
using std::vector;


volatile create_MySQL_LDAP_Authentication_t * create_MySQL_LDAP_Authentication = NULL;
void * __mysql_ldap_auth;

volatile create_Web_Interface_t * create_Web_Interface = NULL;
void * __web_interface;


extern int ProxySQL_create_or_load_TLS(bool bootstrap, std::string& msg);

char *binary_sha1 = NULL;

// MariaDB client library redefines dlerror(), see https://mariadb.atlassian.net/browse/CONC-101
#ifdef dlerror
#undef dlerror
#endif

static pthread_mutex_t *lockarray;
#include "openssl/crypto.h"


// this fuction will be called as a deatached thread
static void * waitpid_thread(void *arg) {
	pid_t *cpid_ptr=(pid_t *)arg;
	int status;
	set_thread_name("waitpid");
	waitpid(*cpid_ptr, &status, 0);
	free(cpid_ptr);
	return NULL;
}



struct MemoryStruct {
	char *memory;
	size_t size;
};


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
	assert(mem->memory);
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}


char * know_latest_version = NULL;
static unsigned int randID = 0;

/**
 * @brief Checks for the latest version of ProxySQL by querying the specified URL.
 *
 * This function sends an HTTP GET request to the ProxySQL website to fetch the latest version information.
 * It sets a custom user-agent string containing the version, SHA1 hash of the binary (if available), and a random ID.
 * The response is stored in memory and returned as a character pointer.
 *
 * @return A character pointer containing the response data from the Proxysql website.
 *         If an error occurs during the HTTP request, NULL is returned.
 */
static char * main_check_latest_version() {
	CURL *curl_handle; // CURL handle for performing HTTP requests
	CURLcode res; // Variable to store CURL operation result
	struct MemoryStruct chunk; // // Struct to store memory chunk received from HTTP response

	// Initialize memory struct to store response data
	chunk.memory = (char *)malloc(1);
	chunk.size = 0;

	// Initialize CURL library
	curl_global_init(CURL_GLOBAL_ALL);
	// Initialize CURL handle for HTTP request
	curl_handle = curl_easy_init();
	// Set CURL options for the HTTP request
	curl_easy_setopt(curl_handle, CURLOPT_URL, "https://www.proxysql.com/latest");
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYSTATUS, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, "0-31");
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	// Set custom user-agent string including ProxySQL version, binary SHA1 hash, and a random ID
	string s = "proxysql-agent/";
	s += PROXYSQL_VERSION;
	if (binary_sha1) {
		s += " (" ;
			s+= binary_sha1;
		s += ")" ;
	}
	s += " " + std::to_string(randID);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, s.c_str());

	// Set timeout and connect timeout for the HTTP request
	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10);

	// Perform the HTTP request
	res = curl_easy_perform(curl_handle);

	// Check if the request was successful
	if (res != CURLE_OK) {
		switch (res) {
			// Handle common errors and free memory if necessary
			case CURLE_COULDNT_RESOLVE_HOST:
			case CURLE_COULDNT_CONNECT:
			case CURLE_OPERATION_TIMEDOUT:
				// These errors are expected in case of network issues or timeouts
				break;
			default:
				// Log other errors using proxy_error and free memory
				proxy_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
				break;
		}
		free(chunk.memory);
		chunk.memory = NULL;
	}

	// Cleanup CURL handle and global resources
	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	// Return the response data from the ProxySQL website
	return chunk.memory;
}


/**
 * @brief Thread function to check for the latest version of ProxySQL asynchronously.
 *
 * This function is intended to be executed as a separate thread to asynchronously check for the latest version of ProxySQL.
 * It calls the main_check_latest_version function to fetch the latest version information from the ProxySQL website.
 * If the fetched version information is valid and different from the currently known latest version,
 * it updates the known latest version and logs a message indicating the availability of the new version.
 *
 * @param arg Pointer to the argument passed to the thread function (unused).
 * @return NULL.
 */
void * main_check_latest_version_thread(void *arg) {
	set_thread_name("CheckLatestVers");
	// Fetch the latest version information
	char * latest_version = main_check_latest_version();
	// we check for potential invalid data , see issue #4042
	// Check for potential invalid data and update the known latest version if a new version is detected
	if (latest_version != NULL && strlen(latest_version) < 32) {
		if (
			(know_latest_version == NULL) // first check
			|| (strcmp(know_latest_version,latest_version)) // new version detected
		) {
			// Free previously known latest version and update it with the new version
			if (know_latest_version)
				free(know_latest_version);
			// Duplicate latest version string
			know_latest_version = strdup(latest_version);
			// Log the availability of the new version
			proxy_info("Latest ProxySQL version available: %s\n", latest_version);
		}
	}
	free(latest_version);
	return NULL;
}





// Note: if you are running ProxySQL under gdb, you may consider setting this
// variable immediately to 1
// Example:
// set disable_watchdog=1
volatile int disable_watchdog = 0;

void parent_open_error_log() {
	if (GloVars.global.foreground==false) {
		int outfd=0;
		int errfd=0;
		outfd=open(GloVars.errorlog, O_WRONLY | O_APPEND | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (outfd>0) {
			dup2(outfd, STDOUT_FILENO);
			close(outfd);
		} else {
			proxy_error("Impossible to open file\n");
		}
		errfd=open(GloVars.errorlog, O_WRONLY | O_APPEND | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (errfd>0) {
			dup2(errfd, STDERR_FILENO);
			close(errfd);
		} else {
			proxy_error("Impossible to open file\n");
		}
	}
}


void parent_close_error_log() {
	if (GloVars.global.foreground==false) {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
}

pid_t pid;

static const char * proxysql_pid_file() {
	static char fn[512];
	snprintf(fn, sizeof(fn), "%s", daemon_pid_file_ident);
	return fn;
}


/*struct cpu_timer
{
	~cpu_timer()
	{
		auto end = std::clock() ;
		std::cerr << double( end - begin ) / CLOCKS_PER_SEC << " secs.\n" ;
	};
	const std::clock_t begin = std::clock() ;
};
*/
struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{
		unsigned long long end = monotonic_time();
#ifdef DEBUG
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
#endif /* DEBUG */
		begin=end-begin; // here only to make compiler happy
	};
	unsigned long long begin;
};


static unsigned long thread_id(void) {
	unsigned long ret;
	ret = (unsigned long)pthread_self();
	return ret;
}

static void init_locks(void) {
	int i;
	lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for(i = 0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(lockarray[i]), NULL);
	}
	CRYPTO_set_id_callback((unsigned long (*)())thread_id);
	// deprecated
	//CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))lock_callback);
}




void ProxySQL_Main_init_SSL_module() {
	int rc = SSL_library_init();
	if (rc==0) {
		proxy_error("%s\n", SSL_alert_desc_string_long(rc));
	}
	init_locks();
	proxy_info("Using OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
	SSL_METHOD *ssl_method;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	//ssl_method = (SSL_METHOD *)TLSv1_server_method();
	//ssl_method = (SSL_METHOD *)SSLv23_server_method();
	ssl_method = (SSL_METHOD *)TLS_server_method();
	GloVars.global.ssl_ctx = SSL_CTX_new(ssl_method);
	if (GloVars.global.ssl_ctx==NULL)	{
		ERR_print_errors_fp(stderr);
		proxy_error("Unable to initialize SSL. Shutting down...\n");
		exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
	}
	if (!SSL_CTX_set_min_proto_version(GloVars.global.ssl_ctx,TLS1_VERSION)) {
		proxy_error("Unable to initialize SSL. SSL_set_min_proto_version failed. Shutting down...\n");
		exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
	}
	//SSL_CTX_set_options(GloVars.global.ssl_ctx, SSL_OP_NO_SSLv3); // no necessary, because of previous SSL_CTX_set_min_proto_version
#ifdef DEBUG
#if 0
	{
		STACK_OF(SSL_CIPHER) *ciphers;
		ciphers = SSL_CTX_get_ciphers(GloVars.global.ssl_ctx);
		fprintf(stderr,"List of cipher avaiable:\n");
		if (ciphers) {
			int num = sk_SSL_CIPHER_num(ciphers);
			char buf[130];
			for(int i = 0; i < num; i++){
				const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
				fprintf(stderr,"%s:  %s", SSL_CIPHER_get_name(cipher), SSL_CIPHER_description(cipher, buf, 128));
			}
		}
		fprintf(stderr,"\n");
	}
#endif // 0
#endif // DEBUG
	std::string msg = "";
	ProxySQL_create_or_load_TLS(true, msg);
}


/*
void example_listern() {
// few examples tests to demonstrate the ability to add and remove listeners at runtime
	GloMTH->listener_add((char *)"0.0.0.0:6033");
	sleep(3);
	GloMTH->listener_add((char *)"127.0.0.1:5033");
	sleep(3);
	GloMTH->listener_add((char *)"127.0.0.2:5033");
	sleep(3);
	GloMTH->listener_add((char *)"/tmp/proxysql.sock");
	for (int t=0; t<10; t++) {
		GloMTH->listener_add((char *)"127.0.0.1",7000+t);
		sleep(3);
	}

	GloMTH->listener_del((char *)"0.0.0.0:6033");
	sleep(3);
	GloMTH->listener_del((char *)"127.0.0.1:5033");
	sleep(3);
	GloMTH->listener_del((char *)"127.0.0.2:5033");
	sleep(3);
	GloMTH->listener_del((char *)"/tmp/proxysql.sock");
}
*/




void * __qc;
void * __mysql_thread;
void * __mysql_threads_handler;
void * __query_processor;
//void * __mysql_auth;



using namespace std;


//__cmd_proxysql_config_file=NULL;
#define MAX_EVENTS 100

static volatile int load_;

//__thread l_sfp *__thr_sfp=NULL;
//#ifdef DEBUG
//const char *malloc_conf = "xmalloc:true,lg_tcache_max:16,purge:decay,junk:true,tcache:false";
//#else
//const char *malloc_conf = "xmalloc:true,lg_tcache_max:16,purge:decay";
#ifndef __FreeBSD__
const char *malloc_conf = "xmalloc:true,lg_tcache_max:16,prof:true,prof_accum:true,prof_leak:true,lg_prof_sample:20,lg_prof_interval:30,prof_active:false";
#endif
//#endif /* DEBUG */
//const char *malloc_conf = "prof_leak:true,lg_prof_sample:0,prof_final:true,xmalloc:true,lg_tcache_max:16";

int listen_fd;
int socket_fd;


Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
MySQL_LDAP_Authentication *GloMyLdapAuth;
#ifdef PROXYSQLCLICKHOUSE
ClickHouse_Authentication *GloClickHouseAuth;
#endif /* PROXYSQLCLICKHOUSE */
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH = NULL;
Web_Interface *GloWebInterface;
MySQL_STMT_Manager_v14 *GloMyStmt;

MySQL_Monitor *GloMyMon;
std::thread *MyMon_thread = NULL;

MySQL_Logger *GloMyLogger;
MySQL_Variables mysql_variables;

SQLite3_Server *GloSQLite3Server;
#ifdef PROXYSQLCLICKHOUSE
ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */


ProxySQL_Cluster *GloProxyCluster = NULL;

ProxySQL_Statistics *GloProxyStats = NULL;

void * mysql_worker_thread_func(void *arg) {

//	__thr_sfp=l_mem_init();

	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads,tmp_stack_size);
		}
	}

	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	MySQL_Thread *worker = new MySQL_Thread();
	mysql_thread->worker=worker;
	worker->init();
//	worker->poll_listener_add(listen_fd);
//	worker->poll_listener_add(socket_fd);
	__sync_fetch_and_sub(&load_,1);
	do { usleep(50); } while (load_);

	worker->run();
	//delete worker;
	delete worker;
	mysql_thread->worker=NULL;
//	l_mem_destroy(__thr_sfp);
	__sync_fetch_and_sub(&GloVars.statuses.stack_memory_mysql_threads,tmp_stack_size);
	return NULL;
}

#ifdef IDLE_THREADS
void * mysql_worker_thread_func_idles(void *arg) {

	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads,tmp_stack_size);
		}
	}

//	__thr_sfp=l_mem_init();
	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	MySQL_Thread *worker = new MySQL_Thread();
	mysql_thread->worker=worker;
	worker->epoll_thread=true;
	worker->init();
//	worker->poll_listener_add(listen_fd);
//	worker->poll_listener_add(socket_fd);
	__sync_fetch_and_sub(&load_,1);
	do { usleep(50); } while (load_);

	worker->run();
	//delete worker;
	delete worker;
//	l_mem_destroy(__thr_sfp);

	__sync_fetch_and_sub(&GloVars.statuses.stack_memory_mysql_threads,tmp_stack_size);

	return NULL;
}
#endif // IDLE_THREADS

void * mysql_shared_query_cache_funct(void *arg) {
	GloQC->purgeHash_thread(NULL);
	return NULL;
}


void ProxySQL_Main_process_global_variables(int argc, const char **argv) {
	GloVars.errorlog = NULL;
	GloVars.pid = NULL;
	GloVars.parse(argc,argv);
	GloVars.process_opts_pre();
	GloVars.restart_on_missing_heartbeats = 10; // default
	GloVars.console_logging_verbosity_level = loglevel_info; // output all logging entries to stderr by default
	// alwasy try to open a config file
	if (GloVars.confFile->OpenFile(GloVars.config_file) == true) {
		GloVars.configfile_open=true;
		proxy_info("Using config file %s\n", GloVars.config_file);
		const Setting& root = GloVars.confFile->cfg.getRoot();
		if (root.exists("restart_on_missing_heartbeats")==true) {
			// restart_on_missing_heartbeats datadir from config file
			int restart_on_missing_heartbeats;
			bool rc;
			rc=root.lookupValue("restart_on_missing_heartbeats", restart_on_missing_heartbeats);
			if (rc==true) {
				GloVars.restart_on_missing_heartbeats=restart_on_missing_heartbeats;
			}
		}
		if (root.exists("console_logging_verbosity_level")==true) {
			// read console_logging_verbosity_level from config file
			int console_logging_verbosity_level;
			bool rc;
			rc=root.lookupValue("console_logging_verbosity_level", console_logging_verbosity_level);
			if (rc==true) {
				GloVars.console_logging_verbosity_level=console_logging_verbosity_level;
			}
		}
		if (root.exists("execute_on_exit_failure")==true) {
			// restart_on_missing_heartbeats datadir from config file
			string execute_on_exit_failure;
			bool rc;
			rc=root.lookupValue("execute_on_exit_failure", execute_on_exit_failure);
			if (rc==true) {
				GloVars.execute_on_exit_failure=strdup(execute_on_exit_failure.c_str());
			}
		}
		if (root.exists("errorlog")==true) {
			// restart_on_missing_heartbeats datadir from config file
			string errorlog_path;
			bool rc;
			rc=root.lookupValue("errorlog", errorlog_path);
			if (rc==true) {
				GloVars.errorlog = strdup(errorlog_path.c_str());
			}
		}
		if (root.exists("uuid")==true) {
			string uuid;
			bool rc;
			rc=root.lookupValue("uuid", uuid);
			if (rc==true) {
				uuid_t uu;
				if (uuid_parse(uuid.c_str(), uu)==0) {
					if (GloVars.uuid == NULL) {
						// it is not set yet, that means it wasn't specified on the cmdline
						GloVars.uuid = strdup(uuid.c_str());
					}
				} else {
					proxy_error("The config file is configured with an invalid UUID: %s\n", uuid.c_str());
				}
			}
		}
		// if cluster_sync_interfaces is true, interfaces variables are synced too
		if (root.exists("cluster_sync_interfaces")==true) {
			bool value_bool;
			bool rc;
			rc=root.lookupValue("cluster_sync_interfaces", value_bool);
			if (rc==true) {
				GloVars.cluster_sync_interfaces=value_bool;
			} else {
				proxy_error("The config file is configured with an invalid cluster_sync_interfaces\n");
			}
		}
		if (root.exists("pidfile")==true) {
			string pidfile_path;
			bool rc;
			rc=root.lookupValue("pidfile", pidfile_path);
			if (rc==true) {
				GloVars.pid = strdup(pidfile_path.c_str());
      }
    }
		if (root.exists("sqlite3_plugin")==true) {
			string sqlite3_plugin;
			bool rc;
			rc=root.lookupValue("sqlite3_plugin", sqlite3_plugin);
			if (rc==true) {
				GloVars.sqlite3_plugin=strdup(sqlite3_plugin.c_str());
			}
		}
		if (root.exists("web_interface_plugin")==true) {
			string web_interface_plugin;
			bool rc;
			rc=root.lookupValue("web_interface_plugin", web_interface_plugin);
			if (rc==true) {
				GloVars.web_interface_plugin=strdup(web_interface_plugin.c_str());
			}
		}
		if (root.exists("ldap_auth_plugin")==true) {
			string ldap_auth_plugin;
			bool rc;
			rc=root.lookupValue("ldap_auth_plugin", ldap_auth_plugin);
			if (rc==true) {
				GloVars.ldap_auth_plugin=strdup(ldap_auth_plugin.c_str());
			}
		}
		const map<string, char**> varnames_globals_map {
			{ "mysql-ssl_p2s_ca", &GloVars.global.gr_bootstrap_ssl_ca },
			{ "mysql-ssl_p2s_capath", &GloVars.global.gr_bootstrap_ssl_capath },
			{ "mysql-ssl_p2s_cert", &GloVars.global.gr_bootstrap_ssl_cert },
			{ "mysql-ssl_p2s_key", &GloVars.global.gr_bootstrap_ssl_key },
			{ "mysql-ssl_p2s_cipher", &GloVars.global.gr_bootstrap_ssl_cipher },
			{ "mysql-ssl_p2s_crl", &GloVars.global.gr_bootstrap_ssl_crl },
			{ "mysql-ssl_p2s_crlpath", &GloVars.global.gr_bootstrap_ssl_crlpath }
		};
		// Command line options always take precedence
		if (GloVars.global.gr_bootstrap_mode && root.exists("mysql_variables")) {
			const Setting& mysql_vars = root["mysql_variables"];

			for (const pair<const string,char**>& name_global : varnames_globals_map) {
				for (const auto& setting_it : mysql_vars) {
					if (*name_global.second == nullptr) {
						if (setting_it.getName() == name_global.first && setting_it.isString()) {
							const char* setting_val = setting_it.c_str();
							*name_global.second = strdup(setting_val);
						}
					}
				}
			}
		}
	} else {
		proxy_warning("Unable to open config file %s\n", GloVars.config_file); // issue #705
		if (GloVars.__cmd_proxysql_config_file) {
			proxy_error("Unable to open config file %s specified in the command line. Aborting!\n", GloVars.config_file);
			exit(EXIT_SUCCESS); // we exit gracefully to avoid restart
		}
	}
	char *t=getcwd(NULL, 512);
	if (GloVars.__cmd_proxysql_datadir==NULL) {
		// datadir was not specified , try to read config file
		if (GloVars.configfile_open==true) {
			const Setting& root = GloVars.confFile->cfg.getRoot();
			if (root.exists("datadir")==true) {
				// reading datadir from config file
				std::string datadir;
				bool rc;
				rc=root.lookupValue("datadir", datadir);
				if (rc==true) {
					GloVars.datadir=strdup(datadir.c_str());
				} else {
					GloVars.datadir=strdup(t);
				}
			} else {
				// datadir was not specified in config file
				GloVars.datadir=strdup(t);
			}
			if (root.exists("restart_on_missing_heartbeats")==true) {
				// restart_on_missing_heartbeats datadir from config file
				int restart_on_missing_heartbeats;
				bool rc;
				rc=root.lookupValue("restart_on_missing_heartbeats", restart_on_missing_heartbeats);
				if (rc==true) {
					GloVars.restart_on_missing_heartbeats=restart_on_missing_heartbeats;
				} else {
					GloVars.restart_on_missing_heartbeats = 10; // default
				}
			} else {
				// restart_on_missing_heartbeats was not specified in config file
				GloVars.restart_on_missing_heartbeats = 10; // default
			}
		} else {
			// config file not readable
			GloVars.datadir=strdup(t);
			std::cerr << "[Warning]: Cannot open any default config file . Using default datadir in current working directory " << GloVars.datadir << endl;
		}
	} else {
		GloVars.datadir=GloVars.__cmd_proxysql_datadir;
	}
	free(t);

	GloVars.admindb=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.db")+2);
	sprintf(GloVars.admindb,"%s/%s",GloVars.datadir, (char *)"proxysql.db");

	GloVars.sqlite3serverdb=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"sqlite3server.db")+2);
	sprintf(GloVars.sqlite3serverdb,"%s/%s",GloVars.datadir, (char *)"sqlite3server.db");

	GloVars.statsdb_disk=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql_stats.db")+2);
	sprintf(GloVars.statsdb_disk,"%s/%s",GloVars.datadir, (char *)"proxysql_stats.db");

	if (GloVars.errorlog == NULL) {
		GloVars.errorlog=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.log")+2);
		sprintf(GloVars.errorlog,"%s/%s",GloVars.datadir, (char *)"proxysql.log");
	}

	if (GloVars.pid == NULL) {
		GloVars.pid=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.pid")+2);
		sprintf(GloVars.pid,"%s/%s",GloVars.datadir, (char *)"proxysql.pid");
	}

	if (GloVars.__cmd_proxysql_initial==true) {
		std::cerr << "Renaming database file " << GloVars.admindb << endl;
		char *newpath=(char *)malloc(strlen(GloVars.admindb)+8);
		sprintf(newpath,"%s.bak",GloVars.admindb);
		rename(GloVars.admindb,newpath);	// FIXME: should we check return value, or ignore whatever it successed or not?
	}

	GloVars.confFile->ReadGlobals();
	GloVars.process_opts_post();
}

void ProxySQL_Main_init_main_modules() {
	GloQC=NULL;
	GloQPro=NULL;
	GloMTH=NULL;
	GloMyAuth=NULL;
#ifdef PROXYSQLCLICKHOUSE
	GloClickHouseAuth=NULL;
#endif /* PROXYSQLCLICKHOUSE */
	GloMyMon=NULL;
	GloMyLogger=NULL;
	GloMyStmt=NULL;

	// initialize libev
	if (!ev_default_loop (EVBACKEND_POLL | EVFLAG_NOENV)) {
		fprintf(stderr,"could not initialise libev");
		exit(EXIT_FAILURE);
	}

	MyHGM=new MySQL_HostGroups_Manager();
	MyHGM->init();
	MySQL_Threads_Handler * _tmp_GloMTH = NULL;
	_tmp_GloMTH=new MySQL_Threads_Handler();
	GloMTH = _tmp_GloMTH;
	GloMyLogger = new MySQL_Logger();
	GloMyLogger->print_version();
	GloMyStmt=new MySQL_STMT_Manager_v14();
}


void ProxySQL_Main_init_Admin_module(const bootstrap_info_t& bootstrap_info) {
	// cluster module needs to be initialized before
	GloProxyCluster = new ProxySQL_Cluster();
	GloProxyCluster->init();
	GloProxyCluster->print_version();
	GloProxyStats = new ProxySQL_Statistics();
	//GloProxyStats->init();
	GloProxyStats->print_version();
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->init(bootstrap_info);
	GloAdmin->print_version();
	if (binary_sha1) {
		proxy_info("ProxySQL SHA1 checksum: %s\n", binary_sha1);
	}
}

void ProxySQL_Main_init_Auth_module() {
	GloMyAuth = new MySQL_Authentication();
	GloMyAuth->print_version();
	GloAdmin->init_users();
	//GloMyLdapAuth = create_MySQL_LDAP_Authentication();
	if (GloMyLdapAuth) {
		GloMyLdapAuth->print_version();
	}
}

void ProxySQL_Main_init_Query_module() {
	GloQPro = new Query_Processor();
	GloQPro->print_version();
	GloAdmin->init_mysql_query_rules();
	GloAdmin->init_mysql_firewall();
//	if (GloWebInterface) {
//		GloWebInterface->print_version();
//	}
}

void ProxySQL_Main_init_MySQL_Threads_Handler_module() {
	unsigned int i;
	GloMTH->init();
	load_ = 1;
	load_ += GloMTH->num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		load_ += GloMTH->num_threads;
	} else {
		proxy_warning("proxysql instance running without --idle-threads : most workloads benefit from this option\n");
		proxy_warning("proxysql instance running without --idle-threads : enabling it can potentially improve performance\n");
	}
#endif // IDLE_THREADS
	for (i=0; i<GloMTH->num_threads; i++) {
		GloMTH->create_thread(i,mysql_worker_thread_func, false);
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads) {
			GloMTH->create_thread(i,mysql_worker_thread_func_idles, true);
		}
#endif // IDLE_THREADS
	}
}

void ProxySQL_Main_init_Query_Cache_module() {
	GloQC = new Query_Cache();
	GloQC->print_version();
	pthread_create(&GloQC->purge_thread_id, NULL, mysql_shared_query_cache_funct , NULL);
}

void ProxySQL_Main_init_MySQL_Monitor_module() {
	// start MySQL_Monitor
//	GloMyMon = new MySQL_Monitor();
	if (MyMon_thread == NULL) { // only if not created yet
		MyMon_thread = new std::thread(&MySQL_Monitor::run,GloMyMon);
		GloMyMon->print_version();
	}
}


void ProxySQL_Main_init_SQLite3Server() {
	// start SQLite3Server
	GloSQLite3Server = new SQLite3_Server();
	GloSQLite3Server->init();
	// NOTE: Always perform the 'load_*_to_runtime' after module start, otherwise values won't be properly
	// loaded from disk at ProxySQL startup.
	GloAdmin->load_sqliteserver_variables_to_runtime();
	GloAdmin->init_sqliteserver_variables();
	GloSQLite3Server->print_version();
}
#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Main_init_ClickHouseServer() {
	// start SQServer
	GloClickHouseServer = new ClickHouse_Server();
	GloClickHouseServer->init();
	// NOTE: Always perform the 'load_*_to_runtime' after module start, otherwise values won't be properly
	// loaded from disk at ProxySQL startup.
	GloAdmin->load_clickhouse_variables_to_runtime();
	GloAdmin->init_clickhouse_variables();
	GloClickHouseServer->print_version();
	GloClickHouseAuth = new ClickHouse_Authentication();
	GloClickHouseAuth->print_version();
	GloAdmin->init_clickhouse_users();
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Main_join_all_threads() {
	cpu_timer t;
	if (GloMTH) {
		cpu_timer t;
		GloMTH->shutdown_threads();
#ifdef DEBUG
		std::cerr << "GloMTH joined in ";
#endif
	}
	if (GloQC) {
		GloQC->shutdown=1;
	}

	if (GloMyMon) {
		GloMyMon->shutdown=true;
	}

	// join GloMyMon thread
	if (GloMyMon && MyMon_thread) {
		cpu_timer t;
		MyMon_thread->join();
		delete MyMon_thread;
		MyMon_thread = NULL;
#ifdef DEBUG
		std::cerr << "GloMyMon joined in ";
#endif
	}

	// join GloQC thread
	if (GloQC) {
		cpu_timer t;
		pthread_join(GloQC->purge_thread_id, NULL);
#ifdef DEBUG
		std::cerr << "GloQC joined in ";
#endif
	}
#ifdef DEBUG
	std::cerr << "All threads joined in ";
#endif
}

void ProxySQL_Main_shutdown_all_modules() {
	if (GloMyMon) {
		cpu_timer t;
		delete GloMyMon;
		GloMyMon=NULL;
#ifdef DEBUG
		std::cerr << "GloMyMon shutdown in ";
#endif
	}

	if (GloQC) {
		cpu_timer t;
		delete GloQC;
		GloQC=NULL;
#ifdef DEBUG
		std::cerr << "GloQC shutdown in ";
#endif
	}
	if (GloQPro) {
		cpu_timer t;
		delete GloQPro;
		GloQPro=NULL;
#ifdef DEBUG
		std::cerr << "GloQPro shutdown in ";
#endif
	}
#ifdef PROXYSQLCLICKHOUSE
	if (GloClickHouseAuth) {
		cpu_timer t;
		delete GloClickHouseAuth;
		GloClickHouseAuth=NULL;
#ifdef DEBUG
		std::cerr << "GloClickHouseAuth shutdown in ";
#endif
	}
	if (GloClickHouseServer) {
		cpu_timer t;
		delete GloClickHouseServer;
		GloClickHouseServer=NULL;
#ifdef DEBUG
		std::cerr << "GloClickHouseServer shutdown in ";
#endif
	}
#endif /* PROXYSQLCLICKHOUSE */
	if (GloSQLite3Server) {
		cpu_timer t;
		delete GloSQLite3Server;
		GloSQLite3Server=NULL;
#ifdef DEBUG
		std::cerr << "GloSQLite3Server shutdown in ";
#endif
	}
	if (GloMyAuth) {
		cpu_timer t;
		delete GloMyAuth;
		GloMyAuth=NULL;
#ifdef DEBUG
		std::cerr << "GloMyAuth shutdown in ";
#endif
	}
	if (GloMTH) {
		cpu_timer t;
		pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
		delete GloMTH;
		GloMTH=NULL;
		pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);
#ifdef DEBUG
		std::cerr << "GloMTH shutdown in ";
#endif
	}
	if (GloMyLogger) {
		cpu_timer t;
		delete GloMyLogger;
		GloMyLogger=NULL;
#ifdef DEBUG
		std::cerr << "GloMyLogger shutdown in ";
#endif
	}

	{
#ifdef TEST_WITHASAN
		pthread_mutex_lock(&GloAdmin->sql_query_global_mutex);
#endif
		cpu_timer t;
		delete GloAdmin;
#ifdef DEBUG
		std::cerr << "GloAdmin shutdown in ";
#endif
	}
	{
		cpu_timer t;
		MyHGM->shutdown();
		delete MyHGM;
#ifdef DEBUG
		std::cerr << "GloHGM shutdown in ";
#endif
	}
	if (GloMyStmt) {
		delete GloMyStmt;
		GloMyStmt=NULL;
	}
}

void ProxySQL_Main_init() {
#ifdef DEBUG
	GloVars.global.gdbg=false;
	glovars.has_debug=true;
#else
	glovars.has_debug=false;
#endif /* DEBUG */
//	__thr_sfp=l_mem_init();
	proxysql_init_debug_prometheus_metrics();
}





static void LoadPlugins() {
	GloMyLdapAuth = NULL;
	if (proxy_sqlite3_open_v2 == nullptr) {
		SQLite3DB::LoadPlugin(GloVars.sqlite3_plugin);
	}
	if (GloVars.web_interface_plugin) {
		dlerror();
		char * dlsym_error = NULL;
		dlerror();
		dlsym_error=NULL;
		__web_interface = dlopen(GloVars.web_interface_plugin, RTLD_NOW);
		if (!__web_interface) {
			cerr << "Cannot load library: " << dlerror() << '\n';
			exit(EXIT_FAILURE);
		} else {
			dlerror();
			create_Web_Interface = (create_Web_Interface_t *) dlsym(__web_interface, "create_Web_Interface_func");
			dlsym_error = dlerror();
			if (dlsym_error!=NULL) {
				cerr << "Cannot load symbol create_Web_Interface: " << dlsym_error << '\n';
				exit(EXIT_FAILURE);
			}
		}
		if (__web_interface==NULL || dlsym_error) {
			proxy_error("Unable to load Web_Interface from %s\n", GloVars.web_interface_plugin);
			exit(EXIT_FAILURE);
		} else {
			GloWebInterface = create_Web_Interface();
			if (GloWebInterface) {
				//GloAdmin->init_WebInterfacePlugin();
				//GloAdmin->load_ldap_variables_to_runtime();
			} else {
				proxy_error("Failed to load 'Web_Interface' plugin\n");
			}
		}
	}
	if (GloVars.ldap_auth_plugin) {
		dlerror();
		char * dlsym_error = NULL;
		dlerror();
		dlsym_error=NULL;
		__mysql_ldap_auth = dlopen(GloVars.ldap_auth_plugin, RTLD_NOW);
		if (!__mysql_ldap_auth) {
			cerr << "Cannot load library: " << dlerror() << '\n';
			exit(EXIT_FAILURE);
		} else {
			dlerror();
			create_MySQL_LDAP_Authentication = (create_MySQL_LDAP_Authentication_t *) dlsym(__mysql_ldap_auth, "create_MySQL_LDAP_Authentication_func");
			dlsym_error = dlerror();
			if (dlsym_error!=NULL) {
				cerr << "Cannot load symbol create_MySQL_LDAP_Authentication: " << dlsym_error << '\n';
				exit(EXIT_FAILURE);
			}
		}
		if (__mysql_ldap_auth==NULL || dlsym_error) {
			proxy_error("Unable to load MySQL_LDAP_Authentication from %s\n", GloVars.ldap_auth_plugin);
			exit(EXIT_FAILURE);
		} else {
			GloMyLdapAuth = create_MySQL_LDAP_Authentication();

			if (!GloMyLdapAuth) {
				proxy_error("Failed to load 'MySQL_LDAP_Authentication' plugin\n");
			}

			// we are removing this from here, and copying in
			//     ProxySQL_Main_init_phase2___not_started
			// the keep record of these two lines to make sure we don't
			// do a similar mistakes with other plugins
			//
			//if (GloMyLdapAuth) {
			//	GloAdmin->init_ldap();
			//	GloAdmin->load_ldap_variables_to_runtime();
			//}
		}
	}
}

/**
 * @brief Unloads all the plugins that hold some resources that
 *  need to be deallocated.
 */
void UnloadPlugins() {
	if (GloWebInterface) {
		GloWebInterface->stop();
	}
}

void ProxySQL_Main_init_phase2___not_started(const bootstrap_info_t& boostrap_info) {
	std::string msg;
	ProxySQL_create_or_load_TLS(false, msg);

	LoadPlugins();

	ProxySQL_Main_init_main_modules();
	ProxySQL_Main_init_Admin_module(boostrap_info);
	GloMTH->print_version();

	{
		cpu_timer t;
		GloMyLogger->events_set_datadir(GloVars.datadir);
		GloMyLogger->audit_set_datadir(GloVars.datadir);
#ifdef DEBUG
		std::cerr << "Main phase3 : GloMyLogger initialized in ";
#endif
	}
	if (GloVars.configfile_open) {
		GloVars.confFile->CloseFile();
	}

	if (GloMyLdapAuth) {
		GloAdmin->load_ldap_variables_to_runtime();
	}

	ProxySQL_Main_init_Auth_module();

	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
}


void ProxySQL_Main_init_phase3___start_all() {

	{
		cpu_timer t;
		GloMyLogger->events_set_datadir(GloVars.datadir);
		GloMyLogger->audit_set_datadir(GloVars.datadir);
#ifdef DEBUG
		std::cerr << "Main phase3 : GloMyLogger initialized in ";
#endif
	}
	// Initialized monitor, no matter if it will be started or not
	GloMyMon = new MySQL_Monitor();
	// load all mysql servers to GloHGH
	{
		cpu_timer t;
		GloAdmin->init_mysql_servers();
		GloAdmin->init_proxysql_servers();
		GloAdmin->load_scheduler_to_runtime();
#ifdef DEBUG
		std::cerr << "Main phase3 : GloAdmin initialized in ";
#endif
	}
	{
		cpu_timer t;
		ProxySQL_Main_init_Query_module();
#ifdef DEBUG
		std::cerr << "Main phase3 : Query Processor initialized in ";
#endif
	}
	{
		cpu_timer t;
		ProxySQL_Main_init_MySQL_Threads_Handler_module();
#ifdef DEBUG
		std::cerr << "Main phase3 : MySQL Threads Handler initialized in ";
#endif
	}
	{
		cpu_timer t;
		ProxySQL_Main_init_Query_Cache_module();
#ifdef DEBUG
		std::cerr << "Main phase3 : Query Cache initialized in ";
#endif
	}

	do { /* nothing */
#ifdef DEBUG
		usleep(5+rand()%10);
#endif
	} while (load_ != 1);
	load_ = 0;
	__sync_fetch_and_add(&GloMTH->status_variables.threads_initialized, 1);

	{
		cpu_timer t;
		GloMTH->start_listeners();
#ifdef DEBUG
		std::cerr << "Main phase3 : MySQL Threads Handler listeners started in ";
#endif
	}
	if ( GloVars.global.sqlite3_server == true ) {
		cpu_timer t;
		ProxySQL_Main_init_SQLite3Server();
		sleep(1);
#ifdef DEBUG
		std::cerr << "Main phase3 : SQLite3 Server initialized in ";
#endif
	}
	if (GloVars.global.monitor==true)
		{
			cpu_timer t;
			ProxySQL_Main_init_MySQL_Monitor_module();
#ifdef DEBUG
			std::cerr << "Main phase3 : MySQL Monitor initialized in ";
#endif
		}
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
		cpu_timer t;
		ProxySQL_Main_init_ClickHouseServer();
#ifdef DEBUG
		std::cerr << "Main phase3 : ClickHouse Server initialized in ";
#endif
	}
#endif /* PROXYSQLCLICKHOUSE */

	// LDAP
	if (GloMyLdapAuth) {
		GloAdmin->init_ldap_variables();
	}

	// HTTP Server should be initialized after other modules. See #4510
	GloAdmin->init_http_server();
	GloAdmin->proxysql_restapi().load_restapi_to_runtime();

	// Signal ProxySQL_Admin that all modules have been started
	GloAdmin->all_modules_started = true;

	// Load the config not previously loaded for these modules
	GloAdmin->load_http_server();
	GloAdmin->load_restapi_server();
}



void ProxySQL_Main_init_phase4___shutdown() {
	cpu_timer t;
	ProxySQL_Main_join_all_threads();

	//write(GloAdmin->pipefd[1], &GloAdmin->pipefd[1], 1);	// write a random byte
	if (GloVars.global.nostart) {
		pthread_mutex_unlock(&GloVars.global.start_mutex);
	}

	ProxySQL_Main_shutdown_all_modules();
#ifdef DEBUG
	std::cerr << "Main init phase4 shutdown completed in ";
#endif
}

/**
 * @brief Phase 1 of the daemonization process for ProxySQL.
 *
 * This function performs the first phase of the daemonization process for ProxySQL. It sets up essential parameters
 * and checks for conditions necessary for daemonization. If any of the conditions are not met or if an error occurs,
 * the function logs an error message and exits with a failure status code.
 *
 * @param argv0 The name of the executable file used to start ProxySQL.
 * @return void.
 * @note This function does not return if an error occurs; it exits the process.
 */
void ProxySQL_daemonize_phase1(char *argv0) {
	int rc; // Variable to store the return code of system calls

	// Set the PID file identification to the global PID variable
	daemon_pid_file_ident=GloVars.pid;

	// Set the log identification based on the executable file name
	daemon_log_ident=daemon_ident_from_argv0(argv0);

	// Change the current working directory to the data directory
	rc=chdir(GloVars.datadir);
	if (rc) {
		// Log an error message if changing the directory fails and exit with failure status
		daemon_log(LOG_ERR, "Could not chdir into datadir: %s . Error: %s", GloVars.datadir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Set the PID file process to the ProxySQL PID file
	daemon_pid_file_proc = proxysql_pid_file;

	// Check if ProxySQL is already running by checking the PID file
	pid=daemon_pid_file_is_running();
	if (pid>=0) {
		// Log an error message if ProxySQL is already running and exit with failure status
		daemon_log(LOG_ERR, "Daemon already running on PID file %u", pid);
		exit(EXIT_FAILURE);
	}
	if (daemon_retval_init() < 0) {
		// Initialize the return value for daemonization; log an error if initialization fails
		daemon_log(LOG_ERR, "Failed to create pipe.");
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief Wait for the return value from the daemon process.
 *
 * This function waits for the return value from the daemon process for a specified duration. If the return value is
 * received within the specified time, the function logs the return value. If an error occurs during the waiting process,
 * the function logs an error message and exits with a failure status code.
 *
 * @return void.
 * @note This function does not return if an error occurs; it exits the process.
 */
void ProxySQL_daemonize_wait_daemon() {
	int ret; // Variable to store the return value from daemon_retval_wait()
	// Wait for 20 seconds for the return value passed from the daemon process
	if ((ret = daemon_retval_wait(20)) < 0) {
		// Log an error message if waiting for the return value fails and exit with failure status
		daemon_log(LOG_ERR, "Could not receive return value from daemon process: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// If a return value is received, log it
	if (ret) {
		daemon_log(LOG_ERR, "Daemon returned %i as return value.", ret);
	}

	// Exit with the return value received from the daemon process
	exit(ret);
}


bool ProxySQL_daemonize_phase2() {
	int rc;
/*
	// we DO NOT close FDs anymore. See:
	// https://github.com/sysown/proxysql/issues/2628
	//
	// Close FDs
	if (daemon_close_all(-1) < 0) {
		daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));

		// Send the error condition to the parent process
		daemon_retval_send(1);
		return false;
	}
*/

	rc=chdir(GloVars.datadir);
	if (rc) {
		daemon_log(LOG_ERR, "Could not chdir into datadir: %s . Error: %s", GloVars.datadir, strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* Create the PID file */
	if (daemon_pid_file_create() < 0) {
		daemon_log(LOG_ERR, "Could not create PID file (%s).", strerror(errno));
		daemon_retval_send(2);
		return false;
	}

	/* Send OK to parent process */
	daemon_retval_send(0);
	GloAdmin->flush_error_log();
	//daemon_log(LOG_INFO, "Starting ProxySQL\n");
	//daemon_log(LOG_INFO, "Sucessfully started");
	proxy_info("Starting ProxySQL\n");
	proxy_info("Successfully started\n");
	return true;
}

/**
 * @brief Calls an external script upon exit failure.
 *
 * This function attempts to execute an external script specified in the global variable `GloVars.execute_on_exit_failure`
 * if the program exits due to failure. It first checks if the variable is set, and if not, returns without further action.
 * If the variable is set, it attempts to fork a child process to execute the script. If forking fails, the function exits
 * with failure status. If forking succeeds, the child process attempts to execute the script using the `system` function.
 * If the script execution fails, an error message is logged, and the child process exits with failure status. Otherwise, the
 * child process exits with success status. Additionally, the function creates a detached thread to wait for the child process
 * to exit, ensuring that the parent process does not block. If thread creation fails, the function logs an error message and
 * exits with failure status.
 *
 * @return void.
 * @note This function does not return if an error occurs; it exits the process.
 */
void call_execute_on_exit_failure() {
	// Log a message indicating the attempt to call the external script
	proxy_info("Trying to call external script after exit failure: %s\n", GloVars.execute_on_exit_failure ? GloVars.execute_on_exit_failure : "(null)");

	// Check if the global variable execute_on_exit_failure is NULL
	if (GloVars.execute_on_exit_failure == NULL) {
		// Exit the function if the variable is not set
		return;
	}

	// Fork a child process
	pid_t cpid;
	cpid = fork();

	// Check for fork failure
	if (cpid == -1) {
		// Exit with failure status if fork fails
		exit(EXIT_FAILURE);
	}

	// Child process
	if (cpid == 0) {
		int rc;
		// Execute the external script
		rc = system(GloVars.execute_on_exit_failure);

		// Check if script execution failed
		if (rc) {
			// Log an error message and exit with failure status if execution fails
			proxy_error("Execute on EXIT_FAILURE: Failed to run %s\n", GloVars.execute_on_exit_failure);
			perror("system()");
			exit(EXIT_FAILURE);
		} else {
			// Exit with success status if script execution succeeds
			exit(EXIT_SUCCESS);
		}
	}
	// Parent process
	else {
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize (&attr, 64*1024);
		pid_t *cpid_ptr=(pid_t *)malloc(sizeof(pid_t));
		*cpid_ptr=cpid;
		pthread_t thr;

		// Create a detached thread to wait for the child process to exit
		if (pthread_create(&thr, &attr, waitpid_thread, (void *)cpid_ptr) !=0 ) {
			perror("Thread creation");
			exit(EXIT_FAILURE);
		}
	}
}


bool ProxySQL_daemonize_phase3() {
	int rc;
	int status;
	//daemon_log(LOG_INFO, "Angel process started ProxySQL process %d\n", pid);
	parent_open_error_log();
	proxy_info("Angel process started ProxySQL process %d\n", pid);
	parent_close_error_log();
	rc=waitpid(pid, &status, 0);
	if (rc==-1) {
		parent_open_error_log();
		perror("waitpid");
		//proxy_error("[FATAL]: waitpid: %s\n", perror("waitpid"));
		exit(EXIT_FAILURE);
	}
	rc=WIFEXITED(status);
	if (rc) { // client exit()ed
		rc=WEXITSTATUS(status);
		if (rc==0) {
			//daemon_log(LOG_INFO, "Shutdown angel process\n");
			parent_open_error_log();
			proxy_info("Shutdown angel process\n");
			exit(EXIT_SUCCESS);
		} else {
			//daemon_log(LOG_INFO, "ProxySQL exited with code %d . Restarting!\n", rc);
			parent_open_error_log();
			proxy_error("ProxySQL exited with code %d . Restarting!\n", rc);
			call_execute_on_exit_failure();
			parent_close_error_log();
			return false;
		}
	} else {
		//daemon_log(LOG_INFO, "ProxySQL crashed. Restarting!\n");
		parent_open_error_log();
		proxy_error("ProxySQL crashed. Restarting!\n");
		proxy_info("ProxySQL version %s\n", PROXYSQL_VERSION);
		if (binary_sha1) {
			proxy_info("ProxySQL SHA1 checksum: %s\n", binary_sha1);
		}
		call_execute_on_exit_failure();
		// automatic reload of TLS certificates after a crash , see #4658
		std::string msg;
		ProxySQL_create_or_load_TLS(false, msg);
		//  Honor --initial after a crash , see #4659
		if (GloVars.__cmd_proxysql_initial==true) {
			std::cerr << "Renaming database file " << GloVars.admindb << endl;
			char *newpath=(char *)malloc(strlen(GloVars.admindb)+8);
			sprintf(newpath,"%s.bak",GloVars.admindb);
			rename(GloVars.admindb,newpath);	// FIXME: should we check return value, or ignore whatever it successed or not?
		}
		parent_close_error_log();
		return false;
	}
	return true;
}

void my_terminate(void) {
	proxy_error("ProxySQL crashed due to exception\n");
	print_backtrace();
}

namespace {
	static const bool SET_TERMINATE = std::set_terminate(my_terminate);
}

/**
 * @brief Regex for parsing URI connections.
 * @details Groups explanation:
 *  + HierPart doesn't hold '//' making previous non-capturing group optional. E.g:
 *     - '127.0.0.1:3306'
 *     - 'mysql-server-1:3306'
 *  + UserInfo is inside a non-capturing group to avoid matching '@'.
 *  + Host,Port groups are inside a non-capturing group to allow URI like: 'mysql://user:pass@'
 *  + RegName matches any valid Ipv4 or domain name.
 *  + Ipv6 matches Ipv6, it's NOT spec conforming, we don't verify the supplied Ip in the regex.
 *  + Port matches the supplied port.
 *  + Optionally match a supplied (/).
 *  + Ensure match termination in HierPart group, forcing conditional subgroups matching.
 */
const char CONN_URI_REGEX[] {
	"^(:?(?P<Scheme>[a-z][a-z0-9\\+\\-\\.]*):\\/\\/)?"
	"(?P<HierPart>"
		"(?:(?P<UserInfo>(?:\\%[0-9a-f][0-9a-f]|[a-z0-9\\-\\.\\_\\~]|[\\!\\$\\&\\'\\(\\)\\*\\+\\,\\;\\=]|\\:)*)\\@)?"
		"(:?"
			"(?P<Host>"
				"(?P<RegName>(?:\\%[0-9a-f][0-9a-f]|[a-z0-9\\-\\.\\_\\~]|[\\!\\$\\&\\'\\(\\)\\*\\+\\,\\;\\=]])*)|"
				"(?P<Ipv6>\\[(?:[0-9a-f]|[\\:])*\\]))"
			"(?:\\:(?P<Port>[0-9]+)?)?"
		")?"
		"(?:\\/)?"
	")?$"
};

/**
 * @brief Holds each of the groups matched in a string by 'CONN_URI_REGEX'.
 */
struct conn_uri_t {
	string scheme;
	string hierpart;
	string user;
	string pass;
	string host;
	uint32_t port;
};

/**
 * @brief Uses Regex 'CONN_URI_REGEX' to parse the supplied string.
 * @details Tries to perform a 'PartialMatchN' over the 'CONN_URI_REGEX'. Right now doesn't perform a *full*
 *   check on the validity of the semantics of the URI itself. It does perform some checks.
 * @param conn_uri A connection URI.
 * @return On success `{EXIT_SUCCESS, conn_uri_t}`, otherwise `{EXIT_FAILURE, conn_uri_t{}}`. Error cause is
 *   logged.
 */
pair<int,conn_uri_t> parse_conn_uri(const string& conn_uri) {
	re2::RE2::Options opts(RE2::Quiet);
	opts.set_case_sensitive(false);

	re2::RE2 re(CONN_URI_REGEX, opts);;
	if (re.error_code()) {
		proxy_error("Regex creation failed - %s\n", re.error().c_str());
		assert(0);
	}

	const int num_groups = re.NumberOfCapturingGroups();
	std::vector<std::string> str_args(num_groups, std::string {});
	std::vector<RE2::Arg> re2_args {};

	for (std::string& str_arg : str_args) {
		re2_args.push_back(RE2::Arg(&str_arg));
	}

	std::vector<const RE2::Arg*> matches {};
	for (RE2::Arg& re2_arg : re2_args) {
		matches.push_back(&re2_arg);
	}

	const re2::RE2::Arg* const* args = &matches[0];
	RE2::PartialMatchN(conn_uri, re, args, num_groups);

	const map<string, int>& groups = re.NamedCapturingGroups();
	map<string,int>::const_iterator group_it;

	string scheme {};
	string hierpart {};
	string userinfo {};
	string host {};
	uint32_t port = 0;

	if ((group_it = groups.find("Scheme")) != groups.end()) { scheme = str_args[group_it->second - 1]; }
	if ((group_it = groups.find("HierPart")) != groups.end()) { hierpart = str_args[group_it->second - 1]; }
	if ((group_it = groups.find("UserInfo")) != groups.end()) { userinfo = str_args[group_it->second - 1]; }
	if ((group_it = groups.find("Host")) != groups.end()) { host = str_args[group_it->second - 1]; }

	// Remove the enclosing(`[]`) from IPv6 addresses
	if (host.empty() == false && host.size() > 2) {
		if (host[0] == '[') {
			host = host.substr(1, host.size()-2);
		}
	}

	string user {};
	string pass {};

	int32_t match_err = EXIT_SUCCESS;

	// Extract supplied info for user:pass
	vector<string> v_userinfo = split_str(userinfo, ':');
	if (v_userinfo.size() == 1) {
		user = v_userinfo[0];
	} else if (v_userinfo.size() == 2) {
		user = v_userinfo[0];
		pass = v_userinfo[1];
	} else if (v_userinfo.size() > 2) {
		proxy_error(
			"Invalid UserInfo '%s' supplied in connection URI. UserInfo should contain at max two fields 'user:pass'\n",
			userinfo.c_str()
		);
		match_err = EXIT_FAILURE;
	}

	if ((group_it = groups.find("Port")) != groups.end()) {
		const string s_port { str_args[group_it->second - 1] };

		if (!s_port.empty()) {
			char* p_end = nullptr;
			port = std::strtol(s_port.c_str(), &p_end, 10);

			if (errno == ERANGE || p_end == s_port.c_str()) {
				proxy_error("Invalid Port '%s' supplied in connection URI.\n", s_port.c_str());
				match_err = EXIT_FAILURE;
			}
		}
	}

	struct conn_uri_t uri_data { scheme, hierpart, user, pass, host, port };

	return { match_err, uri_data };
}

/**
 * @brief Helper function to serialize 'conn_uri_t' for debugging purposes.
 */
string to_string(const conn_uri_t& conn_uri) {
	nlohmann::ordered_json j;

	j["scheme"] = conn_uri.scheme;
	j["user"] = conn_uri.user;
#ifdef DEBUG
	j["pass"] = conn_uri.pass;
#endif
	j["host"] = conn_uri.host;
	j["port"] = conn_uri.port;

	return j.dump();
}

/**
 * @brief Query for fetching MySQL users during bootstrapping.
 * @details For security reasons, users matching the following names are excluded:
 *   - `mysql.%`
 *   - `root`
 *   - `bt_proxysql_%`
 *   Users starting with `bt_proxysql_` are considered `ProxySQL` created used during `bootstrap` for
 *   monitoring purposes. A user, could create it's own monitoring accounts under this prefix, to avoid
 *   ProxySQL fetching them as regular users.
 */
const char BOOTSTRAP_SELECT_USERS[] {
	"SELECT DISTINCT user,ssl_type,authentication_string,plugin,password_expired FROM mysql.user"
		" WHERE user NOT LIKE 'mysql.%' AND user NOT LIKE 'bt_proxysql_%'"
#ifndef DEBUG
		" AND user != 'root'"
#endif
};

/**
 * @brief Query for fetching MySQL servers during bootstrapping.
 * @details As the regular GR monitoring queries, makes use of `replication_group_members` table.
 */
const char BOOTSTRAP_SELECT_SERVERS[] {
	"SELECT MEMBER_ID,MEMBER_HOST,MEMBER_PORT,MEMBER_STATE,MEMBER_ROLE,MEMBER_VERSION FROM"
		" performance_schema.replication_group_members"
};

/**
 * @brief Stores credentials for monitoring created accounts during bootstrap.
 */
struct acct_creds_t {
	string user;
	string pass;
};

/**
 * @brief Minimal set of permissions for a created GR monitoring account.
 * @details Right now we **do not grant** permissions to `mysql_innodb_cluster_metadata` tables, since for now
 *   we don't make any use of them.
 */
const vector<string> t_grant_perms_queries {
	"GRANT USAGE ON *.* TO `%s`@`%%`",
//  NOTE: For now, we don't make use of any `mysql_innodb_cluster_metadata` tables
//	"GRANT SELECT, EXECUTE ON `mysql_innodb_cluster_metadata`.* TO `%s`@`%%`",
//  NOTE: For now, we don't make use of 'routers' and 'v2_routers' table
//	"GRANT INSERT, UPDATE, DELETE ON `mysql_innodb_cluster_metadata`.`routers` TO `%s`@`%%`",
//	"GRANT INSERT, UPDATE, DELETE ON `mysql_innodb_cluster_metadata`.`v2_routers` TO `%s`@`%%`",
	"GRANT SELECT ON `performance_schema`.`global_variables` TO `%s`@`%%`",
	"GRANT SELECT ON `performance_schema`.`replication_group_member_stats` TO `%s`@`%%`",
	"GRANT SELECT ON `performance_schema`.`replication_group_members` TO `%s`@`%%`"
};

/**
 * @brief Grants the minimal set of permissions for GR monitoring to a supplies user.
 * @details All permissions will be granted for host `%`.
 * @param mysql An already opened MySQL connection.
 * @param user The username to grant permissions to.
 * @return Either `0` for success, or the corresponding `mysql_errno` for failure.
 */
int grant_user_perms(MYSQL* mysql, const string& user) {
	for (const string& t_query : t_grant_perms_queries) {
		const string query { cstr_format(t_query.c_str(), user.c_str()).str };

		proxy_info("GRANT permissions '%s' to user\n", query.c_str());
		int myerr = mysql_query(mysql, query.c_str());
		if (myerr) {
			return mysql_errno(mysql);
		}
	}

	return 0;
}

/**
 * @brief Generates a random password conforming with MySQL 'MEDIUM' policy.
 * @param size The target password size.
 * @return The random password generated.
 */
string gen_rand_password(std::size_t size) {
	const string lowercase { "abcdefghijklmnopqrstuvwxyz" };
	const string uppercase { "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
	const string digits { "0123456789" };
	const string symbols { "~@#$^&*]}[{()|-=+;:.>,</?" };
	string allphabet { lowercase + uppercase + digits + symbols };

	std::random_device rd {};
	std::mt19937 gen { rd() };

	string pass {};

	if (size == 0) {
		return pass;
	} else if (size <= 4) {
		std::shuffle(allphabet.begin(), allphabet.end(), gen);
		pass = allphabet.substr(0, size);
	} else {
		// 1 numeric character
		pass += digits[gen() % digits.size()];
		// 1 lowercase character
		pass += lowercase[gen() % lowercase.size()];
		// 1 uppercase character
		pass += toupper(lowercase[gen() % lowercase.size()]);
		// 1 special (nonalphanumeric) character
		pass += symbols[gen() % symbols.size()];

		std::shuffle(allphabet.begin(), allphabet.end(), gen);
		std::size_t remains = size - 4;

		if (remains < allphabet.size()) {
			pass += allphabet.substr(0, remains);
		} else {
			std::size_t req_modulus = static_cast<std::size_t>(remains / allphabet.size());
			std::size_t req_reminder = remains % allphabet.size();

			for (std::size_t i = 0; i < req_modulus; i++) {
				std::shuffle(allphabet.begin(), allphabet.end(), gen);
				pass += allphabet;
			}

			std::shuffle(allphabet.begin(), allphabet.end(), gen);
			pass += allphabet.substr(0, req_reminder);
		}
	}

	return pass;
}

/**
 * @brief Creates a random monitoring account for bootstrap with a random generated password.
 * @param mysql An already opened MySQL connection.
 * @param max_retries Maximum number of attempts for creating the user.
 * @return On success `{0, acct_creds_t}`, otherwise `{mysql_errno, acct_creds_t{}}`. Error cause is logged.
 */
pair<int32_t,acct_creds_t> create_random_bootstrap_account(MYSQL* mysql, uint32_t max_retries) {
	// Random username
	const string monitor_user { "bt_proxysql_" + rand_str(12) };
	string monitor_pass {};

	int myerr = ER_NOT_VALID_PASSWORD;
	uint32_t retries = 0;

	while (retries < max_retries && (myerr == ER_NOT_VALID_PASSWORD)) {
		monitor_pass = gen_rand_password(16);

		const string user_create {
			"CREATE USER IF NOT EXISTS '" + monitor_user + "'@'%' IDENTIFIED BY '" + monitor_pass + "'"
		};

		int myres = mysql_query(mysql, user_create.c_str());
		myerr = mysql_errno(mysql);

		if (myres || myerr) {
			if (myerr != ER_NOT_VALID_PASSWORD) {
				return { myerr, { "", "" } };
			} else {
				proxy_info(
					"Bootstrap config, failed to create password for user '%s'. Retrying...\n", monitor_user.c_str()
				);
				retries += 1;
			}
		} else {
			break;
		}
	}

	if (myerr == 0) {
		myerr = grant_user_perms(mysql, monitor_user);
	}

	return { myerr, { monitor_user, monitor_pass } };
}

/**
 * @brief Creates a monitoring account for bootstrap with the supplied parameters.
 * @param mysql An already opened MySQL connection.
 * @param user The username for the new account.
 * @param pass The password for the new account.
 * @return On success `{0,acct_creds_t}`, otherwise `{mysql_errno,acct_creds_t}`. Doesn't log errors.
 */
pair<int32_t,acct_creds_t> create_bootstrap_account(MYSQL* mysql, const string& user, const string& pass) {
	const string monitor_user { "'" + user + "'" };
	const string user_create {
		"CREATE USER IF NOT EXISTS " + monitor_user + "@'%' IDENTIFIED BY '" + pass + "'"
	};

	int myerr = mysql_query(mysql, user_create.c_str());

	if (myerr == 0) {
		myerr = grant_user_perms(mysql, user);
	}

	return { myerr, { user, pass } };
}


/**
 * @brief This function handles the restart of a process based on certain conditions.
 * 
 * If glovars.proxy_restart_on_error is true, the process restart logic is executed.
 * The function implements exponential backoff and terminates if the maximum number of restart attempts is reached.
 */
void handleProcessRestart() {
	// Maximum number of restart attempts allowed
	constexpr int MAX_RESTART_ATTEMPTS = 5;
	// Threshold in seconds for considering restarts too frequent
	constexpr int EXECUTION_THRESHOLD = 10;

	// Initialize restart attempts counter
	time_t laststart = 0;
	int restartAttempts = 0;
	do {
		// Check if laststart is set. It means that the process was already started at least once
		if (laststart) {
			// Get current time
			time_t currenttime = time(NULL);
			// Calculate elapsed time since laststart
			time_t elapsed_seconds = currenttime - laststart;

			// Check if elapsed time is less than threshold
			if (elapsed_seconds < EXECUTION_THRESHOLD) {
				// if restart is too frequent, something really bad is going on
				// Implement exponential backoff - wait exponentially longer after each failed attempt
				restartAttempts++;

				// Check if restart attempts exceed the maximum allowed
				if (restartAttempts > MAX_RESTART_ATTEMPTS) {
					// the parent exits before the fork
					parent_open_error_log();
					proxy_error("Angel process already attempted to restart ProxySQL %d times and has no retries left. exit() with failure.\n", MAX_RESTART_ATTEMPTS);
					exit(EXIT_FAILURE);
				}

				// Calculate wait time using exponential backoff
				int waitTime = 1 << restartAttempts;
				parent_open_error_log();
				proxy_info("ProxySQL exited after only %ld seconds , below the %d seconds threshold. Restarting attempt %d\n", elapsed_seconds, EXECUTION_THRESHOLD, restartAttempts);
				proxy_info("Angel process is waiting %d seconds before starting a new ProxySQL process\n", waitTime);
				parent_close_error_log();

				// Wait for the calculated time before next restart attempt
				sleep(waitTime);
			} else {
				// Reset restart attempts counter if elapsed time is greater than or equal to threshold
				restartAttempts = 0;
			}
		}

		// Update laststart time to current time
		laststart=time(NULL);

		// Fork the process
		pid = fork();

		// Check for fork error
		if (pid < 0) {
			parent_open_error_log();
			proxy_error("[FATAL]: Error in fork()\n");

			// Exit with failure
			exit(EXIT_FAILURE);
		}

		// Check if the process is the parent
		if (pid) { // The parent
			parent_close_error_log();
			if (ProxySQL_daemonize_phase3()==true) {
				break;
			}
		} else { // The daemon
			// we open the files also on the child process
			// this is required if the child process was created after a crash
			parent_open_error_log();
			GloVars.global.start_time=monotonic_time();
			GloVars.install_signal_handler();
		}
	} while (pid > 0);
}

#ifndef NOJEM
int print_jemalloc_conf() {
	int rc = 0;

	bool xmalloc = 0;
	bool prof_accum = 0;
	bool prof_leak = 0;

	size_t lg_cache_max = 0;
	size_t lg_prof_sample = 0;
	size_t lg_prof_interval = 0;

	size_t bool_sz = sizeof(bool);
	size_t size_sz = sizeof(size_t);
	size_t ssize_sz = sizeof(ssize_t);

	rc = mallctl("config.xmalloc", &xmalloc, &bool_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'config.xmalloc' with error %d", rc); return rc; }

	rc = mallctl("opt.lg_tcache_max", &lg_cache_max, &size_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'opt.lg_tcache_max' with error %d", rc);  return rc; }

	rc = mallctl("opt.prof_accum", &prof_accum, &bool_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'opt.prof_accum' with error %d", rc); return rc; }

	rc = mallctl("opt.prof_leak", &prof_leak, &bool_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'opt.prof_leak' with error %d", rc);  return rc; }

	rc = mallctl("opt.lg_prof_sample", &lg_prof_sample, &size_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'opt.lg_prof_sample' with error %d", rc);  return rc; }

	rc = mallctl("opt.lg_prof_interval", &lg_prof_interval, &ssize_sz, NULL, 0);
	if (rc) { proxy_error("Failed to fetch 'opt.lg_prof_interval' with error %d", rc);  return rc; }

	proxy_info(
		"Using jemalloc with MALLOC_CONF:"
			" config.xmalloc:%d, lg_tcache_max:%lu, opt.prof_accum:%d, opt.prof_leak:%d,"
			" opt.lg_prof_sample:%lu, opt.lg_prof_interval:%lu, rc:%d\n",
		xmalloc, lg_cache_max, prof_accum, prof_leak, lg_prof_sample, lg_prof_interval, rc
	);

	return 0;
}
#else
int print_jemalloc_conf() {
	return 0;
}
#endif

int main(int argc, const char * argv[]) {
#ifdef DEBUG
	{
		// This run some ProxyProtocolInfo tests.
		// It will assert() if any test fails
		ProxyProtocolInfo ppi;
		ppi.run_tests();
	}
#endif // DEBUG

	{
		MYSQL *my = mysql_init(NULL);
		mysql_close(my);
//		cpu_timer t;
		ProxySQL_Main_init();
#ifdef DEBUG
//		std::cerr << "Main init phase0 completed in ";
#endif
	}
#ifdef DEBUG
	{
		// Automated testing
		SetParser parser("");
		parser.test_parse_USE_query();
	}
#endif // DEBUG
	{
		cpu_timer t;
		ProxySQL_Main_process_global_variables(argc, argv);
		GloVars.global.start_time=monotonic_time(); // always initialize it
		srand(GloVars.global.start_time*thread_id());
		randID = rand();
#ifdef DEBUG
		std::cerr << "Main init global variables completed in ";
#endif
	}

	// Output current jemalloc conf; no action taken when disabled
	{
		int rc = print_jemalloc_conf();
		if (rc) { exit(EXIT_FAILURE); }
	}

	struct rlimit nlimit;
	{
		int rc = getrlimit(RLIMIT_NOFILE, &nlimit);
		if (rc == 0) {
			proxy_info("Current RLIMIT_NOFILE: %lu\n", nlimit.rlim_cur);
			if (nlimit.rlim_cur <= 1024) {
				proxy_error("Current RLIMIT_NOFILE is very low: %lu .  Tune RLIMIT_NOFILE correctly before running ProxySQL\n", nlimit.rlim_cur);
				if (nlimit.rlim_max > nlimit.rlim_cur) {
					if (nlimit.rlim_max >= 102400) {
						nlimit.rlim_cur = 102400;
					} else {
						nlimit.rlim_cur = nlimit.rlim_max;
					}
					proxy_warning("Automatically setting RLIMIT_NOFILE to %lu\n", nlimit.rlim_cur);
					rc = setrlimit(RLIMIT_NOFILE, &nlimit);
					if (rc) {
						proxy_error("Unable to increase RLIMIT_NOFILE: %s: \n", strerror(errno));
					}
				} else {
					proxy_error("Unable to increase RLIMIT_NOFILE because rlim_max is low: %lu\n", nlimit.rlim_max);
				}
			}
		} else {
			proxy_error("Call to getrlimit failed: %s\n", strerror(errno));
		}
	}

	bootstrap_info_t bootstrap_info {};
	// Try to connect to MySQL for performing the bootstrapping process:
	//   - If data isn't found we perform the bootstrap process.
	//   - If non-empty datadir is present, reconfiguration should be performed.
	if (GloVars.global.gr_bootstrap_mode == 1) {
		// Check the other required arguments for performing the bootstrapping process:
		//  - Username
		//  - Password - asked by prompt or supplied
		//  - Connection string parsing is required
		const string conn_uri { GloVars.global.gr_bootstrap_uri };
		const pair<int32_t,conn_uri_t> parse_uri_res { parse_conn_uri(conn_uri) };
		const conn_uri_t uri_data = parse_uri_res.second;

		if (parse_uri_res.first == EXIT_FAILURE) {
			proxy_info("Aborting bootstrap due to failed to parse or match URI - `%s`\n", to_string(uri_data).c_str());
			exit(parse_uri_res.first);
		} else {
			proxy_info("Bootstrap connection data supplied via URI - `%s`\n", to_string(uri_data).c_str());
		}

		const char* c_host = uri_data.host.c_str();
		const char* c_user = uri_data.user.empty() ? "root" : uri_data.user.c_str();
		const char* c_pass = nullptr;
		uint32_t port = uri_data.port == 0 ? 3306 : uri_data.port;
		uint32_t flags = CLIENT_SSL;

		nlohmann::ordered_json conn_data { { "host", c_host }, { "user", c_user }, { "port", port } };
		proxy_info("Performing bootstrap connection using URI data and defaults - `%s`\n", conn_data.dump().c_str());

		if (uri_data.pass.empty()) {
			c_pass = getpass("Enter password: ");
		} else {
			c_pass = uri_data.pass.c_str();
		}

		MYSQL* mysql = mysql_init(NULL);

		// SSL explicitly disabled by user for backend connections
		if (GloVars.global.gr_bootstrap_ssl_mode) {
			if (!strcasecmp(GloVars.global.gr_bootstrap_ssl_mode, "DISABLED")) {
				flags = 0;
			}
		}

		if (flags == CLIENT_SSL) {
			mysql_ssl_set(
				mysql,
				GloVars.global.gr_bootstrap_ssl_key,
				GloVars.global.gr_bootstrap_ssl_cert,
				GloVars.global.gr_bootstrap_ssl_ca,
				GloVars.global.gr_bootstrap_ssl_capath,
				GloVars.global.gr_bootstrap_ssl_cipher
			);
		}

		if (!mysql_real_connect(mysql, c_host, c_user, c_pass, nullptr, port, NULL, flags)) {
			proxy_error("Bootstrap failed, connection error '%s'\n", mysql_error(mysql));
			exit(EXIT_FAILURE);
		}

		if (uri_data.pass.empty()) {
			uint32_t passlen = strlen(c_pass);
			memset(static_cast<void*>(const_cast<char*>(c_pass)), 0, passlen);
		}

		// Get server default collation and version directly from initial handshake
		bootstrap_info.server_language = mysql->server_language;
		bootstrap_info.server_version = mysql->server_version;

		// Fetch all required data for Bootstrap
		int myrc = mysql_query(mysql, BOOTSTRAP_SELECT_SERVERS);

		if (myrc) {
			proxy_error("Bootstrap failed, query failed with error - %s\n", mysql_error(mysql));
			exit(EXIT_FAILURE);
		}

		MYSQL_RES* myres_members = mysql_store_result(mysql);

		if (myres_members == nullptr || mysql_num_rows(myres_members) == 0) {
			proxy_error("Bootstrap failed, expected server %s:%d to have Group Replication configured\n", c_host, port);
			exit(EXIT_FAILURE);
		}

		myrc = mysql_query(mysql, BOOTSTRAP_SELECT_USERS);

		if (myrc) {
			proxy_error("Bootstrap failed, query failed with error - %s\n", mysql_error(mysql));
			exit(EXIT_FAILURE);
		}

		MYSQL_RES* myres_users = mysql_store_result(mysql);

		if (myres_users == nullptr) {
			proxy_error("Bootstrap failed, storing resultset failed with error - %s\n", mysql_error(mysql));
			exit(EXIT_FAILURE);
		}

		// TODO-NOTE: Maybe further data verification should be performed here; bootstrap-info holding final types
		bootstrap_info.servers = myres_members;
		bootstrap_info.users = myres_users;

		// Setup a bootstrap account - monitoring
		const string account_create_policy {
			GloVars.global.gr_bootstrap_account_create == nullptr ? "if-not-exists" :
				GloVars.global.gr_bootstrap_account_create
		};

		if (GloVars.global.gr_bootstrap_account == nullptr && GloVars.global.gr_bootstrap_account_create != nullptr) {
			proxy_error("Bootstrap failed, option '--account-create' can only be used in combination with '--account'\n");
			exit(EXIT_FAILURE);
		}

		const uint32_t password_retries = GloVars.global.gr_bootstrap_password_retries;
		string new_mon_user {};
		string new_mon_pass {};

		if (GloVars.global.gr_bootstrap_account != nullptr) {
			const vector<string> valid_policies { "if-not-exists", "always", "never" };
			if (std::find(valid_policies.begin(), valid_policies.end(), account_create_policy) == valid_policies.end()) {
				proxy_error("Bootstrap failed, unknown '--account-create' option '%s'\n", account_create_policy.c_str());
				exit(EXIT_FAILURE);
			}

			// Since an account has been specified, we require the password for the account
			const string mon_user { GloVars.global.gr_bootstrap_account };
			const string get_acc_pass_msg { "Please enter MySQL password for " + mon_user + ": " };

			// Get the account pass directly from user input
			const string mon_pass = getpass(get_acc_pass_msg.c_str());

			// 1. Check if account exists
			const string get_user_cnt { "SELECT COUNT(*) FROM mysql.user WHERE user='" + mon_user + "'" };
			int cnt_err = mysql_query(mysql, get_user_cnt.c_str());
			MYSQL_RES* myres = mysql_store_result(mysql);

			if (cnt_err || myres == nullptr) {
				proxy_error("Bootstrap failed, detecting count existence failed with error - %s\n", mysql_error(mysql));
				exit(EXIT_FAILURE);
			}

			MYSQL_ROW myrow = mysql_fetch_row(myres);
			uint32_t acc_exists = atoi(myrow[0]);
			mysql_free_result(myres);

			if (account_create_policy == "if-not-exists") {
				// 2. Account doesn't exists, create new account. Otherwise reuse current
				if (acc_exists == 0) {
					pair<int32_t,acct_creds_t> new_creds { create_bootstrap_account(mysql, mon_user, mon_pass) };

					if (new_creds.first) {
						proxy_error("Bootstrap failed, user creation failed with error - %s\n", mysql_error(mysql));
						exit(EXIT_FAILURE);
					} {
						// Store the credentials as the new 'monitor' ones.
						new_mon_user = mon_user;
						new_mon_pass = new_creds.second.pass;
					}
				} else {
					new_mon_user = mon_user;
					new_mon_pass = mon_pass;
				}
			} else if (account_create_policy == "always") {
				if (acc_exists == 0) {
					pair<int32_t,acct_creds_t> new_creds { create_bootstrap_account(mysql, mon_user, mon_pass) };

					if (new_creds.first) {
						proxy_error("Bootstrap failed, user creation failed with error - %s\n", mysql_error(mysql));
						exit(EXIT_FAILURE);
					}
				} else {
					proxy_error(
						"Bootstrap failed, account '%s' already exists but supplied option '--account-create=\"always\"'\n",
						mon_user.c_str()
					);
					exit(EXIT_FAILURE);
				}

				new_mon_user = mon_user;
				new_mon_pass = mon_pass;
			} else if (account_create_policy == "never") {
				if (acc_exists == 0) {
					proxy_error(
						"Bootstrap failed, account '%s' doesn't exists but supplied option '--account-create=\"never\"'\n",
						mon_user.c_str()
					);
					exit(EXIT_FAILURE);
				}

				new_mon_user = mon_user;
				new_mon_pass = mon_pass;
			} else {
				proxy_error("Bootstrap failed, unknown '--account-create' option '%s'\n", account_create_policy.c_str());
				exit(EXIT_FAILURE);
			}
		} else {
			string prev_bootstrap_user {};
			string prev_bootstrap_pass {};

			if (Proxy_file_exists(GloVars.admindb)) {
				SQLite3DB::LoadPlugin(GloVars.sqlite3_plugin);
				SQLite3DB* configdb = new SQLite3DB();
				configdb->open((char*)GloVars.admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

				{
					const char check_table[] {
						"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bootstrap_variables'"
					};

					int table_exists = 0;

					char* error = nullptr;
					int cols = 0;
					int affected_rows = 0;
					SQLite3_result* resultset = NULL;

					configdb->execute_statement(check_table, &error , &cols , &affected_rows , &resultset);

					if (error == nullptr && resultset) {
						table_exists = atoi(resultset->rows[0]->fields[0]);
						delete resultset;
					} else {
						const char* err_msg = error != nullptr ? error : "Empty resultset";
						proxy_error("Bootstrap failed, query failed with error - %s", err_msg);
						exit(EXIT_FAILURE);
					}

					if (table_exists != 0) {
						const char query_user_pass[] {
							"SELECT variable_name,variable_value FROM bootstrap_variables"
								" WHERE variable_name='bootstrap_username' OR variable_name='bootstrap_password'"
								" ORDER BY variable_name"
						};
						configdb->execute_statement(query_user_pass, &error, &cols, &affected_rows, &resultset);

						if (resultset->rows.size() != 0) {
							prev_bootstrap_user = resultset->rows[1]->fields[1];
							prev_bootstrap_pass = resultset->rows[0]->fields[1];
						}

						if (resultset) {
							delete resultset;
						}
					}
				}

				delete configdb;
			}

			if (!prev_bootstrap_pass.empty() && !prev_bootstrap_user.empty()) {
				proxy_info(
					"Bootstrap info, detected previous bootstrap user '%s' reusing account...\n",
					prev_bootstrap_user.c_str()
				);

				new_mon_user = prev_bootstrap_user;
				new_mon_pass = prev_bootstrap_pass;
			} else {
				// Create random account with random password
				pair<int32_t,acct_creds_t> mon_creds { create_random_bootstrap_account(mysql, password_retries) };

				if (mon_creds.first) {
					proxy_error(
						"Bootstrap failed, user creation '%s' failed with error - %s\n",
						mon_creds.second.user.c_str(), mysql_error(mysql)
					);
					exit(EXIT_FAILURE);
				} else {
					new_mon_user = mon_creds.second.user;
					new_mon_pass = mon_creds.second.pass;
					bootstrap_info.rand_gen_user = true;
				}
			}
		}

		bootstrap_info.mon_user = new_mon_user;
		bootstrap_info.mon_pass = new_mon_pass;

		mysql_close(mysql);
	}

	{
		cpu_timer t;
		ProxySQL_Main_init_SSL_module();
#ifdef DEBUG
		std::cerr << "Main SSL init variables completed in ";
#endif
	}

	{
		cpu_timer t;
		int fd = -1;
		char buff[PATH_MAX+1];
		ssize_t len = -1;
#if defined(__FreeBSD__)
		len = readlink("/proc/curproc/file", buff, sizeof(buff)-1);
#else
		len = readlink("/proc/self/exe", buff, sizeof(buff)-1);
#endif
		if (len != -1) {
			buff[len] = '\0';
			fd = open(buff, O_RDONLY);
		}
		if(fd >= 0) {
			struct stat statbuf;
			if(fstat(fd, &statbuf) == 0) {
				unsigned char *fb = (unsigned char *)mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
				if (fb != MAP_FAILED) {
					unsigned char temp[SHA_DIGEST_LENGTH];
					SHA1(fb, statbuf.st_size, temp);
					binary_sha1 = (char *)malloc(SHA_DIGEST_LENGTH*2+1);
					memset(binary_sha1, 0, SHA_DIGEST_LENGTH*2+1);
					char buf[SHA_DIGEST_LENGTH*2 + 1];
					for (int i=0; i < SHA_DIGEST_LENGTH; i++) {
						sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
					}
					memcpy(binary_sha1, buf, SHA_DIGEST_LENGTH*2);
					munmap(fb,statbuf.st_size);
				} else {
					proxy_error("Unable to mmap %s: %s\n", buff, strerror(errno));
				}
			} else {
				proxy_error("Unable to fstat %s: %s\n", buff, strerror(errno));
			}
		} else {
			proxy_error("Unable to open %s: %s\n", argv[0], strerror(errno));
		}
#ifdef DEBUG
		std::cerr << "SHA1 generated in ";
#endif
	}
	if (GloVars.global.foreground==false) {
		{
			cpu_timer t;
			ProxySQL_daemonize_phase1((char *)argv[0]);
#ifdef DEBUG
			std::cerr << "Main daemonize phase1 completed in ";
#endif
		}
	/* Do the fork */
		if ((pid = daemon_fork()) < 0) {
			/* Exit on error */
			daemon_retval_done();
			exit(EXIT_FAILURE);

		} else if (pid) { /* The parent */

			ProxySQL_daemonize_wait_daemon();

		} else { /* The daemon */

			cpu_timer t;
			GloVars.global.start_time=monotonic_time();
			GloVars.install_signal_handler();
			if (ProxySQL_daemonize_phase2()==false) {
				goto finish;
			}

#ifdef DEBUG
			std::cerr << "Main daemonize phase1 completed in ";
#endif
		}

		if (glovars.proxy_restart_on_error) {
			handleProcessRestart();
		}

	} else {
		GloAdmin->flush_error_log();
		GloVars.install_signal_handler();
	}

__start_label:
	{
		cpu_timer t;
		ProxySQL_Main_init_phase2___not_started(bootstrap_info);
#ifdef DEBUG
		std::cerr << "Main init phase2 completed in ";
#endif
	}
	if (glovars.shutdown) {
		goto __shutdown;
	}

	{
		cpu_timer t;
		ProxySQL_Main_init_phase3___start_all();
#ifdef DEBUG
		std::cerr << "Main init phase3 completed in ";
#endif
	}
#ifdef DEBUG
		std::cerr << "WARNING: this is a DEBUG release and can be slow or perform poorly. Do not use it in production" << std::endl;
#endif
	proxy_info("For information about products and services visit: https://proxysql.com/\n");
	proxy_info("For online documentation visit: https://proxysql.com/documentation/\n");
	proxy_info("For support visit: https://proxysql.com/services/support/\n");
	proxy_info("For consultancy visit: https://proxysql.com/services/consulting/\n");

	{
#if 0
		{
			// the following commented code is here only to manually test handleProcessRestart()
			// DO NOT ENABLE
			//proxy_info("Service is up\n");
			//sleep(2);
			//assert(0);
		}
#endif
		unsigned int missed_heartbeats = 0;
		unsigned long long previous_time = monotonic_time();
		unsigned int inner_loops = 0;
		unsigned long long time_next_version_check = 0;
		while (glovars.shutdown==0) {
			usleep(200000);
			if (disable_watchdog) {
				continue;
			}
			unsigned long long curtime = monotonic_time();
			if (GloVars.global.version_check) {
				if (curtime > time_next_version_check) {
					pthread_attr_t attr;
					pthread_attr_init(&attr);
					pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
					pthread_t thr;
					if (pthread_create(&thr, &attr, main_check_latest_version_thread, NULL) !=0 ) {
						perror("Thread creation");
						exit(EXIT_FAILURE);
					}
					if (time_next_version_check == 0)
						time_next_version_check = curtime;
					unsigned long long inter = 24*3600*1000;
					inter *= 1000;
					time_next_version_check += inter;
				}
			}
			inner_loops++;
			if (curtime >= inner_loops*300000 + previous_time ) {
				// if this happens, it means that this very simple loop is blocked
				// probably we are running under gdb
				previous_time = curtime;
				inner_loops = 0;
				continue;
			}
			if (GloMTH) {
				unsigned long long atomic_curtime = 0;
				unsigned long long poll_timeout = (unsigned int)GloMTH->variables.poll_timeout;
				unsigned int threads_missing_heartbeat = 0;
				poll_timeout += 1000; // add 1 second (rounding up)
				poll_timeout *= 1000; // convert to us
				if (curtime < previous_time + poll_timeout) {
					continue;
				}
				previous_time = curtime;
				inner_loops = 0;
				unsigned int i;
				if (GloMTH->mysql_threads) {
					for (i=0; i<GloMTH->num_threads; i++) {
						if (GloMTH->mysql_threads[i].worker) {
							atomic_curtime = GloMTH->mysql_threads[i].worker->atomic_curtime;
							if (curtime > atomic_curtime + poll_timeout) {
								threads_missing_heartbeat++;
							}
						}
					}
				}
#ifdef IDLE_THREADS
				if (GloVars.global.idle_threads) {
					if (GloMTH->mysql_threads) {
						for (i=0; i<GloMTH->num_threads; i++) {
							if (GloMTH->mysql_threads_idles[i].worker) {
								atomic_curtime = GloMTH->mysql_threads_idles[i].worker->atomic_curtime;
								if (curtime > atomic_curtime + poll_timeout) {
									threads_missing_heartbeat++;
								}
							}
						}
					}
				}
#endif
				if (threads_missing_heartbeat) {
					proxy_error("Watchdog: %u threads missed a heartbeat\n", threads_missing_heartbeat);
					missed_heartbeats++;
					if (missed_heartbeats >= (unsigned int)GloVars.restart_on_missing_heartbeats) {
#ifdef RUNNING_ON_VALGRIND
						proxy_error("Watchdog: reached %u missed heartbeats. Not aborting because running under Valgrind\n", missed_heartbeats);
#else
						if (GloVars.restart_on_missing_heartbeats) {
							proxy_error("Watchdog: reached %u missed heartbeats. Aborting!\n", missed_heartbeats);
							proxy_error("Watchdog: see details at https://github.com/sysown/proxysql/wiki/Watchdog\n");
							assert(0);
						}
#endif
					}
				} else {
					missed_heartbeats = 0;
				}
			}
		}
	}

__shutdown:

	proxy_info("Starting shutdown...\n");

	// First shutdown step is to unload plugins
	UnloadPlugins();

	ProxySQL_Main_init_phase4___shutdown();

	proxy_info("Shutdown completed!\n");

	if (glovars.reload) {
		if (glovars.reload==2) {
			GloVars.global.nostart=true;
		}
		glovars.reload=0;
		glovars.shutdown=0;
		goto __start_label;
	}

finish:
	//daemon_log(LOG_INFO, "Exiting...");
	proxy_info("Exiting...\n");
	daemon_retval_send(255);
	daemon_signal_done();
	daemon_pid_file_remove();

//	l_mem_destroy(__thr_sfp);

#ifdef RUNNING_ON_VALGRIND
	if (RUNNING_ON_VALGRIND==0) {
		if (__web_interface) {
			dlclose(__web_interface);
		}
		if (__mysql_ldap_auth) {
			dlclose(__mysql_ldap_auth);
		}
	}
#endif
	return 0;
}
