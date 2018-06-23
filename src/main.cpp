#include <iostream>
#include <thread>
#include "btree_map.h"
#include "proxysql.h"
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <fcntl.h>
#endif

#ifdef SYSTEMD
#include <systemd/sd-daemon.h>
#endif


//#define PROXYSQL_EXTERN
#include "cpp.h"


#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

// MariaDB client library redefines dlerror(), see https://mariadb.atlassian.net/browse/CONC-101
#ifdef dlerror
#undef dlerror
#endif



// this fuction will be called as a deatached thread
static void * waitpid_thread(void *arg) {
	pid_t *cpid_ptr=(pid_t *)arg;
	int status;
	waitpid(*cpid_ptr, &status, 0);
	free(cpid_ptr);
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

time_t laststart;
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

/*
void ProxySQL_Main_init_SSL_module() {
	SSL_library_init();
	SSL_METHOD *ssl_method;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ssl_method = (SSL_METHOD *)TLSv1_server_method();
	GloVars.global.ssl_ctx = SSL_CTX_new(ssl_method);
	if (GloVars.global.ssl_ctx==NULL)	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if ( SSL_CTX_use_certificate_file(GloVars.global.ssl_ctx, "newreq.pem", SSL_FILETYPE_PEM) <= 0 )	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( SSL_CTX_use_PrivateKey_file(GloVars.global.ssl_ctx, "privkey.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( !SSL_CTX_check_private_key(GloVars.global.ssl_ctx) ) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
*/

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
void * __mysql_auth; 



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
const char *malloc_conf = "xmalloc:true,lg_tcache_max:16,purge:decay,prof:true,prof_leak:true,lg_prof_sample:20,lg_prof_interval:30,prof_active:false";
#endif
//#endif /* DEBUG */
//const char *malloc_conf = "prof_leak:true,lg_prof_sample:0,prof_final:true,xmalloc:true,lg_tcache_max:16";

int listen_fd;
int socket_fd;


Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
#ifdef PROXYSQLCLICKHOUSE
ClickHouse_Authentication *GloClickHouseAuth;
#endif /* PROXYSQLCLICKHOUSE */
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH;

MySQL_STMT_Manager_v14 *GloMyStmt;

MySQL_Monitor *GloMyMon;
std::thread *MyMon_thread = NULL;

MySQL_Logger *GloMyLogger;

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
	GloVars.parse(argc,argv);
	GloVars.process_opts_pre();
	GloVars.restart_on_missing_heartbeats = 10; // default
	// alwasy try to open a config file
	if (GloVars.confFile->OpenFile(GloVars.config_file) == true) {
		GloVars.configfile_open=true;
		const Setting& root = GloVars.confFile->cfg->getRoot();
		if (root.exists("restart_on_missing_heartbeats")==true) {
			// restart_on_missing_heartbeats datadir from config file
			int restart_on_missing_heartbeats;
			bool rc;
			rc=root.lookupValue("restart_on_missing_heartbeats", restart_on_missing_heartbeats);
			if (rc==true) {
				GloVars.restart_on_missing_heartbeats=restart_on_missing_heartbeats;
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
	} else {
		proxy_warning("Unable to open config file %s\n", GloVars.config_file); // issue #705
	}
	char *t=getcwd(NULL, 512);
	if (GloVars.__cmd_proxysql_datadir==NULL) {
		// datadir was not specified , try to read config file
		if (GloVars.configfile_open==true) {
			const Setting& root = GloVars.confFile->cfg->getRoot();
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

	GloVars.statsdb_disk=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql_stats.db")+2);
	sprintf(GloVars.statsdb_disk,"%s/%s",GloVars.datadir, (char *)"proxysql_stats.db");

	GloVars.errorlog=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.log")+2);
	sprintf(GloVars.errorlog,"%s/%s",GloVars.datadir, (char *)"proxysql.log");

	GloVars.pid=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.pid")+2);
	sprintf(GloVars.pid,"%s/%s",GloVars.datadir, (char *)"proxysql.pid");

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
	MyHGM=new MySQL_HostGroups_Manager();
	GloMTH=new MySQL_Threads_Handler();
	GloMyLogger = new MySQL_Logger();
	GloMyStmt=new MySQL_STMT_Manager_v14();
}


void ProxySQL_Main_init_Admin_module() {
	// cluster module needs to be initialized before
	GloProxyCluster = new ProxySQL_Cluster();
	GloProxyCluster->init();
	GloProxyCluster->print_version();
	GloProxyStats = new ProxySQL_Statistics();
	//GloProxyStats->init();
	GloProxyStats->print_version();
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->init();
	GloAdmin->print_version();
}

void ProxySQL_Main_init_Auth_module() {
	GloMyAuth = new MySQL_Authentication();
	GloMyAuth->print_version();
	GloAdmin->init_users();
}

void ProxySQL_Main_init_Query_module() {
	GloQPro = new Query_Processor();
  GloQPro->print_version();
	GloAdmin->init_mysql_query_rules();
}

void ProxySQL_Main_init_MySQL_Threads_Handler_module() {
	unsigned int i;
	GloMTH->init();
	load_ = 1;
	load_ += GloMTH->num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		load_ += GloMTH->num_threads;
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
	MyMon_thread = new std::thread(&MySQL_Monitor::run,GloMyMon);
	GloMyMon->print_version();
}


void ProxySQL_Main_init_SQLite3Server() {
	// start SQLite3Server
	GloSQLite3Server = new SQLite3_Server();
	GloSQLite3Server->init();
	GloAdmin->init_sqliteserver_variables();
	GloSQLite3Server->print_version();
}
#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Main_init_ClickHouseServer() {
	// start SQServer
	GloClickHouseServer = new ClickHouse_Server();
	GloClickHouseServer->init();
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
		delete GloMTH;
		GloMTH=NULL;
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
		cpu_timer t;
		delete GloAdmin;
#ifdef DEBUG
		std::cerr << "GloAdmin shutdown in ";
#endif
	}
	{
		cpu_timer t;
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

	{
		/* moved here, so if needed by multiple modules it applies to all of them */
		int i=sqlite3_config(SQLITE_CONFIG_URI, 1);
		if (i!=SQLITE_OK) {
			fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
			assert(i==SQLITE_OK);
			exit(EXIT_FAILURE);
		}
	}
}






void ProxySQL_Main_init_phase2___not_started() {
	ProxySQL_Main_init_main_modules();
	ProxySQL_Main_init_Admin_module();
	GloMTH->print_version();

	{
		cpu_timer t;
		GloMyLogger->set_datadir(GloVars.datadir);
#ifdef DEBUG
		std::cerr << "Main phase3 : GloMyLogger initialized in ";
#endif
	}
	if (GloVars.configfile_open) {
		GloVars.confFile->CloseFile();
	}

	ProxySQL_Main_init_Auth_module();

	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
}


void ProxySQL_Main_init_phase3___start_all() {

	{
		cpu_timer t;
		GloMyLogger->set_datadir(GloVars.datadir);
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

	do { /* nothing */ } while (load_ != 1);
	load_ = 0;

	{
		cpu_timer t;
		GloMTH->start_listeners();
#ifdef DEBUG
		std::cerr << "Main phase3 : MySQL Threads Handler listeners started in ";
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
	if ( GloVars.global.sqlite3_server == true ) {
		cpu_timer t;
		ProxySQL_Main_init_SQLite3Server();
#ifdef DEBUG
		std::cerr << "Main phase3 : SQLite3 Server initialized in ";
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


void ProxySQL_daemonize_phase1(char *argv0) {
	int rc;
	daemon_pid_file_ident=GloVars.pid;
	daemon_log_ident=daemon_ident_from_argv0(argv0);
	rc=chdir(GloVars.datadir);
	if (rc) {
		daemon_log(LOG_ERR, "Could not chdir into datadir: %s . Error: %s", GloVars.datadir, strerror(errno));
		exit(EXIT_FAILURE);
	}
	daemon_pid_file_proc=proxysql_pid_file;
	pid=daemon_pid_file_is_running();
	if (pid>=0) {
		daemon_log(LOG_ERR, "Daemon already running on PID file %u", pid);
		exit(EXIT_FAILURE);
	}
	if (daemon_retval_init() < 0) {
		daemon_log(LOG_ERR, "Failed to create pipe.");
		exit(EXIT_FAILURE);
	}
}


void ProxySQL_daemonize_wait_daemon() {
	int ret;
	/* Wait for 20 seconds for the return value passed from the daemon process */
	if ((ret = daemon_retval_wait(20)) < 0) {
		daemon_log(LOG_ERR, "Could not receive return value from daemon process: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (ret) {
		daemon_log(LOG_ERR, "Daemon returned %i as return value.", ret);
	}
	exit(ret);
}


bool ProxySQL_daemonize_phase2() {
	int rc;
	/* Close FDs */
	if (daemon_close_all(-1) < 0) {
		daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));

		/* Send the error condition to the parent process */
		daemon_retval_send(1);
		return false;
	}

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
	proxy_info("Sucessfully started\n");

	return true;
}


void call_execute_on_exit_failure() {
	if (GloVars.execute_on_exit_failure == NULL) {
		return;
	}
	proxy_error("Trying to call external script after exit failure: %s\n", GloVars.execute_on_exit_failure);
	pid_t cpid;
	cpid = fork();
	if (cpid == -1) {
		exit(EXIT_FAILURE);
	}
	if (cpid == 0) {
		int rc;
		rc = system(GloVars.execute_on_exit_failure);
		if (rc) {
			proxy_error("Execute on EXIT_FAILURE: Failed to run %s\n", GloVars.execute_on_exit_failure);
			perror("system()");
			exit(EXIT_FAILURE);
		} else {
			exit(EXIT_SUCCESS);
		}
	} else {
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize (&attr, 64*1024);
		pid_t *cpid_ptr=(pid_t *)malloc(sizeof(pid_t));
		*cpid_ptr=cpid;
		pthread_t thr;
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
		call_execute_on_exit_failure();
		parent_close_error_log();
		return false;
	}
	return true;
}


int main(int argc, const char * argv[]) {

	{
		cpu_timer t;
		ProxySQL_Main_init();
#ifdef DEBUG
		std::cerr << "Main init phase0 completed in ";
#endif
	}
	{
		cpu_timer t;
		ProxySQL_Main_process_global_variables(argc, argv);
		GloVars.global.start_time=monotonic_time(); // always initialize it
#ifdef DEBUG
		std::cerr << "Main init global variables completed in ";
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

	laststart=0;
	if (glovars.proxy_restart_on_error) {
gotofork:
		if (laststart) {
			int currenttime=time(NULL);
			if (currenttime == laststart) { /// we do not want to restart multiple times in the same second
				// if restart is too frequent, something really bad is going on
				//daemon_log(LOG_INFO, "Angel process is waiting %d seconds before starting a new ProxySQL process\n", glovars.proxy_restart_delay);
				parent_open_error_log();
				proxy_info("Angel process is waiting %d seconds before starting a new ProxySQL process\n", glovars.proxy_restart_delay);
				parent_close_error_log();
				sleep(glovars.proxy_restart_delay);
			}
		}
		laststart=time(NULL);
		pid = fork();
		if (pid < 0) {
			//daemon_log(LOG_INFO, "[FATAL]: Error in fork()\n");
			parent_open_error_log();
			proxy_error("[FATAL]: Error in fork()\n");
			exit(EXIT_FAILURE);
		}

		if (pid) { /* The parent */

			parent_close_error_log();
			if (ProxySQL_daemonize_phase3()==false) {
				goto gotofork;
			}

		} else { /* The daemon */

			// we open the files also on the child process
			// this is required if the child process was created after a crash
			parent_open_error_log();
			GloVars.global.start_time=monotonic_time();
			GloVars.install_signal_handler();
		}
	}



	} else {
		GloAdmin->flush_error_log();
	}

__start_label:

	{
		cpu_timer t;
		ProxySQL_Main_init_phase2___not_started();
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

	{
		unsigned int missed_heartbeats = 0;
		unsigned long long previous_time = monotonic_time();
		unsigned int inner_loops = 0;
#ifdef SYSTEMD
                sd_notifyf(0, "READY=1\n"
                              "STATUS=ProxySQL is now processing requests...");
#endif
		while (glovars.shutdown==0) {
			usleep(200000);
			if (disable_watchdog) {
				continue;
			}
			unsigned long long curtime = monotonic_time();
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
						if (GloVars.restart_on_missing_heartbeats) {
							proxy_error("Watchdog: reached %u missed heartbeats. Aborting!\n", missed_heartbeats);
							assert(0);
						}
					}
				} else {
					missed_heartbeats = 0;
				}
			}
		}
	}

__shutdown:

#ifdef SYSTEMD
        sd_notify(0, "STOPPING=1");
#endif
	proxy_info("Starting shutdown...\n");

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
	return 0;
}

