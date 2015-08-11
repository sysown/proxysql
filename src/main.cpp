#include <iostream>
#include <thread>
#include "btree_map.h"
#include "proxysql.h"

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


time_t laststart;
pid_t pid;

static const char * proxysql_pid_file() {
	static char fn[512];
	snprintf(fn, sizeof(fn), "%s", daemon_pid_file_ident);
	return fn;
}


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

__thread l_sfp *__thr_sfp=NULL;

const char *malloc_conf = "xmalloc:true,lg_tcache_max:17";

int listen_fd;
int socket_fd;


Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH;

MySQL_Monitor *GloMyMon;
std::thread *MyMon_thread;


void * mysql_worker_thread_func(void *arg) {

	__thr_sfp=l_mem_init();
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
	l_mem_destroy(__thr_sfp);
	return NULL;
}

void * mysql_shared_query_cache_funct(void *arg) {
	GloQC->purgeHash_thread(NULL);
	return NULL;
}


void ProxySQL_Main_process_global_variables(int argc, const char **argv) {
	GloVars.parse(argc,argv);
	GloVars.process_opts_pre();
	// alwasy try to open a config file
	if (GloVars.confFile->OpenFile(GloVars.config_file) == true) {
		GloVars.configfile_open=true;
	}
	char *t=get_current_dir_name();
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
		} else {
			// config file not readable
			GloVars.datadir=strdup(t);
			std::cerr << "[Warning]: Cannot open any deault config file . Using default datadir in current working directory " << GloVars.datadir << endl;
		}
	} else {
		GloVars.datadir=GloVars.__cmd_proxysql_datadir;
	}
	free(t);

	GloVars.admindb=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.db")+2);
	sprintf(GloVars.admindb,"%s/%s",GloVars.datadir, (char *)"proxysql.db");

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
	GloMyMon=NULL;
	MyHGM=new MySQL_HostGroups_Manager();
	GloMTH=new MySQL_Threads_Handler();
}


void ProxySQL_Main_init_Admin_module() {
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->init();
//	GloAdmin->flush_error_log();
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
	load_ = GloMTH->num_threads + 1;
	for (i=0; i<GloMTH->num_threads; i++) {
		GloMTH->create_thread(i,mysql_worker_thread_func);
	}
}

void ProxySQL_Main_init_Query_Cache_module() {
	GloQC = new Query_Cache();
	GloQC->print_version();
	pthread_create(&GloQC->purge_thread_id, NULL, mysql_shared_query_cache_funct , NULL);
}

void ProxySQL_Main_init_MySQL_Monitor_module() {
	// start MySQL_Monitor
	GloMyMon = new MySQL_Monitor();
	MyMon_thread = new std::thread(&MySQL_Monitor::run,GloMyMon);
	GloMyMon->print_version();
}

void ProxySQL_Main_join_all_threads() {
	if (GloMTH) {
		GloMTH->shutdown_threads();
	}
	if (GloQC) {
		GloQC->shutdown=1;
	}

	if (GloMyMon) {
		GloMyMon->shutdown=true;
	}

	// join GloMyMon thread
	if (GloMyMon) {
		MyMon_thread->join();
	}

	// join GloQC thread
	if (GloQC) {
		pthread_join(GloQC->purge_thread_id, NULL);
	}
}

void ProxySQL_Main_shutdown_all_modules() {
	if (GloMyMon) {
		delete GloMyMon;
		GloMyMon=NULL;
	}

	if (GloQC) {
		delete GloQC;
		GloQC=NULL;
	}
	if (GloQPro) {
		delete GloQPro;
		GloQPro=NULL;
	}
	if (GloMyAuth) {
		delete GloMyAuth;
		GloMyAuth=NULL;
	}
	if (GloMTH) {
		delete GloMTH;
		GloMTH=NULL;
	}

	delete GloAdmin;
	delete MyHGM;
}

void ProxySQL_Main_init() {
#ifdef DEBUG
	GloVars.global.gdbg=false;
	glovars.has_debug=true;
#else
	glovars.has_debug=false;
#endif /* DEBUG */
	GloVars.global.start_time=monotonic_time();
	__thr_sfp=l_mem_init();

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

	if (GloVars.configfile_open) {
		GloVars.confFile->CloseFile();
	}

	ProxySQL_Main_init_Auth_module();

	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
}


void ProxySQL_Main_init_phase3___start_all() {
	// load all mysql servers to GloHGH
	GloAdmin->init_mysql_servers();
	ProxySQL_Main_init_Query_module();
	ProxySQL_Main_init_MySQL_Threads_Handler_module();
	ProxySQL_Main_init_Query_Cache_module();

	do { /* nothing */ } while (load_ != 1);
	load_ = 0;

	GloMTH->start_listeners();
	ProxySQL_Main_init_MySQL_Monitor_module();
}



void ProxySQL_Main_init_phase4___shutdown() {
	ProxySQL_Main_join_all_threads();

	if (GloVars.global.nostart) {
		pthread_mutex_unlock(&GloVars.global.start_mutex);
	}

	ProxySQL_Main_shutdown_all_modules();
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
		daemon_log(LOG_ERR, "Could not recieve return value from daemon process: %s", strerror(errno));
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
	daemon_log(LOG_INFO, "Starting ProxySQL\n");
	daemon_log(LOG_INFO, "Sucessfully started");

	return true;
}

bool ProxySQL_daemonize_phase3() {
	int rc;
	int status;
	daemon_log(LOG_INFO, "Angel process started ProxySQL process %d\n", pid);
	rc=waitpid(pid, &status, 0);
	if (rc==-1) {
		perror("waitpid");
		//proxy_error("[FATAL]: waitpid: %s\n", perror("waitpid"));
		exit(EXIT_FAILURE);
	}
	rc=WIFEXITED(status);
	if (rc) { // client exit()ed
		rc=WEXITSTATUS(status);
		if (rc==0) {
			daemon_log(LOG_INFO, "Shutdown angel process\n");
			exit(EXIT_SUCCESS);
		} else {
			daemon_log(LOG_INFO, "ProxySQL exited with code %d . Restarting!\n", rc);
			return false;;
		}
	} else {
		daemon_log(LOG_INFO, "ProxySQL crashed. Restarting!\n");
		return false;
	}
	return true;
}


int main(int argc, const char * argv[]) {

	ProxySQL_Main_init();
	ProxySQL_Main_process_global_variables(argc, argv);


	if (GloVars.global.foreground==false) {

		ProxySQL_daemonize_phase1((char *)argv[0]);

	/* Do the fork */
		if ((pid = daemon_fork()) < 0) {
			/* Exit on error */
			daemon_retval_done();
			exit(EXIT_FAILURE);

		} else if (pid) { /* The parent */

			ProxySQL_daemonize_wait_daemon();

		} else { /* The daemon */

			if (ProxySQL_daemonize_phase2()==false) {
				goto finish;
			}

		}

	laststart=0;
	if (glovars.proxy_restart_on_error) {
gotofork:
		if (laststart) {
			daemon_log(LOG_INFO, "Angel process is waiting %d seconds before starting a new ProxySQL process\n", glovars.proxy_restart_delay);
			sleep(glovars.proxy_restart_delay);
		}
		laststart=time(NULL);
		pid = fork();
		if (pid < 0) {
			daemon_log(LOG_INFO, "[FATAL]: Error in fork()\n");
		exit(EXIT_FAILURE);
		}

		if (pid) {

			if (ProxySQL_daemonize_phase3()==false) {
				goto gotofork;
			}

		}
	}



	}

__start_label:

	ProxySQL_Main_init_phase2___not_started();

	if (glovars.shutdown) {
		goto __shutdown;
	}

	ProxySQL_Main_init_phase3___start_all();


	while (glovars.shutdown==0) {
		sleep(1);   // FIXME: TERRIBLE UGLY
	}
		
__shutdown:

	ProxySQL_Main_init_phase4___shutdown();

	if (glovars.reload) {
		if (glovars.reload==2) {
			GloVars.global.nostart=true;
		}
		glovars.reload=0;
		glovars.shutdown=0;
		goto __start_label;
	}

finish:
	daemon_log(LOG_INFO, "Exiting...");
	daemon_retval_send(255);
	daemon_signal_done();
	daemon_pid_file_remove();

	l_mem_destroy(__thr_sfp);
	return 0;
}

