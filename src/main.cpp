#include <iostream>
#include <thread>
#include "btree_map.h"
#include "proxysql.h"

//#define PROXYSQL_EXTERN
#include "cpp.h"

// MariaDB client library redefines dlerror(), see https://mariadb.atlassian.net/browse/CONC-101
#ifdef dlerror
#undef dlerror
#endif

//ProxySQL_GlobalVariables GloVars;




void * __qc;
void * __mysql_thread;
void * __mysql_threads_handler;
void * __query_processor;
void * __mysql_auth; 



//void (*__memcached_main)(int,char **);
//pthread_t memcached_pthread;



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

/*
typedef struct _proxysql_mysql_thread_t proxysql_mysql_thread_t;


struct _proxysql_mysql_thread_t {
	MySQL_Thread *worker;
	pthread_t thread_id;
};
*/
//static proxysql_mysql_thread_t *mysql_threads;

#define NUM_THREADS	8





static unsigned int g_seed;


inline void fast_srand( int seed ) {
g_seed = seed;
}
inline int fastrand() {
    g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
}

static char _s[128];

void gen_random_stdstring(string *s, const int len) {
	//char *_s=(char *)alloca(len+1);
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < len; ++i) {
        _s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }
    _s[len] = '\0';
	*s=string(_s);
    //return s;
}



char * gen_random_string(const int len) {
    char *s=(char *)malloc(len+1);
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
    return s;
}



void * mysql_worker_thread_func(void *arg) {

	__thr_sfp=l_mem_init();
	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	//MySQL_Thread *worker = new MySQL_Thread;
	MySQL_Thread *worker = new MySQL_Thread();
	mysql_thread->worker=worker;
	worker->init();
//	worker->poll_listener_add(listen_fd);
//	worker->poll_listener_add(socket_fd);
	__sync_fetch_and_sub(&load_,1);
//	if (__sync_fetch_and_sub(&load_,1)==(NUM_THREADS+1)) {
//		worker->print_version();
//	}
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


#include <dlfcn.h>


int main(int argc, const char * argv[]) {

	unsigned int i;
{
#ifdef DEBUG
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

	GloVars.parse(argc,argv);

	GloVars.process_opts_pre();

	// alwasy try to open a config file
	if (GloVars.confFile->OpenFile(GloVars.config_file) == true) {
		GloVars.configfile_open=true;
	}

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
					GloVars.datadir=(char *)"/var/run/proxysql";
				}
			} else {
			// datadir was not specified in config file
			GloVars.datadir=(char *)"/var/run/proxysql";
			}
		} else {
			// config file not readable
			GloVars.datadir=(char *)"/var/run/proxysql";
			std::cerr << "[Warning]: Cannot open config file " << GloVars.config_file << ". Using default datadir " << GloVars.datadir << endl;
		}
	} else {
		GloVars.datadir=GloVars.__cmd_proxysql_datadir;
	}

	GloVars.admindb=(char *)malloc(strlen(GloVars.datadir)+strlen((char *)"proxysql.db")+2);
	sprintf(GloVars.admindb,"%s/%s",GloVars.datadir, (char *)"proxysql.db");

	if (GloVars.__cmd_proxysql_initial==true) {
		std::cerr << "Renaming database file " << GloVars.admindb << endl;
		char *newpath=(char *)malloc(strlen(GloVars.admindb)+8);
		sprintf(newpath,"%s.bak",GloVars.admindb);
		rename(GloVars.admindb,newpath);	// FIXME: should we check return value, or ignore whatever it successed or not?
	}

	GloVars.confFile->ReadGlobals();



	GloVars.process_opts_post();

/*
	//if (GloVars.confFile->OpenFile("proxysql.cnf2") == true) {
	if (GloVars.confFile->OpenFile(GloVars.config_file) == true) {
		// open config file
	} else {
		std::cerr << "[Warning]: Cannot open config file " << GloVars.config_file << endl;
		//exit(EXIT_FAILURE);
	}
*/

__start_label:

	GloQC=NULL;
	GloQPro=NULL;
	GloMTH=NULL;
	GloMyAuth=NULL;
	GloMyMon=NULL;
//	MyHGH=new MySQL_HostGroups_Handler();
	MyHGM=new MySQL_HostGroups_Manager();

	GloMTH=new MySQL_Threads_Handler();
	GloMTH->print_version();

{
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->print_version();
	GloAdmin->init();
}

	if (GloVars.configfile_open) {
		GloVars.confFile->CloseFile();
	}

	GloMyAuth = new MySQL_Authentication();
	GloMyAuth->print_version();

	GloAdmin->init_users();


	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}

	//mysql_threads=NULL;

	if (glovars.shutdown) {
		goto __shutdown;
	}

	// load all mysql servers to GloHGH
	GloAdmin->init_mysql_servers();


{
	GloQPro = new Query_Processor();
  GloQPro->print_version();
}
	GloAdmin->init_mysql_query_rules();

/*
	GModule * __mysql_auth = g_module_open("../lib/Standard_MySQL_Authentication.so", G_MODULE_BIND_LAZY);
	if (!__mysql_auth) {
		cerr << "Cannot load library: " << g_module_error() << '\n';
		return 1;
	}
	rc= g_module_symbol(__mysql_auth, "create_MySQL_Authentication", (void **)&create_MySQL_Authentication);
	if (rc==FALSE) {
		cerr << "Cannot load symbol create: " << g_module_error() << '\n';
		return 1;
	}
*/





	//parse all the arguments and the config file
  //main_opts(cmd_option_entries, &argc, &argv, &__cmd_proxysql_config_file);


//  main_opts(&argc, (gchar ***)&argv);


	// start admin thread

	// wait for admin thread to exit

	// read sqlite config file

	// daemonize if needed
	// fork if needed

	// start all services



	GloMTH->init();
	
	load_ = GloMTH->num_threads + 1;


	for (i=0; i<GloMTH->num_threads; i++) {
		//pthread_create(&mysql_threads[i].thread_id, &attr, mysql_worker_thread_func , &mysql_threads[i]);
		GloMTH->create_thread(i,mysql_worker_thread_func);
		//pthread_create(&mysql_threads[i].thread_id, &attr, mysql_worker_thread_func , &mysql_threads[i]);
	}

	
	//SQC = new Shared_Query_Cache(DEFAULT_SQC_size);
	GloQC = new Query_Cache();
	GloQC->print_version();
	pthread_create(&GloQC->purge_thread_id, NULL, mysql_shared_query_cache_funct , NULL);
	//void *(*__f)(void *) = (void* (*)(void*))&SQC->purgeHash_thread;
	//pthread_create(&SQC_purge_thread_id, NULL, &SQC->purgeHash_thread , NULL);



		

	do { /* nothing */ } while (load_ != 1);


	load_ = 0;

/*
 * few examples tests to demonstrate the ability to add and remove listeners at runtime
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
*/


	GloMTH->start_listeners();

	//sleep(10);

	// start MySQL_Monitor
	GloMyMon = new MySQL_Monitor();
	MyMon_thread = new std::thread(&MySQL_Monitor::run,GloMyMon);
	GloMyMon->print_version();


	while (glovars.shutdown==0) {
		sleep(1);   // FIXME: TERRIBLE UGLY
	}
		
__shutdown:

	if (GloMTH) {
		GloMTH->shutdown_threads();
	}
/*
	if (mysql_threads) {

		for (i=0; i<NUM_THREADS; i++) {
			mysql_threads[i].worker->shutdown=1;
		}

		for (i=0; i<NUM_THREADS; i++) {
			pthread_join(mysql_threads[i].thread_id,NULL);
		}
		free(mysql_threads);
		mysql_threads=NULL;
	}
*/
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


	//if (GloVars.__cmd_proxysql_nostart) {
	if (GloVars.global.nostart) {
		pthread_mutex_unlock(&GloVars.global.start_mutex);
	}

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
	//delete MyHGH;
	delete MyHGM;

	if (glovars.reload) {
		//sleep(1);
		if (glovars.reload==2) {
			GloVars.global.nostart=true;
		}
		glovars.reload=0;
		glovars.shutdown=0;
		goto __start_label;
	}

	l_mem_destroy(__thr_sfp);


	return 0;
}

