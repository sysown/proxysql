#include <iostream>
#include "btree_map.h"
#include "proxysql.h"

//#define PROXYSQL_EXTERN
#include "cpp.h"

using namespace std;

// MariaDB client library redefines dlerror(), see https://mariadb.atlassian.net/browse/CONC-101
#ifdef dlerror
#undef dlerror
#endif

extern "C" Query_Cache* create_QC_func();
extern "C" MySQL_Thread * create_MySQL_Thread_func();
extern "C" void destroy_MySQL_Thread_func();
extern "C" MySQL_Threads_Handler * create_MySQL_Threads_Handler_func();
extern "C" MySQL_Authentication * create_MySQL_Authentication_func();
extern "C" Query_Processor * create_Query_Processor_func();
extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func();


void * __qc;
void * __mysql_thread;
void * __mysql_threads_handler;
void * __query_processor;
void * __mysql_auth; 
void * __proxysql_admin; 


create_MySQL_Thread_t * create_MySQL_Thread = NULL;
destroy_MySQL_Thread_t * destroy_MySQL_Thread = NULL;
create_MySQL_Threads_Handler_t * create_MySQL_Threads_Handler = NULL;
destroy_MySQL_Threads_Handler_t * destroy_MySQL_Threads_Handler = NULL;
create_MySQL_Authentication_t * create_MySQL_Authentication = NULL;
create_Query_Processor_t * create_Query_Processor = NULL;
create_ProxySQL_Admin_t * create_ProxySQL_Admin = NULL;

#define MAX_EVENTS 100

static volatile int load_;

__thread l_sfp *__thr_sfp=NULL;

Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH;

void * mysql_worker_thread_func(void *arg) {
	__thr_sfp=l_mem_init();
	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	MySQL_Thread *worker = create_MySQL_Thread();
	mysql_thread->worker=worker;
	worker->init();
	__sync_fetch_and_sub(&load_,1);
	do { usleep(50); } while (load_);

	worker->run();
	destroy_MySQL_Thread(worker);
	l_mem_destroy(__thr_sfp);
	return NULL;
}

void * mysql_shared_query_cache_funct(void *arg) {
	GloQC->purgeHash_thread(NULL);
	return NULL;
}


#include <dlfcn.h>


int main(int argc, const char * argv[]) {


{
#ifdef DEBUG
	glovars.has_debug=true;
#else
	glovars.has_debug=false;
#endif /* DEBUG */

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

	dlerror();
	char* dlsym_error = NULL;
	create_QC_t* create_QC = NULL;

{
	__qc = dlopen("../lib/Standard_Query_Cache.so", RTLD_LAZY);
	if (!__qc) {
		cerr << "Cannot load library: " << dlerror() << '\n';
	//	exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_QC = (create_QC_t*) dlsym(__qc, "create_QC_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol create_QC: " << dlsym_error << '\n';
			//exit(EXIT_FAILURE);
		}
	}
}

{
	dlerror();
	dlsym_error=NULL;
	__mysql_thread = dlopen("../lib/Standard_MySQL_Thread.so", RTLD_LAZY);
	if (!__mysql_thread) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_MySQL_Threads_Handler = (create_MySQL_Threads_Handler_t *) dlsym(__mysql_thread, "create_MySQL_Threads_Handler_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol create_MySQL_Threads_Handler_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
		dlerror();
		create_MySQL_Thread = (create_MySQL_Thread_t *) dlsym(__mysql_thread, "create_MySQL_Thread_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol create_MySQL_Thread_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
		dlerror();
		destroy_MySQL_Threads_Handler = (destroy_MySQL_Threads_Handler_t *) dlsym(__mysql_thread, "destroy_MySQL_Threads_Handler_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol destroy_MySQL_Threads_Handler_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
		dlerror();
		destroy_MySQL_Thread = (destroy_MySQL_Thread_t *) dlsym(__mysql_thread, "destroy_MySQL_Thread_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol destroy_MySQL_Thread_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
	}
}

{
	dlerror();
	dlsym_error=NULL;
	__query_processor = dlopen("../lib/Standard_Query_Processor.so", RTLD_LAZY);
	if (!__query_processor) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_Query_Processor = (create_Query_Processor_t *) dlsym(__query_processor, "create_Query_Processor_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol &create_Query_Processor_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
	}
}

{
	dlerror();
	dlsym_error=NULL;
	__mysql_auth = dlopen("../lib/Standard_MySQL_Authentication.so", RTLD_LAZY);
	if (!__mysql_auth) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		//exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_MySQL_Authentication = (create_MySQL_Authentication_t *) dlsym(__mysql_auth, "create_MySQL_Authentication_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol &create_MySQL_Authentication: " << dlsym_error << '\n';
			//exit(EXIT_FAILURE);
		}
	}
	if (__mysql_auth==NULL || dlsym_error) {
		create_MySQL_Authentication=&create_MySQL_Authentication_func;
	}
}

{
	dlerror();
	dlsym_error=NULL;
	__proxysql_admin = dlopen("../lib/Standard_ProxySQL_Admin.so", RTLD_LAZY);
	if (!__proxysql_admin) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_ProxySQL_Admin = (create_ProxySQL_Admin_t *) dlsym(__proxysql_admin, "create_ProxySQL_Admin_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol &create_ProxySQL_Admin_func: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
	}
}

__start_label:

	GloQC=NULL;
	GloQPro=NULL;
	GloMTH=NULL;
	MyHGM=new MySQL_HostGroups_Manager();

	GloMTH=create_MySQL_Threads_Handler();
	GloMTH->print_version();

{
	GloAdmin = create_ProxySQL_Admin();
	GloAdmin->print_version();
	GloAdmin->init();
}

	if (GloVars.configfile_open) {
		GloVars.confFile->CloseFile();
	}

	GloMyAuth = create_MySQL_Authentication();
	GloMyAuth->print_version();

	GloAdmin->init_users();


	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}

	if (glovars.shutdown) {
		goto __shutdown;
	}

	// load all mysql servers to GloHGH
	GloAdmin->init_mysql_servers();


{
	GloQPro = create_Query_Processor();
  GloQPro->print_version();
}
	GloAdmin->init_mysql_query_rules();
	unsigned int i;

	GloMTH->init();

	for (i=0; i<GloMTH->num_threads; i++) {
		GloMTH->create_thread(i,mysql_worker_thread_func);
	}

	GloQC = create_QC();
	GloQC->print_version();
	pthread_create(&GloQC->purge_thread_id, NULL, mysql_shared_query_cache_funct , NULL);

	do { /* nothing */ } while (load_ != 1);


	load_ = 0;
	GloMTH->start_listeners();

	while (glovars.shutdown==0) {
		sleep(1);   // FIXME: TERRIBLE UGLY
	}

__shutdown:

	if (GloMTH) {
		GloMTH->shutdown_threads();
	}

	if (GloQC) {
		GloQC->shutdown=1;
		pthread_join(GloQC->purge_thread_id, NULL);
	}

	//if (GloVars.__cmd_proxysql_nostart) {
	if (GloVars.global.nostart) {
		pthread_mutex_unlock(&GloVars.global.start_mutex);
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

	if (glovars.reload) {
		if (glovars.reload==2) {
			GloVars.global.nostart=true;
		}
		glovars.reload=0;
		glovars.shutdown=0;
		goto __start_label;
	}

	if (RUNNING_ON_VALGRIND==0) {
		dlclose(__qc);
		dlclose(__mysql_thread);
		dlclose(__query_processor);
		dlclose(__mysql_auth);
		dlclose(__proxysql_admin);
	}
	l_mem_destroy(__thr_sfp);


	return 0;
}

