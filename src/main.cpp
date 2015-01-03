#include <iostream>
#include "btree_map.h"
#include "proxysql.h"

//#define PROXYSQL_EXTERN
#include "cpp.h"

// MariaDB client library redefines dlerror(), see https://mariadb.atlassian.net/browse/CONC-101
#ifdef dlerror
#undef dlerror
#endif

//ProxySQL_GlobalVariables GloVars;


extern "C" Query_Cache* create_QC_func();
extern "C" MySQL_Thread * create_MySQL_Thread_func();
extern "C" void destroy_MySQL_Thread_func();
extern "C" MySQL_Authentication * create_MySQL_Authentication_func();
extern "C" Query_Processor * create_Query_Processor_func();
extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func();


void * __qc;
void * __mysql_thread;
void * __query_processor;
void * __mysql_auth; 
void * __proxysql_admin; 


create_MySQL_Thread_t * create_MySQL_Thread = NULL;
destroy_MySQL_Thread_t * destroy_MySQL_Thread = NULL;
create_MySQL_Authentication_t * create_MySQL_Authentication = NULL;
create_Query_Processor_t * create_Query_Processor = NULL;
create_ProxySQL_Admin_t * create_ProxySQL_Admin = NULL;

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

typedef struct _proxysql_mysql_thread_t proxysql_mysql_thread_t;


struct _proxysql_mysql_thread_t {
	MySQL_Thread *worker;
	pthread_t thread_id;
};

static proxysql_mysql_thread_t *mysql_threads;

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



void diagnostic_myds(MySQL_Data_Stream *myds) {
	if (!myds) return;
	fprintf(stderr,"      fd=%d, pkts_sent=%llu, pkts_recv=%llu, bytes_sent=%llu, bytes_recv=%llu\n", myds->fd, myds->pkts_sent, myds->pkts_recv, myds->bytes_info.bytes_sent, myds->bytes_info.bytes_recv);
	//struct pollfd *_pollfd;
	//_pollfd=&myds->sess->thread->mypolls.fds[myds->poll_fds_idx];
	//fprintf(stderr,"      poll_fds_idx=%d pollfd={fd=%d, events=%d, revents=%d}\n", myds->poll_fds_idx, _pollfd->fd, _pollfd->events, _pollfd->revents);
}

void diagnostic_all() {
	fprintf(stderr,"Diagnostic\n");
	int i;
	for (i=0;i<NUM_THREADS;i++) {
		fprintf(stderr,"MySQL Thread: Object=%p, thread_id=0x%08lx\n", mysql_threads[i].worker, mysql_threads[i].thread_id);
		unsigned int j;
		MySQL_Thread *thr=mysql_threads[i].worker;
		for (j=0; j<thr->mysql_sessions->len; j++) {
			MySQL_Session *sess=(MySQL_Session *)thr->mysql_sessions->index(j);
			fprintf(stderr," Session=%p\n", sess);
			fprintf(stderr,"    Client Data Stream=%p, fd=%d\n", sess->client_myds, ( sess->client_myds ? sess->client_myds->fd : 0 ));
			diagnostic_myds(sess->client_myds);
			fprintf(stderr,"    Server Data Stream=%p, fd=%d\n", sess->server_myds, ( sess->server_myds ? sess->server_myds->fd : 0 ));
			diagnostic_myds(sess->server_myds);
		}
	}
}

void * mysql_worker_thread_func(void *arg) {

	__thr_sfp=l_mem_init();
	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	//MySQL_Thread *worker = new MySQL_Thread;
	MySQL_Thread *worker = create_MySQL_Thread();
	mysql_thread->worker=worker;
	worker->init();
	worker->poll_listener_add(listen_fd);
	worker->poll_listener_add(socket_fd);
	if (__sync_fetch_and_sub(&load_,1)==(NUM_THREADS+1)) {
		worker->print_version();
	}
	do { usleep(50); } while (load_);

	worker->run();
	//delete worker;
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
	__thr_sfp=l_mem_init();

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

	if (GloVars.confFile->OpenFile("proxysql.cnf2") == true) {
		// open config file
	} else {
		std::cerr << "Cannot open config file, aborted" << endl;
		//exit(EXIT_FAILURE);
	}
	GloVars.confFile->ReadGlobals();

	GloVars.parse(argc,argv);

	GloVars.process_opts_pre();
	GloVars.process_opts_post();


	bool rc;

	dlerror();
	char* dlsym_error = NULL;

/*
{
	void * __memcached = dlopen("../deps/memcached/memcached/proxymemcached.so", RTLD_LAZY);
	if (!__memcached) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		exit(EXIT_FAILURE);
	} else {
		dlerror();
		*(void **) (&__memcached_main) = dlsym(__memcached, "memcached_main");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol memcached_main: " << dlsym_error << '\n';
			exit(EXIT_FAILURE);
		}
		pthread_create(&memcached_pthread, NULL, memcached_main_thread , NULL);
	}
}
*/

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
//	if (__qc==NULL || dlsym_error) {
//		create_QC=&create_QC_func;
//	}
}

{
	dlerror();
	dlsym_error=NULL;
	//void* __mysql_thread = dlopen("../lib/Standard_MySQL_Thread.so", RTLD_LAZY|RTLD_DEEPBIND);
	__mysql_thread = dlopen("../lib/Standard_MySQL_Thread.so", RTLD_LAZY);
	if (!__mysql_thread) {
		cerr << "Cannot load library: " << dlerror() << '\n';
		exit(EXIT_FAILURE);
	} else {
		dlerror();
		create_MySQL_Thread = (create_MySQL_Thread_t *) dlsym(__mysql_thread, "create_MySQL_Thread_func");
		dlsym_error = dlerror();
		if (dlsym_error!=NULL) {
			cerr << "Cannot load symbol create_MySQL_Thread_func: " << dlsym_error << '\n';
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
//	if (__mysql_thread==NULL ||	dlsym_error) {
//		create_MySQL_Thread=&create_MySQL_Thread_func;
//	}
}

{
	dlerror();
	dlsym_error=NULL;
	//void* __mysql_thread = dlopen("../lib/Standard_MySQL_Thread.so", RTLD_LAZY|RTLD_DEEPBIND);
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
//	if (__mysql_thread==NULL ||	dlsym_error) {
//		create_MySQL_Thread=&create_MySQL_Thread_func;
//	}
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
	MyHGH=new MySQL_HostGroups_Handler();

{
	GloAdmin = create_ProxySQL_Admin();
	GloAdmin->print_version();
	GloAdmin->init();
}


	GloMyAuth = create_MySQL_Authentication();
	GloMyAuth->print_version();

	GloAdmin->init_users();


	if (GloVars.global.nostart) {
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}

	mysql_threads=NULL;

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


	listen_fd=listen_on_port((char *)"127.0.0.1",6033, 50);
	socket_fd=listen_on_unix((char *)"/tmp/proxysql.sock", 50);
	ioctl_FIONBIO(listen_fd, 1);
	ioctl_FIONBIO(socket_fd, 1);
	int i;


	mysql_threads=(proxysql_mysql_thread_t *)malloc(sizeof(proxysql_mysql_thread_t)*NUM_THREADS);
	assert(mysql_threads);

	load_ = NUM_THREADS + 1;

	pthread_attr_t attr;


{
	rc=pthread_attr_init(&attr);
  rc=pthread_attr_setstacksize(&attr, 512*1024);
  assert(rc==0);

}

	for (i=0; i<NUM_THREADS; i++) {
		pthread_create(&mysql_threads[i].thread_id, &attr, mysql_worker_thread_func , &mysql_threads[i]);
	}

	
	//SQC = new Shared_Query_Cache(DEFAULT_SQC_size);
	GloQC = create_QC();
	GloQC->print_version();
	pthread_create(&GloQC->purge_thread_id, NULL, mysql_shared_query_cache_funct , NULL);
	//void *(*__f)(void *) = (void* (*)(void*))&SQC->purgeHash_thread;
	//pthread_create(&SQC_purge_thread_id, NULL, &SQC->purgeHash_thread , NULL);



		

	do { /* nothing */ } while (load_ != 1);


	load_ = 0;

	//sleep(10);

	while (glovars.shutdown==0) {
		sleep(1);   // FIXME: TERRIBLE UGLY
	}
		
__shutdown:

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
	if (GloQC) {
		GloQC->shutdown=1;
		pthread_join(GloQC->purge_thread_id, NULL);
	}
	//SQC->empty();
	//SQC->flush();




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
	delete GloAdmin;
	delete MyHGH;

	if (glovars.reload) {
		//sleep(1);
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

