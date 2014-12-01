#include "proxysql.h"
void set_thread_attr(pthread_attr_t *attr, size_t stacksize) {
//	int rc;
	//assert(rc==0);
//	pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
//	int ss;
}

void start_background_threads(pthread_attr_t *attra, void **stackspts) {
	pthread_attr_t attr;

	int r;
	r=pthread_attr_init(&attr);
		assert(r==0);
	void *sp;
#ifdef DEBUG
		r=posix_memalign(&sp, sysconf(_SC_PAGESIZE), glovars.stack_size);
		assert(r==0);
		stackspts[glovars.mysql_threads+2+0]=sp;
		r=pthread_attr_setstack(&attr, sp, glovars.stack_size);
		assert(r==0);
	r=pthread_create(&thread_dbg_logger, &attr, debug_logger , NULL);
	assert(r==0);
#endif
	if (glovars.mysql_query_cache_enabled==TRUE) {
		PROXY_TRACE();
		fdb_hashes_new(&QC,glovars.mysql_query_cache_partitions, glovars.mysql_query_cache_default_timeout, glovars.mysql_query_cache_size);
//		pthread_t qct;
		r=posix_memalign(&sp, sysconf(_SC_PAGESIZE), glovars.stack_size);
		assert(r==0);
		stackspts[glovars.mysql_threads+2+1]=sp;
		r=pthread_attr_setstack(&attr, sp, glovars.stack_size);
		assert(r==0);
		r=pthread_create(&thread_qct, &attr, purgeHash_thread, &QC);
		assert(r==0);
	}

	// Added by chan
	//printf("=> create new qr_hash\n");
	qr_hashes_new(&QR_HASH_T);
	//printf("=> end\n");

	r=posix_memalign(&sp, sysconf(_SC_PAGESIZE), glovars.stack_size);
	assert(r==0);
	stackspts[glovars.mysql_threads+2+2]=sp;
	r=pthread_attr_setstack(&attr, sp, glovars.stack_size);
	assert(r==0);
	r=pthread_create(&thread_qr, &attr, qr_report_thread, &QR_HASH_T);
	assert(r==0);
	// Added by chan end. 


//	pthread_t cppt;
	r=posix_memalign(&sp, sysconf(_SC_PAGESIZE), glovars.stack_size);
	assert(r==0);
	stackspts[glovars.mysql_threads+2+3]=sp;
	r=pthread_attr_setstack(&attr, sp, glovars.stack_size);
	assert(r==0);
	r=pthread_create(&thread_cppt, &attr, mysql_connpool_purge_thread , NULL);
	assert(r==0);
}

void init_proxyipc() {
	int i;
	PROXY_TRACE();
	proxyipc.fdIn=g_malloc0_n(glovars.mysql_threads,sizeof(int));
	proxyipc.fdOut=g_malloc0_n(glovars.mysql_threads,sizeof(int));
	proxyipc.queue=g_malloc0_n(glovars.mysql_threads+1,sizeof(GAsyncQueue *));
	// create pipes
	for (i=0; i<glovars.mysql_threads; i++) {
		int fds[2];
		int rc;
		rc=pipe(fds);
		assert(rc==0);
//		if (rc==-1) {
//			perror("pipe");
//			assert(rc==0);
//		}
		proxyipc.fdIn[i]=fds[0];
		proxyipc.fdOut[i]=fds[1];
	}
	// initialize the async queue
	for (i=0; i<glovars.mysql_threads+1; i++) {
		proxyipc.queue[i]=g_async_queue_new();
	}
}
