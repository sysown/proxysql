#include "proxysql.h"

#include "cpp.h"


#define MAX_EVENTS 100


//struct epoll_event ev, events[MAX_EVENTS];
//int listen_sock, conn_sock, nfds, epollfd;

int listen_fd;
int socket_fd;

typedef struct _proxysql_mysql_thread_t proxysql_mysql_thread_t;

struct _proxysql_mysql_thread_t {
	MySQL_Thread *worker;
	pthread_t thread_id;
};

static proxysql_mysql_thread_t *mysql_threads;

#define NUM_THREADS	8

void diagnostic_myds(MySQL_Data_Stream *myds) {
	if (!myds) return;
	fprintf(stderr,"      fd=%d, pkts_sent=%llu, pkts_recv=%llu, bytes_sent=%llu, bytes_recv=%llu\n", myds->fd, myds->pkts_sent, myds->pkts_recv, myds->bytes_info.bytes_sent, myds->bytes_info.bytes_recv);
	struct pollfd *_pollfd;
	_pollfd=&myds->sess->thread->mypolls.fds[myds->poll_fds_idx];
	fprintf(stderr,"      poll_fds_idx=%d pollfd={fd=%d, events=%d, revents=%d}\n", myds->poll_fds_idx, _pollfd->fd, _pollfd->events, _pollfd->revents);
//	fprintf(stderr,"      \n");
//	fprintf(stderr,"      \n");
}

void diagnostic_all() {
	fprintf(stderr,"Diagnostic\n");
	int i;
	for (i=0;i<NUM_THREADS;i++) {
		fprintf(stderr,"MySQL Thread: Object=%p, thread_id=0x%08lx\n", mysql_threads[i].worker, mysql_threads[i].thread_id);
		unsigned int j;
		MySQL_Thread *thr=mysql_threads[i].worker;
		for (j=0; j<thr->mysql_sessions->len; j++) {
			MySQL_Session *sess=(MySQL_Session *)g_ptr_array_index(thr->mysql_sessions,j);
			fprintf(stderr," Session=%p\n", sess);
			fprintf(stderr,"    Client Data Stream=%p, fd=%d\n", sess->client_myds, ( sess->client_myds ? sess->client_myds->fd : 0 ));
			diagnostic_myds(sess->client_myds);
			fprintf(stderr,"    Server Data Stream=%p, fd=%d\n", sess->server_myds, ( sess->server_myds ? sess->server_myds->fd : 0 ));
			diagnostic_myds(sess->server_myds);
		}
	}
}

void * mysql_worker_thread_func(void *arg) {

	//int listen_fd=*(int *)arg;
	proxysql_mysql_thread_t *mysql_thread=(proxysql_mysql_thread_t *)arg;
	MySQL_Thread *worker = new MySQL_Thread;
	mysql_thread->worker=worker;
	worker->init();
	//thr1->epoll_listener_add(listen_fd);
	worker->poll_listener_add(listen_fd);
	worker->poll_listener_add(socket_fd);
	worker->run();
	delete worker;
	return NULL;
}




int main(int argc, char **argv) {

	setenv("G_SLICE","always-malloc",1);

#ifdef DEBUG
	gdbg=0;
	proxysql_foreground=1;

	init_debug_struct();

	gdbg_lvl[PROXY_DEBUG_NET].verbosity=0;
	gdbg_lvl[PROXY_DEBUG_MYSQL_PROTOCOL].verbosity=0;

#endif /* DEBUG */


	listen_fd=listen_on_port((char *)"127.0.0.1",6033, 50);
	socket_fd=listen_on_unix((char *)"/tmp/proxysql.sock", 50);
	ioctl_FIONBIO(listen_fd, 1);
	ioctl_FIONBIO(socket_fd, 1);
	int i;

	mysql_threads=(proxysql_mysql_thread_t *)malloc(sizeof(proxysql_mysql_thread_t)*NUM_THREADS);
	assert(mysql_threads);

	for (i=0; i<NUM_THREADS; i++) {
		pthread_create(&mysql_threads[i].thread_id, NULL, mysql_worker_thread_func , &mysql_threads[i]);
	}
	sleep(1000);
//	diagnostic_all();
//	sleep(1000);
	
	for (i=0; i<NUM_THREADS; i++) {
		mysql_threads[i].worker->shutdown=1;
	}
	for (i=0; i<NUM_THREADS; i++) {
		pthread_join(mysql_threads[i].thread_id,NULL);
	}
	free(mysql_threads);
	return 0;
}

