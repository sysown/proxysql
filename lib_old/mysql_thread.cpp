#include "proxysql.h"
#include "cpp.h"



MySQL_Thread::MySQL_Thread() {
}

void MySQL_Thread::init() {
	mysql_sessions=g_ptr_array_new();
	assert(mysql_sessions);
	shutdown=0;
	init_epoll(MYSQL_THREAD_EPOLL_MAXEVENTS);
}

int MySQL_Thread::init_epoll(int me) {
	epoll_maxevents=me; // define maximum number of events for epoll()
	epollfd=epoll_create(epoll_maxevents); // create epoll
	if (epollfd==-1) {
		perror("epoll_create");
		assert(0);
		//exit(EXIT_FAILURE);
	}
	events=(struct epoll_event *)malloc(sizeof(struct epoll_event)*epoll_maxevents);
	assert(events);
	return epollfd;
}


void MySQL_Thread::epoll_listener_add(int sock) {
	struct epoll_event ev;
	int rc;
	MySQL_Data_Stream *listener_DS = new MySQL_Data_Stream;	
	listener_DS->listener=1;
	listener_DS->fd=sock;
	memset(&ev,0,sizeof(struct epoll_event));
	//ev.events = EPOLLIN | EPOLLERR | EPOLLHUP ;
	ev.events = EPOLLIN;
	ev.data.ptr=listener_DS;
	rc=epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev);
	if (rc==-1) {
		perror("epoll_ctl");
		assert(0);
		//exit(EXIT_FAILURE);
	}	
}

// main loop
void MySQL_Thread::run() {
	int n;
	int arg_on=1;
	while (shutdown==0) {
		nfds=epoll_wait(epollfd, events, epoll_maxevents, 1000);
		for (n = 0; n < nfds; ++n) {
			MySQL_Data_Stream *myds=(MySQL_Data_Stream *)events[n].data.ptr;
			if (myds->listener==1) {
				// we got a new connection!
				int c=accept(myds->fd, NULL, NULL);
				if (c>-1) {
					MySQL_Session *sess=new MySQL_Session;
	proxy_debug(PROXY_DEBUG_NET,1,"Created new Session %p\n", sess);
					sess->client_fd=c;
	setsockopt(sess->client_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));

					sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->init();
  sess->client_myds->sess=sess;
	proxy_debug(PROXY_DEBUG_NET,1,"Created new DS %p sess %p\n", sess->client_myds, sess);
  sess->client_myds->fd=sess->client_fd;
  sess->server_fd=connect_socket((char *)"127.0.0.1", 3306);
	setsockopt(sess->server_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
  sess->server_myds = new MySQL_Data_Stream();
	sess->server_myds->init();
  sess->server_myds->sess=sess;
	proxy_debug(PROXY_DEBUG_NET,1,"Created new DS %p sess %p\n", sess->server_myds, sess);
  sess->server_myds->fd=sess->server_fd;

  ioctl_FIONBIO(sess->client_fd, 1);
  ioctl_FIONBIO(sess->server_fd, 1);



  sess->client_myds->epollfd=epollfd;
  sess->server_myds->epollfd=epollfd;

  //sess->client_myds->ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP ;
  sess->client_myds->ev.events = EPOLLIN | EPOLLOUT;
  sess->client_myds->ev.data.ptr=sess->client_myds;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, sess->client_fd, &sess->client_myds->ev);
  //sess->server_myds->ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP ;
  sess->server_myds->ev.events = EPOLLIN | EPOLLOUT;
  sess->server_myds->ev.data.ptr=sess->server_myds;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, sess->server_fd, &sess->server_myds->ev);
	proxy_debug(PROXY_DEBUG_NET,1,"Adding client FD %d and server FD %d\n", sess->client_fd, sess->server_fd);

				}
				continue;
			} else {
				// data on exiting connection
				MySQL_Session *sess=myds->sess;
				


      myds->rev=&events[n];
      myds->read_from_net();
      myds->read_pkts();

      if (myds->fd==sess->client_fd) {
        unsigned char *pkt;
        /*while ((pkt=(unsigned char *)g_queue_pop_head(sess->client_myds->queueIN))!=NULL) {
          g_queue_push_tail(sess->server_myds->queueOUT,pkt);
        }*/
        while (sess->client_myds->QarrayIN->len) {
					pkt=(unsigned char *)g_ptr_array_remove_index(sess->client_myds->QarrayIN,0);
			proxy_debug(PROXY_DEBUG_NET,1,"Session %p\n", sess);
			parse_mysql_pkt(pkt, &sess->sess_states, 1);
          if (sess->server_myds) {
          g_ptr_array_add(sess->server_myds->QarrayOUT,pkt);
					} else {
						free(pkt);
					}
        }
      }
      if (myds->fd==sess->server_fd) {
        unsigned char *pkt;
        /*while ((pkt=(unsigned char *)g_queue_pop_head(sess->server_myds->queueIN))!=NULL) {
          g_queue_push_tail(sess->client_myds->queueOUT,pkt);
        }*/
        while (sess->server_myds->QarrayIN->len) {
					pkt=(unsigned char *)g_ptr_array_remove_index(sess->server_myds->QarrayIN,0);
			proxy_debug(PROXY_DEBUG_NET,1,"Session %p\n", sess);
			parse_mysql_pkt(pkt, &sess->sess_states, 0);
          if (sess->client_myds) {
						g_ptr_array_add(sess->client_myds->QarrayOUT,pkt);
					} else {
						free(pkt);
					}
        }
      }

      if (myds->active==FALSE) {
				epoll_ctl(epollfd, EPOLL_CTL_DEL, myds->fd, NULL);
				proxy_debug(PROXY_DEBUG_NET,1, "Deleting FD %d\n", myds->fd);
				myds->shut_hard();
				if (sess->client_myds==myds) sess->client_myds=NULL;
				if (sess->server_myds==myds) sess->server_myds=NULL;
				delete myds;
     		if (sess->client_myds==NULL && sess->server_myds==NULL) {
					delete sess;
					continue;
				}
        //exit(1);
      }

	      // always move pkts from queue to evbuffer
				sess->writeout();

			myds->write_to_net_epoll();




			}
		}
	}
}
