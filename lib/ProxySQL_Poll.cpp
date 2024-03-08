#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "StatCounters.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "ProxySQL_Poll.h"
#include "proxysql_structs.h"
#include <poll.h>
#include "cpp.h"

template<class T>
void ProxySQL_Poll<T>::shrink() {
	unsigned int new_size=l_near_pow_2(len+1);
	fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
	myds=(T **)realloc(myds,new_size*sizeof(T *));
	last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
	last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
	size=new_size;
}

template<class T>
void ProxySQL_Poll<T>::expand(unsigned int more) {
	if ( (len+more) > size ) {
		unsigned int new_size=l_near_pow_2(len+more);
		fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
		myds=(T **)realloc(myds,new_size*sizeof(T *));
		last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
		size=new_size;
	}
}

template<class T>
ProxySQL_Poll<T>::ProxySQL_Poll() {
	loop_counters=new StatCounters(15,10);
	poll_timeout=0;
	loops=0;
	len=0;
	pending_listener_add=0;
	pending_listener_del=0;
	bootstrapping_listeners = true;
	size=MIN_POLL_LEN;
	fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
	myds=(T**)malloc(size*sizeof(T *));
	last_recv=(unsigned long long *)malloc(size*sizeof(unsigned long long));
	last_sent=(unsigned long long *)malloc(size*sizeof(unsigned long long));
}

template<class T>
ProxySQL_Poll<T>::~ProxySQL_Poll() {
	unsigned int i;
	for (i=0;i<len;i++) {
		if (
			myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
			myds[i]->myds_type==MYDS_LISTENER) {
				delete myds[i];
		}
	}
	free(myds);
	free(fds);
	free(last_recv);
	free(last_sent);
	delete loop_counters;
}

template<class T>
void ProxySQL_Poll<T>::add(uint32_t _events, int _fd, T *_myds, unsigned long long sent_time) {
	if (len==size) {
		expand(1);
	}
	myds[len]=_myds;
	fds[len].fd=_fd;
	fds[len].events=_events;
	fds[len].revents=0;
	if (_myds) {
		_myds->mypolls=this;
		_myds->poll_fds_idx=len;  // fix a serious bug
	}
	last_recv[len]=monotonic_time();
	last_sent[len]=sent_time;
	len++;
}

template<class T>
void ProxySQL_Poll<T>::remove_index_fast(unsigned int i) {
	if ((int)i==-1) return;
	myds[i]->poll_fds_idx=-1; // this prevents further delete
	if (i != (len-1)) {
		myds[i]=myds[len-1];
		fds[i].fd=fds[len-1].fd;
		fds[i].events=fds[len-1].events;
		fds[i].revents=fds[len-1].revents;
		myds[i]->poll_fds_idx=i;  // fix a serious bug
		last_recv[i]=last_recv[len-1];
		last_sent[i]=last_sent[len-1];
	}
	len--;
	if ( ( len>MIN_POLL_LEN ) && ( size > len*MIN_POLL_DELETE_RATIO ) ) {
		shrink();
	}
}

template<class T>
int ProxySQL_Poll<T>::find_index(int fd) {
	unsigned int i;
	for (i=0; i<len; i++) {
		if (fds[i].fd==fd) {
			return i;
		}
	}
	return -1;
}

template class ProxySQL_Poll<PgSQL_Data_Stream>;
template class ProxySQL_Poll<MySQL_Data_Stream>;