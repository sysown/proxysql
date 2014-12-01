#include "proxysql.h"
#include "cpp.h"

//static void cleanup(const void *data, size_t len, void *arg) {
//	free(arg);
//}

// Constructor
MySQL_Data_Stream::MySQL_Data_Stream() {
	bytes_info.bytes_recv=0;
	bytes_info.bytes_sent=0;
	pkts_recv=0;
	pkts_sent=0;
	evbIN=NULL;
	evbOUT=NULL;

	QarrayIN=NULL;
	QarrayOUT=NULL;
	queueIN=NULL;
	queueOUT=NULL;
	listener=0;
	mybe=NULL;
	active=TRUE;
	memset(&ev,0,sizeof(struct epoll_event));
}


// Destructor
MySQL_Data_Stream::~MySQL_Data_Stream() {
	if (evbIN) evbuffer_free(evbIN);
	if (evbIN) evbuffer_free(evbOUT);
	if (queueIN) g_queue_free_full(queueIN,free);
	if (queueOUT) g_queue_free_full(queueOUT,free);
	//destroy_databuffer(&bufferOUT);
	proxy_debug(PROXY_DEBUG_NET,1, "Shutdown Data Stream %p, Session %p\n" , this, sess);
}



// this function initialze a MySQL_Data_Stream 
// needs to be called only if listener=0
void MySQL_Data_Stream::init() {
	if (listener==0) {
		evbIN=evbuffer_new();
		assert(evbIN!=NULL);
		evbOUT=evbuffer_new();
		assert(evbOUT!=NULL);
		queueIN=g_queue_new();
		assert(queueIN!=NULL);
		queueOUT=g_queue_new();
		assert(queueOUT!=NULL);
		QarrayIN=g_ptr_array_new();
		assert(QarrayIN);
		QarrayOUT=g_ptr_array_new();
		assert(QarrayOUT);
		//create_databuffer(&bufferOUT, 8192);
		//printf("%p %p\n, queueIN, queueOUT");
	}
}

// Soft shutdown of socket : it only deactivate the data stream
void MySQL_Data_Stream::shut_soft() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown soft %d\n", fd);
	active=FALSE;
	sess->net_failure=1;
}

// Hard shutdown of socket
void MySQL_Data_Stream::shut_hard() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown hard %d\n", fd);
	if (fd >= 0) {
		shutdown(fd, SHUT_RDWR);
		close(fd);
		fd = -1;
	}
}


/*
void MySQL_Data_Stream::create_databuffer(mysql_data_buffer_t *databuf, unsigned int size) {
	memset(databuf, 0, sizeof(mysql_data_buffer_t));
	databuf->size=size;
	databuf->buffer=malloc(size);
	assert(databuf->buffer);
}

void MySQL_Data_Stream::destroy_databuffer(mysql_data_buffer_t *databuf) {
	free(databuf->buffer);
	if (databuf->pkt) free(databuf->pkt);
	memset(databuf, 0, sizeof(mysql_data_buffer_t));	
}
*/

/*
 * reads data from file descriptor and write it into evbIN .
 * reads only if rev->events has EPOLLIN enabled
 * in case of failure calls shut_soft()
*/
int MySQL_Data_Stream::read_from_net() {
	if ((rev->events & EPOLLIN)==0) return 0; // there is no data to read, return immediately
	int bytes_io=0;
	int rc;
	while (( rc = evbuffer_read(evbIN, fd, -1)) > 0) {
		proxy_debug(PROXY_DEBUG_NET,1,"Read %d bytes from FD %d\n", rc, fd);
		bytes_io+=rc;
	}
	if (rc==-1) proxy_debug(PROXY_DEBUG_NET,1,"Total: Read %d bytes from FD %d, errno %d\n", bytes_io, fd, errno);
	if (rc==0) proxy_debug(PROXY_DEBUG_NET,1,"Total: Read %d bytes from FD %d\n", bytes_io, fd);
	//if (bytes_io < 1) {
	//	if (bytes_io==0 || (bytes_io==-1 && errno != EINTR && errno != EAGAIN)) {
	if (rc < 1) {
		if (rc==0 || (rc==-1 && errno != EINTR && errno != EAGAIN)) {
			shut_soft();
		}
	} else {
		bytes_info.bytes_recv+=bytes_io;		
		if (mybe) {
 		//	__sync_fetch_and_add(&mybe->mshge->server_bytes.bytes_recv,r);
		}
	}
	return bytes_io;
}

int MySQL_Data_Stream::write_to_net() {
	int bytes_io;
	bytes_io = evbuffer_write(evbOUT, fd);
	proxy_debug(PROXY_DEBUG_NET,1,"Written %d bytes into FD %d\n", bytes_io, fd);
	if (bytes_io < 0) {
		shut_soft();
	} else {
		bytes_info.bytes_sent+=bytes_io;
		if (mybe) {
 		//	__sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_sent,r);
		}	
	}
	return bytes_io;
}


void MySQL_Data_Stream::set_epollout() {

	struct epoll_event evtmp;

	int buflen=evbuffer_get_length(evbOUT);	
	if (buflen) {
		//evtmp.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP ;
		evtmp.events = EPOLLIN | EPOLLOUT;
	} else {
		//evtmp.events = EPOLLIN | EPOLLERR | EPOLLHUP ;
		evtmp.events = EPOLLIN;
	}
	//printf("buflen=%d , events=%d , newevents=%d\n", buflen, ev.events, evtmp.events);
	if (evtmp.events != ev.events) {
		ev.events=evtmp.events;
		epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
		proxy_debug(PROXY_DEBUG_NET,1,"Setting events %d for FD %d\n", ev.events, fd);
	}
}


int MySQL_Data_Stream::write_to_net_epoll() {
	int rc=0;
	if (evbuffer_get_length(evbOUT) && (rev->events & EPOLLOUT)) {
		rc=write_to_net();
	}
	set_epollout();
	return rc;
}

int MySQL_Data_Stream::read_pkts() {
	int pkts=0;
	int rc;
	int pkt_totlen, pkt_length, buffer_len;
	unsigned char *pkt;
	buffer_len=evbuffer_get_length(evbIN);
	if (buffer_len==0) return 0;	// there is no data, return immediately
	while ((pkt=evbuffer_pullup(evbIN, 4))!=NULL) {
		// read pkt length
		pkt_length=CPY3(pkt);
		pkt_totlen=pkt_length+sizeof(mysql_hdr);	// totlen = pkt len + header len
		buffer_len = evbuffer_get_length(evbIN);	// total amount of data in evbuffer
		if (buffer_len < pkt_totlen) {
			goto read_pkts_return;	// returns if there is not enough data in evbuffer
		}
		pkt=(unsigned char *)malloc(pkt_totlen); // allocate a buffer for the whole packet, header included
		assert(pkt);
		rc=evbuffer_remove(evbIN,pkt,pkt_totlen); // copy the packet
		assert(rc==pkt_totlen);
		//parse_mysql_pkt(pkt);
		proxy_debug(PROXY_DEBUG_NET,1,"Read one packet from FD %d, size %d\n", fd, pkt_totlen);
		g_ptr_array_add(QarrayIN,pkt);
		//g_queue_push_tail(queueIN,pkt); // add the packet in the queue

		pkts++;
	}
read_pkts_return:
	pkts_recv+=pkts;
	return pkts;
}

int MySQL_Data_Stream::write_pkts() {
	int pkts=0;
	int rc;
	int pkt_totlen, pkt_length;
	unsigned char *pkt;
	//while ((pkt=(unsigned char *)g_queue_pop_head(queueOUT))!=NULL) {
	while (QarrayOUT->len) {
		pkt=(unsigned char *)g_ptr_array_remove_index(QarrayOUT,0);
		pkt_length=CPY3(pkt);
		pkt_totlen=pkt_length+sizeof(mysql_hdr);	// totlen = pkt len + header len

		// add copying the packet
		rc=evbuffer_add(evbOUT, pkt, pkt_totlen);
		assert(rc==0);
		proxy_debug(PROXY_DEBUG_NET,1,"Write one packet for FD %d, size %d\n", fd, pkt_totlen);
		free(pkt);

/*
		// add by reference
		rc=evbuffer_add_reference(evbOUT, pkt, pkt_totlen, cleanup, pkt);
		assert(rc==0);
*/
		pkts++;	
	}
	pkts_sent+=pkts;
	return pkts;
}
