#include "proxysql.h"
#include "cpp.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif 
//static void cleanup(const void *data, size_t len, void *arg) {
//	free(arg);
//}


#ifdef DEBUG
static void __dump_pkt(const char *func, unsigned char *_ptr, unsigned int len) {

	if (GloVars.global.gdbg==0) return;
	if (GloVars.global.gdbg_lvl[PROXY_DEBUG_PKT_ARRAY].verbosity < 8 ) return;
	unsigned int i;
	fprintf(stderr,"DUMP %d bytes FROM %s\n", len, func);
	for(i = 0; i < len; i++) {
		if(isprint(_ptr[i])) fprintf(stderr,"%c", _ptr[i]); else fprintf(stderr,".");
		if (i>0 && (i%16==15 || i==len-1)) {
			unsigned int j;
			if (i%16!=15) {
				j=15-i%16;
				while (j--) fprintf(stderr," ");
			}
			fprintf(stderr," --- ");
			for (j=(i==len-1 ? ((int)(i/16))*16 : i-15 ) ; j<=i; j++) {
				fprintf(stderr,"%02x ", _ptr[j]);
			}
			fprintf(stderr,"\n");
		}
   }
	fprintf(stderr,"\n\n");
	

}
#endif




#define queue_init(_q,_s) { \
    _q.size=_s; \
    _q.buffer=malloc(_q.size); \
    _q.head=0; \
    _q.tail=0; \
	_q.partial=0; \
	_q.pkt.ptr=NULL; \
	_q.pkt.size=0; \
}

#define queue_destroy(_q) { \
    free(_q.buffer); \
}

#define queue_zero(_q) { \
  memcpy(_q.buffer, (unsigned char *)_q.buffer + _q.tail, _q.head - _q.tail); \
  _q.head-=_q.tail; \
  _q.tail=0; \
}

#define queue_available(_q) (_q.size-_q.head)
#define queue_data(_q) (_q.head-_q.tail)

#define queue_r(_q, _s) { \
  _q.tail+=_s; \
  if (_q.tail==_q.head) { \
    _q.head=0; \
    _q.tail=0; \
  } \
}

#define queue_w(_q,_s) (_q.head+=_s)

#define queue_r_ptr(_q) ((unsigned char *)_q.buffer+_q.tail)
#define queue_w_ptr(_q) ((unsigned char *)_q.buffer+_q.head)



void * MySQL_Data_Stream::operator new(size_t size) {
  return l_alloc(size);
}

void MySQL_Data_Stream::operator delete(void *ptr) {
  l_free(sizeof(MySQL_Data_Stream),ptr);
}


// Constructor
MySQL_Data_Stream::MySQL_Data_Stream() {
	//_pollfd=NULL;
	bytes_info.bytes_recv=0;
	bytes_info.bytes_sent=0;
	pkts_recv=0;
	pkts_sent=0;

	connect_tries=0;
	poll_fds_idx=-1;
	resultset_length=0;
	query_SQL=NULL;

	PSarrayIN=NULL;
	PSarrayOUT=NULL;
	PSarrayOUTpending=NULL;
	resultset=NULL;
	queue_init(queueIN,QUEUE_T_DEFAULT_SIZE);
	queue_init(queueOUT,QUEUE_T_DEFAULT_SIZE);
	//listener=0;
	mybe=NULL;
	active=TRUE;
	mypolls=NULL;
	myconn=NULL;	// 20141011
	//myconn = new MySQL_Connection(); // 20141011
	//myconn->myds=this; // 20141011
	DSS=STATE_NOT_CONNECTED;
	encrypted=false;
	ssl=NULL;
	net_failure=false;
//	ssl_ctx=NULL;
}


// Destructor
MySQL_Data_Stream::~MySQL_Data_Stream() {

	queue_destroy(queueIN);
	queue_destroy(queueOUT);

	proxy_debug(PROXY_DEBUG_NET,1, "Shutdown Data Stream. Session=%p, DataStream=%p\n" , sess, this);
	PtrSize_t pkt;
	if (PSarrayIN) {
		while (PSarrayIN->len) {
			PSarrayIN->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayIN;
	}
	if (PSarrayOUT) {
		while (PSarrayOUT->len) {
			PSarrayOUT->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayOUT;
	}
	if (PSarrayOUTpending) {
		while (PSarrayOUTpending->len) {
			PSarrayOUTpending->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayOUTpending;
	}
	if (resultset) {
		while (resultset->len) {
			resultset->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
	delete resultset;
	}
	if (mypolls) mypolls->remove_index_fast(poll_fds_idx);
	if (fd>0) {
		if (myconn==NULL || myconn->reusable==false) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "MySQL_Connection %p %s: shutdown socket\n", myconn, (myconn ? "not reusable" : "is empty"));
			shut_hard();
//		shutdown(fd,SHUT_RDWR);
//		close(fd);
		}
	}
	if ( (myconn) && (myds_type==MYDS_FRONTEND) ) { delete myconn; myconn=NULL; }
	if (encrypted) {
		if (ssl) SSL_free(ssl);
//		if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	}
}



// this function initializes a MySQL_Data_Stream 
void MySQL_Data_Stream::init() {
	if (myds_type!=MYDS_LISTENER) {
		proxy_debug(PROXY_DEBUG_NET,1, "Init Data Stream. Session=%p, DataStream=%p -- type %d\n" , sess, this, myds_type);
		if (PSarrayIN==NULL) PSarrayIN = new PtrSizeArray();
		if (PSarrayOUT==NULL) PSarrayOUT= new PtrSizeArray();
		if (PSarrayOUTpending==NULL) PSarrayOUTpending= new PtrSizeArray();
		if (resultset==NULL) resultset = new PtrSizeArray();
	}
}

// this function initializes a MySQL_Data_Stream with arguments
void MySQL_Data_Stream::init(enum MySQL_DS_type _type, MySQL_Session *_sess, int _fd) {
	myds_type=_type;
	sess=_sess;
	init();
	fd=_fd;
	proxy_debug(PROXY_DEBUG_NET,1, "Initialized Data Stream. Session=%p, DataStream=%p, type=%d, fd=%d, myconn=%p\n" , sess, this, myds_type, fd, myconn);
	//if (myconn==NULL) myconn = new MySQL_Connection();
	if (myconn) myconn->fd=fd;
}


// Soft shutdown of socket : it only deactivate the data stream
// TODO: should check the status of the data stream, and identify if it is safe to reconnect or if the session should be destroyed
void MySQL_Data_Stream::shut_soft() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown soft fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	active=FALSE;
	net_failure=true;
	//if (sess) sess->net_failure=1;
}

// Hard shutdown of socket
void MySQL_Data_Stream::shut_hard() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown hard fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	net_failure=true;
	if (fd >= 0) {
		shutdown(fd, SHUT_RDWR);
		close(fd);
		fd = -1;
	}
}



void MySQL_Data_Stream::check_data_flow() {
	if ( (PSarrayIN->len || queue_data(queueIN) ) && ( PSarrayOUT->len || queue_data(queueOUT) ) ){
		// there is data at both sides of the data stream: this is considered a fatal error
		proxy_error("Session=%p, DataStream=%p -- Data at both ends of a MySQL data stream: IN <%d bytes %d packets> , OUT <%d bytes %d packets>\n", sess, this, PSarrayIN->len , queue_data(queueIN) , PSarrayOUT->len , queue_data(queueOUT));
		shut_soft();
	}
	//if ((myds_type==MYDS_BACKEND) && (myconn->myconn.net.fd==0) && (revents & POLLOUT)) {
	if ((myds_type==MYDS_BACKEND) && (myconn->fd==0) && (revents & POLLOUT)) {
		int rc;
		int error;
		socklen_t len = sizeof(error);
		rc=getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
		assert(rc==0);
		if (error==0) {
			//myconn->myconn.net.fd=fd; // connect succeeded
			myconn->fd=fd; // connect succeeded
		} else {
			errno=error;
			perror("check_data_flow");
			shut_soft();
		}
	}
}


int MySQL_Data_Stream::read_from_net() {
	if ((revents & POLLIN)==0) return 0;
	int r;
	int s=queue_available(queueIN);
	r = ( encrypted ? SSL_read (ssl, queue_w_ptr(queueIN), s) : recv(fd, queue_w_ptr(queueIN), s, 0) );
	proxy_debug(PROXY_DEBUG_NET, 5, "read %d bytes from fd %d into a buffer of %d bytes free\n", r, fd, s);
	//proxy_error("read %d bytes from fd %d into a buffer of %d bytes free\n", r, fd, s);
	if (r < 1) {
		if (encrypted==false) {
			if (r==0 || (r==-1 && errno != EINTR && errno != EAGAIN)) {
				shut_soft();
			}
		} else {
			int ssl_ret=SSL_get_error(ssl, r);
			if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
		}
	} else {
		queue_w(queueIN,r);
		bytes_info.bytes_recv+=r;
		if (mypolls) mypolls->last_recv[poll_fds_idx]=sess->thread->curtime;
		if (mybe) {
            //__sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_recv,r);
		}
	}
	return r;
}

int MySQL_Data_Stream::write_to_net() {
    int bytes_io=0;
	int s = queue_data(queueOUT);
    if (s==0) return 0;
	VALGRIND_DISABLE_ERROR_REPORTING;
  //bytes_io = ( encrypted ? SSL_write (ssl, queue_r_ptr(queueOUT), s) : send(fd, queue_r_ptr(queueOUT), s, 0) );
	// splitting the ternary operation in IF condition for better readability 
	if (encrypted) {
		bytes_io = SSL_write (ssl, queue_r_ptr(queueOUT), s);
	} else {
		//bytes_io = send(fd, queue_r_ptr(queueOUT), s, 0);
		// fix on bug #183
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, MSG_NOSIGNAL);
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	if (bytes_io < 0) {
		if (encrypted==false)	{
			shut_soft();
		} else {
			int ssl_ret=SSL_get_error(ssl, bytes_io);
			if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
		}
	} else {
		queue_r(queueOUT, bytes_io);
		if (mypolls) mypolls->last_sent[poll_fds_idx]=sess->thread->curtime;
		bytes_info.bytes_sent+=bytes_io;
		if (mybe) {
 		//	__sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_sent,r);
		}	
	}
	return bytes_io;
}

bool MySQL_Data_Stream::available_data_out() {
	int buflen=queue_data(queueOUT);
	if (buflen || PSarrayOUT->len) {
		return true;
	}
	return false;
}

void MySQL_Data_Stream::set_pollout() {
	//int buflen=queue_data(queueOUT);
	struct pollfd *_pollfd;
	_pollfd=&mypolls->fds[poll_fds_idx];
	//_pollfd=&sess->thread->mypolls.fds[poll_fds_idx];
	//_pollfd=sess->thread->get_pollfd(poll_fds_idx);
	//if (buflen || PSarrayOUT->len) {
	if (available_data_out() || queueOUT.partial) {
		_pollfd->events = POLLIN | POLLOUT;
	} else {
		_pollfd->events = POLLIN;
	}
	//FIXME: moved
	//_pollfd->revents=0;
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p -- Setting poll events %d for FD %d\n", sess, this, _pollfd->events , fd);
}


int MySQL_Data_Stream::write_to_net_poll() {
	int rc=0;
	if (active==FALSE) return rc;	
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p --\n", sess, this);
	if (queue_data(queueOUT) && poll_fds_idx>-1 && (mypolls->fds[poll_fds_idx].revents & POLLOUT)) {
	//if (queue_data(queueOUT)) { //FIXME
		rc=write_to_net();
	}
	if (fd>0 && sess->admin==false) set_pollout();
	return rc;
}


int MySQL_Data_Stream::read_pkts() {
	{
		int rc=0;
    	int r=0;
    	while((r=buffer2array())) rc+=r;
	    return rc;

	}
}


int MySQL_Data_Stream::buffer2array() {
	int ret=0;
	int fast_mode=0;
	if (queue_data(queueIN)==0) return ret;
	if ((queueIN.pkt.size==0) && queue_data(queueIN)<sizeof(mysql_hdr)) {
		queue_zero(queueIN);
	}

	if (fast_mode) {
		queueIN.pkt.size=queue_data(queueIN);
		ret=queueIN.pkt.size;
		queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
		memcpy(queueIN.pkt.ptr, queue_r_ptr(queueIN) , queueIN.pkt.size);
		queue_r(queueIN, queueIN.pkt.size);
		PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
		queueIN.pkt.size=0;
		return ret;
	}
	if ((queueIN.pkt.size==0) && queue_data(queueIN)>=sizeof(mysql_hdr)) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new packet\n");
		memcpy(&queueIN.hdr,queue_r_ptr(queueIN),sizeof(mysql_hdr));
		//Copy4B(&queueIN.hdr,queue_r_ptr(queueIN));
		queue_r(queueIN,sizeof(mysql_hdr));
		//proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Allocating %d bytes for a new packet\n", myds->input.hdr.pkt_length+sizeof(mysql_hdr));
		queueIN.pkt.size=queueIN.hdr.pkt_length+sizeof(mysql_hdr);
		queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);

		//MEM_COPY_FWD((unsigned char *)queueIN.pkt.ptr, (unsigned char *)&queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
		memcpy(queueIN.pkt.ptr, &queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
		//Copy4B(queueIN.pkt.ptr,&queueIN.hdr);
		queueIN.partial=sizeof(mysql_hdr);
		ret+=sizeof(mysql_hdr);
	}
	if ((queueIN.pkt.size>0) && queue_data(queueIN)) {
		int b= ( queue_data(queueIN) > (queueIN.pkt.size - queueIN.partial) ? (queueIN.pkt.size - queueIN.partial) : queue_data(queueIN) );
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied %d bytes into packet\n", b);
		memcpy((unsigned char *)queueIN.pkt.ptr + queueIN.partial, queue_r_ptr(queueIN),b);
		queue_r(queueIN,b);
		queueIN.partial+=b;
		ret+=b;
	}
	if ((queueIN.pkt.size>0) && (queueIN.pkt.size==queueIN.partial) ) {
		PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
		pkts_recv++;
		queueIN.pkt.size=0;
		queueIN.pkt.ptr=NULL;
	}  
	return ret;
}



int MySQL_Data_Stream::array2buffer() {
	int ret=0;
	//unsigned int idx=0;
	bool cont=true;
	while (cont) {
		if (queue_available(queueOUT)==0) return ret;
		if (queueOUT.partial==0) { // read a new packet
			//if (PSarrayOUT->len-idx) {
			if (PSarrayOUT->len) {
				proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Removing a packet from array\n", this);
				if (queueOUT.pkt.ptr) {
					l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
					queueOUT.pkt.ptr=NULL;
				}
				PSarrayOUT->remove_index(0,&queueOUT.pkt);
				//memcpy(&queueOUT.pkt,PSarrayOUT->index(idx),sizeof(PtrSize_t));
#ifdef DEBUG
				{ __dump_pkt(__func__,(unsigned char *)queueOUT.pkt.ptr,queueOUT.pkt.size); }
#endif
//			PtrSize_t *pts=PSarrayOUT->index(idx);
//			queueOUT.pkt.ptr=pts->ptr;
//			queueOUT.pkt.size=pts->size;
				//idx++;
			} else {
				cont=false;
				continue;
			}
		}
		int b= ( queue_available(queueOUT) > (queueOUT.pkt.size - queueOUT.partial) ? (queueOUT.pkt.size - queueOUT.partial) : queue_available(queueOUT) );
		memcpy(queue_w_ptr(queueOUT), (unsigned char *)queueOUT.pkt.ptr + queueOUT.partial, b);
		queue_w(queueOUT,b);
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Copied %d bytes into send buffer\n", this, b);
		queueOUT.partial+=b;
		ret=b;
		if (queueOUT.partial==queueOUT.pkt.size) {
			if (queueOUT.pkt.ptr) {
				l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
				queueOUT.pkt.ptr=NULL;
			}
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Packet completely written into send buffer\n", this);
			queueOUT.partial=0;
			pkts_sent+=1;
		}
	}
	//for (int i=0; i<idx; i++) { PSarrayOUT->remove_index(0,NULL); }
	//if (idx) PSarrayOUT->remove_index_range(0,idx);
	return ret;
}

unsigned char * MySQL_Data_Stream::resultset2buffer(bool del) {
	unsigned int i;
	unsigned int l=0;
	unsigned char *mybuff=(unsigned char *)l_alloc(resultset_length);
	PtrSize_t *ps;
	for (i=0;i<resultset->len;i++) {
		ps=resultset->index(i);
		memcpy(mybuff+l,ps->ptr,ps->size);
		if (del) l_free(ps->size,ps->ptr);
		l+=ps->size;
	}
	//while (resultset->len) resultset->remove_index(resultset->len-1,NULL);
	return mybuff;
};

void MySQL_Data_Stream::buffer2resultset(unsigned char *ptr, unsigned int size) {
	unsigned char *__ptr=ptr;
	mysql_hdr hdr;
	unsigned int l;
	void *pkt;
	while (__ptr<ptr+size) {
		memcpy(&hdr,__ptr,sizeof(mysql_hdr));
		//Copy4B(&hdr,__ptr);
		l=hdr.pkt_length+sizeof(mysql_hdr);
		pkt=l_alloc(l);
		memcpy(pkt,__ptr,l);
		resultset->add(pkt,l);
		__ptr+=l;
	}
};

int MySQL_Data_Stream::array2buffer_full() {
	int rc=0;
	int r=0;
	while((r=array2buffer())) rc+=r;
	return rc; 
}

int MySQL_Data_Stream::myds_connect(char *address, int connect_port, int *pending_connect) {
	//assert(myconn==NULL);

	if (myconn==NULL) myconn= new MySQL_Connection(); // FIXME: why here? // 20141011

	struct sockaddr_un u;
	struct sockaddr_in a;
	int s=0;
	int len=0;
	int rc=0;


	if (connect_port) {
		// TCP socket
		if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			close(s);
			return -1;
		}
		ioctl_FIONBIO(s, 1);
		memset(&a, 0, sizeof(a));
		a.sin_port = htons(connect_port);
		a.sin_family = AF_INET;

		if (!inet_aton(address, (struct in_addr *) &a.sin_addr.s_addr)) {
			perror("bad IP address format");
			close(s);
			return -1;
		}
	} else {
		// UNIX socket domain
		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			close(s);
			return -1;
		}
		ioctl_FIONBIO(s, 1);
		memset(u.sun_path,0,UNIX_PATH_MAX);
		u.sun_family = AF_UNIX;
		strncpy(u.sun_path, address, UNIX_PATH_MAX-1);
		len=strlen(u.sun_path)+sizeof(u.sun_family);
	}

	if (connect_port) {
		rc=connect(s, (struct sockaddr *) &a, sizeof(a));
	} else {
		rc=connect(s, (struct sockaddr *) &u, len);
	}
	if (rc==-1) {
		if (errno!=EINPROGRESS) {
			perror("connect()");
			shutdown(s, SHUT_RDWR);
			close(s);
			return -1;
		}
		//*pending_connect=1;  // default
		//myconn->myconn.net.fd=s; // FIXME: why here? // 20141011
	} else {
		*pending_connect=0;
	}
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, old_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->myconn.net.fd, s);
	//myconn->myconn.net.fd=s;
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, new_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->myconn.net.fd, s);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, old_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	myconn->fd=s;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, new_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	return s;

}


void MySQL_Data_Stream::move_from_OUT_to_OUTpending() {
	unsigned int k;
	PtrSize_t pkt2;
	for (k=0; k<PSarrayOUT->len;) {
		PSarrayOUT->remove_index(0,&pkt2);
		PSarrayOUTpending->add(pkt2.ptr, pkt2.size);
	}
}

/*
int MySQL_Data_Stream::assign_mshge(unsigned int hid) {
	assert (myconn);
	return myconn->assign_mshge(hid);
}
*/

int MySQL_Data_Stream::assign_fd_from_mysql_conn() {
	assert(myconn);
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->myconn.net.fd);
	//fd=myconn->myconn.net.fd;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->fd);
	fd=myconn->fd;
	return fd;
}

void MySQL_Data_Stream::unplug_backend() {
	DSS=STATE_NOT_INITIALIZED;
	myconn=NULL;
	myds_type=MYDS_BACKEND_NOT_CONNECTED;
  mypolls->remove_index_fast(poll_fds_idx);
  mypolls=NULL;
  fd=0;
}
