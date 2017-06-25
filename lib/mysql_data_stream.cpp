#include "proxysql.h"
#include "cpp.h"
#include <zlib.h>
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif 

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
	if (_q.buffer) free(_q.buffer); \
	_q.buffer=NULL; \
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
	bytes_info.bytes_recv=0;
	bytes_info.bytes_sent=0;
	pkts_recv=0;
	pkts_sent=0;
	client_addr=NULL;

	addr.addr=NULL;
	addr.port=0;
	proxy_addr.addr=NULL;
	proxy_addr.port=0;

	sess=NULL;
	mysql_real_query.pkt.ptr=NULL;
	mysql_real_query.pkt.size=0;
	mysql_real_query.QueryPtr=NULL;
	mysql_real_query.QuerySize=0;

	query_retries_on_failure=0;
	connect_retries_on_failure=0;
	max_connect_time=0;
	wait_until=0;
	connect_tries=0;
	poll_fds_idx=-1;
	resultset_length=0;

	revents = 0;

	PSarrayIN=NULL;
	PSarrayOUT=NULL;
	resultset=NULL;
	queue_init(queueIN,QUEUE_T_DEFAULT_SIZE);
	queue_init(queueOUT,QUEUE_T_DEFAULT_SIZE);
	mybe=NULL;
	active=1;
	mypolls=NULL;
	myconn=NULL;	// 20141011
	DSS=STATE_NOT_CONNECTED;
	encrypted=false;
	ssl=NULL;
	net_failure=false;
	CompPktIN.pkt.ptr=NULL;
	CompPktIN.pkt.size=0;
	CompPktIN.partial=0;
	CompPktOUT.pkt.ptr=NULL;
	CompPktOUT.pkt.size=0;
	CompPktOUT.partial=0;
	multi_pkt.ptr=NULL;
	multi_pkt.size=0;
}

// Destructor
MySQL_Data_Stream::~MySQL_Data_Stream() {

	queue_destroy(queueIN);
	queue_destroy(queueOUT);
	if (client_addr) {
		free(client_addr);
		client_addr=NULL;
	}
	if (addr.addr) {
		free(addr.addr);
		addr.addr=NULL;
	}
	if (proxy_addr.addr) {
		free(proxy_addr.addr);
		proxy_addr.addr=NULL;
	}

	free_mysql_real_query();

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
	if (resultset) {
		while (resultset->len) {
			resultset->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
	delete resultset;
	}
	if (mypolls) mypolls->remove_index_fast(poll_fds_idx);


	if (fd>0) {
//	// Changing logic here. The socket should be closed only if it is not a backend
		if (myds_type==MYDS_FRONTEND) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p , MYDS:%p , MySQL_Connection %p %s: shutdown socket\n", sess, this, myconn, (myconn ? "not reusable" : "is empty"));
			shut_hard();
		}
	}
	// Commenting the follow line of code and adding an assert. We should ensure that if a myconn exists it should be removed *before*
	if (myds_type==MYDS_BACKEND || myds_type==MYDS_BACKEND_NOT_CONNECTED) {
		assert(myconn==NULL);
	}
	if ( (myconn) && (myds_type==MYDS_FRONTEND) ) { delete myconn; myconn=NULL; }
	if (encrypted) {
		if (ssl) SSL_free(ssl);
	}
	if (multi_pkt.ptr) {
		l_free(multi_pkt.size,multi_pkt.ptr);
		multi_pkt.ptr=NULL;
		multi_pkt.size=0;
	}
	if (CompPktIN.pkt.ptr) {
		l_free(CompPktIN.pkt.size,CompPktIN.pkt.ptr);
		CompPktIN.pkt.ptr=NULL;
		CompPktIN.pkt.size=0;
	}
	if (CompPktOUT.pkt.ptr) {
		l_free(CompPktOUT.pkt.size,CompPktOUT.pkt.ptr);
		CompPktOUT.pkt.ptr=NULL;
		CompPktOUT.pkt.size=0;
	}
}

// this function initializes a MySQL_Data_Stream 
void MySQL_Data_Stream::init() {
	if (myds_type!=MYDS_LISTENER) {
		proxy_debug(PROXY_DEBUG_NET,1, "Init Data Stream. Session=%p, DataStream=%p -- type %d\n" , sess, this, myds_type);
		if (PSarrayIN==NULL) PSarrayIN = new PtrSizeArray();
		if (PSarrayOUT==NULL) PSarrayOUT= new PtrSizeArray();
//		if (PSarrayOUTpending==NULL) PSarrayOUTpending= new PtrSizeArray();
		if (resultset==NULL) resultset = new PtrSizeArray();
	}
	if (myds_type!=MYDS_FRONTEND) {
		queue_destroy(queueIN);
		queue_destroy(queueOUT);
	}
}

void MySQL_Data_Stream::reinit_queues() {
	if (queueIN.buffer==NULL)
		queue_init(queueIN,QUEUE_T_DEFAULT_SIZE);
	if (queueOUT.buffer==NULL)
		queue_init(queueOUT,QUEUE_T_DEFAULT_SIZE);
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
	active=0;
	set_net_failure();
	//if (sess) sess->net_failure=1;
}

// Hard shutdown of socket
void MySQL_Data_Stream::shut_hard() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown hard fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	set_net_failure();
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
	if ((myds_type==MYDS_BACKEND) && myconn && (myconn->fd==0) && (revents & POLLOUT)) {
		int rc;
		int error;
		socklen_t len = sizeof(error);
		rc=getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
		assert(rc==0);
		if (error==0) {
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
			int myds_errno=errno;
			if (r==0 || (r==-1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
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
	}
	return r;
}

int MySQL_Data_Stream::write_to_net() {
    int bytes_io=0;
	int s = queue_data(queueOUT);
    if (s==0) return 0;
	VALGRIND_DISABLE_ERROR_REPORTING;
	// splitting the ternary operation in IF condition for better readability 
	if (encrypted) {
		bytes_io = SSL_write (ssl, queue_r_ptr(queueOUT), s);
	} else {
#ifdef __APPLE__
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, 0);
#else
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, MSG_NOSIGNAL);
#endif
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	if (bytes_io < 0) {
		if (encrypted==false)	{
			if (mypolls->fds[poll_fds_idx].revents & POLLOUT) { // in write_to_net_poll() we has remove this safety
                                                          // so we enforce it here
				shut_soft();
			}
		} else {
			int ssl_ret=SSL_get_error(ssl, bytes_io);
			if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
		}
	} else {
		queue_r(queueOUT, bytes_io);
		if (mypolls) mypolls->last_sent[poll_fds_idx]=sess->thread->curtime;
		bytes_info.bytes_sent+=bytes_io;
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
	struct pollfd *_pollfd;
	_pollfd=&mypolls->fds[poll_fds_idx];
	if (DSS > STATE_MARIADB_BEGIN && DSS < STATE_MARIADB_END) {
		_pollfd->events = myconn->wait_events;
	} else {
		if (PSarrayOUT->len || available_data_out() || queueOUT.partial) {
			_pollfd->events = POLLIN | POLLOUT;
		} else {
			_pollfd->events = POLLIN;
		}
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p -- Setting poll events %d for FD %d , DSS=%d , myconn=%p\n", sess, this, _pollfd->events , fd, DSS, myconn);
}

int MySQL_Data_Stream::write_to_net_poll() {
	int rc=0;
	if (active==0) return rc;
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p --\n", sess, this);
	if (queue_data(queueOUT)) {
		if (sess->session_type == PROXYSQL_SESSION_MYSQL) {
			if (poll_fds_idx>-1) { // NOTE: attempt to force writes
				if (net_failure==false)
					rc=write_to_net();
			}
		} else {
			rc=write_to_net();
		}
	}
	if (fd>0 && sess->session_type == PROXYSQL_SESSION_MYSQL) set_pollout();
	return rc;
}

int MySQL_Data_Stream::read_pkts() {
	int rc=0;
	int r=0;
	while((r=buffer2array())) rc+=r;
	return rc;
}

int MySQL_Data_Stream::buffer2array() {
	int ret=0;
	bool fast_mode=sess->session_fast_forward;
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

	if (myconn->get_status_compression()==true) {
		if ((queueIN.pkt.size==0) && queue_data(queueIN)>=7) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new compressed packet\n");
 			memcpy(&queueIN.hdr,queue_r_ptr(queueIN), sizeof(mysql_hdr));
			queue_r(queueIN,sizeof(mysql_hdr));
			queueIN.pkt.size=queueIN.hdr.pkt_length+sizeof(mysql_hdr)+3;
			queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
			memcpy(queueIN.pkt.ptr, &queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
			memcpy((unsigned char *)queueIN.pkt.ptr+sizeof(mysql_hdr), queue_r_ptr(queueIN), 3); // copy 3 bytes, the length of the uncompressed payload
			queue_r(queueIN,3);
			queueIN.partial=7;
			mysql_hdr *_hdr;
			_hdr=(mysql_hdr *)queueIN.pkt.ptr;
			myconn->compression_pkt_id=_hdr->pkt_id;
			ret+=7;
		}
	} else {

		if ((queueIN.pkt.size==0) && queue_data(queueIN)>=sizeof(mysql_hdr)) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new packet\n");
			memcpy(&queueIN.hdr,queue_r_ptr(queueIN),sizeof(mysql_hdr));
			pkt_sid=queueIN.hdr.pkt_id;
			queue_r(queueIN,sizeof(mysql_hdr));
			queueIN.pkt.size=queueIN.hdr.pkt_length+sizeof(mysql_hdr);
			queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
			memcpy(queueIN.pkt.ptr, &queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
			queueIN.partial=sizeof(mysql_hdr);
			ret+=sizeof(mysql_hdr);
		}
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
		if (myconn->get_status_compression()==true) {
			Bytef *dest;
			uLongf destLen;
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied the whole compressed packet\n");
			unsigned int progress=0;
			unsigned int datalength;
			unsigned int payload_length=0;
			unsigned char *u;
			u=(unsigned char *)queueIN.pkt.ptr;
			payload_length=*(u+6);
			payload_length=payload_length*256+*(u+5);
			payload_length=payload_length*256+*(u+4);
			unsigned char *_ptr=(unsigned char *)queueIN.pkt.ptr+7;
			
			if (payload_length) {
				// the payload is compressed
				destLen=payload_length;
				dest=(Bytef *)l_alloc(destLen);
				int rc=uncompress(dest, &destLen, _ptr, queueIN.pkt.size-7);
				assert(rc==Z_OK); 
				datalength=payload_length;
				// change _ptr to the new buffer
				_ptr=dest;
			} else {
				// the payload is not compressed
				datalength=queueIN.pkt.size-7;
			}
			while (progress<datalength) {
				if (CompPktIN.partial==0) {
					mysql_hdr _a;
					assert(datalength >= progress + sizeof(mysql_hdr)); // FIXME: this is a too optimistic assumption
					memcpy(&_a,_ptr+progress,sizeof(mysql_hdr));
					CompPktIN.pkt.size=_a.pkt_length+sizeof(mysql_hdr);
					CompPktIN.pkt.ptr=(unsigned char *)l_alloc(CompPktIN.pkt.size);
					if ((datalength-progress) >= CompPktIN.pkt.size) {
						// we can copy the whole packet
						memcpy(CompPktIN.pkt.ptr, _ptr+progress, CompPktIN.pkt.size);
						CompPktIN.partial=0; // stays 0
						progress+=CompPktIN.pkt.size;
						PSarrayIN->add(CompPktIN.pkt.ptr, CompPktIN.pkt.size);
						CompPktIN.pkt.ptr=NULL; // sanity
					} else {
						// not enough data for the whole packet
						memcpy(CompPktIN.pkt.ptr, _ptr+progress, (datalength-progress));
						CompPktIN.partial+=(datalength-progress);
						progress=datalength; // we reached the end
					}
				} else {
					if ((datalength-progress) >= (CompPktIN.pkt.size-CompPktIN.partial)) {
						// we can copy till the end of the packet
						memcpy((char *)CompPktIN.pkt.ptr + CompPktIN.partial , _ptr+progress, CompPktIN.pkt.size - CompPktIN.partial);
						CompPktIN.partial=0;
						progress+= CompPktIN.pkt.size - CompPktIN.partial;
						PSarrayIN->add(CompPktIN.pkt.ptr, CompPktIN.pkt.size);
						CompPktIN.pkt.ptr=NULL; // sanity
					} else {
						// not enough data for the whole packet
						memcpy((char *)CompPktIN.pkt.ptr + CompPktIN.partial , _ptr+progress , (datalength-progress));
						CompPktIN.partial+=(datalength-progress);
						progress=datalength; // we reached the end
					}
				}
			}
			if (payload_length) {
				l_free(destLen,dest);
			}
			l_free(queueIN.pkt.size,queueIN.pkt.ptr);
			pkts_recv++;
			queueIN.pkt.size=0;
			queueIN.pkt.ptr=NULL;
		} else {
			PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
			pkts_recv++;
			queueIN.pkt.size=0;
			queueIN.pkt.ptr=NULL;
		}
	}
	return ret;
}


void MySQL_Data_Stream::generate_compressed_packet() {
#define MAX_COMPRESSED_PACKET_SIZE	10*1024*1024
	unsigned int total_size=0;
	unsigned int i=0;
	PtrSize_t *p=NULL;
	while (i<PSarrayOUT->len && total_size<MAX_COMPRESSED_PACKET_SIZE) {
		p=PSarrayOUT->index(i);
		total_size+=p->size;
		i++;
	}
	if (i>=2) {
		// we successfully read at least 2 packets
		if (total_size>MAX_COMPRESSED_PACKET_SIZE) {
			// total_size is too big, we remove the last packet read
			total_size-=p->size;
		}
	}
	if (total_size <= MAX_COMPRESSED_PACKET_SIZE) {
		// this worked in the past . it applies for small packets
		uLong sourceLen=total_size;
		Bytef *source=(Bytef *)l_alloc(total_size);
		uLongf destLen=total_size*120/100+12;
		Bytef *dest=(Bytef *)malloc(destLen);
		i=0;
		total_size=0;
		while (total_size<sourceLen) {
			PtrSize_t p2;
			PSarrayOUT->remove_index(0,&p2);
			memcpy(source+total_size,p2.ptr,p2.size);
			total_size+=p2.size;
			l_free(p2.size,p2.ptr);
		}
		int rc=compress(dest, &destLen, source, sourceLen);
		assert(rc==Z_OK);
		l_free(total_size, source);
		queueOUT.pkt.size=destLen+7;
		queueOUT.pkt.ptr=l_alloc(queueOUT.pkt.size);
		mysql_hdr hdr;
		hdr.pkt_length=destLen;
		hdr.pkt_id=++myconn->compression_pkt_id;
		memcpy((unsigned char *)queueOUT.pkt.ptr,&hdr,sizeof(mysql_hdr));
		hdr.pkt_length=total_size;
		memcpy((unsigned char *)queueOUT.pkt.ptr+4,&hdr,3);
		memcpy((unsigned char *)queueOUT.pkt.ptr+7,dest,destLen);
		free(dest);
	} else {
		// if we reach here, it means we have one single packet larger than MAX_COMPRESSED_PACKET_SIZE
		PtrSize_t p2;
		PSarrayOUT->remove_index(0,&p2);

		unsigned int len1=MAX_COMPRESSED_PACKET_SIZE/2;
		unsigned int len2=p2.size-len1;
		uLongf destLen1;
		uLongf destLen2;
		Bytef *dest1;
		Bytef *dest2;
		int rc;

		mysql_hdr hdr;

		destLen1=len1*120/100+12;
		dest1=(Bytef *)malloc(destLen1+7);
		destLen2=len2*120/100+12;
		dest2=(Bytef *)malloc(destLen2+7);
		rc=compress(dest1+7, &destLen1, (const unsigned char *)p2.ptr, len1);
		assert(rc==Z_OK);
		rc=compress(dest2+7, &destLen2, (const unsigned char *)p2.ptr+len1, len2);
		assert(rc==Z_OK);

		hdr.pkt_length=destLen1;
		hdr.pkt_id=++myconn->compression_pkt_id;
		memcpy(dest1,&hdr,sizeof(mysql_hdr));
		hdr.pkt_length=len1;
		memcpy((char *)dest1+sizeof(mysql_hdr),&hdr,3);

		hdr.pkt_length=destLen2;
		hdr.pkt_id=++myconn->compression_pkt_id;
		memcpy(dest2,&hdr,sizeof(mysql_hdr));
		hdr.pkt_length=len2;
		memcpy((char *)dest2+sizeof(mysql_hdr),&hdr,3);

		queueOUT.pkt.size=destLen1+destLen2+7+7;
		queueOUT.pkt.ptr=l_alloc(queueOUT.pkt.size);
		memcpy((char *)queueOUT.pkt.ptr,dest1,destLen1+7);
		memcpy((char *)queueOUT.pkt.ptr+destLen1+7,dest2,destLen2+7);
		free(dest1);
		free(dest2);
		l_free(p2.size,p2.ptr);
	}
}


int MySQL_Data_Stream::array2buffer() {
	int ret=0;
	unsigned int idx=0;
	bool cont=true;
	if (sess) {
		if (sess->mirror==true) { // if this is a mirror session, just empty it
			idx=PSarrayOUT->len;
			goto __exit_array2buffer;
		}
	}
	while (cont) {
		VALGRIND_DISABLE_ERROR_REPORTING;
		if (queue_available(queueOUT)==0) {
			goto __exit_array2buffer;
		}
		if (queueOUT.partial==0) { // read a new packet
			if (PSarrayOUT->len-idx) {
				proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Removing a packet from array\n", this);
				if (queueOUT.pkt.ptr) {
					l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
					queueOUT.pkt.ptr=NULL;
				}
		VALGRIND_ENABLE_ERROR_REPORTING;
				if (myconn->get_status_compression()==true) {
					proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Compression enabled\n", this);
					generate_compressed_packet();	// it is copied directly into queueOUT.pkt					
				} else {
		VALGRIND_DISABLE_ERROR_REPORTING;
					memcpy(&queueOUT.pkt,PSarrayOUT->index(idx), sizeof(PtrSize_t));
					idx++;
		VALGRIND_ENABLE_ERROR_REPORTING;
					// this is a special case, needed because compression is enabled *after* the first OK
					if (DSS==STATE_CLIENT_AUTH_OK) {
						DSS=STATE_SLEEP;
						// enable compression
						if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
							if (myconn->options.compression_min_length) {
								myconn->set_status_compression(true);
							}
						} else {
							//explicitly disable compression
							myconn->options.compression_min_length=0;
							myconn->set_status_compression(false);
						}
					}
				}
#ifdef DEBUG
				{ __dump_pkt(__func__,(unsigned char *)queueOUT.pkt.ptr,queueOUT.pkt.size); }
#endif
			} else {
				cont=false;
				continue;
			}
		}
		int b= ( queue_available(queueOUT) > (queueOUT.pkt.size - queueOUT.partial) ? (queueOUT.pkt.size - queueOUT.partial) : queue_available(queueOUT) );
		VALGRIND_DISABLE_ERROR_REPORTING;
		memcpy(queue_w_ptr(queueOUT), (unsigned char *)queueOUT.pkt.ptr + queueOUT.partial, b);
		VALGRIND_ENABLE_ERROR_REPORTING;
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
__exit_array2buffer:
	if (idx) {
		PSarrayOUT->remove_index_range(0,idx);
	}
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
	return mybuff;
};

void MySQL_Data_Stream::buffer2resultset(unsigned char *ptr, unsigned int size) {
	unsigned char *__ptr=ptr;
	mysql_hdr hdr;
	unsigned int l;
	void *pkt;
	while (__ptr<ptr+size) {
		memcpy(&hdr,__ptr,sizeof(mysql_hdr));
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

	assert(myconn); // this assert() is to remove the next condition
	if (myconn==NULL) myconn= new MySQL_Connection(); // FIXME: why here? // 20141011 /// should be removed

	myconn->last_time_used=sess->thread->curtime;
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
#ifdef FD_CLOEXEC
		int f_=fcntl(s, F_GETFL);
		// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
		fcntl(s, F_SETFL, f_|FD_CLOEXEC);
#endif /* FD_CLOEXEC */
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
#ifdef FD_CLOEXEC
		int f_=fcntl(s, F_GETFL);
		// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
		fcntl(s, F_SETFL, f_|FD_CLOEXEC);
#endif /* FD_CLOEXEC */
		ioctl_FIONBIO(s, 1);
		memset(u.sun_path,0,UNIX_PATH_MAX);
		u.sun_family = AF_UNIX;
		strncpy(u.sun_path, address, UNIX_PATH_MAX-1);
		len=strlen(u.sun_path)+sizeof(u.sun_family);
	}

	if (connect_port) {
		rc=connect(s, (struct sockaddr *) &a, sizeof(a));
		int arg_on=1;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
#ifdef __APPLE__
		setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
#endif
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
	} else {
		*pending_connect=0;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, old_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	myconn->fd=s;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, new_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	return s;

}

int MySQL_Data_Stream::assign_fd_from_mysql_conn() {
	assert(myconn);
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->myconn.net.fd);
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

void MySQL_Data_Stream::clean_net_failure() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p\n", this->sess, this);
	net_failure=false;
}

void MySQL_Data_Stream::set_net_failure() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d\n", this->sess, this, myds_type);
#ifdef DEBUG
	if (myds_type!=MYDS_FRONTEND) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d not frontend\n", this->sess, this, myds_type);
	}
#endif /* DEBUG */
	net_failure=true;
}

void MySQL_Data_Stream::setDSS_STATE_QUERY_SENT_NET() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p\n", this->sess, this);
	DSS=STATE_QUERY_SENT_NET;
}

void MySQL_Data_Stream::return_MySQL_Connection_To_Pool() {
	MySQL_Connection *mc=myconn;
	mc->last_time_used=sess->thread->curtime;
	if ((mysql_thread___connection_max_age_ms) && (mc->last_time_used > mc->creation_time + mysql_thread___connection_max_age_ms * 1000)) {
		destroy_MySQL_Connection_From_Pool(true);
	} else {
		detach_connection();
		unplug_backend();
#ifdef STRESSTEST_POOL
		MyHGM->push_MyConn_to_pool(mc);  // #644
#else
		sess->thread->push_MyConn_local(mc);
#endif
	}
}

void MySQL_Data_Stream::free_mysql_real_query() {
	if (mysql_real_query.QueryPtr) {
		mysql_real_query.end();
	}
}

void MySQL_Data_Stream::destroy_queues() {
	queue_destroy(queueIN);
	queue_destroy(queueOUT);
}
