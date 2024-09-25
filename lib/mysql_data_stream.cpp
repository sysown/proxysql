#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "proxysql.h"
#include "cpp.h"
#include <zlib.h>
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif 

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"

#include "openssl/x509v3.h"


/**
 * @brief This is the 'bio_st' struct definition from libssl. NOTE: This is an internal struct from
 *   OpenSSL library, currently it's used for performing checks on the reads/writes performed on the BIO objects.
 *   It's extremely important to keep this struct up to date with each OpenSSL dependency update.
 */
typedef int CRYPTO_REF_COUNT;

#if (OPENSSL_VERSION_NUMBER & 0xFFFF0000) == 0x10100000
#pragma message "libssl 1.1.x detected"
struct bio_st {
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    BIO_callback_fn callback;
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};

#elif (OPENSSL_VERSION_NUMBER & 0xFFFF0000) == 0x30000000 || (OPENSSL_VERSION_NUMBER & 0xFFFF0000) == 0x30100000
#pragma message "libssl 3.0.x / 3.1.x detected"
struct bio_st {
    OSSL_LIB_CTX *libctx;
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
#ifndef OPENSSL_NO_DEPRECATED_3_0
    BIO_callback_fn callback;
#endif
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};

#elif (OPENSSL_VERSION_NUMBER & 0xFFFF0000) == 0x30200000 || (OPENSSL_VERSION_NUMBER & 0xFFFF0000) == 0x30300000
#pragma message "libssl 3.2.x / 3.3.x detected"
struct bio_st {
    OSSL_LIB_CTX *libctx;
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
#ifndef OPENSSL_NO_DEPRECATED_3_0
    BIO_callback_fn callback;
#endif
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
};

#else
#error "libssl version not supported: OPENSSL_VERSION_NUMBER = " ##OPENSSL_VERSION_NUMBER
#endif


#define RESULTSET_BUFLEN_DS_16K 16000
#define RESULTSET_BUFLEN_DS_1M 1000*1024

extern MySQL_Threads_Handler *GloMTH;

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
	if (_q.pkt.ptr) { \
		l_free(_q.pkt.size,_q.pkt.ptr); \
		queueOUT.pkt.ptr=NULL; \
	} \
}

#define queue_zero(_q) { \
  if (_q.tail != 0) { \
    memcpy(_q.buffer, (unsigned char *)_q.buffer + _q.tail, _q.head - _q.tail); \
  } \
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

#define add_to_data_packet_history(_o,_p,_s) if (unlikely(GloVars.global.data_packets_history_size)) { \
	if (static_cast<int>(_o.get_max_size()) != GloVars.global.data_packets_history_size) { \
		_o.set_max_size(GloVars.global.data_packets_history_size); \
	} \
	_o.push(_p,_s);\
}

// memory deallocation responsibility is now transferred to the queue as the buffer is directly assigned to it. 
// if the size of data_packet_history is 0, the memory will be released.
#define add_to_data_packet_history_without_alloc(_o,_p,_s) if (unlikely(GloVars.global.data_packets_history_size)) { \
	if (static_cast<int>(_o.get_max_size()) != GloVars.global.data_packets_history_size) { \
		_o.set_max_size(GloVars.global.data_packets_history_size); \
	} \
	_o.push<false>(_p,_s);\
} else { \
	l_free(_s,_p); \
}
//enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

static enum sslstatus get_sslstatus(SSL* ssl, int n)
{
	int err = SSL_get_error(ssl, n);
	ERR_clear_error();
	switch (err) {
	case SSL_ERROR_NONE:
		return SSLSTATUS_OK;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		return SSLSTATUS_WANT_IO;
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SYSCALL:
	default:
		return SSLSTATUS_FAIL;
	}
}


void MySQL_Data_Stream::queue_encrypted_bytes(const char *buf, size_t len)	{
	ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + len);
	memcpy(ssl_write_buf + ssl_write_len, buf, len);
	ssl_write_len += len;
	//proxy_info("New ssl_write_len size: %u\n", ssl_write_len);
}

enum sslstatus MySQL_Data_Stream::do_ssl_handshake() {
	char buf[MY_SSL_BUFFER];
	enum sslstatus status;
	int n = SSL_do_handshake(ssl);
	if (n == 1) {
		//proxy_info("SSL handshake completed\n");
		X509 *cert;
		cert = SSL_get_peer_certificate(ssl);
		if (cert) {
			GENERAL_NAMES *alt_names = (stack_st_GENERAL_NAME *)X509_get_ext_d2i((X509*)cert, NID_subject_alt_name, 0, 0);
			int alt_name_count = sk_GENERAL_NAME_num(alt_names);

			// Iterate all the SAN names, looking for SPIFFE identifier
			for (int i = 0; i < alt_name_count; i++) {
				GENERAL_NAME *san = sk_GENERAL_NAME_value(alt_names, i);

				// We only care about URI names
				if (san->type == GEN_URI) {
					if (san->d.uniformResourceIdentifier->data) {
						const char* resource_data =
							reinterpret_cast<const char*>(san->d.uniformResourceIdentifier->data);
						const char* spiffe_loc = strstr(resource_data, "spiffe");

						// First name starting with 'spiffe' is considered the match.
						if (spiffe_loc == resource_data) {
							x509_subject_alt_name = strdup(resource_data);
						}
					}
				}
			}

			sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
			X509_free(cert);
		} else {
			// we currently disable this annoying error
			// in future we can configure this as per user level, specifying if the certificate is mandatory or not
			// see issue #3424
			//proxy_error("X509 error: no required certificate sent by client\n");
		}
		// In case the supplied certificate has a 'SAN'-'URI' identifier
		// starting with 'spiffe', client certificate verification is performed.
		if (x509_subject_alt_name != NULL) {
			long rc = SSL_get_verify_result(ssl);
			if (rc != X509_V_OK) {
				proxy_error("Disconnecting %s:%d: X509 client SSL certificate verify error: (%ld:%s)\n" , addr.addr, addr.port, rc, X509_verify_cert_error_string(rc));
				return SSLSTATUS_FAIL;
			}
		}
	}
	status = get_sslstatus(ssl, n);
	//proxy_info("SSL status = %d\n", status);
	/* Did SSL request to write bytes? */
	if (status == SSLSTATUS_WANT_IO) {
		//proxy_info("SSL status is WANT_IO %d\n", status);
		do {
			n = BIO_read(wbio_ssl, buf, sizeof(buf));
			//proxy_info("BIO read = %d\n", n);
			if (n > 0) {
				//proxy_info("Queuing %d encrypted bytes\n", n);
				queue_encrypted_bytes(buf, n);
			} else if (!BIO_should_retry(wbio_ssl)) {
				//proxy_info("BIO_should_retry failed\n");
				return SSLSTATUS_FAIL;
			}
		} while (n>0);
	}
	return status;
}

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

	PROXY_info = NULL;

	sess=NULL;
	mysql_real_query.pkt.ptr=NULL;
	mysql_real_query.pkt.size=0;
	mysql_real_query.QueryPtr=NULL;
	mysql_real_query.QuerySize=0;

	query_retries_on_failure=0;
	connect_retries_on_failure=0;
	max_connect_time=0;
	wait_until=0;
	pause_until=0;
	kill_type=0;
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
	switching_auth_stage = 0;
	switching_auth_type = AUTH_UNKNOWN_PLUGIN;
	switching_auth_sent = AUTH_UNKNOWN_PLUGIN;
	auth_in_progress = 0;
	x509_subject_alt_name=NULL;
	ssl=NULL;
	rbio_ssl = NULL;
	wbio_ssl = NULL;
	ssl_write_len = 0;
	ssl_write_buf = NULL;
	net_failure=false;
	CompPktIN.pkt.ptr=NULL;
	CompPktIN.pkt.size=0;
	CompPktIN.partial=0;
	CompPktOUT.pkt.ptr=NULL;
	CompPktOUT.pkt.size=0;
	CompPktOUT.partial=0;
	multi_pkt.ptr=NULL;
	multi_pkt.size=0;
	
	statuses.questions = 0;
	statuses.myconnpoll_get = 0;
	statuses.myconnpoll_put = 0;

	com_field_wild=NULL;
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
	if (PROXY_info) {
		delete PROXY_info;
		PROXY_info = NULL;
	}

	free_mysql_real_query();

	if (com_field_wild) {
		free(com_field_wild);
		com_field_wild=NULL;
	}

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
		if (ssl) {
			// NOTE: SSL standard requires a final 'close_notify' alert on socket
			// shutdown. But for avoiding any kind of locking IO waiting for the
			// other part, we perform a 'quiet' shutdown. For more context see
			// MYSQL #29579.
			SSL_set_quiet_shutdown(ssl, 1);
			if (SSL_shutdown(ssl) < 0)
				ERR_clear_error();
		}
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
	if (x509_subject_alt_name) {
		free(x509_subject_alt_name);
		x509_subject_alt_name=NULL;
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

		if (unlikely(GloVars.global.data_packets_history_size)) {
			data_packets_history_IN.set_max_size(GloVars.global.data_packets_history_size);
			data_packets_history_OUT.set_max_size(GloVars.global.data_packets_history_size);
		}
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
	if (encrypted) {
		// NOTE: SSL standard requires a final 'close_notify' alert on socket
		// shutdown. But for avoiding any kind of locking IO waiting for the
		// other part, we perform a 'quiet' shutdown. For more context see
		// MYSQL #29579.
		SSL_set_quiet_shutdown(ssl, 1);
		if (SSL_shutdown(ssl) < 0)
			ERR_clear_error();
	}
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
		generate_coredump();
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
	if (encrypted) {
		//proxy_info("Entering\n");
	}
	if ( (revents & POLLHUP) && ((revents & POLLIN)==0) ) {
		// Previously this was (revents & POLLHUP) , but now
		// we call shut_soft() only if POLLIN is not set .
		//
		// This means that if we receive data (POLLIN) we process it
		// temporarily ignoring POLLHUP .
		// In this way we can intercept a COM_QUIT executed by the client
		// before closing the socket
		shut_soft();
		return -1;
	}
	// this check was moved after the previous one about POLLHUP,
	// otherwise the previous check was never true
	if ((revents & POLLIN)==0) return 0;

	int r=0;
	int s=queue_available(queueIN);

	if (encrypted == false) {
		if (pkts_recv) {
			r = recv(fd, queue_w_ptr(queueIN), s, 0);
		} else {
			if (queueIN.partial == 0) {
				// we are reading the very first packet
				// to avoid issue with SSL, we will only read the header and eventually the first packet
				r = recv(fd, queue_w_ptr(queueIN), 4, 0);
				if (r == 4) {
					// let's try to read a whole packet
					mysql_hdr Hdr;
					memcpy(&Hdr,queueIN.buffer,sizeof(mysql_hdr));
					r += recv(fd, queue_w_ptr(queueIN)+4, Hdr.pkt_length, 0);
				}
			} else {
				r = recv(fd, queue_w_ptr(queueIN), s, 0);
			}
		}
	} else { // encrypted == true
		PROXY_TRACE();
		if (s < MY_SSL_BUFFER) {
			return 0;	// no enough space for reads
		}
		char buf[MY_SSL_BUFFER];
		int ssl_recv_bytes = recv(fd, buf, sizeof(buf), 0);
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p: recv() read %d bytes. num_write: %lu ,  num_read: %lu\n", sess, ssl_recv_bytes,  rbio_ssl->num_write , rbio_ssl->num_read);

		if (ssl_recv_bytes > 0 || rbio_ssl->num_write > rbio_ssl->num_read) {
			char buf2[MY_SSL_BUFFER];
			int n2;
			enum sslstatus status;
			char *src = buf;
			int len = ssl_recv_bytes;
			while (len > 0) {
				n2 = BIO_write(rbio_ssl, src, len);
				proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: write %d bytes into BIO %p, len=%d\n", sess, n2, rbio_ssl, len);

				if (n2 <= 0) {
					shut_soft();
					return -1;
				}
				src += n2;
				len -= n2;
				if (!SSL_is_init_finished(ssl)) {
					proxy_debug(PROXY_DEBUG_NET, 5, "SSL handshake not finished yet   session=%p bytes=%d BIO=%p len=%d\n", sess, n2, rbio_ssl, len);
					if (do_ssl_handshake() == SSLSTATUS_FAIL) {
						proxy_debug(PROXY_DEBUG_NET, 5, "SSL handshake failed   session=%p bytes=%d BIO=%p len=%d\n", sess, n2, rbio_ssl, len);
						shut_soft();
						return -1;
					}
					if (!SSL_is_init_finished(ssl)) {
						proxy_debug(PROXY_DEBUG_NET, 5, "SSL handshake not finished yet   session=%p bytes=%d BIO=%p len=%d\n", sess, n2, rbio_ssl, len);
						return 0;
					}
				} else {
					proxy_debug(PROXY_DEBUG_NET, 5, "SSL handshake finished   session=%p bytes=%d BIO=%p len=%d\n", sess, n2, rbio_ssl, len);
				}
			}
			n2 = SSL_read (ssl, queue_w_ptr(queueIN), s);
			proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: read %d bytes from BIO %p into a buffer with %d bytes free\n", sess, n2, rbio_ssl, s);
			r = n2;
			status = get_sslstatus(ssl, n2);

			if (status == SSLSTATUS_WANT_IO) {
				do {
					n2 = BIO_read(wbio_ssl, buf2, sizeof(buf2));

					if (n2 > 0) {
          				queue_encrypted_bytes(buf2, n2);
					} else if (!BIO_should_retry(wbio_ssl)) {
						shut_soft();
						return -1;
					}
				} while (n2>0);
			}
			if (status == SSLSTATUS_FAIL) {
				shut_soft();
				return -1;
			}
		} else {
			// Shutdown if we either received the EOF, or operation failed with non-retryable error.
			if (ssl_recv_bytes==0 || (ssl_recv_bytes==-1 && errno != EINTR && errno != EAGAIN)) {
				proxy_debug(PROXY_DEBUG_NET, 5, "Received EOF, shutting down soft socket -- Session=%p, Datastream=%p\n", sess, this);
				shut_soft();
				return -1;
			}
			r = ssl_recv_bytes;
		}
	}

	proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: read %d bytes from fd %d into a buffer of %d bytes free\n", sess, r, fd, s);

	if (r < 1) {
		if (encrypted==false) {
			int myds_errno=errno;
			if (r==0 || (r==-1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
				shut_soft();
			}
		} else {
			int ssl_ret=SSL_get_error(ssl, r);
			proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- session_id: %u , SSL_get_error(): %d , errno: %d\n", sess, this, sess->thread_session_id, ssl_ret, errno);
			const int st = ERR_get_error();
			if (
				(ssl_ret == SSL_ERROR_SYSCALL) &&
				(
					((errno == EINTR || errno == EAGAIN))
					|| (st == 0)
				)
			) {
				// the read was interrupted, do nothing
				proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- SSL_get_error() is SSL_ERROR_SYSCALL, errno: %d, ERR_get_error=%d\n", sess, this, errno, st);
			} else {
				if (r==0) { // we couldn't read any data
					if (revents & POLLIN) {
						// If revents is holding either POLLIN, or POLLIN and POLLHUP, but 'recv()' returns 0,
						// reading no data, the socket has been already closed by the peer. Due to this we can
						// ignore POLLHUP in this check, since we should reach here ONLY if POLLIN was set.
						proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- shutdown soft\n", sess, this);
						shut_soft();
					}
				}
				if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
				// it seems we end in shut_soft() anyway
			}
		}
		if ( (revents & POLLHUP) ) {
			// this is a final check
			// Only if the amount of data read is 0 or less, then we check POLLHUP
			proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- shutdown soft. revents=%d , bytes read = %d\n", sess, this, revents, r);
			shut_soft();
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
	int n;
	if (encrypted) {
		//proxy_info("Data in write buffer: %d bytes\n", s);
	}
	if (s==0) {
		if (encrypted == false) {
			return 0;
		}
		if (ssl_write_len == 0 && wbio_ssl->num_write == wbio_ssl->num_read) {
			return 0;
		}
	}
	//VALGRIND_DISABLE_ERROR_REPORTING;
	// splitting the ternary operation in IF condition for better readability 
	if (encrypted) {
		bytes_io = SSL_write (ssl, queue_r_ptr(queueOUT), s);
		//proxy_info("Used SSL_write to write %d bytes\n", bytes_io);
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: SSL_write() wrote %d bytes . queueOUT before: %u\n", sess, this, bytes_io, queue_data(queueOUT));
		if (ssl_write_len || wbio_ssl->num_write > wbio_ssl->num_read) {
			//proxy_info("ssl_write_len = %d , num_write = %d , num_read = %d\n", ssl_write_len , wbio_ssl->num_write , wbio_ssl->num_read);
			char buf[MY_SSL_BUFFER];
			do {
				n = BIO_read(wbio_ssl, buf, sizeof(buf));
				proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: BIO_read() read %d bytes\n", sess, this, n);
				//proxy_info("BIO read = %d\n", n);
				if (n > 0) {
					//proxy_info("Setting %d byte in queue encrypted\n", n);
					queue_encrypted_bytes(buf, n);
				}
        		else if (!BIO_should_retry(wbio_ssl)) {
					//proxy_info("BIO_should_retry failed\n");
					shut_soft();
					return -1;
				}
			} while (n>0);
		}
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: current ssl_write_len is %lu bytes\n", sess, this, ssl_write_len);
		if (ssl_write_len) {
			n = write(fd, ssl_write_buf, ssl_write_len);
			proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: write() wrote %d bytes in FD %d\n", sess, this, n, fd);
			//proxy_info("Calling write() on SSL: %d\n", n);
			if (n>0) {
				if ((size_t)n < ssl_write_len) {
					memmove(ssl_write_buf, ssl_write_buf+n, ssl_write_len-n);
				}
				ssl_write_len -= n;
				if (ssl_write_len) {
					ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
				} else {
					free(ssl_write_buf);
					ssl_write_buf = NULL;
				}
				//proxy_info("new ssl_write_len: %u\n", ssl_write_len);
				//if (ssl_write_len) {
    			//	return n; // stop here
				//} else {
				//	rc = n; // and continue
				//}
				//bytes_io += n;
  			} else {
				int myds_errno=errno;
				if (n==0 || (n==-1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
					shut_soft();
					return 0;
				} else {
					return -1;
				}
			}
		}
	} else {
#ifdef __APPLE__
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, 0);
#else
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, MSG_NOSIGNAL);
#endif
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: send() wrote %d bytes in FD %d\n", sess, this, bytes_io, fd);
	}
	if (encrypted) {
		//proxy_info("bytes_io: %d\n", bytes_io);
	}
	//VALGRIND_ENABLE_ERROR_REPORTING;
	if (bytes_io < 0) {
		if (encrypted==false)	{
			if ((poll_fds_idx < 0) || (mypolls->fds[poll_fds_idx].revents & POLLOUT)) { // in write_to_net_poll() we has remove this safety
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
	if (bytes_io > 0) {
		if (myds_type == MYDS_FRONTEND) {
			if (sess) {
				if (sess->thread) {
					sess->thread->status_variables.stvar[st_var_queries_frontends_bytes_sent] += bytes_io;
				}
			}
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

void MySQL_Data_Stream::remove_pollout() {
	struct pollfd *_pollfd;
	_pollfd=&mypolls->fds[poll_fds_idx];
	_pollfd->events = 0;
}

void MySQL_Data_Stream::set_pollout() {
	struct pollfd *_pollfd;
	_pollfd=&mypolls->fds[poll_fds_idx];
	if (DSS > STATE_MARIADB_BEGIN && DSS < STATE_MARIADB_END) {
		_pollfd->events = myconn->wait_events;
	} else {
		_pollfd->events = POLLIN;
		//if (PSarrayOUT->len || available_data_out() || queueOUT.partial || (encrypted && !SSL_is_init_finished(ssl))) {
		if (PSarrayOUT->len || available_data_out() || queueOUT.partial) {
			_pollfd->events |= POLLOUT;
		}
		if (encrypted) {
			if (ssl_write_len || wbio_ssl->num_write > wbio_ssl->num_read) {
				_pollfd->events |= POLLOUT;
			} else {
				if (!SSL_is_init_finished(ssl)) {
					//proxy_info("SSL_is_init_finished NOT completed\n");
					if (do_ssl_handshake() == SSLSTATUS_FAIL) {
						//proxy_info("SSL_is_init_finished failed!!\n");
						shut_soft();
						return;
					}
					if (!SSL_is_init_finished(ssl)) {
						//proxy_info("SSL_is_init_finished yet NOT completed\n");
						return;
					}
					_pollfd->events |= POLLOUT;
				} else {
					//proxy_info("SSL_is_init_finished completed\n");
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p -- Setting poll events %d for FD %d , DSS=%d , myconn=%p\n", sess, this, _pollfd->events , fd, DSS, myconn);
}

int MySQL_Data_Stream::write_to_net_poll() {
	int rc=0;
	if (active==0) return rc;
/*
	if (encrypted && !SSL_is_init_finished(ssl)) {
		int ret = SSL_do_handshake(ssl);
		int ret2;
		if (ret != 1) {
			//ERR_print_errors_fp(stderr);
			ret2 = SSL_get_error(ssl, ret);
			fprintf(stderr,"%d\n",ret2);
		}
		return 0;
	}
*/
	if (encrypted) {
		if (!SSL_is_init_finished(ssl)) {
			//proxy_info("SSL_is_init_finished completed: NO!\n");
					if (do_ssl_handshake() == SSLSTATUS_FAIL) {
						//proxy_info("SSL_is_init_finished failed!!\n");
						shut_soft();
						return -1;
					}
		} else {
			//proxy_info("SSL_is_init_finished completed: YES\n");
		}
/*
		if (!SSL_is_init_finished(ssl)) {
			proxy_info("SSL_is_init_finished completed: NO!\n");
			if (fd>0 && sess->session_type == PROXYSQL_SESSION_MYSQL) {
				set_pollout();
				return 0;
			}
		}
*/
		//proxy_info("ssl_write_len: %u\n", ssl_write_len);
		if (ssl_write_len) {
			int n = write(fd, ssl_write_buf, ssl_write_len);
			//proxy_info("Calling write() on SSL: %d\n", n);
			if (n>0) {
				if ((size_t)n < ssl_write_len) {
					memmove(ssl_write_buf, ssl_write_buf+n, ssl_write_len-n);
				}
				ssl_write_len -= n;
				if (ssl_write_len) {
					ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
				} else {
					free(ssl_write_buf);
					ssl_write_buf = NULL;
				}
				//proxy_info("new ssl_write_len: %u\n", ssl_write_len);
				if (ssl_write_len) {
    				return n; // stop here
				} else {
					rc = n; // and continue
				}
  			} else {
				int myds_errno=errno;
				if (n==0 || (n==-1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
					shut_soft();
					return 0;
				} else {
					return -1;
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p --\n", sess, this);
	bool call_write_to_net = false;
	if (queue_data(queueOUT)) {
		call_write_to_net = true;
	}
	if (call_write_to_net == false) {
		if (encrypted) {
			if (ssl_write_len || wbio_ssl->num_write > wbio_ssl->num_read) {
				call_write_to_net = true;
			}
		}
	}
	if (call_write_to_net) {
		if (sess->session_type == PROXYSQL_SESSION_MYSQL) {
			if (poll_fds_idx>-1) { // NOTE: attempt to force writes
				if (net_failure==false)
					rc += write_to_net();
			}
		} else {
			rc += write_to_net();
		}
	}
	if (fd>0 && sess->session_type == PROXYSQL_SESSION_MYSQL) {
		// PROXYSQL_SESSION_MYSQL is a requirement, because it uses threads pool
		// the other session types do not
		set_pollout();
	}
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
	{
		unsigned long s = queue_data(queueIN);
		if (s==0) return ret;
		if ((queueIN.pkt.size==0) && s<sizeof(mysql_hdr)) {
			queue_zero(queueIN);
		}
	}

	if (fast_mode) {
		if (pkts_recv==0) { pkts_recv=1; }
		queueIN.pkt.size=queue_data(queueIN);
		ret=queueIN.pkt.size;
		if (ret >= RESULTSET_BUFLEN_DS_16K) {
			// legacy approach
			queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
			memcpy(queueIN.pkt.ptr, queue_r_ptr(queueIN) , queueIN.pkt.size);
			queue_r(queueIN, queueIN.pkt.size);
			PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
			add_to_data_packet_history(data_packets_history_IN,queueIN.pkt.ptr,queueIN.pkt.size);
			queueIN.pkt.ptr = NULL;
		} else {
			if (PSarrayIN->len == 0) {
				// it is empty, create a new block
				// we allocate RESULTSET_BUFLEN_DS_16K instead of queueIN.pkt.size
				// the block may be used later
				queueIN.pkt.ptr=l_alloc(RESULTSET_BUFLEN_DS_16K);
				memcpy(queueIN.pkt.ptr, queue_r_ptr(queueIN) , queueIN.pkt.size);
				queue_r(queueIN, queueIN.pkt.size);
				PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
				add_to_data_packet_history(data_packets_history_IN,queueIN.pkt.ptr,queueIN.pkt.size);
				queueIN.pkt.ptr = NULL;
			} else {
				// get a pointer to the last entry in PSarrayIN
				PtrSize_t *last_pkt = PSarrayIN->index(PSarrayIN->len - 1);
				if ((last_pkt->size + queueIN.pkt.size) > RESULTSET_BUFLEN_DS_16K) {
					// there is not enough space, create a new block
					// we allocate RESULTSET_BUFLEN_DS_16K instead of queueIN.pkt.size
					// the block may be used later
					queueIN.pkt.ptr=l_alloc(RESULTSET_BUFLEN_DS_16K);
					memcpy(queueIN.pkt.ptr, queue_r_ptr(queueIN) , queueIN.pkt.size);
					queue_r(queueIN, queueIN.pkt.size);
					PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
					add_to_data_packet_history(data_packets_history_IN,queueIN.pkt.ptr,queueIN.pkt.size);
					queueIN.pkt.ptr = NULL;
				} else {
					// we append the packet at the end of the previous packet
					memcpy((char *)last_pkt->ptr+last_pkt->size, queue_r_ptr(queueIN) , queueIN.pkt.size);
					last_pkt->size += queueIN.pkt.size;
					queue_r(queueIN, queueIN.pkt.size);

				}
			}
		}
		queueIN.pkt.size=0;
		return ret;
	}

	if (myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION)==true) {
		if ((queueIN.pkt.size==0) && queue_data(queueIN)>=7) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Reading the header of a new compressed packet\n", sess);
 			memcpy(&queueIN.hdr,queue_r_ptr(queueIN), sizeof(mysql_hdr));
			queue_r(queueIN,sizeof(mysql_hdr));
			pkt_sid=queueIN.hdr.pkt_id;
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
			// check if this is a PROXY protocol packet
			if (
				pkts_recv==0 && // checks if no packets have been received yet
				queueIN.tail == 0 && // checks if the input queue (`queueIN`) was never rotated . This check is redundant
				queueIN.head > 7 && // ensures that there are at least 8 bytes in the input buffer (`queueIN.buffer`)
									// This is because the PROXY protocol signature (`PROXY`) is 5 bytes long, and we need at least 3 more bytes to check for the `\r\n` delimiter.
				strncmp((char *)queueIN.buffer,"PROXY ",6) == 0 // checks if the first 6 bytes of the buffer match the "PROXY " string, indicating a potential PROXY protocol packet
			) {
				bool found_delimiter = false;
				size_t b = 0;
				const char *ptr = (char *)queueIN.buffer;
				// This loop iterates through the buffer, starting from the 8th byte (index 7) until the end of the buffer (index `queueIN.head - 1`).
				// The loop continues as long as the delimiter hasn't been found (`found_delimiter == false`)
				// the loop looks for \r\n , the delimiter of the PROXY packet
				for (size_t i = 7; found_delimiter == false && i < queueIN.head - 1; i++) {
					if (
						ptr[i] == '\r'
						&&
						ptr[i+1] == '\n'
					) {
						found_delimiter = true;
						b = i+2;
					}
				}
				if (found_delimiter) {
/*
					// we could return a packet, but it is actually better to handle it here
					queueIN.pkt.size = b;
					queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
					memcpy(queueIN.pkt.ptr, queueIN.buffer, b);
					PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
					add_to_data_packet_history(data_packets_history_IN,queueIN.pkt.ptr,queueIN.pkt.size);
*/
					// we move forward the internal pointer.
					// note that parseProxyProtocolHeader() will read from the beginning of the buffer
					queue_r(queueIN, b);

					bool accept_proxy = false; // by default, we do not accept a PROXY header
					const char * proxy_protocol_networks = mysql_thread___proxy_protocol_networks;

					ProxyProtocolInfo ppi;
					if (strcmp(proxy_protocol_networks,"*") == 0) { // all networks are accepted
						accept_proxy = true;
					} else {
						if (client_addr) {
							if (ppi.is_client_in_any_subnet(client_addr, proxy_protocol_networks) == true) {
								accept_proxy = true;
							}
						}
					}
					if (accept_proxy == true) {
						if (ppi.parseProxyProtocolHeader((const char *)queueIN.buffer, b)) {
							PROXY_info = new ProxyProtocolInfo(ppi);
							// we take a copy of old address/port
							if (addr.addr) {
								strncpy(PROXY_info->proxy_address, addr.addr, INET6_ADDRSTRLEN);
								free(addr.addr);
							}
							PROXY_info->proxy_port = addr.port;
							// we override old address/port
							addr.addr = strdup(PROXY_info->source_address);
							addr.port = PROXY_info->source_port;
						} else {
							if (addr.addr) {
								proxy_warning("Unable to parse PROXY header from IP %s . Skipping PROXY header\n", addr.addr);
							}
						}
					} else { // the PROXY header was not accepted
						if (addr.addr) {
							proxy_warning("Skipping PROXY header from IP %s because not matching mysql-proxy_protocol_networks. Skipping PROXY header\n", addr.addr);
						}
					}


					pkts_recv++;
					queueIN.pkt.size=0;
					queueIN.pkt.ptr=NULL;
					return b;
				} else {
					// set the connection unhealthy , this will cause the session to be destroyed
					if (sess) {
						sess->set_unhealthy();
					}
				}
				return 0; // we always return
			}
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Reading the header of a new packet\n", sess);
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
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Copied %d bytes into packet\n", sess, b);
		memcpy((unsigned char *)queueIN.pkt.ptr + queueIN.partial, queue_r_ptr(queueIN),b);
		queue_r(queueIN,b);
		queueIN.partial+=b;
//		if (queueIN.partial == 80) {
//			proxy_info("Breakpoint\n");
//		}
		ret+=b;
	}
	if ((queueIN.pkt.size>0) && (queueIN.pkt.size==queueIN.partial) ) {
		if (myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION)==true) {
			Bytef *dest = NULL;
			uLongf destLen;
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Copied the whole compressed packet\n", sess);
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
				//dest=(Bytef *)l_alloc(destLen);
				dest=(Bytef *)malloc(destLen);
				int rc=uncompress(dest, &destLen, _ptr, queueIN.pkt.size-7);
				if (rc!=Z_OK) {
					// for some reason, uncompress failed
					// accoding to debugging on #1410 , it seems some library may send uncompress data claiming it is compressed
					// we try to assume it is not compressed, and we do some sanity check
					memcpy(dest, _ptr, queueIN.pkt.size-7);
					datalength=queueIN.pkt.size-7;
					// some sanity check now
					unsigned char _u;
					bool sanity_check = false;
					_u = *(u+9);
					// 2nd and 3rd bytes are 0
					if (_u == 0) {
						_u = *(u+8);
						if (_u == 0) {
							_u = *(u+7);
							// 1st byte = size - 7
							unsigned int _size = _u ;
							if (queueIN.pkt.size-7 == _size) {
								sanity_check = true;
							}
						}
					}
					if (sanity_check == false) {
						proxy_error("Unable to uncompress a compressed packet\n");
						shut_soft();
						return ret;
					}
				}
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
						// 'progress' is required to be updated with the actual copied size to the target packet. This
						// is, taking into account the already copied data, 'CompPktIN.partial', otherwise, in case of
						// split packets, we could jump over the remaining unprocessed data.
						progress+= CompPktIN.pkt.size - CompPktIN.partial;
						PSarrayIN->add(CompPktIN.pkt.ptr, CompPktIN.pkt.size);
						// Reset partial after full packet datalength has been processed
						CompPktIN.partial=0;
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
				//l_free(destLen,dest);
				free(dest);
			}
			l_free(queueIN.pkt.size,queueIN.pkt.ptr);
			pkts_recv++;
			queueIN.pkt.size=0;
			queueIN.pkt.ptr=NULL;
		} else {
			PSarrayIN->add(queueIN.pkt.ptr,queueIN.pkt.size);
			add_to_data_packet_history(data_packets_history_IN,queueIN.pkt.ptr,queueIN.pkt.size);
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
		//VALGRIND_DISABLE_ERROR_REPORTING;
		if (queue_available(queueOUT)==0) {
			goto __exit_array2buffer;
		}
		if (queueOUT.partial==0) { // read a new packet
			if (PSarrayOUT->len-idx) {
				proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Removing a packet from array\n", sess, this);
				if (queueOUT.pkt.ptr) {
					//l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
					add_to_data_packet_history_without_alloc(data_packets_history_OUT,queueOUT.pkt.ptr,queueOUT.pkt.size);
					queueOUT.pkt.ptr=NULL;
				}
		//VALGRIND_ENABLE_ERROR_REPORTING;
				if (myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION)==true) {
					proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Compression enabled\n", sess, this);
					generate_compressed_packet();	// it is copied directly into queueOUT.pkt					
				} else {
		//VALGRIND_DISABLE_ERROR_REPORTING;
					memcpy(&queueOUT.pkt,PSarrayOUT->index(idx), sizeof(PtrSize_t));
					idx++;
		//VALGRIND_ENABLE_ERROR_REPORTING;
					// This is a special case, needed because compression is enabled *after* the first OK. In
					// case of 'caching_sha2_password', not only the first packet needs to be processed, since
					// there are other scenarios in which one extra byte is sent prior to the final OK packet
					// flagging auth success. The generation of these extra packets should all be queued at
					// the same time, since they represent the final client response. Right now this is
					// handled during 'MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE'.
					// Because of this, we can make the assumption that once we have sent all the packets
					// currently in 'PSarrayOUT', it's safe to change the 'DSS' status, and enable compression
					// if connections requires it.
					if (DSS==STATE_CLIENT_AUTH_OK && idx == PSarrayOUT->len) {
						DSS=STATE_SLEEP;
						// enable compression
						if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
							if (myconn->options.compression_min_length) {
								myconn->set_status(true, STATUS_MYSQL_CONNECTION_COMPRESSION);
							}
						} else {
							//explicitly disable compression
							myconn->options.compression_min_length=0;
							myconn->set_status(false, STATUS_MYSQL_CONNECTION_COMPRESSION);
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
		//VALGRIND_DISABLE_ERROR_REPORTING;
		memcpy(queue_w_ptr(queueOUT), (unsigned char *)queueOUT.pkt.ptr + queueOUT.partial, b);
		//VALGRIND_ENABLE_ERROR_REPORTING;
		queue_w(queueOUT,b);
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Copied %d bytes into send buffer\n", sess, this, b);
		queueOUT.partial+=b;
		ret=b;
		if (queueOUT.partial==queueOUT.pkt.size) {
			if (queueOUT.pkt.ptr) {
				//l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
				add_to_data_packet_history_without_alloc(data_packets_history_OUT,queueOUT.pkt.ptr,queueOUT.pkt.size);
				queueOUT.pkt.ptr=NULL;
			}
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Packet completely written into send buffer\n", sess, this);
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
	void *buff = NULL;
	unsigned int bl;
	unsigned int bf;
	while (__ptr<ptr+size) {
		memcpy(&hdr,__ptr,sizeof(mysql_hdr));
		l=hdr.pkt_length+sizeof(mysql_hdr); // amount of space we need
		if (buff) {
			if ( bf < l ) {
				// we ran out of space
				resultset->add(buff,bl-bf);
				buff=NULL;
			}
		}
		if (buff == NULL) {
			if (__ptr+RESULTSET_BUFLEN_DS_1M <= ptr+size) {
				bl = RESULTSET_BUFLEN_DS_1M;
			} else {
				bl = RESULTSET_BUFLEN_DS_16K;
			}
			if (l > bl) {
				bl = l; // make sure there is the space to copy a packet
			}
			buff = malloc(bl);
			bf = bl;
		}
		memcpy((char *)buff + (bl-bf), __ptr, l);
		bf -= l;
		__ptr+=l;
/*
		l=hdr.pkt_length+sizeof(mysql_hdr);
		pkt=l_alloc(l);
		memcpy(pkt,__ptr,l);
		resultset->add(pkt,l);
		__ptr+=l;
*/
	}
	if (buff) {
		// last buffer to add
		resultset->add(buff,bl-bf);
	}
};

int MySQL_Data_Stream::array2buffer_full() {
	int rc=0;
	int r=0;
	while((r=array2buffer())) rc+=r;
	return rc; 
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
	// before detaching, check if last_HG_affected_rows matches . if yes, set it back to -1
	if (mybe) {
		if (mybe->hostgroup_id == sess->last_HG_affected_rows) {
			sess->last_HG_affected_rows = -1;
		}
	}
	unsigned long long intv = mysql_thread___connection_max_age_ms;
	intv *= 1000;
	if (
		(( (intv) && (mc->last_time_used > mc->creation_time + intv) )
		||
		( mc->local_stmts->get_num_backend_stmts() > (unsigned int)GloMTH->variables.max_stmts_per_connection ))
		&&
		// NOTE: If the current session if in 'PINGING_SERVER' status, there is
		// no need to reset the session. The destruction and creation of a new
		// session in case this session has exceeded the time specified by
		// 'connection_max_age_ms' will be deferred to the next time the session
		// is used outside 'PINGING_SERVER' operation. For more context see #3502.
		sess->status != PINGING_SERVER
	) {
		if (mysql_thread___reset_connection_algorithm == 2) {
			sess->create_new_session_and_reset_connection(this);
		} else {
			destroy_MySQL_Connection_From_Pool(true);
		}
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

void MySQL_Data_Stream::destroy_MySQL_Connection_From_Pool(bool sq) {
	MySQL_Connection *mc=myconn;
	mc->last_time_used=sess->thread->curtime;
	detach_connection();
	unplug_backend();
	mc->send_quit=sq;
	MyHGM->destroy_MyConn_from_pool(mc);
}

bool MySQL_Data_Stream::data_in_rbio() {
	if (rbio_ssl->num_write > rbio_ssl->num_read) {
		return true;
	}
	return false;
}

void MySQL_Data_Stream::reset_connection() {
	if (myconn) {
		if (mysql_thread___multiplexing && (DSS == STATE_MARIADB_GENERIC || DSS == STATE_READY) && myconn->reusable == true && myconn->IsActiveTransaction() == false && myconn->MultiplexDisabled() == false && myconn->async_state_machine == ASYNC_IDLE) {
			myconn->last_time_used = sess->thread->curtime;
			return_MySQL_Connection_To_Pool();
		}
		else {
			if (sess && sess->session_fast_forward == false) {
				destroy_MySQL_Connection_From_Pool(true);
			}
			else {
				destroy_MySQL_Connection_From_Pool(false);
			}
		}
	}
}

void MySQL_Data_Stream::get_client_myds_info_json(json& j) {
	json& jc1 = j["client"];
	json& jc2 = j["conn"];
	jc1["stream"]["pkts_recv"] = pkts_recv;
	jc1["stream"]["pkts_sent"] = pkts_sent;
	jc1["stream"]["bytes_recv"] = bytes_info.bytes_recv;
	jc1["stream"]["bytes_sent"] = bytes_info.bytes_sent;
	jc1["client_addr"]["address"] = ( addr.addr ? addr.addr : "" );
	jc1["client_addr"]["port"] = addr.port;
	jc1["proxy_addr"]["address"] = ( proxy_addr.addr ? proxy_addr.addr : "" );
	jc1["proxy_addr"]["port"] = proxy_addr.port;
	if (PROXY_info != NULL) {
		jc1["PROXY_V1"]["source_address"] = PROXY_info->source_address;
		jc1["PROXY_V1"]["destination_address"] = PROXY_info->destination_address;
		jc1["PROXY_V1"]["proxy_address"] = PROXY_info->proxy_address;
		jc1["PROXY_V1"]["source_port"] = PROXY_info->source_port;
		jc1["PROXY_V1"]["destination_port"] = PROXY_info->destination_port;
		jc1["PROXY_V1"]["proxy_port"] = PROXY_info->proxy_port;
	}
	jc1["encrypted"] = encrypted;
	if (encrypted) {
		const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
		if (cipher) {
			const char * name = SSL_CIPHER_get_name(cipher);
			if (name) {
				j["ssl_cipher"] = name;
			}
		}
	}
	jc1["DSS"] = DSS;
	jc1["switching_auth_sent"] = switching_auth_sent;
	jc1["switching_auth_type"] = switching_auth_type;
	jc1["prot"]["sent_auth_plugin_id"] = myprot.sent_auth_plugin_id;
	jc1["prot"]["auth_plugin_id"] = myprot.auth_plugin_id;

	switch (myprot.auth_plugin_id) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			jc1["prot"]["auth_plugin"] = "mysql_native_password";
			break;
		case AUTH_MYSQL_CLEAR_PASSWORD:
			jc1["prot"]["auth_plugin"] = "mysql_clear_password";
			break;
		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			jc1["prot"]["auth_plugin"] = "caching_sha2_password";
			break;
		default:
			break;
	}
	if (myconn != NULL) { // only if myconn is defined
		if (myconn->userinfo != NULL) { // only if userinfo is defined
			jc1["userinfo"]["username"]   = ( myconn->userinfo->username   ? myconn->userinfo->username   : "" );
			jc1["userinfo"]["schemaname"] = ( myconn->userinfo->schemaname ? myconn->userinfo->schemaname : "" );
#ifdef DEBUG
			jc1["userinfo"]["password"]   = ( myconn->userinfo->password   ? myconn->userinfo->password   : "" );
#endif
		}
		jc2["session_track_gtids"] = ( myconn->options.session_track_gtids ? myconn->options.session_track_gtids : "") ;
		for (auto idx = 0; idx < SQL_NAME_LAST_LOW_WM; idx++) {
			myconn->variables[idx].fill_client_internal_session(jc2, idx);
		}
		{
			for (std::vector<uint32_t>::const_iterator it_c = myconn->dynamic_variables_idx.begin(); it_c != myconn->dynamic_variables_idx.end(); it_c++) {
				myconn->variables[*it_c].fill_client_internal_session(jc2, *it_c);
			}
		}

		jc2["autocommit"] = ( myconn->options.autocommit ? "ON" : "OFF" );
		jc2["client_flag"]["value"] = myconn->options.client_flag;
		jc2["client_flag"]["client_found_rows"] = (myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
		jc2["client_flag"]["client_multi_statements"] = (myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
		jc2["client_flag"]["client_multi_results"] = (myconn->options.client_flag & CLIENT_MULTI_RESULTS ? 1 : 0);
		jc2["client_flag"]["client_deprecate_eof"] = (myconn->options.client_flag & CLIENT_DEPRECATE_EOF ? 1 : 0);
		jc2["no_backslash_escapes"] = myconn->options.no_backslash_escapes;
		jc2["status"]["compression"] = myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION);
		jc2["ps"]["client_stmt_to_global_ids"] = myconn->local_stmts->client_stmt_to_global_ids;
	}
}
