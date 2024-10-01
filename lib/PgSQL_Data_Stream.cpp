
#include "proxysql.h"
#include "cpp.h"
#include <zlib.h>
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif 

#include "MySQL_PreparedStatement.h"
#include "PgSQL_Data_Stream.h"

#include "openssl/x509v3.h"

/*

in libssl 1.1.0
struct bio_st {
	const BIO_METHOD *method;
	long (*callback) (struct bio_st *, int, const char *, int, long, long);
	char *cb_arg;
	int init;
	int shutdown;
	int flags;
	int retry_reason;
	int num;
	void *ptr;
	struct bio_st *next_bio;
	struct bio_st *prev_bio;
	int references;
	uint64_t num_read;
	uint64_t num_write;
	CRYPTO_EX_DATA ex_data;
	CRYPTO_RWLOCK *lock;
};
*/

typedef int CRYPTO_REF_COUNT;

/**
 * @brief This is the 'bio_st' struct definition from libssl 3.0.0. NOTE: This is an internal struct from
 *   OpenSSL library, currently it's used for performing checks on the reads/writes performed on the BIO objects.
 *   It's extremely important to keep this struct up to date with each OpenSSL dependency update.
 */
struct bio_st {
	OSSL_LIB_CTX* libctx;
	const BIO_METHOD* method;
	/* bio, mode, argp, argi, argl, ret */
#ifndef OPENSSL_NO_DEPRECATED_3_0
	BIO_callback_fn callback;
#endif
	BIO_callback_fn_ex callback_ex;
	char* cb_arg;               /* first argument for the callback */
	int init;
	int shutdown;
	int flags;                  /* extra storage */
	int retry_reason;
	int num;
	void* ptr;
	struct bio_st* next_bio;    /* used by filter BIOs */
	struct bio_st* prev_bio;    /* used by filter BIOs */
	CRYPTO_REF_COUNT references;
	uint64_t num_read;
	uint64_t num_write;
	CRYPTO_EX_DATA ex_data;
	CRYPTO_RWLOCK* lock;
};


#define RESULTSET_BUFLEN_DS_16K 16000
#define RESULTSET_BUFLEN_DS_1M 1000*1024

extern PgSQL_Threads_Handler* GloPTH;

#ifdef DEBUG
static void __dump_pkt(const char* func, unsigned char* _ptr, unsigned int len) {

	if (GloVars.global.gdbg == 0) return;
	if (GloVars.global.gdbg_lvl[PROXY_DEBUG_PKT_ARRAY].verbosity < 8) return;
	unsigned int i;
	fprintf(stderr, "DUMP %d bytes FROM %s\n", len, func);
	for (i = 0; i < len; i++) {
		if (isprint(_ptr[i])) fprintf(stderr, "%c", _ptr[i]); else fprintf(stderr, ".");
		if (i > 0 && (i % 16 == 15 || i == len - 1)) {
			unsigned int j;
			if (i % 16 != 15) {
				j = 15 - i % 16;
				while (j--) fprintf(stderr, " ");
			}
			fprintf(stderr, " --- ");
			for (j = (i == len - 1 ? ((int)(i / 16)) * 16 : i - 15); j <= i; j++) {
				fprintf(stderr, "%02x ", _ptr[j]);
			}
			fprintf(stderr, "\n");
		}
	}
	fprintf(stderr, "\n\n");


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

static enum pgsql_sslstatus get_sslstatus(SSL* ssl, int n)
{
	int err = SSL_get_error(ssl, n);
	ERR_clear_error();
	switch (err) {
	case SSL_ERROR_NONE:
		return PGSQL_SSLSTATUS_OK;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		return PGSQL_SSLSTATUS_WANT_IO;
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SYSCALL:
	default:
		return PGSQL_SSLSTATUS_FAIL;
	}
}


void PgSQL_Data_Stream::queue_encrypted_bytes(const char* buf, size_t len) {
	ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + len);
	memcpy(ssl_write_buf + ssl_write_len, buf, len);
	ssl_write_len += len;
	//proxy_info("New ssl_write_len size: %u\n", ssl_write_len);
}

enum pgsql_sslstatus PgSQL_Data_Stream::do_ssl_handshake() {
	char buf[MY_SSL_BUFFER];
	enum pgsql_sslstatus status;
	int n = SSL_do_handshake(ssl);
	if (n == 1) {
		//proxy_info("SSL handshake completed\n");
		X509* cert;
		cert = SSL_get_peer_certificate(ssl);
		if (cert) {
			GENERAL_NAMES* alt_names = (stack_st_GENERAL_NAME*)X509_get_ext_d2i((X509*)cert, NID_subject_alt_name, 0, 0);
			int alt_name_count = sk_GENERAL_NAME_num(alt_names);

			// Iterate all the SAN names, looking for SPIFFE identifier
			for (int i = 0; i < alt_name_count; i++) {
				GENERAL_NAME* san = sk_GENERAL_NAME_value(alt_names, i);

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
		}
		else {
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
				proxy_error("Disconnecting %s:%d: X509 client SSL certificate verify error: (%ld:%s)\n", addr.addr, addr.port, rc, X509_verify_cert_error_string(rc));
				return PGSQL_SSLSTATUS_FAIL;
			}
		}
	}
	status = get_sslstatus(ssl, n);
	//proxy_info("SSL status = %d\n", status);
	/* Did SSL request to write bytes? */
	if (status == PGSQL_SSLSTATUS_WANT_IO) {
		//proxy_info("SSL status is WANT_IO %d\n", status);
		do {
			n = BIO_read(wbio_ssl, buf, sizeof(buf));
			//proxy_info("BIO read = %d\n", n);
			if (n > 0) {
				//proxy_info("Queuing %d encrypted bytes\n", n);
				queue_encrypted_bytes(buf, n);
			}
			else if (!BIO_should_retry(wbio_ssl)) {
				//proxy_info("BIO_should_retry failed\n");
				return PGSQL_SSLSTATUS_FAIL;
			}
		} while (n > 0);
	}
	return status;
}

void* PgSQL_Data_Stream::operator new(size_t size) {
	return l_alloc(size);
}

void PgSQL_Data_Stream::operator delete(void* ptr) {
	l_free(sizeof(PgSQL_Data_Stream), ptr);
}

// Constructor
PgSQL_Data_Stream::PgSQL_Data_Stream() {
	bytes_info.bytes_recv = 0;
	bytes_info.bytes_sent = 0;
	pkts_recv = 0;
	pkts_sent = 0;
	client_addr = NULL;

	addr.addr = NULL;
	addr.port = 0;
	proxy_addr.addr = NULL;
	proxy_addr.port = 0;

	sess = NULL;
	mysql_real_query.pkt.ptr = NULL;
	mysql_real_query.pkt.size = 0;
	mysql_real_query.QueryPtr = NULL;
	mysql_real_query.QuerySize = 0;

	query_retries_on_failure = 0;
	connect_retries_on_failure = 0;
	max_connect_time = 0;
	wait_until = 0;
	pause_until = 0;
	kill_type = 0;
	connect_tries = 0;
	poll_fds_idx = -1;
	resultset_length = 0;

	revents = 0;

	PSarrayIN = NULL;
	PSarrayOUT = NULL;
	resultset = NULL;
	queue_init(queueIN, QUEUE_T_DEFAULT_SIZE);
	queue_init(queueOUT, QUEUE_T_DEFAULT_SIZE);
	mybe = NULL;
	active = 1;
	mypolls = NULL;
	myconn = NULL;	// 20141011
	DSS = STATE_NOT_CONNECTED;
	encrypted = false;
	switching_auth_stage = 0;
	switching_auth_type = 0;
	x509_subject_alt_name = NULL;
	ssl = NULL;
	rbio_ssl = NULL;
	wbio_ssl = NULL;
	ssl_write_len = 0;
	ssl_write_buf = NULL;
	net_failure = false;
	CompPktIN.pkt.ptr = NULL;
	CompPktIN.pkt.size = 0;
	CompPktIN.partial = 0;
	CompPktOUT.pkt.ptr = NULL;
	CompPktOUT.pkt.size = 0;
	CompPktOUT.partial = 0;
	multi_pkt.ptr = NULL;
	multi_pkt.size = 0;

	statuses.questions = 0;
	statuses.pgconnpoll_get = 0;
	statuses.pgconnpoll_put = 0;

	com_field_wild = NULL;
	scram_state = nullptr;
}

// Destructor
PgSQL_Data_Stream::~PgSQL_Data_Stream() {

	queue_destroy(queueIN);
	queue_destroy(queueOUT);
	if (client_addr) {
		free(client_addr);
		client_addr = NULL;
	}
	if (addr.addr) {
		free(addr.addr);
		addr.addr = NULL;
	}
	if (proxy_addr.addr) {
		free(proxy_addr.addr);
		proxy_addr.addr = NULL;
	}

	free_mysql_real_query();

	if (com_field_wild) {
		free(com_field_wild);
		com_field_wild = NULL;
	}

	proxy_debug(PROXY_DEBUG_NET, 1, "Shutdown Data Stream. Session=%p, DataStream=%p\n", sess, this);
	PtrSize_t pkt;
	if (PSarrayIN) {
		while (PSarrayIN->len) {
			PSarrayIN->remove_index_fast(0, &pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayIN;
	}
	if (PSarrayOUT) {
		while (PSarrayOUT->len) {
			PSarrayOUT->remove_index_fast(0, &pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayOUT;
	}
	if (resultset) {
		while (resultset->len) {
			resultset->remove_index_fast(0, &pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete resultset;
	}
	if (mypolls) mypolls->remove_index_fast(poll_fds_idx);


	if (fd > 0) {
		//	// Changing logic here. The socket should be closed only if it is not a backend
		if (myds_type == MYDS_FRONTEND) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p , MYDS:%p , PgSQL_Connection %p %s: shutdown socket\n", sess, this, myconn, (myconn ? "not reusable" : "is empty"));
			shut_hard();
		}
	}
	// Commenting the follow line of code and adding an assert. We should ensure that if a myconn exists it should be removed *before*
	if (myds_type == MYDS_BACKEND || myds_type == MYDS_BACKEND_NOT_CONNECTED) {
		assert(myconn == NULL);
	}
	if ((myconn) && (myds_type == MYDS_FRONTEND)) { delete myconn; myconn = NULL; }
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
		l_free(multi_pkt.size, multi_pkt.ptr);
		multi_pkt.ptr = NULL;
		multi_pkt.size = 0;
	}
	if (CompPktIN.pkt.ptr) {
		l_free(CompPktIN.pkt.size, CompPktIN.pkt.ptr);
		CompPktIN.pkt.ptr = NULL;
		CompPktIN.pkt.size = 0;
	}
	if (CompPktOUT.pkt.ptr) {
		l_free(CompPktOUT.pkt.size, CompPktOUT.pkt.ptr);
		CompPktOUT.pkt.ptr = NULL;
		CompPktOUT.pkt.size = 0;
	}
	if (x509_subject_alt_name) {
		free(x509_subject_alt_name);
		x509_subject_alt_name = NULL;
	}

	free_scram_state(scram_state);
}

// this function initializes a PgSQL_Data_Stream 
void PgSQL_Data_Stream::init() {
	if (myds_type != MYDS_LISTENER) {
		proxy_debug(PROXY_DEBUG_NET, 1, "Init Data Stream. Session=%p, DataStream=%p -- type %d\n", sess, this, myds_type);
		if (PSarrayIN == NULL) PSarrayIN = new PtrSizeArray();
		if (PSarrayOUT == NULL) PSarrayOUT = new PtrSizeArray();
		//		if (PSarrayOUTpending==NULL) PSarrayOUTpending= new PtrSizeArray();
		if (resultset == NULL) resultset = new PtrSizeArray();

		if (unlikely(GloVars.global.data_packets_history_size)) {
			data_packets_history_IN.set_max_size(GloVars.global.data_packets_history_size);
			data_packets_history_OUT.set_max_size(GloVars.global.data_packets_history_size);
		}
	}
	if (myds_type != MYDS_FRONTEND) {
		queue_destroy(queueIN);
		queue_destroy(queueOUT);
	}
}

void PgSQL_Data_Stream::reinit_queues() {
	if (queueIN.buffer == NULL)
		queue_init(queueIN, QUEUE_T_DEFAULT_SIZE);
	if (queueOUT.buffer == NULL)
		queue_init(queueOUT, QUEUE_T_DEFAULT_SIZE);
}

// this function initializes a PgSQL_Data_Stream with arguments
void PgSQL_Data_Stream::init(enum MySQL_DS_type _type, PgSQL_Session* _sess, int _fd) {
	myds_type = _type;
	sess = _sess;
	init();
	fd = _fd;
	proxy_debug(PROXY_DEBUG_NET, 1, "Initialized Data Stream. Session=%p, DataStream=%p, type=%d, fd=%d, myconn=%p\n", sess, this, myds_type, fd, myconn);
	//if (myconn==NULL) myconn = new PgSQL_Connection();
	if (myconn) myconn->fd = fd;
}

// Soft shutdown of socket : it only deactivate the data stream
// TODO: should check the status of the data stream, and identify if it is safe to reconnect or if the session should be destroyed
void PgSQL_Data_Stream::shut_soft() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown soft fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	active = 0;
	set_net_failure();
	//if (sess) sess->net_failure=1;
}

// Hard shutdown of socket
void PgSQL_Data_Stream::shut_hard() {
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

void PgSQL_Data_Stream::check_data_flow() {
	if ((PSarrayIN->len || queue_data(queueIN)) && (PSarrayOUT->len || queue_data(queueOUT))) {
		// there is data at both sides of the data stream: this is considered a fatal error
		proxy_error("Session=%p, DataStream=%p -- Data at both ends of a MySQL data stream: IN <%d bytes %d packets> , OUT <%d bytes %d packets>\n", sess, this, PSarrayIN->len, queue_data(queueIN), PSarrayOUT->len, queue_data(queueOUT));
		shut_soft();
		generate_coredump();
	}
	if ((myds_type == MYDS_BACKEND) && myconn && (myconn->fd == 0) && (revents & POLLOUT)) {
		int rc;
		int error;
		socklen_t len = sizeof(error);
		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
		assert(rc == 0);
		if (error == 0) {
			myconn->fd = fd; // connect succeeded
		}
		else {
			errno = error;
			perror("check_data_flow");
			shut_soft();
		}
	}
}

int PgSQL_Data_Stream::read_from_net() {
	if (encrypted) {
		//proxy_info("Entering\n");
	}
	if ((revents & POLLHUP) && ((revents & POLLIN) == 0)) {
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
	if ((revents & POLLIN) == 0) return 0;

	int r = 0;
	int s = queue_available(queueIN);
	if (encrypted) {
		//	proxy_info("Queue available of %d bytes\n", s);
	}
	if (encrypted == false) {
		if (pkts_recv) {
			r = recv(fd, queue_w_ptr(queueIN), s, 0);
		}
		else {
			if (queueIN.partial == 0) {
				// we are reading the very first packet
				// to avoid issue with SSL, we will only read the header and eventually the first packet
				r = recv(fd, queue_w_ptr(queueIN), 5, 0);
				if (r == 5) {
					// let's try to read a whole packet
					unsigned int read_pos = 0;
					unsigned char* buff = (unsigned char*)queueIN.buffer;
					const uint8_t type8 = buff[0];
					if (type8 != 0)
						read_pos++;

					uint32_t length = 0;
					unsigned a, b, c, d;
					a = buff[read_pos++];
					b = buff[read_pos++];
					c = buff[read_pos++];
					d = buff[read_pos++];
					length = (a << 24) | (b << 16) | (c << 8) | d;
					
					r += recv(fd, queue_w_ptr(queueIN) + 5, length, 0);
				}
			}
			else {
				r = recv(fd, queue_w_ptr(queueIN), s, 0);
			}
		}
	}
	else { // encrypted == true
		/*
				if (!SSL_is_init_finished(ssl)) {
					int ret = SSL_do_handshake(ssl);
					int ret2;
					if (ret != 1) {
						//ERR_print_errors_fp(stderr);
						ret2 = SSL_get_error(ssl, ret);
						fprintf(stderr,"%d\n",ret2);
					}
					return 0;
				} else {
					r = SSL_read (ssl, queue_w_ptr(queueIN), s);
				}
		*/
		PROXY_TRACE();
		if (s < MY_SSL_BUFFER) {
			return 0;	// no enough space for reads
		}
		char buf[MY_SSL_BUFFER];
		//ssize_t n = read(fd, buf, sizeof(buf));
		int n = recv(fd, buf, sizeof(buf), 0);
		//proxy_info("SSL recv of %d bytes\n", n);
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p: recv() read %d bytes. num_write: %lu ,  num_read: %lu\n", sess, n, rbio_ssl->num_write, rbio_ssl->num_read);
		if (n > 0 || rbio_ssl->num_write > rbio_ssl->num_read) {
			//on_read_cb(buf, (size_t)n);

			char buf2[MY_SSL_BUFFER];
			int n2;
			//enum pgsql_sslstatus pgsql_status;
			char* src = buf;
			int len = n;
			while (len > 0) {
				n2 = BIO_write(rbio_ssl, src, len);
				proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: write %d bytes into BIO %p, len=%d\n", sess, n2, rbio_ssl, len);
				//proxy_info("BIO_write with len = %d and %d bytes\n", len , n2);
				if (n2 <= 0) {
					shut_soft();
					return -1;
				}
				src += n2;
				len -= n2;
				if (!SSL_is_init_finished(ssl)) {
					//proxy_info("SSL_is_init_finished NOT completed\n");
					if (do_ssl_handshake() == PGSQL_SSLSTATUS_FAIL) {
						//proxy_info("SSL_is_init_finished failed!!\n");
						shut_soft();
						return -1;
					}
					if (!SSL_is_init_finished(ssl)) {
						//proxy_info("SSL_is_init_finished yet NOT completed\n");
						return 0;
					}
				}
				else {
					//proxy_info("SSL_is_init_finished completed\n");
				}
			}
			n2 = SSL_read(ssl, queue_w_ptr(queueIN), s);
			proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: read %d bytes from BIO %p into a buffer with %d bytes free\n", sess, n2, rbio_ssl, s);
			r = n2;
			//proxy_info("Read %d bytes from SSL\n", r);
			if (n2 > 0) {
			}
			/*
						do {
							n2 = SSL_read(ssl, buf2, sizeof(buf2));
							if (n2 > 0) {

							}
						} while (n > 0);
			*/
			status = get_sslstatus(ssl, n2);
			//proxy_info("SSL status = %d\n", status);
			if (status == PGSQL_SSLSTATUS_WANT_IO) {
				do {
					n2 = BIO_read(wbio_ssl, buf2, sizeof(buf2));
					//proxy_info("BIO_read with %d bytes\n", n2);
					if (n2 > 0) {
						queue_encrypted_bytes(buf2, n2);
					}
					else if (!BIO_should_retry(wbio_ssl)) {
						shut_soft();
						return -1;
					}
				} while (n2 > 0);
			}
			if (status == PGSQL_SSLSTATUS_FAIL) {
				shut_soft();
				return -1;
			}
		}
		else {
			r = n;
			//r += SSL_read (ssl, queue_w_ptr(queueIN), s);
			//proxy_info("Read %d bytes from SSL\n", r);
		}
	}
	//__exit_read_from_next:
	proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: read %d bytes from fd %d into a buffer of %d bytes free\n", sess, r, fd, s);
	//proxy_error("read %d bytes from fd %d into a buffer of %d bytes free\n", r, fd, s);
	if (r < 1) {
		if (encrypted == false) {
			int myds_errno = errno;
			if (r == 0 || (r == -1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
				shut_soft();
			}
		}
		else {
			int ssl_ret = SSL_get_error(ssl, r);
			proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- session_id: %u , SSL_get_error(): %d , errno: %d\n", sess, this, sess->thread_session_id, ssl_ret, errno);
			if (ssl_ret == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN)) {
				// the read was interrupted, do nothing
				proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- SSL_get_error() is SSL_ERROR_SYSCALL, errno: %d\n", sess, this, errno);
			}
			else {
				if (r == 0) { // we couldn't read any data
					if (revents & POLLIN) {
						// If revents is holding either POLLIN, or POLLIN and POLLHUP, but 'recv()' returns 0,
						// reading no data, the socket has been already closed by the peer. Due to this we can
						// ignore POLLHUP in this check, since we should reach here ONLY if POLLIN was set.
						proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, Datastream=%p -- shutdown soft\n", sess, this);
						shut_soft();
					}
				}
				if (ssl_ret != SSL_ERROR_WANT_READ && ssl_ret != SSL_ERROR_WANT_WRITE) shut_soft();
				// it seems we end in shut_soft() anyway
			}
		}
	}
	else {
		queue_w(queueIN, r);
		bytes_info.bytes_recv += r;
		if (mypolls) mypolls->last_recv[poll_fds_idx] = sess->thread->curtime;
	}
	return r;
}

int PgSQL_Data_Stream::write_to_net() {
	int bytes_io = 0;
	int s = queue_data(queueOUT);
	int n;
	if (encrypted) {
		//proxy_info("Data in write buffer: %d bytes\n", s);
	}
	if (s == 0) {
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
		bytes_io = SSL_write(ssl, queue_r_ptr(queueOUT), s);
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
			} while (n > 0);
		}
		proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: current ssl_write_len is %lu bytes\n", sess, this, ssl_write_len);
		if (ssl_write_len) {
			n = write(fd, ssl_write_buf, ssl_write_len);
			proxy_debug(PROXY_DEBUG_NET, 7, "Session=%p, Datastream=%p: write() wrote %d bytes in FD %d\n", sess, this, n, fd);
			//proxy_info("Calling write() on SSL: %d\n", n);
			if (n > 0) {
				if ((size_t)n < ssl_write_len) {
					memmove(ssl_write_buf, ssl_write_buf + n, ssl_write_len - n);
				}
				ssl_write_len -= n;
				if (ssl_write_len) {
					ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
				}
				else {
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
			}
			else {
				int myds_errno = errno;
				if (n == 0 || (n == -1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
					shut_soft();
					return 0;
				}
				else {
					return -1;
				}
			}
		}
	}
	else {
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
		if (encrypted == false) {
			if ((poll_fds_idx < 0) || (mypolls->fds[poll_fds_idx].revents & POLLOUT)) { // in write_to_net_poll() we has remove this safety
				// so we enforce it here
				shut_soft();
			}
		}
		else {
			int ssl_ret = SSL_get_error(ssl, bytes_io);
			if (ssl_ret != SSL_ERROR_WANT_READ && ssl_ret != SSL_ERROR_WANT_WRITE) shut_soft();
		}
	}
	else {
		queue_r(queueOUT, bytes_io);
		if (mypolls) mypolls->last_sent[poll_fds_idx] = sess->thread->curtime;
		bytes_info.bytes_sent += bytes_io;
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

bool PgSQL_Data_Stream::available_data_out() {
	int buflen = queue_data(queueOUT);
	if (buflen || PSarrayOUT->len) {
		return true;
	}
	return false;
}

void PgSQL_Data_Stream::remove_pollout() {
	struct pollfd* _pollfd;
	_pollfd = &mypolls->fds[poll_fds_idx];
	_pollfd->events = 0;
}

void PgSQL_Data_Stream::set_pollout() {
	struct pollfd* _pollfd;
	_pollfd = &mypolls->fds[poll_fds_idx];
	if (DSS > STATE_MARIADB_BEGIN && DSS < STATE_MARIADB_END) {
		_pollfd->events = myconn->wait_events;
	}
	else {
		_pollfd->events = POLLIN;
		//if (PSarrayOUT->len || available_data_out() || queueOUT.partial || (encrypted && !SSL_is_init_finished(ssl))) {
		if (PSarrayOUT->len || available_data_out() || queueOUT.partial) {
			_pollfd->events |= POLLOUT;
		}
		if (encrypted) {
			if (ssl_write_len || wbio_ssl->num_write > wbio_ssl->num_read) {
				_pollfd->events |= POLLOUT;
			}
			else {
				if (!SSL_is_init_finished(ssl)) {
					//proxy_info("SSL_is_init_finished NOT completed\n");
					if (do_ssl_handshake() == PGSQL_SSLSTATUS_FAIL) {
						//proxy_info("SSL_is_init_finished failed!!\n");
						shut_soft();
						return;
					}
					if (!SSL_is_init_finished(ssl)) {
						//proxy_info("SSL_is_init_finished yet NOT completed\n");
						return;
					}
					_pollfd->events |= POLLOUT;
				}
				else {
					//proxy_info("SSL_is_init_finished completed\n");
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_NET, 1, "Session=%p, DataStream=%p -- Setting poll events %d for FD %d , DSS=%d , myconn=%p\n", sess, this, _pollfd->events, fd, DSS, myconn);
}

int PgSQL_Data_Stream::write_to_net_poll() {
	int rc = 0;
	if (active == 0) return rc;
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
			if (do_ssl_handshake() == PGSQL_SSLSTATUS_FAIL) {
				//proxy_info("SSL_is_init_finished failed!!\n");
				shut_soft();
				return -1;
			}
		}
		else {
			//proxy_info("SSL_is_init_finished completed: YES\n");
		}
		/*
				if (!SSL_is_init_finished(ssl)) {
					proxy_info("SSL_is_init_finished completed: NO!\n");
					if (fd>0 && sess->session_type == PROXYSQL_SESSION_PGSQL) {
						set_pollout();
						return 0;
					}
				}
		*/
		//proxy_info("ssl_write_len: %u\n", ssl_write_len);
		if (ssl_write_len) {
			int n = write(fd, ssl_write_buf, ssl_write_len);
			//proxy_info("Calling write() on SSL: %d\n", n);
			if (n > 0) {
				if ((size_t)n < ssl_write_len) {
					memmove(ssl_write_buf, ssl_write_buf + n, ssl_write_len - n);
				}
				ssl_write_len -= n;
				if (ssl_write_len) {
					ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
				}
				else {
					free(ssl_write_buf);
					ssl_write_buf = NULL;
				}
				//proxy_info("new ssl_write_len: %u\n", ssl_write_len);
				if (ssl_write_len) {
					return n; // stop here
				}
				else {
					rc = n; // and continue
				}
			}
			else {
				int myds_errno = errno;
				if (n == 0 || (n == -1 && myds_errno != EINTR && myds_errno != EAGAIN)) {
					shut_soft();
					return 0;
				}
				else {
					return -1;
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_NET, 1, "Session=%p, DataStream=%p --\n", sess, this);
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
		if (sess->session_type == PROXYSQL_SESSION_PGSQL) {
			if (poll_fds_idx > -1) { // NOTE: attempt to force writes
				if (net_failure == false)
					rc += write_to_net();
			}
		}
		else {
			rc += write_to_net();
		}
	}
	if (fd > 0 && sess->session_type == PROXYSQL_SESSION_PGSQL) {
		// PROXYSQL_SESSION_PGSQL is a requirement, because it uses threads pool
		// the other session types do not
		set_pollout();
	}
	return rc;
}

int PgSQL_Data_Stream::read_pkts() {
	int rc = 0;
	int r = 0;
	while ((r = buffer2array())) rc += r;
	return rc;
}

void PgSQL_Data_Stream::generate_compressed_packet() {
#define MAX_COMPRESSED_PACKET_SIZE	10*1024*1024
	unsigned int total_size = 0;
	unsigned int i = 0;
	PtrSize_t* p = NULL;
	while (i < PSarrayOUT->len && total_size < MAX_COMPRESSED_PACKET_SIZE) {
		p = PSarrayOUT->index(i);
		total_size += p->size;
		i++;
	}
	if (i >= 2) {
		// we successfully read at least 2 packets
		if (total_size > MAX_COMPRESSED_PACKET_SIZE) {
			// total_size is too big, we remove the last packet read
			total_size -= p->size;
		}
	}
	if (total_size <= MAX_COMPRESSED_PACKET_SIZE) {
		// this worked in the past . it applies for small packets
		uLong sourceLen = total_size;
		Bytef* source = (Bytef*)l_alloc(total_size);
		uLongf destLen = total_size * 120 / 100 + 12;
		Bytef* dest = (Bytef*)malloc(destLen);
		i = 0;
		total_size = 0;
		while (total_size < sourceLen) {
			PtrSize_t p2;
			PSarrayOUT->remove_index(0, &p2);
			memcpy(source + total_size, p2.ptr, p2.size);
			total_size += p2.size;
			l_free(p2.size, p2.ptr);
		}
		int rc = compress(dest, &destLen, source, sourceLen);
		assert(rc == Z_OK);
		l_free(total_size, source);
		queueOUT.pkt.size = destLen + 7;
		queueOUT.pkt.ptr = l_alloc(queueOUT.pkt.size);
		mysql_hdr hdr;
		hdr.pkt_length = destLen;
		hdr.pkt_id = ++myconn->compression_pkt_id;
		memcpy((unsigned char*)queueOUT.pkt.ptr, &hdr, sizeof(mysql_hdr));
		hdr.pkt_length = total_size;
		memcpy((unsigned char*)queueOUT.pkt.ptr + 4, &hdr, 3);
		memcpy((unsigned char*)queueOUT.pkt.ptr + 7, dest, destLen);
		free(dest);
	}
	else {
		// if we reach here, it means we have one single packet larger than MAX_COMPRESSED_PACKET_SIZE
		PtrSize_t p2;
		PSarrayOUT->remove_index(0, &p2);

		unsigned int len1 = MAX_COMPRESSED_PACKET_SIZE / 2;
		unsigned int len2 = p2.size - len1;
		uLongf destLen1;
		uLongf destLen2;
		Bytef* dest1;
		Bytef* dest2;
		int rc;

		mysql_hdr hdr;

		destLen1 = len1 * 120 / 100 + 12;
		dest1 = (Bytef*)malloc(destLen1 + 7);
		destLen2 = len2 * 120 / 100 + 12;
		dest2 = (Bytef*)malloc(destLen2 + 7);
		rc = compress(dest1 + 7, &destLen1, (const unsigned char*)p2.ptr, len1);
		assert(rc == Z_OK);
		rc = compress(dest2 + 7, &destLen2, (const unsigned char*)p2.ptr + len1, len2);
		assert(rc == Z_OK);

		hdr.pkt_length = destLen1;
		hdr.pkt_id = ++myconn->compression_pkt_id;
		memcpy(dest1, &hdr, sizeof(mysql_hdr));
		hdr.pkt_length = len1;
		memcpy((char*)dest1 + sizeof(mysql_hdr), &hdr, 3);

		hdr.pkt_length = destLen2;
		hdr.pkt_id = ++myconn->compression_pkt_id;
		memcpy(dest2, &hdr, sizeof(mysql_hdr));
		hdr.pkt_length = len2;
		memcpy((char*)dest2 + sizeof(mysql_hdr), &hdr, 3);

		queueOUT.pkt.size = destLen1 + destLen2 + 7 + 7;
		queueOUT.pkt.ptr = l_alloc(queueOUT.pkt.size);
		memcpy((char*)queueOUT.pkt.ptr, dest1, destLen1 + 7);
		memcpy((char*)queueOUT.pkt.ptr + destLen1 + 7, dest2, destLen2 + 7);
		free(dest1);
		free(dest2);
		l_free(p2.size, p2.ptr);
	}
}


int PgSQL_Data_Stream::array2buffer() {
	int ret = 0;
	unsigned int idx = 0;
	bool cont = true;
	if (sess) {
		if (sess->mirror == true) { // if this is a mirror session, just empty it
			idx = PSarrayOUT->len;
			goto __exit_array2buffer;
		}
	}
	while (cont) {
		//VALGRIND_DISABLE_ERROR_REPORTING;
		if (queue_available(queueOUT) == 0) {
			goto __exit_array2buffer;
		}
		if (queueOUT.partial == 0) { // read a new packet
			if (PSarrayOUT->len - idx) {
				proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Removing a packet from array\n", sess, this);
				if (queueOUT.pkt.ptr) {
					//l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
					add_to_data_packet_history_without_alloc(data_packets_history_OUT, queueOUT.pkt.ptr, queueOUT.pkt.size);
					queueOUT.pkt.ptr = NULL;
				}
				//VALGRIND_ENABLE_ERROR_REPORTING;
				if (myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION) == true) {
					proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Compression enabled\n", sess, this);
					generate_compressed_packet();	// it is copied directly into queueOUT.pkt					
				}
				else {
					//VALGRIND_DISABLE_ERROR_REPORTING;
					memcpy(&queueOUT.pkt, PSarrayOUT->index(idx), sizeof(PtrSize_t));
					idx++;
					//VALGRIND_ENABLE_ERROR_REPORTING;
								// this is a special case, needed because compression is enabled *after* the first OK
					if (DSS == STATE_CLIENT_AUTH_OK) {
						DSS = STATE_SLEEP;
						// enable compression
						if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
							if (myconn->options.compression_min_length) {
								myconn->set_status(true, STATUS_MYSQL_CONNECTION_COMPRESSION);
							}
						}
						else {
							//explicitly disable compression
							myconn->options.compression_min_length = 0;
							myconn->set_status(false, STATUS_MYSQL_CONNECTION_COMPRESSION);
						}
					}
				}
#ifdef DEBUG
				{ __dump_pkt(__func__, (unsigned char*)queueOUT.pkt.ptr, queueOUT.pkt.size); }
#endif
			}
			else {
				cont = false;
				continue;
			}
		}
		int b = (queue_available(queueOUT) > (queueOUT.pkt.size - queueOUT.partial) ? (queueOUT.pkt.size - queueOUT.partial) : queue_available(queueOUT));
		//VALGRIND_DISABLE_ERROR_REPORTING;
		memcpy(queue_w_ptr(queueOUT), (unsigned char*)queueOUT.pkt.ptr + queueOUT.partial, b);
		//VALGRIND_ENABLE_ERROR_REPORTING;
		queue_w(queueOUT, b);
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Copied %d bytes into send buffer\n", sess, this, b);
		queueOUT.partial += b;
		ret = b;
		if (queueOUT.partial == queueOUT.pkt.size) {
			if (queueOUT.pkt.ptr) {
				//l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
				add_to_data_packet_history_without_alloc(data_packets_history_OUT, queueOUT.pkt.ptr, queueOUT.pkt.size);
				queueOUT.pkt.ptr = NULL;
			}
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . DataStream: %p -- Packet completely written into send buffer\n", sess, this);
			queueOUT.partial = 0;
			pkts_sent += 1;
		}
	}
__exit_array2buffer:
	if (idx) {
		PSarrayOUT->remove_index_range(0, idx);
	}
	return ret;
}

unsigned char* PgSQL_Data_Stream::resultset2buffer(bool del) {
	unsigned int i;
	unsigned int l = 0;
	unsigned char* mybuff = (unsigned char*)l_alloc(resultset_length);
	PtrSize_t* ps;
	for (i = 0; i < resultset->len; i++) {
		ps = resultset->index(i);
		memcpy(mybuff + l, ps->ptr, ps->size);
		if (del) l_free(ps->size, ps->ptr);
		l += ps->size;
	}
	return mybuff;
};

void PgSQL_Data_Stream::buffer2resultset(unsigned char* ptr, unsigned int size) {
	unsigned char* __ptr = ptr;
	mysql_hdr hdr;
	unsigned int l;
	void* buff = NULL;
	unsigned int bl;
	unsigned int bf;
	while (__ptr < ptr + size) {
		memcpy(&hdr, __ptr, sizeof(mysql_hdr));
		l = hdr.pkt_length + sizeof(mysql_hdr); // amount of space we need
		if (buff) {
			if (bf < l) {
				// we ran out of space
				resultset->add(buff, bl - bf);
				buff = NULL;
			}
		}
		if (buff == NULL) {
			if (__ptr + RESULTSET_BUFLEN_DS_1M <= ptr + size) {
				bl = RESULTSET_BUFLEN_DS_1M;
			}
			else {
				bl = RESULTSET_BUFLEN_DS_16K;
			}
			if (l > bl) {
				bl = l; // make sure there is the space to copy a packet
			}
			buff = malloc(bl);
			bf = bl;
		}
		memcpy((char*)buff + (bl - bf), __ptr, l);
		bf -= l;
		__ptr += l;
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
		resultset->add(buff, bl - bf);
	}
};

int PgSQL_Data_Stream::array2buffer_full() {
	int rc = 0;
	int r = 0;
	while ((r = array2buffer())) rc += r;
	return rc;
}

int PgSQL_Data_Stream::assign_fd_from_mysql_conn() {
	assert(myconn);
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->myconn.net.fd);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->fd);
	fd = myconn->fd;
	return fd;
}

void PgSQL_Data_Stream::unplug_backend() {
	DSS = STATE_NOT_INITIALIZED;
	myconn = NULL;
	myds_type = MYDS_BACKEND_NOT_CONNECTED;
	mypolls->remove_index_fast(poll_fds_idx);
	mypolls = NULL;
	fd = 0;
}

void PgSQL_Data_Stream::set_net_failure() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d\n", this->sess, this, myds_type);
#ifdef DEBUG
	if (myds_type != MYDS_FRONTEND) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d not frontend\n", this->sess, this, myds_type);
	}
#endif /* DEBUG */
	net_failure = true;
}

void PgSQL_Data_Stream::setDSS_STATE_QUERY_SENT_NET() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p\n", this->sess, this);
	DSS = STATE_QUERY_SENT_NET;
}

void PgSQL_Data_Stream::return_MySQL_Connection_To_Pool() {
	PgSQL_Connection* mc = myconn;
	mc->last_time_used = sess->thread->curtime;
	// before detaching, check if last_HG_affected_rows matches . if yes, set it back to -1
	if (mybe) {
		if (mybe->hostgroup_id == sess->last_HG_affected_rows) {
			sess->last_HG_affected_rows = -1;
		}
	}
	unsigned long long intv = pgsql_thread___connection_max_age_ms;
	intv *= 1000;
	if (
		(((intv) && (mc->last_time_used > mc->creation_time + intv))
			||
			(mc->local_stmts->get_num_backend_stmts() > (unsigned int)GloPTH->variables.max_stmts_per_connection))
		&&
		// NOTE: If the current session if in 'PINGING_SERVER' status, there is
		// no need to reset the session. The destruction and creation of a new
		// session in case this session has exceeded the time specified by
		// 'connection_max_age_ms' will be deferred to the next time the session
		// is used outside 'PINGING_SERVER' operation. For more context see #3502.
		sess->status != PINGING_SERVER
		) {
		sess->create_new_session_and_reset_connection(this);
	} else {
		detach_connection();
		unplug_backend();
#ifdef STRESSTEST_POOL
		PgHGM->push_MyConn_to_pool(mc);  // #644
#else
		sess->thread->push_MyConn_local(mc);
#endif
	}
}

void PgSQL_Data_Stream::free_mysql_real_query() {
	if (mysql_real_query.QueryPtr) {
		mysql_real_query.end();
	}
}

void PgSQL_Data_Stream::destroy_queues() {
	queue_destroy(queueIN);
	queue_destroy(queueOUT);
}

void PgSQL_Data_Stream::destroy_MySQL_Connection_From_Pool(bool sq) {
	PgSQL_Connection* mc = myconn;
	PgSQL_SrvC* mysrvc = mc->parent;
	if (sq && mysrvc->status == MYSQL_SERVER_STATUS_ONLINE &&
		mc->async_state_machine == ASYNC_IDLE &&
		mc->is_connection_in_reusable_state() == true) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Trying to reset PgSQL_Connection %p, server %s:%d\n", mc, mysrvc->address, mysrvc->port);
		sess->create_new_session_and_reset_connection(this);
	} else {
		mc->last_time_used = sess->thread->curtime;
		mc->send_quit = sq;
		detach_connection();
		unplug_backend();
		PgHGM->destroy_MyConn_from_pool(mc);
	}
}

bool PgSQL_Data_Stream::data_in_rbio() {
	if (rbio_ssl->num_write > rbio_ssl->num_read) {
		return true;
	}
	return false;
}

void PgSQL_Data_Stream::reset_connection() {
	if (myconn) {
		if (pgsql_thread___multiplexing && (DSS == STATE_MARIADB_GENERIC || DSS == STATE_READY) && myconn->reusable == true &&
			myconn->IsActiveTransaction() == false && myconn->MultiplexDisabled() == false && myconn->async_state_machine == ASYNC_IDLE) {
			myconn->last_time_used = sess->thread->curtime;
			return_MySQL_Connection_To_Pool();
		} else {
			if (sess && sess->session_fast_forward == false) {
				destroy_MySQL_Connection_From_Pool(true);
			} else {
				destroy_MySQL_Connection_From_Pool(false);
			}
		}
	}
}

int PgSQL_Data_Stream::buffer2array() {
	int ret = 0;
	{
		unsigned long s = queue_data(queueIN);
		if (s == 0) return ret;
		if ((queueIN.pkt.size == 0) && s < 5) {
			queue_zero(queueIN);
		}
	}
	unsigned char header[5];
	if ((queueIN.pkt.size == 0) && queue_data(queueIN) >= sizeof(header)) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Reading the header of a new packet\n", sess);
		memcpy(header, queue_r_ptr(queueIN), sizeof(header));
		//pkt_sid=queueIN.hdr.pkt_id;
		queue_r(queueIN, sizeof(header));
		uint32_t pkgsize = 0;


		unsigned int read_pos = 0;
		const uint8_t type8 = header[0];
		if (type8 != 0) {
			read_pos++;
			pkgsize++;
		}

		unsigned a, b, c, d;

		a = header[read_pos++];
		b = header[read_pos++];
		c = header[read_pos++];
		d = header[read_pos++];
		pkgsize += (a << 24) | (b << 16) | (c << 8) | d;

		queueIN.pkt.size = pkgsize;
		queueIN.pkt.ptr = l_alloc(queueIN.pkt.size);
		memcpy(queueIN.pkt.ptr, header, sizeof(header)); // immediately copy the header into the packet
		queueIN.partial = sizeof(header);
		ret += sizeof(header);
	}
	if ((queueIN.pkt.size > 0) && queue_data(queueIN)) {
		int b = (queue_data(queueIN) > (queueIN.pkt.size - queueIN.partial) ? (queueIN.pkt.size - queueIN.partial) : queue_data(queueIN));
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Session=%p . Copied %d bytes into packet\n", sess, b);
		memcpy((unsigned char*)queueIN.pkt.ptr + queueIN.partial, queue_r_ptr(queueIN), b);
		queue_r(queueIN, b);
		queueIN.partial += b;
		ret += b;
	}
	if ((queueIN.pkt.size > 0) && (queueIN.pkt.size == queueIN.partial)) {
		PSarrayIN->add(queueIN.pkt.ptr, queueIN.pkt.size);
		pkts_recv++;
		queueIN.pkt.size = 0;
		queueIN.pkt.ptr = NULL;
	}
	return ret;
}