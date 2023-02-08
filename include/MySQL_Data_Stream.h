#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Protocol.h"

#ifndef uchar
typedef unsigned char uchar;
#endif

#include "ma_pvio.h"
// here we define P_MARIADB_TLS as a copy of MARIADB_TLS
// copied from ma_tls.h
// note that ma_pvio.h defines it as void
typedef struct P_st_ma_pvio_tls {
  void *data;
  MARIADB_PVIO *pvio;
  void *ssl;
} P_MARIADB_TLS;


#define QUEUE_T_DEFAULT_SIZE	32768
#define MY_SSL_BUFFER	8192

typedef struct _queue_t {
	void *buffer;
	unsigned int size;
	unsigned int head;
	unsigned int tail;
	unsigned int partial;
	PtrSize_t pkt;
	mysql_hdr hdr;
} queue_t;


// this class avoid copying data
class MyDS_real_query {
	public:
	PtrSize_t pkt; // packet coming from the client
	char *QueryPtr;	// pointer to beginning of the query
	unsigned int QuerySize;	// size of the query
	void init(PtrSize_t *_pkt) {
/*
		assert(QueryPtr==NULL);
		assert(QuerySize==0);
		assert(pkt.ptr==NULL);
		assert(pkt.size==0);
*/
		pkt.ptr=_pkt->ptr;
		pkt.size=_pkt->size;
		QuerySize=pkt.size-5;
		if (QuerySize == 0) {
			QueryPtr=const_cast<char*>("");
		} else {
			QueryPtr=(char *)pkt.ptr+5;
		}
	}
	void end() {
		l_free(pkt.size,pkt.ptr);
		pkt.size=0;
		QuerySize=0;
		pkt.ptr=NULL;
		QueryPtr=NULL;
	}
};

enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

class MySQL_Data_Stream
{
	private:
	int array2buffer();
	int buffer2array();
	void generate_compressed_packet();
	enum sslstatus do_ssl_handshake();
	void queue_encrypted_bytes(const char *buf, size_t len);
	public:
	void * operator new(size_t);
	void operator delete(void *);

	queue_t queueIN;
	uint64_t pkts_recv; // counter of received packets
	queue_t queueOUT;
	uint64_t pkts_sent; // counter of sent packets

	struct {
		PtrSize_t pkt;
		unsigned int partial;
	} CompPktIN;
	struct {
		PtrSize_t pkt;
		unsigned int partial;
	} CompPktOUT;

	MySQL_Protocol myprot;
	MyDS_real_query mysql_real_query;
	bytes_stats_t bytes_info; // bytes statistics

	PtrSize_t multi_pkt;

	unsigned long long pause_until;
	unsigned long long wait_until;
	unsigned long long killed_at;
	unsigned long long max_connect_time;
	
	struct {
		unsigned long long questions;
		unsigned long long myconnpoll_get;
		unsigned long long myconnpoll_put;
	} statuses;

	PtrSizeArray *PSarrayIN;
	PtrSizeArray *PSarrayOUT;
	//PtrSizeArray *PSarrayOUTpending;
	PtrSizeArray *resultset;
	unsigned int resultset_length;

	ProxySQL_Poll *mypolls;
	//int listener;
	MySQL_Connection *myconn;
	MySQL_Session *sess;  // pointer to the session using this data stream
	MySQL_Backend *mybe;  // if this is a connection to a mysql server, this points to a backend structure
	char *x509_subject_alt_name;
	SSL *ssl;
	BIO *rbio_ssl;
	BIO *wbio_ssl;
	char *ssl_write_buf;
	size_t ssl_write_len;
	struct sockaddr *client_addr;

	struct {
		char *addr;
		int port;
	} addr;
	struct {
		char *addr;
		int port;
	} proxy_addr;

	unsigned int connect_tries;
	int query_retries_on_failure;
	int connect_retries_on_failure;
	enum mysql_data_stream_status DSS;
	enum MySQL_DS_type myds_type;

	socklen_t client_addrlen;

	int fd; // file descriptor
	int poll_fds_idx;


	int active_transaction; // 1 if there is an active transaction
	int active; // data stream is active. If not, shutdown+close needs to be called
	int status; // status . FIXME: make it a ORable variable

	int switching_auth_stage;
	int switching_auth_type;
	unsigned int tmp_charset;

	short revents;

	char kill_type;

	bool encrypted;
	bool net_failure;

	uint8_t pkt_sid;

	bool com_field_list;
	char *com_field_wild;

	MySQL_Data_Stream();
	~MySQL_Data_Stream();

	int array2buffer_full();
	void init();	// initialize the data stream
	void init(enum MySQL_DS_type, MySQL_Session *, int); // initialize with arguments
	void shut_soft();
	void shut_hard();
	int read_from_net();
	int write_to_net();
	int write_to_net_poll();
	bool available_data_out();	
	void remove_pollout();
	void set_pollout();	
	void mysql_free();

	void set_net_failure();
	void setDSS_STATE_QUERY_SENT_NET();

	void setDSS(enum mysql_data_stream_status dss) {
		DSS=dss;
	}

	int read_pkts();
	int write_pkts();

	void unplug_backend();

	void check_data_flow();
	int assign_fd_from_mysql_conn();

	unsigned char * resultset2buffer(bool);
	void buffer2resultset(unsigned char *, unsigned int);

	// safe way to attach a MySQL Connection
	void attach_connection(MySQL_Connection *mc) {
		statuses.myconnpoll_get++;
		myconn=mc;
		myconn->statuses.myconnpoll_get++;
		mc->myds=this;
		encrypted = false; // this is the default
		// PMC-10005
		// we handle encryption for backend
		//
		// we have a similar code in MySQL_Connection
		// in case of ASYNC_CONNECT_SUCCESSFUL
		if (sess != NULL && sess->session_fast_forward == true) {
			// if frontend and backend connection use SSL we will set
			// encrypted = true and we will start using the SSL structure
			// directly from P_MARIADB_TLS structure.
			//
			// For futher details:
			// - without ssl: we use the file descriptor from mysql connection
			// - with ssl: we use the SSL structure from mysql connection
			if (myconn->mysql && myconn->ret_mysql) {
				if (myconn->mysql->options.use_ssl == 1) {
					encrypted = true;
					if (ssl == NULL) {
						// check the definition of P_MARIADB_TLS
						P_MARIADB_TLS * matls = (P_MARIADB_TLS *)myconn->mysql->net.pvio->ctls;
						ssl = (SSL *)matls->ssl;
						rbio_ssl = BIO_new(BIO_s_mem());
						wbio_ssl = BIO_new(BIO_s_mem());
						SSL_set_bio(ssl, rbio_ssl, wbio_ssl);
					}
				}
			}
		}
	}

	// safe way to detach a MySQL Connection
	void detach_connection() {
		assert(myconn);
		myconn->statuses.myconnpoll_put++;
		statuses.myconnpoll_put++;
		myconn->myds=NULL;
		myconn=NULL;
		if (encrypted == true) {
			if (sess != NULL && sess->session_fast_forward == true) {
				// it seems we are a connection with SSL on a fast_forward session.
				// See attach_connection() for more details .
				// We now disable SSL metadata from the Data Stream
				encrypted = false;
				ssl = NULL;
			}
		}
	}

	void return_MySQL_Connection_To_Pool();
	
	void destroy_MySQL_Connection_From_Pool(bool sq);
	void free_mysql_real_query();	
	void reinit_queues();
	void destroy_queues();

	bool data_in_rbio();
};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
