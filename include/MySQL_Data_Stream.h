#ifndef PROXYSQL_MYSQL_DATA_STREAM_H
#define PROXYSQL_MYSQL_DATA_STREAM_H

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Protocol.h"
#include "proxy_protocol_info.h"

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

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


#ifdef PROXYSQL31
// Input ring. One per connection, paid by idle clients.
#define QUEUE_IN_DEFAULT_SIZE	32768
// Output ring. Packs only what is not sent as its own span.
// 1 KiB holds protocol chatter; result slabs point at their own buffer.
// The ring is not a fixed staging area for large packets: when it is empty and
// the next packet is larger than this, the packet itself becomes the send span
// (see queue_t). This is what keeps idle MySQL connections small.
#define QUEUE_OUT_DEFAULT_SIZE	1024
// Compressed connections stage every compressed frame through the ring, and
// recompression already happened before the copy. Keep the historical 32 KiB
// for them; the ring is raised once, when compression is negotiated.
#define QUEUE_OUT_COMPRESSED_SIZE	32768
// Bytes on the wire before writeout() looks at the client rate. Not a capacity.
// The old code compared against QUEUE_T_DEFAULT_SIZE because the output ring was
// always 32 KiB; the throttle is about wire bytes, so keep it as its own name.
#define WRITEOUT_THROTTLE_BYTES	32768
// Historical name for the input ring.
#define QUEUE_T_DEFAULT_SIZE	QUEUE_IN_DEFAULT_SIZE

/*
 * A queue has two independent identities:
 *
 *   storage / capacity
 *       The owned, contiguous ring. It is allocated by queue_init() and never
 *       resized, with one exception: a compressed MySQL connection grows
 *       queueOUT once, from QUEUE_OUT_DEFAULT_SIZE to QUEUE_OUT_COMPRESSED_SIZE,
 *       because every compressed frame is staged through the ring.
 *
 *   buffer / size
 *       The span the next send()/SSL_write() reads. It is normally storage, but
 *       while a packet larger than the ring is being sent from an empty ring it
 *       points directly at that packet ("borrowed span"). Borrowing avoids the
 *       copy that the old staging path made for every large resultset slab.
 *
 * head / tail are offsets into buffer and queue_data(q) == head - tail is the
 * number of queued bytes in the current span. For an owned ring, array2buffer()
 * appends at head. For a borrowed span the whole packet is one span: head is
 * its length and tail advances as the socket accepts bytes. Because a borrowed
 * packet is not ring storage:
 *
 *   - a borrow may only start when the ring is empty (queue_data() == 0);
 *   - array2buffer() must not append while a borrow is active;
 *   - release_borrowed_out_span() restores storage only after the span drains;
 *   - queue_zero(), which compacts in place, is used on queueIN only.
 *
 * partial is the number of bytes of pkt already copied into an owned ring. It
 * is always 0 for a borrowed span. pkt owns the packet (from PSarrayOUT, or the
 * compressed frame built by generate_compressed_packet()) and is freed by
 * queue_destroy() if the stream dies mid-transfer.
 */
typedef struct _queue_t {
	void *buffer;		// span send()/SSL_write() read; storage, or a borrowed packet
	void *storage;		// owned ring. destroy() frees this, never buffer
	unsigned int size;	// length of the current span (capacity for an owned ring)
	unsigned int capacity;	// size of storage; set at init, raised once for compression
	unsigned int head;	// end of queued data within buffer
	unsigned int tail;	// start of unsent data within buffer
	unsigned int partial;	// bytes of pkt already copied into an owned ring
	PtrSize_t pkt;		// packet being staged, or the borrowed span
	mysql_hdr hdr;
} queue_t;
#else
#define QUEUE_T_DEFAULT_SIZE	32768

typedef struct _queue_t {
	void *buffer;
	unsigned int size;
	unsigned int head;
	unsigned int tail;
	unsigned int partial;
	PtrSize_t pkt;
	mysql_hdr hdr;
} queue_t;
#endif // PROXYSQL31
#define MY_SSL_BUFFER	8192


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
#ifdef PROXYSQL31
	std::string frontend_server_version_;
#endif
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
		// Bytes of an inner packet header split across compressed frames
		unsigned char hdr[sizeof(mysql_hdr)];
		unsigned int hdr_len;
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
	FixedSizeQueue data_packets_history_IN;
	FixedSizeQueue data_packets_history_OUT;
	//PtrSizeArray *PSarrayOUTpending;
	PtrSizeArray *resultset;
	unsigned int resultset_length;

	ProxySQL_Poll<MySQL_Data_Stream> *mypolls;
	//int listener;
	MySQL_Connection *myconn;
	MySQL_Session *sess;  // pointer to the session using this data stream
	MySQL_Backend *mybe;  // if this is a connection to a mysql server, this points to a backend structure
	std::vector<std::pair<std::string, std::string>> client_connect_attrs;
	std::unique_ptr<char[]> x509_subject_alt_name;
#ifdef PROXYSQL31
	bool client_cert_present;
	long client_cert_verify_result;
	bool frontend_authenticated_via_spiffe;
#endif
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
	ProxyProtocolInfo * PROXY_info;

	unsigned int connect_tries;
	int query_retries_on_failure;
	int connect_retries_on_failure;
	uint32_t unexp_com_pings { 0 };
	enum mysql_data_stream_status DSS;
	enum MySQL_DS_type myds_type;

	socklen_t client_addrlen;

	int fd; // file descriptor
	int poll_fds_idx;


	int active_transaction; // 1 if there is an active transaction
	int active; // data stream is active. If not, shutdown+close needs to be called
	int status; // status . FIXME: make it a ORable variable

	int switching_auth_stage;
	enum proxysql_auth_plugins switching_auth_type;
	// Updated **only** when an 'auth_switch' has been sent to client
	enum proxysql_auth_plugins switching_auth_sent;
	int auth_in_progress; // if 0 , no authentication is in progress. Any value greater than 0 depends from the implementation
	// Pass-through authentication: cleartext password received from the
	// client during the caching_sha2_password full-auth exchange (spec
	// §4.1). Captured by PPHR_passthrough_init at stage 5 and consumed by
	// handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT when it
	// drives the non-blocking backend connect. Lives on a dedicated field
	// (NOT userinfo->password) because process_pkt_handshake_response's
	// epilogue overwrites userinfo->password with "" when auth is still in
	// progress -- which would clobber the borrowed cleartext before the
	// session handler runs. NULL when no pass-through probe is in flight.
	char *passthrough_cleartext;
	unsigned int tmp_charset;

	short revents;

	char kill_type;

	bool encrypted;
	// defer_close_due_to_fast_forward: Flag to prevent immediate closure of data stream
	// during fast forward grace close, allowing buffers to drain.
	bool defer_close_due_to_fast_forward;
	bool net_failure;
#ifdef PROXYSQL31
	// Set once when growing queueOUT for a compressed connection fails. The
	// growth is retried on later frames, but the failure is logged only once so
	// a persistent allocation failure cannot flood the error log per frame.
	bool queue_out_grow_failed;
#endif // PROXYSQL31

	uint8_t pkt_sid;

	bool com_field_list;
	char *com_field_wild;

	MySQL_Data_Stream();
	virtual ~MySQL_Data_Stream();
	int array2buffer_full();
	void reset_frontend_certificate_evidence();
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

#ifdef PROXYSQL31
	void pin_frontend_server_version(const std::string& version) {
		frontend_server_version_ = version;
	}
	const std::string& frontend_server_version() const {
		return frontend_server_version_;
	}
#endif

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
		if (sess != NULL && sess->session_fast_forward) {
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
			if (sess != NULL && sess->session_fast_forward) {
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

	void reset_connection();

	void get_client_myds_info_json(nlohmann::json&);
};

// Decompress a MySQL compressed-protocol payload into `dest` (capacity
// `destLen` == the claimed pre-compression length from the wire header).
// Returns true only when the payload decompresses successfully AND the
// actual decompressed size matches the claimed `destLen`. Exposed (rather
// than file-static) so it can be exercised directly by the unit test for
// GHSA-fvch-fpgq-pwfx; see lib/mysql_data_stream.cpp for details.
bool decompress_mysql_payload(
	const MySQL_Connection* myconn, unsigned char* dest, unsigned long destLen,
	const unsigned char* source, size_t sourceLen
);

#endif /* PROXYSQL_MYSQL_DATA_STREAM_H */
