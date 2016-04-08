#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"


#define QUEUE_T_DEFAULT_SIZE	32768

typedef struct _queue_t {
	void *buffer;
	unsigned int size;
	unsigned int head;
	unsigned int tail;
	unsigned int partial;
	//unsigned char *pkt;
	PtrSize_t pkt;
	mysql_hdr hdr;
} queue_t;


/*
typedef struct _mysql_data_buffer_t {
  unsigned char *buffer;
  unsigned int size;
  unsigned int head;
  unsigned int tail;
	mysql_hdr hdr;
	unsigned int partial;
	unsigned char *pkt;
} mysql_data_buffer_t;
*/

// this class avoid copying data
class MyDS_real_query {
	public:
	PtrSize_t pkt; // packet coming from the client
	char *QueryPtr;	// pointer to beginning of the query
	unsigned int QuerySize;	// size of the query
	void init(PtrSize_t *_pkt) {
		assert(QueryPtr==NULL);
		assert(QuerySize==0);
		assert(pkt.ptr==NULL);
		assert(pkt.size==0);
		pkt.ptr=_pkt->ptr;
		pkt.size=_pkt->size;
		QueryPtr=(char *)pkt.ptr+5;
		QuerySize=pkt.size-5;
	}
	void end() {
		l_free(pkt.size,pkt.ptr);
		pkt.size=0;
		QuerySize=0;
		pkt.ptr=NULL;
		QueryPtr=NULL;
	}
};

class MySQL_Data_Stream
{
	private:
	//mysql_data_buffer_t bufferOUT;
	int array2buffer();
	int buffer2array();
	void generate_compressed_packet();
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

	MyDS_real_query mysql_real_query;

	PtrSize_t multi_pkt;

	unsigned long long wait_until;
	unsigned long long killed_at;
	unsigned long long max_connect_time;

	PtrSizeArray *PSarrayIN;
	PtrSizeArray *PSarrayOUT;
	//PtrSizeArray *PSarrayOUTpending;
	PtrSizeArray *resultset;
	unsigned int resultset_length;

	unsigned int connect_tries;
	ProxySQL_Poll *mypolls;
	int array2buffer_full();
	//int listener;
	MySQL_Connection *myconn;
	MySQL_Protocol myprot;
	int connect_retries_on_failure;
	enum mysql_data_stream_status DSS;
	enum MySQL_DS_type myds_type;
	MySQL_Session *sess;  // pointer to the session using this data stream
	MySQL_Backend *mybe;  // if this is a connection to a mysql server, this points to a backend structure
	bytes_stats_t bytes_info; // bytes statistics
	int fd; // file descriptor

	struct sockaddr *client_addr;
	socklen_t client_addrlen;

	int poll_fds_idx;
	SSL *ssl;


	int active_transaction; // 1 if there is an active transaction
	int active; // data stream is active. If not, shutdown+close needs to be called
	int status; // status . FIXME: make it a ORable variable

	short revents;

	bool encrypted;
	bool net_failure;

	uint8_t pkt_sid;

//	struct {
//		char *ptr;
//		unsigned int size;
//	} mysql_real_query;


	MySQL_Data_Stream();
	~MySQL_Data_Stream();


	void init();	// initialize the data stream
	void init(enum MySQL_DS_type, MySQL_Session *, int); // initialize with arguments
	void shut_soft();
	void shut_hard();
	int read_from_net();
	int write_to_net();
	int write_to_net_poll();
	bool available_data_out();	
	void set_pollout();	
	void mysql_free();

	void clean_net_failure();
	void set_net_failure();
	void setDSS_STATE_QUERY_SENT_NET();

	void setDSS(enum mysql_data_stream_status dss) {
		DSS=dss;
	}

	int read_pkts();
	int write_pkts();

	void unplug_backend();

	//int assign_mshge(unsigned int);
	int myds_connect(char *, int, int *); // the data stream MUST be initialized

	void check_data_flow();
	int assign_fd_from_mysql_conn();

	//void move_from_OUT_to_OUTpending();
	unsigned char * resultset2buffer(bool);
	void buffer2resultset(unsigned char *, unsigned int);

	// safe way to attach a MySQL Connection
	void attach_connection(MySQL_Connection *mc) {
		myconn=mc;
		mc->myds=this;
	}

	// safe way to detach a MySQL Connection
	void detach_connection() {
		assert(myconn);
		myconn->myds=NULL;
		myconn=NULL;
	}

	void return_MySQL_Connection_To_Pool();
	
	void destroy_MySQL_Connection_From_Pool(bool sq) {
		MySQL_Connection *mc=myconn;
		detach_connection();
		unplug_backend();
		mc->send_quit=sq;
		MyHGM->destroy_MyConn_from_pool(mc);
	}
	void free_mysql_real_query();	
	void reinit_queues();
//	void destroy_MySQL_Connection() {
//		MySQL_Connection *mc=myconn;
//		detach_connection();
//		unplug_backend();
//		delete mc;
//	}

};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
