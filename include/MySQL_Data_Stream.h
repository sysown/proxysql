#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"


#define QUEUE_T_DEFAULT_SIZE	8192

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
	unsigned int connect_tries;
	ProxySQL_Poll *mypolls;
	int array2buffer_full();
	//int listener;
	MySQL_Connection *myconn;
	MySQL_Protocol myprot;
	enum mysql_data_stream_status DSS;
	enum MySQL_DS_type myds_type;
	MySQL_Session *sess;  // pointer to the session using this data stream
	MySQL_Backend *mybe;  // if this is a connection to a mysql server, this points to a backend structure
	uint64_t pkts_recv; // counter of received packets
	uint64_t pkts_sent; // counter of sent packets
	bytes_stats_t bytes_info; // bytes statistics
	int fd; // file descriptor

	unsigned long long timeout;
	int poll_fds_idx;
	short revents;

	bool encrypted;
	SSL *ssl;

	queue_t queueIN;	
	queue_t queueOUT;	
	//struct evbuffer *evbIN;
	//struct evbuffer *evbOUT;
	//GPtrArray *QarrayIN;
	//GPtrArray *QarrayOUT;
	PtrSizeArray *PSarrayIN;
	PtrSizeArray *PSarrayOUT;
	PtrSizeArray *PSarrayOUTpending;
	PtrSizeArray *resultset;
	unsigned int resultset_length;
	unsigned char * query_SQL;	

	int active_transaction; // 1 if there is an active transaction
	int active; // data stream is active. If not, shutdown+close needs to be called
	int status; // status . FIXME: make it a ORable variable

	bool net_failure;

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

	int read_pkts();
	int write_pkts();

	void unplug_backend();

	//int assign_mshge(unsigned int);
	int myds_connect(char *, int, int *); // the data stream MUST be initialized

	void check_data_flow();
	int assign_fd_from_mysql_conn();

	void move_from_OUT_to_OUTpending();
	unsigned char * resultset2buffer(bool);
	void buffer2resultset(unsigned char *, unsigned int);
};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
