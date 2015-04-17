#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"


#define QUEUE_T_DEFAULT_SIZE	8192

typedef struct _raw_bytes_queue_t {
	// The buffer containing the raw bytes
	void *buffer;

	// The total size of the buffer
	unsigned int size;
	// All data from the queue has been processed up to the index "tail"
	unsigned int tail;
	// We are currently processing data between "tail" and "head" (head > tail)
	unsigned int head;

	// The current packet that is being built from the raw bytes data or
	// that is being written to the raw bytes data.
	PtrSize_t pkt;
	// How much of the packet has been processed yet (0 <= partial <= pkt.size)
	unsigned int partial;

	// The header of the packet, when it is first extracted separately
	mysql_hdr hdr;
} raw_bytes_queue_t;

class MySQL_Data_Stream
{
	private:
	int array2buffer();
	int buffer2array();
	void generate_compressed_packet();
	public:
	void * operator new(size_t);
	void operator delete(void *);
	unsigned int connect_tries;
	ProxySQL_Poll *mypolls;
	int array2buffer_full();
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

	// Data read from the raw socket, organized as a buffer which contains
	// concatenated pieces of packets. It might contain several different
	// packets or just a piece of a bigger one.
	raw_bytes_queue_t queueIN;

	// Data to be written to the raw socket, organized as a buffer which
	// contains concatenated pieces of packets. It might contain several
	// different packets or just a piece of a bigger one.
	raw_bytes_queue_t queueOUT;

	PtrSizeArray *incoming_packets;
	PtrSizeArray *outgoing_packets;

	// Full packets that have been read from the socket, ready to be
	// processed by MySQL_Session. The routine that converts the raw
	// bytes to these packets is buffer2array().
	PtrSizeArray *incoming_fragments;

	// Full packets that have been written by MySQL_Session, that will
	// end up being converted to buffers and written to the socket.
	// The routine that does the conversion is array2buffer().
	PtrSizeArray *outgoing_fragments;

	// Sometimes, packets need to be put on hold as we are trying to
	// send packets to a backend to which we're not connected to yet.
	// Then, the packets to be sent are moved in here, and then the
	// handshake packets are put into outgoing_fragments in order to make
	// sure that an application-level connection is established first.
	PtrSizeArray *outgoing_pending_fragments;

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

	int myds_connect(char *, int, int *); // the data stream MUST be initialized

	void check_data_flow();
	int assign_fd_from_mysql_conn();

	void move_from_OUT_to_OUTpending();
	unsigned char * resultset2buffer(bool);
	void buffer2resultset(unsigned char *, unsigned int);
};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
