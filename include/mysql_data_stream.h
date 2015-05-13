#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"
#include "Raw_Bytes_Queue.h"

#define QUEUE_T_DEFAULT_SIZE	8192

/*
 * MySQL compressed protocol is a protocol in itself. It takes a series of
 * packets, concatenates them, and splits them up into chunks (which may
 * contain incomplete pieces of packets). These chunks are then compressed
 * and sent as normal packets.
 *
 * This class decodes the incoming chunks into packets.
 */
class MySQL_Compression_Chunks_to_Packets_Converter {
	
private:
	PtrSize_t packet;
	unsigned int bytes_so_far;
	PtrSizeArray *packet_queue;

	void init_packet(mysql_hdr *);
	void add_bytes_to_packet(unsigned int, void*);

public:
	MySQL_Compression_Chunks_to_Packets_Converter();
	~MySQL_Compression_Chunks_to_Packets_Converter();

	void ingest_chunk(unsigned int, void*);
	PtrSize_t get_packet();
	bool has_packets();
};

/*
 * This class encodes a series of packets into compressed chunks.
 * 
 * See the explanation for MySQL_Compression_Chunks_to_Packets_Converter for
 * more details.
 */
class MySQL_Compression_Packets_to_Chunks_Converter {

private:
	PtrSize_t chunk;
	unsigned int bytes_so_far, packets_in_chunk;
	PtrSizeArray *chunk_queue;

	void init_chunk();
	void add_bytes_to_chunk(unsigned int, void *);

public:
	MySQL_Compression_Packets_to_Chunks_Converter();
	~MySQL_Compression_Packets_to_Chunks_Converter();

	void ingest_packet(unsigned int, void *);
	void flush();
	PtrSize_t get_chunk();
	bool has_chunks();
};

class MySQL_Data_Stream
{
	private:
	int buffer_to_packets();
	void receive_incoming_packet(void *packet, unsigned int size);
	void __incoming_packet(void *packet, unsigned int size);
	void __outgoing_packet(void *packet, unsigned int size);

	public:
	void * operator new(size_t);
	void operator delete(void *);
	unsigned int connect_tries;
	ProxySQL_Poll *mypolls;
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
	MySQL_Compression_Chunks_to_Packets_Converter *compress_chunks_to_packets;
	MySQL_Compression_Packets_to_Chunks_Converter *compress_packets_to_chunks;


	// Data read from the raw socket, organized as a buffer which contains
	// concatenated pieces of packets. It might contain several different
	// packets or just a piece of a bigger one.
	raw_bytes_queue_t queueIN;

	// Data to be written to the raw socket, organized as a buffer which
	// contains concatenated pieces of packets. It might contain several
	// different packets or just a piece of a bigger one.
	raw_bytes_queue_t queueOUT;

	// The current packet that is processed as incoming.
	//
	// We need this as an intermediate step because the MySQL protocol
	// limits packets to 16MB (because of 3 bytes being allocated to size
	// in the header). Clients are expected to split big packets (such as
	// a big insert, for example) into smaller ones, but ProxySQL needs to
	// analyze such queries for rewrite. Thus, we need to merge the packets
	// in-memory before actually forwarding them.
	// whether a query rewrite is necessary, we
	PtrSize_t current_incoming_packet;

	// Full packets that have been read from the socket, ready to be
	// processed by MySQL_Session. The routine that converts the raw
	// bytes to these packets is buffer_to_packets().
	PtrSizeArray *incoming_packets;

	// Full packets that have been written by MySQL_Session, that will
	// end up being converted to buffers and written to the socket.
	// The routine that does the conversion is packets_to_buffer().
	PtrSizeArray *outgoing_packets;

	// Sometimes, packets need to be put on hold as we are trying to
	// send packets to a backend to which we're not connected to yet.
	// Then, the packets to be sent are moved in here, and then the
	// handshake packets are put into outgoing_packets in order to make
	// sure that an application-level connection is established first.
	PtrSizeArray *outgoing_pending_packets;

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
	int packets_to_buffer();
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
	void move_from_OUTpending_to_OUT();
	unsigned char * resultset2buffer(bool);
	void buffer2resultset(unsigned char *, unsigned int);

	bool is_frontend();
	bool is_backend();
	bool is_listener();
	bool has_incoming_packets();
	void dequeue_incoming_packet(PtrSize_t *pkt);
	void enqueue_outgoing_packet(void *packet, unsigned int size);
	void enqueue_outgoing_packets_from_resultset(PtrSizeArray *);
	void enqueue_outgoing_packets_from_serialized_resultset(unsigned char *, unsigned int);
	void cache_resultset(unsigned char*, unsigned int, unsigned int);
	bool outgoing_data_available();
	unsigned int move_data_from_packet_to_buffer();
	void enable_connection_compression_if_needed();
};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
