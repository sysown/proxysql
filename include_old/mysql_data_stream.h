#ifndef __CLASS_MYSQL_DATA_STREAM_H
#define __CLASS_MYSQL_DATA_STREAM_H

#include "proxysql.h"
#include "cpp.h"


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
	public:
	int listener;
	MySQL_Session *sess;  // pointer to the session using this data stream
	MySQL_Backend *mybe;  // if this is a connection to a mysql server, this points to a backend structure
	uint64_t pkts_recv; // counter of received packets
	uint64_t pkts_sent; // counter of sent packets
	bytes_stats_t bytes_info; // bytes statistics
	int fd; // file descriptor


	int epollfd;
	struct epoll_event ev; //struct sent to epoll. ev.events defines the input events, while ev.data.ptr points to this MySQL_Data_Stream
	struct epoll_event *rev; // pointer to returned events

	struct evbuffer *evbIN;
	struct evbuffer *evbOUT;
	GQueue *queueIN;
	GQueue *queueOUT;
	GPtrArray *QarrayIN;
	GPtrArray *QarrayOUT;
  //mysql_uni_ds_t input;
  //mysql_uni_ds_t output;
	int active_transaction; // 1 if there is an active transaction
	int active; // data stream is active. If not, shutdown+close needs to be called
	int status; // status . FIXME: make it a ORable variable

	MySQL_Data_Stream();
	~MySQL_Data_Stream();

	void init();	// initialize the data stream
	void shut_soft();
	void shut_hard();
	int read_from_net();
	int write_to_net();
	int write_to_net_epoll();

	void set_epollout();

	int read_pkts();
	int write_pkts();

//	void create_databuffer(mysql_data_buffer_t *, unsigned int);
//	void destroy_databuffer(mysql_data_buffer_t *);


};
#endif /* __CLASS_MYSQL_DATA_STREAM_H */
