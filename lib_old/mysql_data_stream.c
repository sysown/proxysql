#include "proxysql.h"
/* create a new mysql_data_stream
 * if mybe is not NULL , the backend is configure
 * fd representw the socket
 */
mysql_data_stream_t * mysql_data_stream_New(mysql_session_t *sess, int fd, mysql_backend_t *mybe) {
	mysql_data_stream_t *my=(mysql_data_stream_t *)malloc(sizeof(mysql_data_stream_t));
	my->mybe=mybe;
//	if (mybe) {
//	  __sync_fetch_and_add(&mybe->mshge->connections_created,1);
//	  __sync_fetch_and_add(&mybe->mshge->connections_active,1);
//	}
	// initialize bytes and packets counters to zero
	my->bytes_info.bytes_recv=0;
	my->bytes_info.bytes_sent=0;
	my->pkts_recv=0;
	my->pkts_sent=0;
	my->evbIN=evbuffer_new();
	my->evbOUT=evbuffer_new();

	//queue_t *q=NULL;
	//pthread_mutex_lock(&conn_queue_pool.mutex);
	//q=&my->input.queue;
	//queue_init(q,glovars.net_buffer_size);
	//q=&my->output.queue;
	//queue_init(q,glovars.net_buffer_size);
	//pthread_mutex_unlock(&conn_queue_pool.mutex);
	//my->input.pkts=l_ptr_array_new();
	//my->output.pkts=l_ptr_array_new();
	//my->input.mypkt=NULL;
	//my->output.mypkt=NULL;
	//my->input.partial=0;
	//my->output.partial=0;
	if (fd>0) {
	}
	my->fd=fd;
/*
	my->active_transaction=0;
	my->active=TRUE;
	my->sess=sess;
	my->shut_soft = shut_soft;
	my->shut_hard = shut_hard;
	my->array2buffer = array2buffer;
	my->buffer2array = buffer2array;
	my->read_from_net = read_from_net;
	my->write_to_net = write_to_net;
	my->setfd=mysql_data_stream_setfd;
*/
	return my;
}

