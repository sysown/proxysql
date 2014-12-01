#include "proxysql.h"


static void mysql_data_stream_setfd(mysql_data_stream_t *myds, int fd) {
	myds->fd=fd;
}

void mysql_data_stream_delete(mysql_data_stream_t *my) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	queue_t *q=NULL;
	q=&my->input.queue;
	queue_destroy(q);
	q=&my->output.queue;
	queue_destroy(q);

	pkt *p;
/*
	if(my->input.mypkt) {
		if(my->input.mypkt->data)
		g_slice_free1(my->input.mypkt->length, my->input.mypkt->data);
		mypkt_free(my->input.mypkt,my->sess);
	}

	if(my->output.mypkt) {
		if(my->output.mypkt->data)
		g_slice_free1(my->output.mypkt->length, my->output.mypkt->data);
//		g_slice_free1(sizeof(pkt), my->output.mypkt);
	}
*/
	if(my->input.mypkt) {
		l_free(my->input.mypkt->length, my->input.mypkt->data);
	}
	if(my->output.mypkt) {
		l_free(my->output.mypkt->length, my->output.mypkt->data);
	}
	while (my->input.pkts->len) {
		p=l_ptr_array_remove_index(my->input.pkts, 0);
		mypkt_free1(p);
	}
	while (my->output.pkts->len) {
		p=l_ptr_array_remove_index(my->output.pkts, 0);
		mypkt_free1(p);
	}


	l_ptr_array_free1(my->input.pkts);
	l_ptr_array_free1(my->output.pkts);
	g_slice_free1(sizeof(mysql_data_stream_t),my);
	//stack_free(my,&myds_pool);
}

static void shut_soft(mysql_data_stream_t *myds) {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown soft %d\n", myds->fd);
	myds->active=FALSE;
	myds->sess->net_failure=1;
}

static void shut_hard(mysql_data_stream_t *myds) {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown hard %d\n", myds->fd);
	if (myds->fd >= 0) {
		shutdown(myds->fd, SHUT_RDWR);
		close(myds->fd);
		myds->fd = -1;
	}
}


static int buffer2array(mysql_data_stream_t *myds) {
	int ret=0;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	queue_t *qin = &myds->input.queue;
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "BEGIN : bytes in buffer = %d\n", queue_data(qin));
	if (queue_data(qin)==0) return ret;
	if (myds->input.mypkt==NULL) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Allocating a new packet\n");
		myds->input.mypkt=mypkt_alloc();
		//myds->input.mypkt=mypkt_alloc(myds->sess);
		myds->input.mypkt->length=0;
	}	
	if ((myds->input.mypkt->length==0) && queue_data(qin)<sizeof(mysql_hdr)) {
		queue_zero(qin);
	}
	if ((myds->input.mypkt->length==0) && queue_data(qin)>=sizeof(mysql_hdr)) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new packet\n");
		memcpy(&myds->input.hdr,queue_r_ptr(qin),sizeof(mysql_hdr));
		queue_r(qin,sizeof(mysql_hdr));
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Allocating %d bytes for a new packet\n", myds->input.hdr.pkt_length+sizeof(mysql_hdr));
		myds->input.mypkt->length=myds->input.hdr.pkt_length+sizeof(mysql_hdr);
		//myds->input.mypkt->data=l_alloc(thrLD->sfp, myds->input.mypkt->length);
		myds->input.mypkt->data=l_alloc(myds->input.mypkt->length);
		//myds->input.mypkt->data=g_slice_alloc(myds->input.mypkt->length);

		//void *__a=myds->input.mypkt->data;
		//void *__b=&myds->input.hdr;
		//MEM_COPY_FWD(__a, __b, sizeof(mysql_hdr));
		MEM_COPY_FWD(myds->input.mypkt->data, &myds->input.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
		//memcpy(myds->input.mypkt->data, &myds->input.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
		myds->input.partial=sizeof(mysql_hdr);
		ret+=sizeof(mysql_hdr);
	}
	if ((myds->input.mypkt->length>0) && queue_data(qin)) {
		int b= ( queue_data(qin) > (myds->input.mypkt->length-myds->input.partial) ? myds->input.mypkt->length-myds->input.partial : queue_data(qin) );
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied %d bytes into packet\n", b);
		memcpy(myds->input.mypkt->data + myds->input.partial, queue_r_ptr(qin),b);
		queue_r(qin,b);			
		myds->input.partial+=b;
		ret+=b;
	}
	if ((myds->input.mypkt->length>0) && (myds->input.mypkt->length==myds->input.partial) ) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Packet (%d bytes) completely read, moving into input.pkts array\n", myds->input.mypkt->length);
		l_ptr_array_add(myds->input.pkts, myds->input.mypkt);
		myds->pkts_recv+=1;
		myds->input.mypkt=NULL;
	}
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "END : bytes in buffer = %d\n", queue_data(qin));
	return ret;
}

static int array2buffer(mysql_data_stream_t *myds) {
	int ret=0;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	queue_t *qout = &myds->output.queue;
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Entering array2buffer with partial_send = %d and queue_available = %d\n", myds->output.partial, queue_available(qout));
	if (queue_available(qout)==0) return ret;	// no space to write
	if (myds->output.partial==0) { // read a new packet
		if (myds->output.pkts->len) {
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "%s\n", "Removing a packet from array");
			if (myds->output.mypkt) {
				//mypkt_free0(myds->output.mypkt);
				mypkt_free1(myds->output.mypkt);
				myds->output.mypkt=NULL;
			}
			myds->output.mypkt=l_ptr_array_remove_index(myds->output.pkts, 0);
		} else {
			return ret;
		}
	}
	int b= ( queue_available(qout) > (myds->output.mypkt->length - myds->output.partial) ? (myds->output.mypkt->length - myds->output.partial) : queue_available(qout) );
	memcpy(queue_w_ptr(qout), myds->output.mypkt->data + myds->output.partial, b);
	queue_w(qout,b);	
	proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied %d bytes into send buffer\n", b);
	myds->output.partial+=b;
	ret=b;
	if (myds->output.partial==myds->output.mypkt->length) {
		//g_slice_free1(myds->output.mypkt->length, myds->output.mypkt->data);
		//l_free(thrLD->sfp,myds->output.mypkt->length, myds->output.mypkt->data);
		if (myds->output.mypkt) {
			//l_free(myds->output.mypkt->length, myds->output.mypkt->data);
			mypkt_free1(myds->output.mypkt);
			myds->output.mypkt=NULL;
		}
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Packet completely written into send buffer\n");
		myds->output.partial=0;
		myds->pkts_sent+=1;
	}
	return ret;
}

static int read_from_net(mysql_data_stream_t *myds) {
	int r;
	queue_t *q=&myds->input.queue;
	int s=queue_available(q);
	r = recv(myds->fd, queue_w_ptr(q), s, 0);
	proxy_debug(PROXY_DEBUG_NET, 5, "read %d bytes from fd %d into a buffer of %d bytes free\n", r, myds->fd, s);
	if (r < 1) {
//		if (r==-1) {
		myds->shut_soft(myds);
//		} //else { printf("%d\n",errno); }
//		if ((r==0) && (!errno)) { mysql_data_stream_shut_soft(myds); }
	}
	else {
		queue_w(q,r);
		myds->bytes_info.bytes_recv+=r;
		if (myds->mybe) {
			 __sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_recv,r);
		}
	}
	return r;	
}

static int write_to_net(mysql_data_stream_t *myds) {
	int r=0;
	queue_t *q=&myds->output.queue;
//	r = write(myds->fd, queue_r_ptr(&myds->output.queue), queue_data(&myds->output.queue));
	int s = queue_data(q);
	if (s==0) return 0;
	r = send(myds->fd, queue_r_ptr(q), s, 0);
	proxy_debug(PROXY_DEBUG_NET, 5, "wrote %d bytes to fd %d from a buffer with %d bytes of data\n", r, myds->fd, s);
	if (r < 0) {
		myds->shut_soft(myds);
	}
	else {
		queue_r(q,r);
		myds->bytes_info.bytes_sent+=r;
		if (myds->mybe) {
			 __sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_sent,r);
		}
	}
	return r;
}




mysql_data_stream_t * mysql_data_stream_new(mysql_session_t *sess, mysql_backend_t *mybe) {
	mysql_data_stream_t *my=g_slice_new(mysql_data_stream_t);
//	mysql_data_stream_t *my=stack_alloc(&myds_pool);
	my->mybe=mybe;
	if (mybe) {
		__sync_fetch_and_add(&mybe->mshge->connections_created,1);
		__sync_fetch_and_add(&mybe->mshge->connections_active,1);
	}
	my->bytes_info.bytes_recv=0;
	my->bytes_info.bytes_sent=0;
	my->pkts_recv=0;
	my->pkts_sent=0;
	queue_t *q=NULL;
	//pthread_mutex_lock(&conn_queue_pool.mutex);
	q=&my->input.queue;
	queue_init(q,glovars.net_buffer_size);
	q=&my->output.queue;
	queue_init(q,glovars.net_buffer_size);
	//pthread_mutex_unlock(&conn_queue_pool.mutex);
	my->input.pkts=l_ptr_array_new();
	my->output.pkts=l_ptr_array_new();
	my->input.mypkt=NULL;
	my->output.mypkt=NULL;
	my->input.partial=0;
	my->output.partial=0;
//	my->fd=fd;
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
	return my;
}


