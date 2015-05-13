#include "proxysql.h"
#include "cpp.h"
#include <zlib.h>
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif

#include <stdio.h>

extern Query_Cache *GloQC;

#ifdef DEBUG
static void __dump_pkt(const char *func, unsigned char *_ptr, unsigned int len) {

	if (GloVars.global.gdbg==0) return;
	if (GloVars.global.gdbg_lvl[PROXY_DEBUG_PKT_ARRAY].verbosity < 8 ) return;
	unsigned int i;
	fprintf(stderr,"DUMP %d bytes FROM %s\n", len, func);
	for(i = 0; i < len; i++) {
		if(isprint(_ptr[i])) fprintf(stderr,"%c", _ptr[i]); else fprintf(stderr,".");
		if (i>0 && (i%16==15 || i==len-1)) {
			unsigned int j;
			if (i%16!=15) {
				j=15-i%16;
				while (j--) fprintf(stderr," ");
			}
			fprintf(stderr," --- ");
			for (j=(i==len-1 ? ((int)(i/16))*16 : i-15 ) ; j<=i; j++) {
				fprintf(stderr,"%02x ", _ptr[j]);
			}
			fprintf(stderr,"\n");
		}
   }
	fprintf(stderr,"\n\n");
}

static void __dump_pkt_to_file(const char *func, unsigned char *_ptr, unsigned int len) {
	if (GloVars.global.dump_packets_file == NULL) {
		return;
	}

	fprintf(GloVars.global.dump_packets_fd, "DUMP %d bytes FROM %s\n", len, func);

	if (GloVars.global.dump_packets_truncate != -1 && len > GloVars.global.dump_packets_truncate) {
		len = GloVars.global.dump_packets_truncate;
	}

	unsigned int i;

	for(i = 0; i < len; i++) {
		if(isprint(_ptr[i])) fprintf(GloVars.global.dump_packets_fd,"%c", _ptr[i]); else fprintf(GloVars.global.dump_packets_fd,".");
		if (i>0 && (i%16==15 || i==len-1)) {
			unsigned int j;
			if (i%16!=15) {
				j=15-i%16;
				while (j--) fprintf(GloVars.global.dump_packets_fd," ");
			}
			fprintf(GloVars.global.dump_packets_fd," --- ");
			for (j=(i==len-1 ? ((int)(i/16))*16 : i-15 ) ; j<=i; j++) {
				fprintf(GloVars.global.dump_packets_fd,"%02x ", _ptr[j]);
			}
			fprintf(GloVars.global.dump_packets_fd,"\n");
		}
	}
	fprintf(GloVars.global.dump_packets_fd,"\n\n");
	fflush(GloVars.global.dump_packets_fd);
}
#endif

MySQL_Compression_Chunks_to_Packets_Converter::MySQL_Compression_Chunks_to_Packets_Converter() {
	packet_queue = new PtrSizeArray();
	bytes_so_far = 0;
}

MySQL_Compression_Chunks_to_Packets_Converter::~MySQL_Compression_Chunks_to_Packets_Converter() {
	while (packet_queue->len > 0) {
		PtrSize_t packet;
		packet_queue->remove_index(0, &packet);
		l_free(packet.size, packet.ptr);
	}
	delete packet_queue;
}

void MySQL_Compression_Chunks_to_Packets_Converter::init_packet(mysql_hdr *header) {
	packet.size = header->pkt_length + sizeof(mysql_hdr);
	packet.ptr = l_alloc(packet.size);
	memcpy(packet.ptr, header, sizeof(mysql_hdr));
	bytes_so_far = sizeof(mysql_hdr);
}

void MySQL_Compression_Chunks_to_Packets_Converter::add_bytes_to_packet(unsigned int size,
																		void *bytes) {
	memcpy((unsigned char*)packet.ptr + bytes_so_far, bytes, size);
	bytes_so_far += size;
	if (bytes_so_far == packet.size) {
		packet_queue->add(packet.ptr, packet.size);
		packet.ptr = NULL;
		packet.size = 0;
		bytes_so_far = 0;
	}
}

PtrSize_t MySQL_Compression_Chunks_to_Packets_Converter::get_packet() {
	PtrSize_t result;
	packet_queue->remove_index(0, &result);
	// Note that it's okay to return "result", because it will be copied when
	// returned, and not returned as a reference.
	return result;
}

bool MySQL_Compression_Chunks_to_Packets_Converter::has_packets() {
	return packet_queue->len > 0;
}

void MySQL_Compression_Chunks_to_Packets_Converter::ingest_chunk(
										unsigned int size, void *raw_chunk) {
	mysql_hdr header;
	unsigned char* chunk = (unsigned char*) raw_chunk;
	unsigned char* uncompressed_chunk;
	// Sorry for using this weird data-type, but we need to be compatible with
	// zLib :-)
	uLongf uncompressed_chunk_size = 0, chunk_bytes_processed = 0;
	bool was_compressed = false;

	// Part 1 of the processing: uncompress the content in the compressed packet
	// which is in fact a chunk. There are 2 main cases.
	// 
	// First case: the length of the uncompressed payload is 0 (which means that
	// the data is not compressed at all). This is especially true for small
	// packets, where it doesn't pay off to compress things.
	//
	// Second case: the length of the uncompressed payload is non-0, which is
	// when data is compressed using zlib.
	uncompressed_chunk_size = chunk[6];
	uncompressed_chunk_size *= 256;
	uncompressed_chunk_size += chunk[5];
	uncompressed_chunk_size *= 256;
	uncompressed_chunk_size += chunk[4];

	// 0 means that the data is not compressed at all
	if (uncompressed_chunk_size != 0) {
		uncompressed_chunk = (unsigned char*)l_alloc(uncompressed_chunk_size);
		int rc=uncompress((Bytef*)uncompressed_chunk,
						  (uLongf*)&uncompressed_chunk_size,
						  chunk+7,
						  size-7);
		assert(rc==Z_OK);
		was_compressed = true;
	} else {
		uncompressed_chunk_size = size - 7;
		uncompressed_chunk = chunk + 7;
	}

	// Part 2 of the processing begins here: once we have the uncompressed
	// content, see how that contributes to the current packet we were building.
	// Theoretically, we can have both full packets compressed in the payload
	// (and even more than one packet, in the case of a resultset), and also
	// incomplete pieces of a packet.
	while (chunk_bytes_processed < uncompressed_chunk_size) {
		// If the current packet was not started at all, we should expect to
		// read a MySQL packet header from the buffer, which will jumpstart
		// with reading the entire packet in one or more steps.
		if (bytes_so_far == 0) {
			// TODO(andrei): sanity check that there is at least room for a
			// MySQL header to be read in here
			memcpy(&header,
				   uncompressed_chunk + chunk_bytes_processed,
				   sizeof(mysql_hdr));
			init_packet(&header);
			chunk_bytes_processed += sizeof(mysql_hdr);
		// If the current packet is already started, it means that we will
		// find the remainder of the packet (or part of it) in the current
		// chunk. So we should start reading payload bytes directly.
		} else if (bytes_so_far < packet.size) {
			// First, we have to figure out how many bytes to read: we cannot
			// exceed the current packet, nor the uncompressed chunk.
			unsigned int remaining_chunk, remaining_packet, bytes_to_copy;
			remaining_chunk = uncompressed_chunk_size - chunk_bytes_processed;
			remaining_packet = packet.size - bytes_so_far;
			bytes_to_copy = MIN(remaining_chunk, remaining_packet);
			add_bytes_to_packet(bytes_to_copy,
								uncompressed_chunk + chunk_bytes_processed);
			chunk_bytes_processed += bytes_to_copy;
		}
	}

	if (was_compressed) {
		l_free(uncompressed_chunk_size, uncompressed_chunk);
	}

}

MySQL_Compression_Packets_to_Chunks_Converter::MySQL_Compression_Packets_to_Chunks_Converter() {
	chunk_queue = new PtrSizeArray();
	bytes_so_far = 0;
	packets_in_chunk = 0;
}

MySQL_Compression_Packets_to_Chunks_Converter::~MySQL_Compression_Packets_to_Chunks_Converter() {
	while (chunk_queue->len > 0) {
		PtrSize_t chunk;
		chunk_queue->remove_index(0, &chunk);
		l_free(chunk.size, chunk.ptr);
	}
	delete chunk_queue;
}

void MySQL_Compression_Packets_to_Chunks_Converter::init_chunk() {
	// We initialize the buffer and we skip the first 4 bytes, which represent
	// the header. We will copy the header at the end, before moving the current
	// chunk to chunk_queue, because we do not know yet what the dimension of
	// the chunk will be. 
	chunk.size = MYSQL_PROTOCOL_MAX_COMPRESSED_CHUNK_SIZE;
	chunk.ptr = l_alloc(chunk.size);
	bytes_so_far = sizeof(mysql_hdr);
}

void MySQL_Compression_Packets_to_Chunks_Converter::add_bytes_to_chunk(
										unsigned int size, void *bytes) {
	memcpy((unsigned char*)chunk.ptr + bytes_so_far, bytes, size);
	bytes_so_far += size;
	if (bytes_so_far == chunk.size) {
		flush();
	}
}

void MySQL_Compression_Packets_to_Chunks_Converter::flush() {
	if (bytes_so_far == 0) {
		return;
	}

	mysql_hdr header;
	uLongf destLen = bytes_so_far + bytes_so_far / 5 + 12;
	Bytef *dest = (Bytef*) malloc(destLen);
	unsigned int size;
	unsigned char *compressed_packet;

	// Finally copy the header to the chunk before compressing it, now
	// that we know how many bytes it will contain. The packet ID will be 0.
	header.pkt_length = bytes_so_far;
	memcpy(chunk.ptr, &header, sizeof(mysql_hdr));
	int rc = compress(dest, &destLen, (Bytef*)chunk.ptr + sizeof(mysql_hdr), bytes_so_far - sizeof(mysql_hdr));
	assert(rc == Z_OK);

	size = destLen + sizeof(mysql_hdr) + sizeof(mysql_hdr) - 1;
	compressed_packet = (unsigned char*) l_alloc(size);
	/// header.pkt_length = bytes_so_far - 4;
	header.pkt_length = destLen;
	// This is fixed before actually writing the packet to the socket
	header.pkt_id = 0; 

	// Build the compressed packet header
	// First, the 4 bytes comprised of:
	// - 3 bytes compressed payload length
	// - 1 byte compressed packet id (incremented in similar fashion to
	//   normal packet id)
	memcpy(compressed_packet, &header, sizeof(mysql_hdr));
	// Then, bytes 5-7 which are the uncompressed length of the payload
	// (useful in order to know how much memory to allocate when decompressing
	// the buffer).
	/// header.pkt_length = 0;
	header.pkt_length = bytes_so_far;
	memcpy(compressed_packet + sizeof(mysql_hdr), &header, 3);

	// Now, we can finally copy the compressed content
	// Note that this is one extra copy of the compressed data, from the 
	// "dest" buffer to here. The rationale is that packets' memory is
	// managed using l_alloc/l_free, while the temporary buffer "dest" is
	// managed using the normal malloc/free (in order to make sure that
	// zlib doesn't do anything strange with it).
	/// memcpy(compressed_packet + 7, (unsigned char*)chunk.ptr + 4, bytes_so_far - 4);
	memcpy(compressed_packet + 7, dest, destLen);

	chunk_queue->add(compressed_packet, size);

	// Free the buffer where the compression result was stored
	free(dest);
	// Free the current chunk's memory
	l_free(chunk.size, chunk.ptr);

	// Mark the chunk as pristine
	chunk.size = 0;
	chunk.ptr = NULL;

	// Mark the fact that there has been no byte added to the chunk so far
	bytes_so_far = 0;
	packets_in_chunk = 0;
}

void MySQL_Compression_Packets_to_Chunks_Converter::ingest_packet(
										unsigned int size, void *raw_packet) {
	unsigned char *packet = (unsigned char*) raw_packet;
	unsigned int packet_bytes_processed = 0;

	__dump_pkt_to_file("INGEST", (unsigned char*)raw_packet, size);

	while (packet_bytes_processed < size) {
		if (bytes_so_far == 0) {
			init_chunk();
		} else {
			unsigned int remaining_chunk, remaining_packet, bytes_to_copy;
			remaining_chunk = chunk.size - bytes_so_far;
			remaining_packet = size - packet_bytes_processed;
			bytes_to_copy = MIN(remaining_chunk, remaining_packet);
			add_bytes_to_chunk(bytes_to_copy, packet + packet_bytes_processed);
			packet_bytes_processed += bytes_to_copy;
		}
	}

	packets_in_chunk++;
}

PtrSize_t MySQL_Compression_Packets_to_Chunks_Converter::get_chunk() {
	PtrSize_t result;
	chunk_queue->remove_index(0, &result);
	return result;
}

bool MySQL_Compression_Packets_to_Chunks_Converter::has_chunks() {
	return chunk_queue->len > 0;
}

void * MySQL_Data_Stream::operator new(size_t size) {
  return l_alloc(size);
}

void MySQL_Data_Stream::operator delete(void *ptr) {
  l_free(sizeof(MySQL_Data_Stream),ptr);
}

// Constructor
MySQL_Data_Stream::MySQL_Data_Stream() {
	//_pollfd=NULL;
	bytes_info.bytes_recv=0;
	bytes_info.bytes_sent=0;
	pkts_recv=0;
	pkts_sent=0;

	timeout=0;
	connect_tries=0;
	poll_fds_idx=-1;
	resultset_length=0;
	query_SQL=NULL;

	current_incoming_packet.ptr=NULL;
	current_incoming_packet.size=0;
	incoming_packets=NULL;
	outgoing_packets=NULL;
	outgoing_pending_packets=NULL;

	resultset=NULL;
	queue_init(queueIN,QUEUE_T_DEFAULT_SIZE);
	queue_init(queueOUT,QUEUE_T_DEFAULT_SIZE);
	//listener=0;
	mybe=NULL;
	active=TRUE;
	mypolls=NULL;
	myconn=NULL;	// 20141011
	//myconn = new MySQL_Connection(); // 20141011
	//myconn->myds=this; // 20141011
	DSS=STATE_NOT_CONNECTED;
	encrypted=false;
	ssl=NULL;
	net_failure=false;
//	ssl_ctx=NULL;
	compress_chunks_to_packets = new MySQL_Compression_Chunks_to_Packets_Converter();
}

// Destructor
MySQL_Data_Stream::~MySQL_Data_Stream() {

	queue_destroy(queueIN);
	queue_destroy(queueOUT);

	proxy_debug(PROXY_DEBUG_NET,1, "Shutdown Data Stream. Session=%p, DataStream=%p\n" , sess, this);
	PtrSize_t pkt;
	if (incoming_packets) {
		while (incoming_packets->len) {
			incoming_packets->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete incoming_packets;
	}
	if (outgoing_packets) {
		while (outgoing_packets->len) {
			outgoing_packets->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete outgoing_packets;
	}
	if (outgoing_pending_packets) {
		while (outgoing_pending_packets->len) {
			outgoing_pending_packets->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete outgoing_pending_packets;
	}
	if (resultset) {
		while (resultset->len) {
			resultset->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
	delete resultset;
	}
	if (mypolls) mypolls->remove_index_fast(poll_fds_idx);
	if (fd>0) {
		if (myconn==NULL || myconn->reusable==false) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p , MYDS:%p , MySQL_Connection %p %s: shutdown socket\n", sess, this, myconn, (myconn ? "not reusable" : "is empty"));
			shut_hard();
//		shutdown(fd,SHUT_RDWR);
//		close(fd);
		}
	}
	if ( (myconn) && (myds_type==MYDS_FRONTEND) ) { delete myconn; myconn=NULL; }
	if (encrypted) {
		if (ssl) SSL_free(ssl);
//		if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	}

	if (compress_chunks_to_packets) {
		delete compress_chunks_to_packets;
	}
	}
}

// this function initializes a MySQL_Data_Stream 
void MySQL_Data_Stream::init() {
	if (myds_type!=MYDS_LISTENER) {
		proxy_debug(PROXY_DEBUG_NET,1, "Init Data Stream. Session=%p, DataStream=%p -- type %d\n" , sess, this, myds_type);
		if (incoming_packets==NULL) incoming_packets = new PtrSizeArray();
		if (outgoing_packets==NULL) outgoing_packets= new PtrSizeArray();
		if (outgoing_pending_packets==NULL) outgoing_pending_packets= new PtrSizeArray();
		if (resultset==NULL) resultset = new PtrSizeArray();
	}
}

// this function initializes a MySQL_Data_Stream with arguments
void MySQL_Data_Stream::init(enum MySQL_DS_type _type, MySQL_Session *_sess, int _fd) {
	myds_type=_type;
	sess=_sess;
	init();
	fd=_fd;
	proxy_debug(PROXY_DEBUG_NET,1, "Initialized Data Stream. Session=%p, DataStream=%p, type=%d, fd=%d, myconn=%p\n" , sess, this, myds_type, fd, myconn);
	//if (myconn==NULL) myconn = new MySQL_Connection();
	if (myconn) myconn->fd=fd;
}


// Soft shutdown of socket : it only deactivate the data stream
// TODO: should check the status of the data stream, and identify if it is safe to reconnect or if the session should be destroyed
void MySQL_Data_Stream::shut_soft() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown soft fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	active=FALSE;
	set_net_failure();
	//if (sess) sess->net_failure=1;
}

// Hard shutdown of socket
void MySQL_Data_Stream::shut_hard() {
	proxy_debug(PROXY_DEBUG_NET, 4, "Shutdown hard fd=%d. Session=%p, DataStream=%p\n", fd, sess, this);
	set_net_failure();
	if (fd >= 0) {
		shutdown(fd, SHUT_RDWR);
		close(fd);
		fd = -1;
	}
}

void MySQL_Data_Stream::check_data_flow() {
	if ( (incoming_packets->len || queue_data(queueIN) ) && ( outgoing_packets->len || queue_data(queueOUT) ) ){
		// there is data at both sides of the data stream: this is considered a fatal error
		proxy_error("Session=%p, DataStream=%p -- Data at both ends of a MySQL data stream: IN <%d bytes %d packets> , OUT <%d bytes %d packets>\n", sess, this, incoming_packets->len , queue_data(queueIN) , outgoing_packets->len , queue_data(queueOUT));
		shut_soft();
	}
	//if ((myds_type==MYDS_BACKEND) && (myconn->myconn.net.fd==0) && (revents & POLLOUT)) {
	if ((myds_type==MYDS_BACKEND) && myconn && (myconn->fd==0) && (revents & POLLOUT)) {
		int rc;
		int error;
		socklen_t len = sizeof(error);
		rc=getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
		assert(rc==0);
		if (error==0) {
			//myconn->myconn.net.fd=fd; // connect succeeded
			myconn->fd=fd; // connect succeeded
		} else {
			errno=error;
			perror("check_data_flow");
			shut_soft();
		}
	}
}


int MySQL_Data_Stream::read_from_net() {
	if ((revents & POLLIN)==0) return 0;
	int r;
	int s=queue_available(queueIN);
	r = ( encrypted ? SSL_read (ssl, queue_w_ptr(queueIN), s) : recv(fd, queue_w_ptr(queueIN), s, 0) );
	proxy_debug(PROXY_DEBUG_NET, 5, "read %d bytes from fd %d into a buffer of %d bytes free\n", r, fd, s);
	//proxy_error("read %d bytes from fd %d into a buffer of %d bytes free\n", r, fd, s);
	if (r < 1) {
		if (encrypted==false) {
			if (r==0 || (r==-1 && errno != EINTR && errno != EAGAIN)) {
				shut_soft();
			}
		} else {
			int ssl_ret=SSL_get_error(ssl, r);
			if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
		}
	} else {
		queue_w(queueIN,r);
		bytes_info.bytes_recv+=r;
		if (mypolls) mypolls->last_recv[poll_fds_idx]=sess->thread->curtime;
	}
	return r;
}

int MySQL_Data_Stream::write_to_net() {
    int bytes_io=0;
	int s = queue_data(queueOUT);
    if (s==0) return 0;
	VALGRIND_DISABLE_ERROR_REPORTING;
  //bytes_io = ( encrypted ? SSL_write (ssl, queue_r_ptr(queueOUT), s) : send(fd, queue_r_ptr(queueOUT), s, 0) );
	// splitting the ternary operation in IF condition for better readability 
	if (encrypted) {
		bytes_io = SSL_write (ssl, queue_r_ptr(queueOUT), s);
	} else {
		//bytes_io = send(fd, queue_r_ptr(queueOUT), s, 0);
		// fix on bug #183
		bytes_io = send(fd, queue_r_ptr(queueOUT), s, MSG_NOSIGNAL);
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	if (bytes_io < 0) {
		if (encrypted==false)	{
			shut_soft();
		} else {
			int ssl_ret=SSL_get_error(ssl, bytes_io);
			if (ssl_ret!=SSL_ERROR_WANT_READ && ssl_ret!=SSL_ERROR_WANT_WRITE) shut_soft();
		}
	} else {
		queue_r(queueOUT, bytes_io);
		if (mypolls) mypolls->last_sent[poll_fds_idx]=sess->thread->curtime;
		bytes_info.bytes_sent+=bytes_io;
		if (mybe) {
 		//	__sync_fetch_and_add(&myds->mybe->mshge->server_bytes.bytes_sent,r);
		}	
	}
	return bytes_io;
}

bool MySQL_Data_Stream::available_data_out() {
	int buflen=queue_data(queueOUT);
	if (buflen || outgoing_packets->len) {
		return true;
	}
	return false;
}

void MySQL_Data_Stream::set_pollout() {
	struct pollfd *_pollfd;
	_pollfd=&mypolls->fds[poll_fds_idx];
	if (available_data_out() || queueOUT.partial) {
		_pollfd->events = POLLIN | POLLOUT;
	} else {
		_pollfd->events = POLLIN;
	}
	//FIXME: moved
	//_pollfd->revents=0;
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p -- Setting poll events %d for FD %d\n", sess, this, _pollfd->events , fd);
}


int MySQL_Data_Stream::write_to_net_poll() {
	int rc=0;
	if (active==FALSE) return rc;	
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p --\n", sess, this);
	if (queue_data(queueOUT)) {
		if ((sess->admin==false)) {
			if (poll_fds_idx>-1 && (mypolls->fds[poll_fds_idx].revents & POLLOUT)) {
				if (net_failure==false)
					rc=write_to_net();
			}
		} else {
			rc=write_to_net();
		}
	}
	if (fd>0 && sess->admin==false) set_pollout();
	return rc;
}


int MySQL_Data_Stream::read_pkts() {
	{
		int rc=0;
    	int r=0;
    	while((r=buffer_to_packets())) rc+=r;
	    return rc;
	}
}


int MySQL_Data_Stream::buffer_to_packets() {
	int ret=0;
	if (queue_data(queueIN)==0) return ret;
	if ((queueIN.pkt.size==0) && queue_data(queueIN)<sizeof(mysql_hdr)) {
		queue_defrag(queueIN);
	}

/**/
	if (myconn->get_status_compression()==true) {
		if ((queueIN.pkt.size==0) && queue_data(queueIN)>=7) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new compressed packet\n");
 			memcpy(&queueIN.hdr,queue_r_ptr(queueIN), sizeof(mysql_hdr));
			queue_r(queueIN,sizeof(mysql_hdr));
			queueIN.pkt.size=queueIN.hdr.pkt_length+sizeof(mysql_hdr)+3;
			queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
			memcpy(queueIN.pkt.ptr, &queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
			memcpy((unsigned char *)queueIN.pkt.ptr+sizeof(mysql_hdr), queue_r_ptr(queueIN), 3); // copy 3 bytes, the length of the uncompressed payload
			queue_r(queueIN,3);
			queueIN.partial=7;
			mysql_hdr *_hdr;
			_hdr=(mysql_hdr *)queueIN.pkt.ptr;
			myconn->compression_pkt_id=_hdr->pkt_id;
			ret+=7;
		}
	} else {
/**/
		if ((queueIN.pkt.size==0) && queue_data(queueIN)>=sizeof(mysql_hdr)) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Reading the header of a new packet\n");
			memcpy(&queueIN.hdr,queue_r_ptr(queueIN),sizeof(mysql_hdr));
			queue_r(queueIN,sizeof(mysql_hdr));
			queueIN.pkt.size=queueIN.hdr.pkt_length+sizeof(mysql_hdr);
			queueIN.pkt.ptr=l_alloc(queueIN.pkt.size);
			memcpy(queueIN.pkt.ptr, &queueIN.hdr, sizeof(mysql_hdr)); // immediately copy the header into the packet
			queueIN.partial=sizeof(mysql_hdr);
			ret+=sizeof(mysql_hdr);
		}
	}
	if ((queueIN.pkt.size>0) && queue_data(queueIN)) {
		int b= ( queue_data(queueIN) > (queueIN.pkt.size - queueIN.partial) ? (queueIN.pkt.size - queueIN.partial) : queue_data(queueIN) );
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied %d bytes into packet\n", b);
		memcpy((unsigned char *)queueIN.pkt.ptr + queueIN.partial, queue_r_ptr(queueIN),b);
		queue_r(queueIN,b);
		queueIN.partial+=b;
		ret+=b;
	}
	if ((queueIN.pkt.size>0) && (queueIN.pkt.size==queueIN.partial) ) {
		if (myconn->get_status_compression()==true) {
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "Copied the whole compressed packet\n");

#ifdef DEBUG
			if (is_frontend()) {
				__dump_pkt_to_file("CLIENT_TO_PROXY_receive_incoming_packet__COMPRESSED", (unsigned char*)queueIN.pkt.ptr, queueIN.pkt.size);
			} else if (is_backend()) {
				__dump_pkt_to_file("SERVER_TO_PROXY_receive_incoming_packet__COMPRESSED", (unsigned char*)queueIN.pkt.ptr, queueIN.pkt.size);
			}
#endif

			compress_chunks_to_packets->ingest_chunk(queueIN.pkt.size,
													 queueIN.pkt.ptr);
			while (compress_chunks_to_packets->has_packets()) {
				PtrSize_t packet = compress_chunks_to_packets->get_packet();
				receive_incoming_packet(packet.ptr, packet.size);
			}
			
			pkts_recv++;
			l_free(queueIN.pkt.size,queueIN.pkt.ptr);
			queueIN.pkt.size=0;
			queueIN.pkt.ptr=NULL;
		} else {
			receive_incoming_packet(queueIN.pkt.ptr, queueIN.pkt.size);
			pkts_recv++;
			queueIN.pkt.size=0;
			queueIN.pkt.ptr=NULL;
		}
	}
	return ret;
}


void MySQL_Data_Stream::generate_compressed_packet() {
#define MAX_COMPRESSED_PACKET_SIZE	10*1024*1024
	unsigned int total_size=0;
	unsigned int i=0;
	PtrSize_t *p=NULL;
	while (i<outgoing_packets->len && total_size<MAX_COMPRESSED_PACKET_SIZE) {
		p=outgoing_packets->index(i);
		total_size+=p->size;
		if (i==0) {
			mysql_hdr hdr;
			memcpy(&hdr,p->ptr,sizeof(mysql_hdr));
			if (hdr.pkt_id==0) {
				myconn->compression_pkt_id=-1;
			}
		}
		i++;
	}
	if (i>=2) {
		// we successfully read at least 2 packets
		if (total_size>MAX_COMPRESSED_PACKET_SIZE) {
			// total_size is too big, we remove the last packet read
			total_size-=p->size;
		}
	}
	uLong sourceLen=total_size;
	Bytef *source=(Bytef *)l_alloc(total_size);
	uLongf destLen=total_size*120/100+12;
	Bytef *dest=(Bytef *)malloc(destLen);
	i=0;
	total_size=0;
	while (total_size<sourceLen) {
		PtrSize_t p2;
		outgoing_packets->remove_index(0,&p2);
		memcpy(source+total_size,p2.ptr,p2.size);
		//i++;
		total_size+=p2.size;
		l_free(p2.size,p2.ptr);
	}
	int rc=compress(dest, &destLen, source, sourceLen);
	assert(rc==Z_OK);
	l_free(total_size, source);
	queueOUT.pkt.size=destLen+7;
	queueOUT.pkt.ptr=l_alloc(queueOUT.pkt.size);
	mysql_hdr hdr;
	hdr.pkt_length=destLen;
	hdr.pkt_id=++myconn->compression_pkt_id;
	//hdr.pkt_id=1;
	memcpy((unsigned char *)queueOUT.pkt.ptr,&hdr,sizeof(mysql_hdr));
	hdr.pkt_length=total_size;
	memcpy((unsigned char *)queueOUT.pkt.ptr+4,&hdr,3);
	memcpy((unsigned char *)queueOUT.pkt.ptr+7,dest,destLen);
	free(dest);

#ifdef DEBUG
	if (is_frontend()) {
		__dump_pkt_to_file("PROXY_TO_CLIENT_enqueue_outgoing_packet__COMPRESSED", (unsigned char*)queueOUT.pkt.ptr, queueOUT.pkt.size);
	} else if (is_backend()) {
		__dump_pkt_to_file("PROXY_TO_SERVER_enqueue_outgoing_packet__COMPRESSED", (unsigned char*)queueOUT.pkt.ptr, queueOUT.pkt.size);
	}
#endif	
}


int MySQL_Data_Stream::packets_to_buffer() {
	/*
	 * Fills the output buffer with as many packets as possible (by dequeueing them
	 * from outgoing_packets, and writing them to the queueOUT buffer).
	 *
	 * Returns the total number of bytes written in the buffer.
	 *
	 * It stops writing to the buffer when the outgoing queue of packets is empty OR
	 * when the buffer is full.
	 */
	int ret=0;
	
	bool cont=true;
	while (cont) {
		// If there's no more space left in the buffer, it's time to return.
		if (queue_available(queueOUT)==0) return ret;

		// If the output buffer has no current packet attached to it (that is being written
		// to it), then we will dequeue a new packet and proceed to write it to the buffer.
		if (queueOUT.partial==0) {
			// If there are still outgoing packets to dequeue
			if (outgoing_packets->len) {
				proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Removing a packet from array\n", this);
				if (queueOUT.pkt.ptr) {
					l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
					queueOUT.pkt.ptr=NULL;
				}
				if (myconn->get_status_compression()==true) {
					proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Compression enabled\n", this);
					generate_compressed_packet();	// it is copied directly into queueOUT.pkt					
				} else {
					outgoing_packets->remove_index(0,&queueOUT.pkt);
					// this is a special case, needed because compression is enabled *after* the first OK
					if (DSS==STATE_CLIENT_AUTH_OK) {
						DSS=STATE_SLEEP;
						// enable compression
						if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
							if (myconn->options.compression_min_length) {
								myconn->set_status_compression(true);
							}
						} else {
							//explicitly disable compression
							myconn->options.compression_min_length=0;
							myconn->set_status_compression(false);
						}
					}
				}
#ifdef DEBUG
				{ __dump_pkt(__func__,(unsigned char *)queueOUT.pkt.ptr,queueOUT.pkt.size); }
#endif
			// Else, if there are no more packets to dequeue, our mission is done
			// and it's time to return.
			} else {
				cont=false;
				continue;
			}
		}

		// b is the number of bytes to be written to the buffer.
		//
		// It's either the remainder of the packet being currently processed (queueOUT.pkt)
		// or the remainder of the buffer (if the remainder of queueOUT.pkt is bigger).
		int b= ( queue_available(queueOUT) > (queueOUT.pkt.size - queueOUT.partial) ? (queueOUT.pkt.size - queueOUT.partial) : queue_available(queueOUT) );
		memcpy(queue_w_ptr(queueOUT), (unsigned char *)queueOUT.pkt.ptr + queueOUT.partial, b);
		queue_w(queueOUT,b);
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Copied %d bytes into send buffer\n", this, b);
		queueOUT.partial+=b;
		ret=b;
		if (queueOUT.partial==queueOUT.pkt.size) {
			if (queueOUT.pkt.ptr) {
				l_free(queueOUT.pkt.size,queueOUT.pkt.ptr);
				queueOUT.pkt.ptr=NULL;
			}
			proxy_debug(PROXY_DEBUG_PKT_ARRAY, 5, "DataStream: %p -- Packet completely written into send buffer\n", this);
			queueOUT.partial=0;
			pkts_sent+=1;
		}
	}
	return ret;
}

int MySQL_Data_Stream::myds_connect(char *address, int connect_port, int *pending_connect) {
	//assert(myconn==NULL);

	assert(myconn); // this assert() is to remove the next condition
	if (myconn==NULL) myconn= new MySQL_Connection(); // FIXME: why here? // 20141011 /// should be removed

	myconn->last_time_used=sess->thread->curtime;
	struct sockaddr_un u;
	struct sockaddr_in a;
	int s=0;
	int len=0;
	int rc=0;


	if (connect_port) {
		// TCP socket
		if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			close(s);
			return -1;
		}
		ioctl_FIONBIO(s, 1);
		memset(&a, 0, sizeof(a));
		a.sin_port = htons(connect_port);
		a.sin_family = AF_INET;

		if (!inet_aton(address, (struct in_addr *) &a.sin_addr.s_addr)) {
			perror("bad IP address format");
			close(s);
			return -1;
		}
	} else {
		// UNIX socket domain
		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			close(s);
			return -1;
		}
		ioctl_FIONBIO(s, 1);
		memset(u.sun_path,0,UNIX_PATH_MAX);
		u.sun_family = AF_UNIX;
		strncpy(u.sun_path, address, UNIX_PATH_MAX-1);
		len=strlen(u.sun_path)+sizeof(u.sun_family);
	}

	if (connect_port) {
		rc=connect(s, (struct sockaddr *) &a, sizeof(a));
		int arg_on=1;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
	} else {
		rc=connect(s, (struct sockaddr *) &u, len);
	}
	if (rc==-1) {
		if (errno!=EINPROGRESS) {
			perror("connect()");
			shutdown(s, SHUT_RDWR);
			close(s);
			return -1;
		}
		//*pending_connect=1;  // default
		//myconn->myconn.net.fd=s; // FIXME: why here? // 20141011
	} else {
		*pending_connect=0;
	}
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, old_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->myconn.net.fd, s);
	//myconn->myconn.net.fd=s;
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, new_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->myconn.net.fd, s);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, old_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	myconn->fd=s;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, new_mysql_net_fd=%d, fd=%d\n", this->sess, this, myconn->fd, s);
	return s;

}


void MySQL_Data_Stream::move_from_OUT_to_OUTpending() {
	unsigned int k;
	PtrSize_t pkt2;
	for (k=0; k<outgoing_packets->len;) {
		outgoing_packets->remove_index(0,&pkt2);
		outgoing_pending_packets->add(pkt2.ptr, pkt2.size);
	}
}

void MySQL_Data_Stream::move_from_OUTpending_to_OUT() {
	unsigned int k;
	PtrSize_t pkt2;
	for (k = 0; k < outgoing_pending_packets->len;) {
		outgoing_pending_packets->remove_index(0, &pkt2);
		__outgoing_packet(pkt2.ptr, pkt2.size);
	}
}

/*
int MySQL_Data_Stream::assign_mshge(unsigned int hid) {
	assert (myconn);
	return myconn->assign_mshge(hid);
}
*/

int MySQL_Data_Stream::assign_fd_from_mysql_conn() {
	assert(myconn);
	//proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->myconn.net.fd);
	//fd=myconn->myconn.net.fd;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p, oldFD=%d, newFD=%d\n", this->sess, this, fd, myconn->fd);
	fd=myconn->fd;
	return fd;
}

void MySQL_Data_Stream::unplug_backend() {
	DSS=STATE_NOT_INITIALIZED;
	myconn=NULL;
	myds_type=MYDS_BACKEND_NOT_CONNECTED;
  mypolls->remove_index_fast(poll_fds_idx);
  mypolls=NULL;
  fd=0;
}

void MySQL_Data_Stream::clean_net_failure() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p\n", this->sess, this);
	net_failure=false;
}

void MySQL_Data_Stream::set_net_failure() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d\n", this->sess, this, myds_type);
#ifdef DEBUG
	if (myds_type!=MYDS_FRONTEND) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p , myds_type:%d not frontend\n", this->sess, this, myds_type);
	}
#endif /* DEBUG */
	net_failure=true;
}

void MySQL_Data_Stream::setDSS_STATE_QUERY_SENT_NET() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, myds=%p\n", this->sess, this);
	DSS=STATE_QUERY_SENT_NET;
}

bool MySQL_Data_Stream::has_incoming_packets() {
	return incoming_packets->len > 0;
}

inline bool MySQL_Data_Stream::is_frontend() {
	return myds_type == MYDS_FRONTEND;
}

inline bool MySQL_Data_Stream::is_backend() {
	return (myds_type == MYDS_BACKEND) ||
	       (myds_type == MYDS_BACKEND_NOT_CONNECTED) ||
	       (myds_type == MYDS_BACKEND_PAUSE_CONNECT) ||
	       (myds_type == MYDS_BACKEND_FAILED_CONNECT);
}

inline bool MySQL_Data_Stream::is_listener() {
	return myds_type == MYDS_LISTENER;
}

void MySQL_Data_Stream::dequeue_incoming_packet(PtrSize_t *pkt) {
	incoming_packets->remove_index(0, pkt);
}

inline void MySQL_Data_Stream::__incoming_packet(void *packet, unsigned int size) {

#ifdef DEBUG
	if (myds_type == MYDS_FRONTEND) {
		__dump_pkt_to_file("CLIENT_TO_PROXY___incoming_packet", (unsigned char*)packet, size);
	} else if (myds_type != MYDS_LISTENER) {
		__dump_pkt_to_file("SERVER_TO_PROXY___incoming_packet", (unsigned char*)packet, size);
	}
#endif

	incoming_packets->add(packet, size);
}

inline void MySQL_Data_Stream::__outgoing_packet(void *packet, unsigned int size) {

#ifdef DEBUG
	if (myds_type == MYDS_FRONTEND) {
		__dump_pkt_to_file("PROXY_TO_CLIENT___outgoing_packet", (unsigned char*)packet, size);
	} else if (myds_type != MYDS_LISTENER) {
		__dump_pkt_to_file("PROXY_TO_SERVER___outgoing_packet", (unsigned char*)packet, size);
	}
#endif

	outgoing_packets->add(packet, size);
}

void MySQL_Data_Stream::receive_incoming_packet(void *packet, unsigned int size) {

#ifdef DEBUG
	if (myds_type == MYDS_FRONTEND) {
		__dump_pkt_to_file("CLIENT_TO_PROXY_receive_incoming_packet", (unsigned char*)packet, size);
	} else if (myds_type != MYDS_LISTENER) {
		__dump_pkt_to_file("SERVER_TO_PROXY_receive_incoming_packet", (unsigned char*)packet, size);
	}
#endif

	if (is_backend()) {
		__incoming_packet(packet, size);
		return;
	}

	unsigned int payload_size=size-sizeof(mysql_hdr);
	// If we're already building a concatenated packet in-memory, it means that this
	// packet should be part of it. When concatenating the packets, we must pay attention
	// to not include the header of subsequent packets (only the header of the first packet).
	// One immediate consequence is that code that operates on the packet should NEVER read
	// the length from the packet, but from the associated size field.
	//
	// FIXME: stop storing packet header together with payload, and this hack will no longer be
	// needed
	if (current_incoming_packet.ptr != NULL) {
		// Allocate a new buffer to hold the current packet, and the new piece that
		// has just came in. Concatenate both packets in the new buffer
		unsigned int new_size=current_incoming_packet.size + payload_size;
		unsigned char* new_buffer = (unsigned char*) l_alloc(new_size);
		memcpy(new_buffer, current_incoming_packet.ptr, current_incoming_packet.size);
		memcpy(new_buffer + current_incoming_packet.size, (unsigned char*)packet + sizeof(mysql_hdr), payload_size);
		l_free(current_incoming_packet.size, current_incoming_packet.ptr);
		current_incoming_packet.ptr=new_buffer;
		current_incoming_packet.size=new_size;

		// If the packet is less than 16MB-1 in size, it means that we are done
		// receiving chunks of the current packet, and we can safely move it into
		// incoming_packets.
		// https://dev.mysql.com/doc/internals/en/sending-more-than-16mbyte.html
		if (payload_size < MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE) {
			__incoming_packet(current_incoming_packet.ptr, current_incoming_packet.size);
			current_incoming_packet.ptr=NULL;
			current_incoming_packet.size=0;
		}
	// If there is no current packet being built, let's check if we should start building
	// one or we just forward the package to incoming_packets if it is not the first
	// chunk of a large packet.
	} else {
		if (payload_size < MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE) {
			__incoming_packet(packet, size);
		} else {
			current_incoming_packet.ptr=packet;
			current_incoming_packet.size=size;
		}
	}
}

void MySQL_Data_Stream::enqueue_outgoing_packet(void *packet, unsigned int size) {

#ifdef DEBUG
	if (myds_type == MYDS_FRONTEND) {
		__dump_pkt_to_file("PROXY_TO_CLIENT_enqueue_outgoing_packet", (unsigned char*)packet, size);
	} else if (myds_type != MYDS_LISTENER) {
		__dump_pkt_to_file("PROXY_TO_SERVER_enqueue_outgoing_packet", (unsigned char*)packet, size);
	}
#endif

	if (is_frontend()) {
		__outgoing_packet(packet, size);
		return;
	}

	// Most frequent case: we're dealing with a small packet -- just let it flow through to outgoing_packets
	if (size < MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE) {
		__outgoing_packet(packet, size);
		return;
	}

	// If we've reached this point, it means that we're dealing with a large packet that has been
	// merged into memory (another possibility is that it was a small packet, but it was turned into a
	// large packet by the rewrite of the query). We will proceed by splitting the packet into smaller
	// chunks and sending those smaller chunks instead.

	mysql_hdr hdr;
	memcpy(&hdr, packet, sizeof(hdr));
	
	// Determine into how many chunks will the bigger packet be split.
	// Note: we need to pay attention to not include the header size into the computation, because
	// the MySQL protocol actually defines the maximal size of the payload (so, what comes after the header).
	unsigned int payload_size=size-sizeof(hdr);
	unsigned int num_chunks;
	if (payload_size % MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE == 0) {
		num_chunks = payload_size / MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE;
	} else {
		num_chunks = payload_size / MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE + 1;
	}

	// Proceed to enqueue the smaller chunks. Make sure to split the header of the big packet
	// from splitting the payload.
	unsigned int bytes_split=sizeof(hdr);
	for (unsigned i = 0; i < num_chunks; i++) {
		// Determine the size of the current chunk.
		unsigned int remaining_bytes_to_split = size - bytes_split, chunk_payload_size;
		if (remaining_bytes_to_split > MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE) {
			chunk_payload_size = MYSQL_PROTOCOL_MAX_PAYLOAD_SIZE;
		} else {
			chunk_payload_size = remaining_bytes_to_split;
		}

		// Allocate memory for the current chunk, and copy the header and the current chunk of the big payload
		// We must pay attention to setting the correct length in the header before copying it.
		unsigned int chunk_size=chunk_payload_size + sizeof(hdr);
		unsigned char *chunk = (unsigned char*)l_alloc(chunk_size);
		hdr.pkt_length = chunk_payload_size;
		memcpy(chunk, &hdr, sizeof(hdr));
		memcpy(chunk+sizeof(hdr), (unsigned char*)packet+bytes_split, chunk_payload_size);

		__outgoing_packet(chunk, chunk_size);
		bytes_split+=chunk_payload_size;
		// Make sure to increment the packet id. When MySQL client splits a big query into
		// multiple smaller packets, the packets have consecutive packet ids. If the proxy
		// does not ensure that still holds, we will receive a "Got packets out of order" error
		// from the MySQL server.
		hdr.pkt_id++;
	}
}

void MySQL_Data_Stream::enqueue_outgoing_packets_from_serialized_resultset(unsigned char *buffer, unsigned int size) {
	/*
	 * Given a buffer containing a serialized list of MySQL packets (representing a resultset),
	 * deserialize them and add them to the outgoing packets list.
	 *
	 * One example use-case is when we cache a query's results, and we have to keep the serialized
	 * list of packets together. In order to deliver those query results to the MySQL client, we
	 * will use this routine.
	 */
	unsigned char *ptr = buffer;
	void *packet;
	unsigned int len;
	mysql_hdr hdr;

	while (ptr < buffer + size) {
		memcpy(&hdr, ptr, sizeof(mysql_hdr));
		len = hdr.pkt_length + sizeof(mysql_hdr);
		packet = l_alloc(len);
		memcpy(packet, ptr, len);
		enqueue_outgoing_packet(packet, len);
		ptr += len;
	}
}

void MySQL_Data_Stream::enqueue_outgoing_packets_from_resultset(PtrSizeArray *other_resultset) {
	unsigned int i;

	for (i = 0; i < other_resultset->len; i++) {
		PtrSize_t *pkt = other_resultset->index(i);
		enqueue_outgoing_packet(pkt->ptr, pkt->size);
	}
}

void MySQL_Data_Stream::cache_resultset(unsigned char* key,
										unsigned int key_len,
										unsigned int ttl) {
	/*
	 * Given a resultset stored in the current conversation (MySQL_Data_Stream), 
	 * cache it in the global cache by serializing it first.
     *
     * TODO(andrei): is it really necessary to perform l_free(mybuff) instead of just
     * copying the reference?
	 */

	unsigned int i;
	unsigned int l=0;
	unsigned char *mybuff = (unsigned char *)l_alloc(resultset_length);
	PtrSize_t *ps;

	for (i = 0; i < resultset->len; i++) {
		ps = resultset->index(i);
		memcpy(mybuff + l, ps->ptr, ps->size);
		l += ps->size;
	}

	while (resultset->len) {
		resultset->remove_index(resultset->len-1, NULL);
	}

	GloQC->set(key, key_len, mybuff, resultset_length, ttl);
	l_free(resultset_length, mybuff);
	resultset_length=0;
}
