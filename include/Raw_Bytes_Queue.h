#ifndef __RAW_BYTES_QUEUE__H__
#define __RAW_BYTES_QUEUE__H__

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

// Initialize a byte queue with a given size.
//
// Note: the size of the queue is *extremely* important for the performance
// of the whole proxy. If we choose a big buffer size, the memory footprint
// of the proxy will be larger. If we choose a small buffer size, the number
// of recv() calls from network will be larger, increasing the context
// switches between userspace and kernel and thus bringing a lower
// throughput.
#define queue_init(_q,_s) { \
	_q.size=_s; \
	_q.buffer=malloc(_q.size); \
	_q.head=0; \
	_q.tail=0; \
	_q.partial=0; \
	_q.pkt.ptr=NULL; \
	_q.pkt.size=0; \
}

// Destroy a given queue
#define queue_destroy(_q) { \
	free(_q.buffer); \
}

// Defragment a given queue -- move the remaining unprocessed content to
// the beginning in order to make room for more content to be read/written
// in the remaining space at the end that has been freed up.
#define queue_defrag(_q) { \
	memcpy(_q.buffer, (unsigned char *)_q.buffer + _q.tail, _q.head - _q.tail); \
	_q.head-=_q.tail; \
	_q.tail=0; \
}

// The size of the remaining space
#define queue_available(_q) (_q.size-_q.head)

// The size of the data that we are currently processing
#define queue_data(_q) (_q.head-_q.tail)

// Move the pointer where we can read data from with _s bytes
#define queue_r(_q, _s) { \
  _q.tail+=_s; \
  if (_q.tail==_q.head) { \
    _q.head=0; \
    _q.tail=0; \
  } \
}

// Move the pointer where we can write data to with _s bytes
#define queue_w(_q,_s) (_q.head+=_s)

#define queue_r_ptr(_q) ((unsigned char *)_q.buffer+_q.tail)
#define queue_w_ptr(_q) ((unsigned char *)_q.buffer+_q.head)

#endif