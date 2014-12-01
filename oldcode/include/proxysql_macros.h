#define MY_SESS_ADD_PKT_OUT_CLIENT(__p) l_ptr_array_add(sess->client_myds->output.pkts, __p)
#define MY_SESS_ADD_PKT_OUT_SERVER(__p) l_ptr_array_add(sess->server_mybe->server_myds->output.pkts, __p)
#define mysql_pkt_get_size(__p) ( __p->length-sizeof(mysql_hdr) )
#define ACTIVE_TRANSACTION(__sess) ( __sess->server_mybe->server_myds->active_transaction )

#define MS 5
#define SPIN_LOCK(lock) { \
	while(__sync_bool_compare_and_swap(&lock,0,1)==0) { \
		usleep(MS); \
	} \
}

#define SPIN_UNLOCK(lock) { \
	while(__sync_bool_compare_and_swap(&lock,1,0)==0) { \
		usleep(MS); \
	} \
}


#define MEM_COPY_FWD(dst_p, src_p, bytes)  \
	do { \
		void *__a=dst_p; \
		void *__b=src_p; \
		size_t __nbytes = (bytes); \
		while (__nbytes > 0) { \
    	char __x = ((char *) __b)[0]; \
			__b += 1; \
			__nbytes -= 1; \
			((char *) __a)[0] = __x; \
			__a += 1; \
		} \
	} while (0)


#define ioctl_FIONBIO(fd, mode) \
{ \
	int ioctl_mode=mode; \
	ioctl(fd, FIONBIO, (char *)&ioctl_mode); \
}

#define queue_init(q,s) { \
	q->size=s; \
	q->buffer=l_alloc(q->size); \
	q->head=0; \
	q->tail=0; \
}

#define queue_destroy(q) { \
	l_free(q->size,q->buffer); \
}

#define queue_zero(q) { \
  memcpy(q->buffer, q->buffer+q->tail, q->head - q->tail); \
  q->head-=q->tail; \
  q->tail=0; \
}

#define queue_available(q) (q->size-q->head)
#define queue_data(q) (q->head-q->tail)

#define queue_r(q, s) { \
  q->tail+=s; \
  if (q->tail==q->head) { \
    q->head=0; \
    q->tail=0; \
  } \
}

#define queue_w(q,s) (q->head+=s)

#define queue_r_ptr(q) (q->buffer+q->tail)
#define queue_w_ptr(q) (q->buffer+q->head)

