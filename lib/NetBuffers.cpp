#include "proxysql.h"
#include "cpp.h"
#include <sys/mman.h>


#define NBUF_PER_BLOCK	2048

NetBuffers::NetBuffers() {
	buffers=new PtrArray();
	blocks=new PtrArray();
	spinlock_rwlock_init(&rwlock);
}

NetBuffers::~NetBuffers() {
	while (buffers->len) {
		buffers->remove_index_fast(buffers->len-1);
	}
	while (blocks->len) {
		void *b=blocks->remove_index_fast(blocks->len-1);
		munmap(b,QUEUE_T_DEFAULT_SIZE*2*NBUF_PER_BLOCK);
	}
}

void * NetBuffers::get() {
	void *b=NULL;
	spin_wrlock(&rwlock);
	if (buffers->len) {
		b=buffers->remove_index_fast(buffers->len-1);
	} else {
		void *nmb=mmap(NULL, QUEUE_T_DEFAULT_SIZE*2*NBUF_PER_BLOCK, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (nmb==MAP_FAILED) {
			proxy_error("PANIC: mmap() failed\n");
			exit(EXIT_FAILURE);
		}
		blocks->add(nmb);
		size_t j;
		void *n;
		for (j=0; j<NBUF_PER_BLOCK; j++) {
			n=(char *)nmb+j*QUEUE_T_DEFAULT_SIZE*2;
			buffers->add(n);
		}
		b=buffers->remove_index_fast((buffers->len-1));
	}
	spin_wrunlock(&rwlock);
	return b;
}

void NetBuffers::put(void *b) {
	spin_wrlock(&rwlock);
	buffers->add(b);
	spin_wrunlock(&rwlock);
}

unsigned long long NetBuffers::total_mem() {
	unsigned long long t=0;
	spin_wrlock(&rwlock);
	t=QUEUE_T_DEFAULT_SIZE*2*NBUF_PER_BLOCK*blocks->len;
	spin_wrunlock(&rwlock);
	return t;
}
