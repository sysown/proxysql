#ifndef CLASS_NET_BUFFERS_H
#define CLASS_NET_BUFFERS_H
#include "proxysql.h"
#include "cpp.h"

class NetBuffers {
	private:
	PtrArray *buffers;
	PtrArray *blocks;
	rwlock_t rwlock;
	public:
	NetBuffers();
	~NetBuffers();
	void * get();
	void put(void *);
	unsigned long long total_mem();
};

#endif /* CLASS_NET_BUFFERS_H */
