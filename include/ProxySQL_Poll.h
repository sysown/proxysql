#ifndef PROXYSQL_POLL_H
#define PROXYSQL_POLL_H

//#include "MySQL_Data_Stream.h"

class iface_info {
	public:
	char *iface;
	char *address;
	int port;
	int fd;
	iface_info(char *_i, char *_a, int p, int f) {
		iface=strdup(_i);
		address=strdup(_a);
		port=p;
		fd=f;
	}
	~iface_info() {
		free(iface);
		free(address);
		close(fd);
	}
	iface_info(const iface_info&) = delete;
	iface_info& operator=(const iface_info&) = delete;
};

template<class T>
class ProxySQL_Poll {
	private:
	void shrink();
	void expand(unsigned int more);

	public:
	unsigned int len;
	unsigned int size;
	struct pollfd *fds;
	T **myds;
	unsigned long long *last_recv;
	unsigned long long *last_sent;
	volatile int pending_listener_add;
	volatile int pending_listener_del;
	unsigned int poll_timeout;
	unsigned long loops;
	StatCounters *loop_counters;

	ProxySQL_Poll();
	~ProxySQL_Poll();
	void add(uint32_t _events, int _fd, T *_myds, unsigned long long sent_time);
	void update_fd_at_index(unsigned int idx, int _fd);
	void remove_index_fast(unsigned int i);
	int find_index(int fd);
};
#endif // __CLASS_PROXYSQL_POLL
