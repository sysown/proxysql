#include "proxysql.h"
#include "cpp.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif



/*
class ProxySQL_HTTP {
	private:
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bound_socket *handle;
	unsigned short port;
	public:
	ProxySQL_HTTP();
	~ProxySQL_HTTP();
	bool init();
	void run();
};
*/

ProxySQL_HTTP::ProxySQL_HTTP() {
}
bool ProxySQL_HTTP::init() {
/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) {
		fprintf(stderr, "couldn't create evhttp. Exiting.\n");
		return false;
	}
	return true;
}
