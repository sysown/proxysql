#include "ProxySQL_HTTP.hpp"

#include "mongoose.h"
#include <time.h>

typedef struct _aadata {
	time_t start;
	struct http_message *hm;
} aadata;

static void static_ev_handler_http(struct mg_connection *nc, int ev, void *ev_data) {
	struct http_message *hm = NULL;
	aadata *a=NULL;
	time_t t;
	double dt;
	//printf("%d\n",ev);
	switch (ev) {
//		case MG_EV_ACCEPT:
//			printf("hello\n");
//			nc->user_data=malloc(sizeof(aadata));
//			break;
		case MG_EV_HTTP_REQUEST:
			nc->user_data=malloc(sizeof(aadata));
			a=(aadata *)nc->user_data;
			a->start=time(NULL);
			hm = (struct http_message *) ev_data;
			a->hm=hm;
			dt=a->start;
			dt+=2.3;
			//mg_set_timer(nc, dt);
			mg_set_timer(nc, mg_time() + 3.5);
			//if (
//			if (nc->user_data==NULL) {
//				use
//			}
//			hm = (struct http_message *) ev_data;
//			printf("%s\n",hm->uri);
//			mg_printf(nc, "%s","HTTP/1.0 501 Not Implemented\r\n""Content-Length: 0\r\n\r\n");
			break;
		case MG_EV_TIMER:
			t=time(NULL);
			a=(aadata *)nc->user_data;
			printf("%s\n",a->hm->uri.p);
			mg_printf(nc, "%s","HTTP/1.0 501 Not Implemented\r\n""Content-Length: 0\r\n\r\n");		
		default:
			break;
	}
}

static void static_ev_handler_telnet(struct mg_connection *nc, int ev, void *ev_data) {
	struct mbuf *io = &nc->recv_mbuf;

	//printf("%d\n",ev);
	switch (ev) {
		case MG_EV_RECV:
			// This event handler implements simple TCP echo server
			mg_send(nc, io->buf, io->len);	// Echo received data back
			mbuf_remove(io, io->len);			// Discard data from recv buffer
			//nc->flags=MG_F_SEND_AND_CLOSE;
			break;
		default:
			break;
	}
}

ProxySQL_HTTP::ProxySQL_HTTP() {
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mgr = (struct mg_mgr *)malloc(sizeof(struct mg_mgr));
	mg_mgr_init(mgr, NULL);
	telnet_nc=mg_bind(mgr, "1234", static_ev_handler_telnet);
	HTTP_nc=mg_bind(mgr, "1235", static_ev_handler_http);
	mg_set_protocol_http_websocket(HTTP_nc);
//	mg_enable_multithreading(nc);
}

ProxySQL_HTTP::~ProxySQL_HTTP() {
	mg_mgr_free(mgr);
	free(mgr);
	delete mysql_thr;
}

void ProxySQL_HTTP::run() {
	for (;;) {
		mg_mgr_poll(mgr, 100);
	}
}
