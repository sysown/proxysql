#include <stdio.h>
#include <evhtp.h>

void
testcb(evhtp_request_t * req, void * a) {
    evbuffer_add_reference(req->buffer_out, "foobar", 6, NULL, NULL);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv) {
    evbase_t * evbase = event_base_new();
    evhtp_t  * htp    = evhtp_new(evbase, NULL);

    evhtp_set_cb(htp, "/test", testcb, NULL);
    evhtp_bind_socket(htp, "0.0.0.0", 8080, 1024);
    event_base_loop(evbase, 0);
    return 0;
}
