#include "proxysql.h"
#include "http_client.h"

// Copies the body and status code from a mongoose http_message. It allocates
// the memory needed for the http_response struct and the message body.
//
// Call free_response(http_response *) to free the return struct.
http_response *copy_response(const http_message *m_http_message) {
    http_response *response = (http_response *) malloc(sizeof(http_response));
    response->status_code = m_http_message->resp_code;
    response->body = (char *) malloc(m_http_message->body.len + 1);
    memcpy(response->body, m_http_message->body.p, m_http_message->body.len);
    response->body[m_http_message->body.len] = 0;
    return response;
}

// Frees the response body and then the response itself. Use it on return values of
// copy_response(http_message *)
void free_response(http_response *response) {
    if (response->body) free(response->body);
    free(response);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;
    struct http_client_data *client_data = (http_client_data *) nc->mgr->user_data;

    switch (ev) {
        case MG_EV_CONNECT:
            if (* (int *) ev_data != 0) {
                proxy_debug(PROXY_DEBUG_GENERIC, "HTTP client connect() failed: %s\n", strerror(* (int *) ev_data));
                client_data->exit_flag = 1;
            }
            break;
        case MG_EV_HTTP_REPLY:
            nc->flags |= MG_F_CLOSE_IMMEDIATELY;
            client_data->response = copy_response(hm);
            client_data->exit_flag = 1;
            break;
        case MG_EV_CLOSE:
            if (* (int *) ev_data != 0) {
                proxy_debug(PROXY_DEBUG_GENERIC, "HTTP client connection closed: %s.\n", strerror(*(int *) ev_data));
            }
            client_data->exit_flag = 1;
        default:
            break;
    }
}

// Does a HTTP post using mongoose API and returns the response status and body if all goes
// fine. Returns NULL in case of error.
//
// Take care to delimit headers with \r\n and end the extra headers value with \r\n.
//
// Call free_response(http_response *) on the return value.
http_response * http_post(const char *url, const char *extra_headers, const char *post_data) {
    struct mg_mgr mgr;
    http_client_data hcd;

    hcd.exit_flag = 0;
    hcd.response = NULL;
    mg_mgr_init(&mgr, &hcd);

    mg_connect_http(&mgr, ev_handler, url, extra_headers, post_data);

    while (hcd.exit_flag == 0) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    return hcd.response;
}


