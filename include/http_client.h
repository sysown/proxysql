#ifndef PROXYSQL_HTTP_CLIENT_H
#define PROXYSQL_HTTP_CLIENT_H

#include <mongoose.h>

struct http_response {
    int status_code;
    char *body;
};

struct http_client_data {
    int exit_flag;
    http_response *response;
};

const http_response * copy_response(http_message m_http_message);
void free_response(http_response *response);

http_response * http_get(const char *url, const char *extra_headers);
http_response * http_post(const char *url, const char *extra_headers, const char *post_data);

#endif //PROXYSQL_HTTP_CLIENT_H
