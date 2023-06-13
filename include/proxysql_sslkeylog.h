#ifndef __PROXYSQL_SSLKEYLOG_H
#define __PROXYSQL_SSLKEYLOG_H
#include "proxysql.h"

void proxysql_keylog_init();
bool proxysql_keylog_open(const char* keylog_file);
void proxysql_keylog_close(bool lock = true);
void proxysql_keylog_attach_callback(SSL_CTX* ssl_ctx);
void proxysql_keylog_write_line_callback(const SSL* ssl, const char* line);

#endif // __PROXYSQL_SSLKEYLOG_H
