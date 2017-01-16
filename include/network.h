#ifndef PROXYSQL_NETWORK_H__
#define PROXYSQL_NETWORK_H__

#include <cstdint>

int listen_on_port(char *ip, uint16_t port, int backlog, bool reuseport=false);
int listen_on_unix(char *, int);
int connect_socket(char *, int);

#endif // PROXYSQL_NETWORK_H__
