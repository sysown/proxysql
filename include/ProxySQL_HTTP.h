#ifndef __CLASS_PROXYSQL_HTTP_H
#define __CLASS_PROXYSQL_HTTP_H

#include "proxysql.h"
#include "cpp.h"

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

#endif /* __CLASS_PROXYSQL_HTTP_H */
