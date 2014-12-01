#include "proxysql.h"

long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

