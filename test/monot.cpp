#include <stdio.h>
#include <time.h>
#include <unistd.h>

long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((long)ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

#define LOOPS 10000000

int main() {
  volatile int i;
  volatile long l;
  struct timespec req;
  req.tv_sec = 0;
  req.tv_nsec = 1;
  for (i = 0; i < LOOPS; i++) {
    // usleep(1);
    // nanosleep(&req, NULL);
    l = monotonic_time();
  }
  return 0;
}
