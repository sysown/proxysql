
// If defined then active pthread mutex in ProxySQL_Admin else use the wrlock
#define PA_PTHREAD_MUTEX

#if !defined(__FreeBSD__) && !defined(__APPLE__)
// If enabled, it adds support for auxiliary threads
#define IDLE_THREADS
#endif
