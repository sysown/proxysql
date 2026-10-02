#ifndef CLASS_WEB_INTERFACE
#define CLASS_WEB_INTERFACE

class Web_Interface {
    public:
    Web_Interface() {};
    virtual ~Web_Interface() {};
    virtual void start(int p) {};
    // Must stop accepting requests and synchronously drain active handlers
    // before returning; core keeps the management provider alive until then.
    virtual void stop() {};
    virtual void print_version() {};
};

typedef Web_Interface * create_Web_Interface_t();

#ifdef PROXYSQL40
#include "ProxySQL_ManagedConfiguration.h"
using proxysql_web_bind_managed_configuration_v1_t = bool (*)(
    Web_Interface*, const ProxySQL_ManagedConfigurationServiceV1*, std::string&);
// Exported by the web plugin; called once before managed HTTP serving.
extern "C" bool proxysql_web_bind_managed_configuration_v1(
    Web_Interface*, const ProxySQL_ManagedConfigurationServiceV1*, std::string& error);
#endif

#endif /* CLASS_WEB_INTERFACE */
