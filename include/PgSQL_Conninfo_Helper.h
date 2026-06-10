#ifndef PROXYSQL_PGSQL_CONNINFO_HELPER_H
#define PROXYSQL_PGSQL_CONNINFO_HELPER_H

#include <sstream>

// Append port= only when the configured port is non-zero.
// Some admin configurations use port=0 to indicate that the hostname
// is a Unix-domain socket path; passing "port=0" to libpq produces
// an "invalid port number: \"0\"" error. Centralize the rule here.
inline void append_pg_conninfo_port(std::ostringstream &conninfo, int port) {
    if (port == 0) return;
    conninfo << "port=" << port << " ";
}

#endif // PROXYSQL_PGSQL_CONNINFO_HELPER_H
