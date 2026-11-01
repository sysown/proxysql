#ifndef PGSQL_RESULT_LIBPQ_FIXTURE_H
#define PGSQL_RESULT_LIBPQ_FIXTURE_H

#include <cstddef>
#include "libpq-fe.h"

// Keep libpq's private headers and their configuration macros out of the
// ProxySQL translation unit while exercising the real vendored parser.
namespace pgsql_result_fixture {
bool has_input_buffer(const PGconn* conn);
void set_transport(PGconn* conn, int socket_fd);
void feed(PGconn* conn, const char* bytes, std::size_t size, bool copy_out);
}

#endif
