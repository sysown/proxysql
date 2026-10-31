extern "C" {
#include "postgres_fe.h"
#include "libpq-int.h"
}
#include "pgsql_result_libpq_fixture.h"
#include <cassert>
#include <cstring>

namespace pgsql_result_fixture {
bool has_input_buffer(const PGconn* conn) {
	return conn && conn->inBuffer;
}

void set_transport(PGconn* conn, int socket_fd) {
	conn->sock = socket_fd;
	conn->status = CONNECTION_OK;
	conn->pversion = 196608;
	conn->nonblocking = true;
}

void feed(PGconn* conn, const char* bytes, std::size_t size, bool copy_out) {
	assert(size <= static_cast<std::size_t>(conn->inBufSize));
	memcpy(conn->inBuffer, bytes, size);
	conn->inStart = conn->inCursor = 0;
	conn->inEnd = size;
	conn->asyncStatus = copy_out ? PGASYNC_COPY_OUT : PGASYNC_BUSY;
}
}
