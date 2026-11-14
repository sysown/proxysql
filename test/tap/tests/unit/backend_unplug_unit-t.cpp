/**
 * Regression for #6626: an idle-backend ping can finish before its stream
 * enters the poll set. Unplugging that stream must not call through a null
 * poll owner; streams that were registered must still leave the poll set.
 * The build rule enables null-call checks in the production stream sources,
 * so the regression does not depend on the optimizer dereferencing mypolls.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "ProxySQL_Poll.h"

#include <fcntl.h>
#include <initializer_list>
#include <sys/socket.h>
#include <unistd.h>

template<class Stream>
static void check_detached(const Stream& stream, const char* protocol, const char* scenario) {
	ok(stream.DSS == STATE_NOT_INITIALIZED && stream.myds_type == MYDS_BACKEND_NOT_CONNECTED,
	   "%s %s: backend state is reset", protocol, scenario);
	ok(stream.myconn == nullptr && stream.mypolls == nullptr,
	   "%s %s: connection and poll owner are cleared", protocol, scenario);
	ok(stream.fd == 0 && stream.poll_fds_idx == -1,
	   "%s %s: stream retains no backend descriptor or poll index", protocol, scenario);
}

template<class Stream>
static void test_unregistered(const char* protocol) {
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
		BAIL_OUT("%s: could not create backend socket pair", protocol);

	Stream stream;
	stream.DSS = STATE_MARIADB_PING;
	stream.myds_type = MYDS_BACKEND;
	stream.fd = sockets[0];

	// Match a ping that finishes on its first handler() call, before poll.add().
	ok(stream.mypolls == nullptr && stream.poll_fds_idx == -1,
	   "%s: ping stream has not been registered with poll", protocol);
	stream.unplug_backend();
	check_detached(stream, protocol, "before registration");
	ok(fcntl(sockets[0], F_GETFD) != -1,
	   "%s: unplug preserves the backend socket for connection pooling", protocol);
	close(sockets[0]);
	close(sockets[1]);
}

template<class Stream>
static void test_registered(const char* protocol) {
	// Keep the streams alive until after their poll owner is destroyed.
	Stream first, middle, last;
	ProxySQL_Poll<Stream> polls;
	for (Stream* stream : {&first, &middle, &last}) {
		stream->DSS = STATE_MARIADB_PING;
		stream->myds_type = MYDS_BACKEND;
	}
	polls.add(POLLIN, -1, &first, 101);
	polls.add(POLLOUT, -1, &middle, 202);
	polls.add(POLLIN | POLLOUT, -1, &last, 303);

	middle.unplug_backend();
	check_detached(middle, protocol, "middle entry");
	ok(polls.len == 2 && polls.myds[0] == &first && polls.myds[1] == &last,
	   "%s: unplug removes only the selected backend from poll", protocol);
	ok(first.poll_fds_idx == 0 && first.mypolls == &polls &&
	   last.poll_fds_idx == 1 && last.mypolls == &polls &&
	   polls.fds[1].events == (POLLIN | POLLOUT) && polls.last_sent[1] == 303,
	   "%s: moved backend retains its poll index and readiness metadata", protocol);

	last.unplug_backend();
	check_detached(last, protocol, "tail entry");
	ok(polls.len == 1 && polls.myds[0] == &first,
	   "%s: unplug removes the tail without disturbing the remaining backend", protocol);

	first.unplug_backend();
	check_detached(first, protocol, "final entry");
	ok(polls.len == 0, "%s: unplug removes the final backend from poll", protocol);
}

int main() {
	plan(36);
	if (test_init_minimal() != 0) BAIL_OUT("unit test initialization failed");

	test_unregistered<MySQL_Data_Stream>("MySQL");
	test_registered<MySQL_Data_Stream>("MySQL");
	test_unregistered<PgSQL_Data_Stream>("PgSQL");
	test_registered<PgSQL_Data_Stream>("PgSQL");

	test_cleanup_minimal();
	return exit_status();
}
