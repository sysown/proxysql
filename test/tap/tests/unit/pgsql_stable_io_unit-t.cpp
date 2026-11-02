/** Real-socket regressions for Stable poll scheduling and retryable sends (#6568). */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Logger.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

extern PgSQL_Logger* GloPgSQL_Logger;

static void require(bool condition, const char* what) {
	if (!condition) BAIL_OUT("%s (errno=%d)", what, errno);
}

struct Frontend {
	PgSQL_Thread worker;
	PgSQL_Session* session;
	int peer;

	Frontend() {
		require(worker.init(), "initialize worker");
		worker.curtime = 1000000;
		int sockets[2];
		require(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "create frontend socket pair");
		for (int fd : sockets)
			require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "set nonblocking frontend socket");
#ifdef SO_NOSIGPIPE
		const int no_sigpipe = 1;
		require(setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) == 0,
			"suppress SIGPIPE on the frontend socket");
#endif
		peer = sockets[1];
		session = new PgSQL_Session();
		session->thread = &worker;
		session->connections_handler = true;
		session->status = WAITING_CLIENT_DATA;
		session->client_myds = new PgSQL_Data_Stream();
		session->client_myds->init(MYDS_FRONTEND, session, sockets[0]);
		session->client_myds->myconn = new PgSQL_Connection(true);
		session->client_myds->DSS = STATE_SLEEP;
		// The startup packet has already been accepted; subsequent messages
		// use the normal typed-message framing path.
		session->client_myds->pkts_recv = 1;
		worker.mysql_sessions->add(session);
		worker.mypolls.add(POLLIN | POLLOUT, sockets[0], session->client_myds, worker.curtime);
	}

	~Frontend() {
		if (worker.mysql_sessions->len) {
			worker.unregister_session(0);
			delete session;
		}
		if (peer >= 0) close(peer);
	}

	void poll_ready(short events) {
		auto* stream = session->client_myds;
		worker.mypolls.fds[stream->poll_fds_idx].events = events;
		require(poll(worker.mypolls.fds, worker.mypolls.len, 0) > 0, "poll frontend readiness");
	}

	bool process_ready() {
		auto* stream = session->client_myds;
		return worker.process_data_on_data_stream(stream, stream->poll_fds_idx);
	}

	void queue_output(const std::string& bytes) {
		void* packet = malloc(bytes.size());
		require(packet != nullptr, "allocate queued output");
		memcpy(packet, bytes.data(), bytes.size());
		session->client_myds->PSarrayOUT->add(packet, bytes.size());
		session->client_myds->array2buffer_full();
	}
};

static void send_sync(Frontend& frontend) {
	const unsigned char sync[] = {'S', 0, 0, 0, 4};
	require(send(frontend.peer, sync, sizeof(sync), 0) == sizeof(sync), "send frontend Sync");
	frontend.poll_ready(POLLIN);
}

static void test_poll_read_boundary() {
	Frontend frontend;
	send_sync(frontend);
	ok(frontend.process_ready(), "frontend remains registered after poll processing");
#ifdef PROXYSQL31
	ok(frontend.session->client_myds->PSarrayIN->len == 0,
		"v3.1 records frontend readiness without framing data in the poll scan");
	frontend.worker.consume_data_stream_readiness(frontend.session->client_myds);
#else
	ok(frontend.session->client_myds->PSarrayIN->len == 1,
		"Stable reads and frames frontend data during poll processing");
#endif
	ok(frontend.session->client_myds->PSarrayIN->len == 1 && frontend.session->healthy,
		"the tier's I/O phase retains exactly one complete frontend message");
}

static void test_paused_read_and_disconnect() {
	{
		Frontend frontend;
		frontend.session->pause_until = frontend.worker.curtime + 10000000;
		send_sync(frontend);
		frontend.process_ready();
		frontend.worker.process_all_sessions();
		ok(frontend.worker.mysql_sessions->len == 1 && frontend.session->healthy &&
			frontend.session->status == WAITING_CLIENT_DATA,
			"a future pause does not execute the client's buffered Sync");
		ok(frontend.session->client_myds->PSarrayIN->len == 1,
			"socket input is drained and retained while query execution is paused");
	}
	{
		Frontend frontend;
		frontend.session->pause_until = frontend.worker.curtime + 10000000;
		close(frontend.peer);
		frontend.peer = -1;
		frontend.poll_ready(POLLIN);
		frontend.process_ready();
		frontend.worker.process_all_sessions();
		ok(frontend.worker.mysql_sessions->len == 0,
			"a frontend EOF is reaped in the same worker pass despite a future pause");
	}
}

static void test_send_after_writable_snapshot() {
	Frontend frontend;
	auto* stream = frontend.session->client_myds;
	const int small_buffer = 4096;
	require(setsockopt(stream->fd, SOL_SOCKET, SO_SNDBUF, &small_buffer, sizeof(small_buffer)) == 0,
		"limit send buffer");
	// Preserve the writable snapshot, then exhaust its capacity before the
	// stream writes. Poll readiness does not reserve socket buffer space.
	frontend.poll_ready(POLLOUT);
	require(frontend.worker.mypolls.fds[stream->poll_fds_idx].revents & POLLOUT,
		"capture writable readiness");
	const std::string filler(4096, 'f');
	size_t filled = 0;
	ssize_t written;
	while ((written = send(stream->fd, filler.data(), filler.size(), 0)) > 0)
		filled += written;
	require(filled && written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
		"exhaust nonblocking send capacity");
	const std::string expected = "retained plaintext";
	frontend.queue_output(expected);
	errno = 0;
	const int rc = stream->write_to_net();
	const int send_error = errno;
	ok(rc == -1 && (send_error == EAGAIN || send_error == EWOULDBLOCK) && stream->active && !stream->net_failure,
		"EAGAIN after writable readiness preserves a healthy frontend");
	ok(stream->queueOUT.head - stream->queueOUT.tail == expected.size(),
		"retryable send retains every queued plaintext byte");
	char buffer[4096];
	size_t drained = 0;
	ssize_t received;
	while ((received = recv(frontend.peer, buffer, sizeof(buffer), 0)) > 0) drained += received;
	require(drained == filled && received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
		"drain filler from the socket");
	stream->write_to_net_poll();
	std::string output;
	while ((received = recv(frontend.peer, buffer, sizeof(buffer), 0)) > 0) output.append(buffer, received);
	ok(output == expected && !stream->available_data_out() && stream->active && !stream->net_failure,
		"the next output attempt delivers retained bytes exactly once");
}

static void test_fatal_send() {
	Frontend frontend;
	auto* stream = frontend.session->client_myds;
	frontend.poll_ready(POLLOUT);
	frontend.queue_output("cannot deliver");
	close(frontend.peer);
	frontend.peer = -1;
	const int rc = stream->write_to_net();
	ok(rc == -1 && !stream->active && stream->net_failure,
		"a fatal plaintext send error deactivates the frontend");
	ok(stream->available_data_out(), "fatal send does not falsely account queued bytes as delivered");
}

int main() {
	plan(11);
	if (test_init_minimal() || test_init_auth() || test_init_query_processor() || test_init_hostgroups())
		BAIL_OUT("frontend I/O test initialization failed");
	GloPgSQL_Logger = new PgSQL_Logger();
	test_poll_read_boundary();
	test_paused_read_and_disconnect();
	test_send_after_writable_snapshot();
	test_fatal_send();
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
