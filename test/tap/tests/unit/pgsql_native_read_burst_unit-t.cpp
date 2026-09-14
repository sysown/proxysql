/**
 * @file pgsql_native_read_burst_unit-t.cpp
 * @brief What one pass of the native plaintext read has to get right: stop after
 *        a bounded amount, and do not throw away what it read because the peer
 *        closed in the same pass.
 *
 * PgSQL_Connection::native_recv_into_framer() used to read until the socket ran
 * dry. Against a backend that keeps it full that pulls an entire result set into
 * the framer buffer before a single message is parsed, and since the buffer
 * doubles, never shrinks and belongs to the connection, a pooled connection then
 * holds that peak for the rest of its life.
 *
 * The end-to-end guard for that lives in
 * test/tap/tests/pgsql-native_framer_retention-t.cpp, but it can only see the
 * defect while the backend is outrunning the drain -- on a fast machine or with a
 * slow client the loop exits on a short read anyway and a broken build looks
 * clean. This file removes the timing entirely: the socket is filled before the
 * read is called, so how much one pass takes is a fact, not a race.
 *
 * No server, no Docker, no jemalloc. The plaintext path touches exactly two
 * members -- fd and native_framer -- so the connection is built directly.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>

// Must match burst_max in native_recv_into_framer(): 16 reads of 16 KiB.
static const size_t BURST = 16 * 16384;

// A backend message: type byte, 4-byte length covering itself, then the payload.
// 1029 bytes does not divide the burst, so one message always straddles the cut --
// which is the case worth getting right.
static const size_t PAYLOAD = 1024;
static const size_t MSG_BYTES = 5 + PAYLOAD;

// Comfortably more than one burst, and it fits: an AF_UNIX socketpair with its
// send buffer raised holds several MiB.
static const size_t PREFILL = 2 * 1024 * 1024;

static void append_msg(std::string& s, char type, size_t payload_len, char fill) {
	s.push_back(type);
	const uint32_t L = (uint32_t)(payload_len + 4);
	s.push_back((char)((L >> 24) & 0xff));
	s.push_back((char)((L >> 16) & 0xff));
	s.push_back((char)((L >> 8) & 0xff));
	s.push_back((char)(L & 0xff));
	s.append(payload_len, fill);
}

// Drain every complete message the framer is holding. Returns the bytes they
// account for and appends each one's first payload byte, which is how the test
// checks nothing was dropped or reordered.
static size_t drain(PgSQL_Connection* c, std::string* marks, bool* intact,
                    size_t expect_payload = PAYLOAD) {
	size_t bytes = 0;
	for (;;) {
		PgSQL_Backend_Msg m;
		const PgSQL_Frame_Result r = c->native_framer.next(m);
		if (r != FRAME_OK) break;
		if (m.type != 'D' || m.payload_len != expect_payload) *intact = false;
		if (marks) marks->push_back(m.payload_len ? (char)m.payload[0] : '?');
		bytes += 5 + m.payload_len;
	}
	return bytes;
}

int main(int, char**) {
	plan(9);

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) BAIL_OUT("socketpair failed");
	const int want = 8 * 1024 * 1024;
	setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &want, sizeof(want));
	setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &want, sizeof(want));
	// The read loop must never block: it relies on EAGAIN to know the socket is dry.
	fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
	fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL, 0) | O_NONBLOCK);

	// Fill the socket with complete messages, each tagged with a distinct payload
	// byte so their order can be checked on the way out.
	std::string wire;
	const size_t want_msgs = PREFILL / MSG_BYTES;
	for (size_t i = 0; i < want_msgs; i++)
		append_msg(wire, 'D', PAYLOAD, (char)('a' + (i % 26)));

	size_t written = 0;
	while (written < wire.size()) {
		const ssize_t n = ::send(sv[1], wire.data() + written, wire.size() - written, 0);
		if (n <= 0) break;
		written += (size_t)n;
	}
	const size_t whole_msgs_written = written / MSG_BYTES;
	ok(written > 2 * BURST && whole_msgs_written > 0,
	   "prefilled the socket with %zu bytes (%zu whole messages), more than the %zu-byte burst",
	   written, whole_msgs_written, BURST);

	PgSQL_Connection* conn = new PgSQL_Connection(false);
	conn->fd = sv[0];
	conn->native_mode = true;

	// ---------------------------------------------------------- one pass only
	const int r1 = conn->native_recv_into_framer();
	bool intact = true;
	std::string marks;
	const size_t first = drain(conn, &marks, &intact);

	ok(r1 == 1 && first > 0 && first <= BURST,
	   "one pass delivered %zu bytes, within the %zu-byte burst%s",
	   first, BURST,
	   (first > BURST) ? "  <-- the read loop drained the whole socket instead of handing off"
	                   : "");

	ok(intact && !marks.empty() && marks[0] == 'a',
	   "the messages it did deliver are whole and in order (%zu of them, first marked '%c')",
	   marks.size(), marks.empty() ? '?' : marks[0]);

	// ------------------------------------------- the rest is still on the socket
	size_t total = first;
	std::string all_marks = marks;
	for (int pass = 0; pass < 512 && total < whole_msgs_written * MSG_BYTES; pass++) {
		const int r = conn->native_recv_into_framer();
		if (r < 0) break;
		const size_t got = drain(conn, &all_marks, &intact);
		if (r == 0 && got == 0) break;   // EAGAIN with nothing left to frame
		total += got;
	}

	ok(total >= whole_msgs_written * MSG_BYTES,
	   "further passes recovered the remainder: %zu of %zu bytes, nothing dropped at the cut",
	   total, whole_msgs_written * MSG_BYTES);

	// Every message, in the order written, with none lost where a pass ended
	// mid-message.
	bool order_ok = (all_marks.size() == whole_msgs_written);
	for (size_t i = 0; order_ok && i < all_marks.size(); i++)
		if (all_marks[i] != (char)('a' + (i % 26))) order_ok = false;
	ok(order_ok && intact,
	   "all %zu messages came out intact and in order",
	   all_marks.size());

	conn->fd = -1;      // the test owns the socket, not the connection's destructor
	delete conn;
	close(sv[0]);
	close(sv[1]);

	// ----------------------------------------------------------------------
	//  A reply that ends exactly on a buffer boundary, with the close behind it
	// ----------------------------------------------------------------------
	// The loop stops early on a SHORT read, taking a partial buffer as "the socket
	// is dry". So it only ever meets the close when the previous read filled the
	// buffer to the brim: it goes round once more and gets 0. That EOF used to
	// return failure outright, and everything the pass had already framed went with
	// it -- a result the backend had finished sending reached the client as a
	// connection error instead.
	//
	// Over TCP the alignment cannot be arranged, which is why the end-to-end case in
	// pgsql-native_hostile_backend-t says of itself that it cannot prove this one:
	// the proxy wakes on the first readable segment, about 1448 bytes over a Docker
	// bridge, so the final read is short and the loop never asks again. Over a
	// socketpair it is exact.
	{
		const size_t READBUF = 16384;            // tmp[] in native_recv_into_framer()
		const size_t P = 507;                    // 5 + 507 = 512, and 512 divides 16384
		const size_t MSGS = READBUF / (5 + P);   // exactly one read's worth

		int sv2[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0) BAIL_OUT("socketpair failed");
		fcntl(sv2[0], F_SETFL, fcntl(sv2[0], F_GETFL, 0) | O_NONBLOCK);

		std::string exact;
		for (size_t i = 0; i < MSGS; i++) append_msg(exact, 'D', P, (char)('a' + (i % 26)));

		size_t w = 0;
		while (w < exact.size()) {
			const ssize_t n = ::send(sv2[1], exact.data() + w, exact.size() - w, 0);
			if (n <= 0) break;
			w += (size_t)n;
		}
		::shutdown(sv2[1], SHUT_WR);             // the close, right behind the last byte
		ok(w == READBUF && exact.size() == READBUF,
		   "queued exactly one %zu-byte read (%zu bytes in %zu messages), then closed",
		   READBUF, w, MSGS);

		PgSQL_Connection* c2 = new PgSQL_Connection(false);
		c2->fd = sv2[0];
		c2->native_mode = true;

		const int r = c2->native_recv_into_framer();
		bool intact2 = true;
		std::string marks2;
		const size_t kept = drain(c2, &marks2, &intact2, P);

		// THE VERDICT. The bytes are in the framer either way -- the first read fed
		// them before the second one saw the close. What changes is the answer, and
		// on -1 the caller destroys the connection and reports a connection error for
		// a query the backend answered in full.
		ok(r == 1,
		   "a reply ending on a buffer boundary with the close behind it is kept, not "
		   "discarded (returned %d%s)",
		   r, r == 1 ? "" : "  <-- EOF reported while a complete reply was already framed");

		bool order2 = (marks2.size() == MSGS);
		for (size_t i = 0; order2 && i < marks2.size(); i++)
			if (marks2[i] != (char)('a' + (i % 26))) order2 = false;
		ok(kept == READBUF && order2 && intact2,
		   "all %zu messages came out whole and in order (%zu of %zu bytes)",
		   marks2.size(), kept, READBUF);

		// And the close is still reported, once there is nothing left to hand back --
		// otherwise keeping the data would trade a lost result for a stuck session.
		ok(c2->native_recv_into_framer() < 0,
		   "the next pass reports the close, so the connection still ends");

		c2->fd = -1;
		delete c2;
		close(sv2[0]);
		close(sv2[1]);
	}

	return exit_status();
}
