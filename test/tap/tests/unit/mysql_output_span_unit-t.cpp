/**
 * @file mysql_output_span_unit-t.cpp
 * @brief Uncompressed output queue: defer, borrow, and protect a borrowed span.
 *
 * @details An uncompressed MySQL connection keeps a 1 KiB output ring. A packet
 *   that does not fit is sent directly from its own allocation ("borrowed
 *   span"), but only once the ring is empty. This test drives the three
 *   transitions that make that safe:
 *
 *   1. A small packet is staged in the owned ring.
 *   2. A large packet queued behind it waits in PSarrayOUT instead of being
 *      interleaved with the staged bytes.
 *   3. Once the ring drains, the large packet becomes the send span (borrowed)
 *      and leaves PSarrayOUT.
 *   4. While the span is borrowed, array2buffer_full() does not touch it and
 *      does not consume the next packet.
 *   5. After send() accepts the whole span, the queue returns to its owned ring
 *      and stages the packet that was waiting.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"

#include <cstring>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>

#ifdef PROXYSQL31
int main() {
	plan(15);

	ok(test_init_minimal() == 0, "initialize test globals");

	int fds[2] = { -1, -1 };
	ok(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "create a stream socket");

	{
		MySQL_Data_Stream stream;
		stream.init(MYDS_FRONTEND, nullptr, fds[0]);
		// Frontend stream destruction owns the connection from this handoff onward.
		stream.myconn = std::make_unique<MySQL_Connection>().release();

		ok(stream.queueOUT.capacity == QUEUE_OUT_DEFAULT_SIZE,
			"uncompressed output ring starts at the small default");

		const size_t small_size = 500;
		const size_t large_size = 5000;
		const size_t waiting_size = 100;

		void* small = l_alloc(small_size);
		memset(small, 's', small_size);
		stream.PSarrayOUT->add(small, small_size);
		const int small_staged = stream.array2buffer_full();
		ok(small_staged == static_cast<int>(small_size) &&
			stream.queueOUT.buffer == stream.queueOUT.storage &&
			stream.queueOUT.head == small_size,
			"small packet is staged in the owned ring");

		// Larger than the ring, queued behind the staged bytes. It must stay in
		// PSarrayOUT: the ring and a borrowed span are never mixed in one span.
		void* large = l_alloc(large_size);
		memset(large, 'l', large_size);
		stream.PSarrayOUT->add(large, large_size);
		stream.array2buffer_full();
		ok(stream.PSarrayOUT->len == 1 &&
			stream.queueOUT.buffer == stream.queueOUT.storage &&
			stream.queueOUT.head == small_size,
			"large packet waits in PSarrayOUT while the ring is non-empty");

		ok(stream.write_to_net() == static_cast<int>(small_size),
			"staged bytes are sent");
		ok(stream.queueOUT.head == stream.queueOUT.tail,
			"owned ring is empty after the send");

		const int borrowed = stream.array2buffer_full();
		ok(borrowed == static_cast<int>(large_size), "large packet is published as a span");
		ok(stream.queueOUT.buffer != stream.queueOUT.storage &&
			stream.queueOUT.pkt.ptr == stream.queueOUT.buffer &&
			stream.queueOUT.pkt.size == large_size &&
			stream.queueOUT.head == large_size &&
			stream.queueOUT.tail == 0,
			"large packet is borrowed directly from its own allocation");
		ok(stream.PSarrayOUT->len == 0,
			"borrowed packet left PSarrayOUT exactly once");

		// A packet queued while the span is borrowed must wait: array2buffer()
		// must not write into a span that send() is still reading.
		void* waiting = l_alloc(waiting_size);
		memset(waiting, 'w', waiting_size);
		stream.PSarrayOUT->add(waiting, waiting_size);
		const int while_borrowed = stream.array2buffer_full();
		ok(while_borrowed == 0,
			"array2buffer does nothing while a span is borrowed");
		ok(stream.queueOUT.buffer != stream.queueOUT.storage &&
			stream.queueOUT.head == large_size &&
			stream.PSarrayOUT->len == 1,
			"borrowed span and waiting packet are untouched");

		ok(stream.write_to_net() == static_cast<int>(large_size),
			"the borrowed span is accepted in full");
		ok(stream.queueOUT.buffer == stream.queueOUT.storage &&
			stream.queueOUT.pkt.ptr == NULL &&
			stream.queueOUT.head == stream.queueOUT.tail,
			"queue returns to its owned ring after the span drains");

		const int waiting_staged = stream.array2buffer_full();
		ok(waiting_staged == static_cast<int>(waiting_size) &&
			stream.queueOUT.buffer == stream.queueOUT.storage &&
			stream.queueOUT.head == waiting_size &&
			stream.PSarrayOUT->len == 0,
			"the waiting packet is staged after the release");
	}

	// fds[0] belongs to the data stream; its destructor already closed it.
	if (fds[1] >= 0) close(fds[1]);
	test_cleanup_minimal();
	return exit_status();
}
#else
int main() {
	// The output-span model is a PROXYSQL31 feature; v3.0 keeps the staging path.
	plan(1);
	ok(1, "SKIP: PROXYSQL31 is not enabled");
	return exit_status();
}
#endif // PROXYSQL31
