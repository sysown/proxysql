/**
 * @file mysql_compressed_output_ring_unit-t.cpp
 * @brief Compressed MySQL keeps the historical 32 KiB output ring.
 *
 * @details Uncompressed connections use a 1 KiB output ring: a result slab
 *   larger than the ring is sent in place, without a second copy. Compression
 *   changes that: every compressed frame is built first and then staged through
 *   the ring, so a 1 KiB ring would send one frame in dozens of calls. The ring
 *   is raised to QUEUE_OUT_COMPRESSED_SIZE once, when compression is active.
 *
 *   This test enables compression on a frontend stream and asserts:
 *   1. The ring starts at the small default.
 *   2. Compression raises it to the 32 KiB size.
 *   3. A small compressed frame is staged in the owned ring, not borrowed.
 *   4. The packet left PSarrayOUT, so the frame was consumed exactly once.
 *   5. A compressed frame larger than the ring (incompressible payload) is
 *      sent from its own allocation as a borrowed span.
 *
 *   Case 5 is the compressed counterpart of the uncompressed borrow path: the
 *   frame is produced by generate_compressed_packet() and, because it does not
 *   fit the 32 KiB ring and the ring is empty, becomes the send span directly.
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
	plan(14);

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

		// The zlib path is selected unless the connection opts into zstd.
		mysql_thread___protocol_compression_level = 3;
		stream.myconn->set_status(true, STATUS_MYSQL_CONNECTION_COMPRESSION);

		const size_t payload = 4096;
		void* packet = l_alloc(payload);
		memset(packet, 'a', payload);
		stream.PSarrayOUT->add(packet, payload);
		const int staged = stream.array2buffer_full();

		ok(staged > 0, "compressed frame is staged");
		ok(stream.queueOUT.capacity == QUEUE_OUT_COMPRESSED_SIZE,
			"compression raises the output ring to 32 KiB");
		ok(stream.queueOUT.buffer == stream.queueOUT.storage,
			"compressed frame is staged in the owned ring, not borrowed");
		ok(stream.queueOUT.head > stream.queueOUT.tail,
			"staged frame is queued for send");
		ok(stream.PSarrayOUT->len == 0,
			"consumed packet left PSarrayOUT exactly once");

		// Drain the small frame so the ring is empty for the borrow case.
		ok(stream.write_to_net() > 0,
			"small compressed frame drains before the large one");
		ok(stream.queueOUT.head == stream.queueOUT.tail,
			"owned ring is empty after the small frame");

		// Incompressible payload larger than the ring: the compressed frame
		// cannot fit and must be borrowed instead of split across the ring.
		const size_t large = 48 * 1024;
		void* large_packet = l_alloc(large);
		unsigned int seed = 0x12345678U;
		for (size_t i = 0; i < large; ++i) {
			seed = seed * 1103515245U + 12345U;
			static_cast<unsigned char*>(large_packet)[i] = static_cast<unsigned char>(seed >> 16);
		}
		stream.PSarrayOUT->add(large_packet, large);
		const int large_staged = stream.array2buffer_full();

		ok(large_staged > 0, "large compressed frame is staged");
		ok(stream.queueOUT.buffer != stream.queueOUT.storage,
			"compressed frame larger than the ring is borrowed, not copied");
		ok(stream.queueOUT.pkt.size > QUEUE_OUT_COMPRESSED_SIZE &&
			stream.queueOUT.head == stream.queueOUT.pkt.size &&
			stream.queueOUT.tail == 0,
			"borrowed span covers the whole compressed frame");
		ok(stream.PSarrayOUT->len == 0,
			"large packet left PSarrayOUT exactly once");
	}

	if (fds[0] >= 0) close(fds[0]);
	if (fds[1] >= 0) close(fds[1]);
	test_cleanup_minimal();
	return exit_status();
}
#else
int main() {
	// The compressed output ring is a PROXYSQL31 feature; v3.0 keeps the staging path.
	plan(0);
	return exit_status();
}
#endif // PROXYSQL31
