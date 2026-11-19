/**
 * @file mysql_client_packet_size_unit-t.cpp
 * @brief Unit tests for the client packet size checks added for GHSA-w9p8-gf9c-hffr.
 *
 * - mysql_multi_packet_append_ok(): a MySQL message larger than 16MiB-1 arrives as continuation
 *   packets that MySQL_Session reassembles. The running size was a 32-bit 'PtrSize_t::size' with no
 *   limit while continuation packets kept coming: after ~256 of them it wrapped, and the next
 *   allocation was smaller than the copy into it. The reassembled message is now bounded by
 *   MYSQL_MAX_MULTI_PACKET_SIZE (1GiB), computed in 64 bits.
 * - mysql_command_packet_size_ok(): a packet with an empty payload has no command byte; reading
 *   it went one byte past the allocation.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"

#include <cstdint>

namespace {

constexpr uint64_t HDR = sizeof(mysql_hdr);
constexpr uint64_t FULL_PKT = 0xFFFFFF + HDR; // a continuation packet, header included

} // namespace

int main() {
	plan(11);

	ok(MYSQL_MAX_MULTI_PACKET_SIZE == 1024ULL * 1024 * 1024, "the reassembly limit is 1GiB");

	// Reassembled size: one header plus every payload.
	ok(mysql_multi_packet_append_ok(FULL_PKT, FULL_PKT), "a second full 16MiB packet is accepted");
	ok(mysql_multi_packet_append_ok(FULL_PKT, HDR), "empty final packet is accepted");

	{
		// Build a message up to the limit, one full packet at a time, as the session does.
		uint64_t acc = FULL_PKT;
		uint64_t n = 1;
		while (mysql_multi_packet_append_ok(acc, FULL_PKT)) {
			acc += FULL_PKT - HDR;
			n++;
		}
		ok(acc - HDR <= MYSQL_MAX_MULTI_PACKET_SIZE && acc - HDR + (FULL_PKT - HDR) > MYSQL_MAX_MULTI_PACKET_SIZE,
			"full packets are accepted up to the limit, the next one is refused (%llu packets, payload %llu)",
			(unsigned long long)n, (unsigned long long)(acc - HDR));
		ok(acc <= UINT32_MAX, "an accepted message always fits in the 32-bit PtrSize_t::size");

		const uint64_t room = MYSQL_MAX_MULTI_PACKET_SIZE - (acc - HDR);
		ok(mysql_multi_packet_append_ok(acc, room + HDR), "a final packet filling the limit exactly is accepted");
		ok(!mysql_multi_packet_append_ok(acc, room + HDR + 1), "one byte over the limit is refused");
	}

	// The sizes at which the 32-bit running total used to wrap.
	ok(!mysql_multi_packet_append_ok(256 * (FULL_PKT - HDR) + HDR, FULL_PKT),
		"a message of ~4GiB (where the 32-bit size wrapped) is refused");
	ok(!mysql_multi_packet_append_ok(UINT32_MAX, FULL_PKT), "a running size at UINT32_MAX is refused");

	ok(!mysql_command_packet_size_ok(HDR), "command packet with an empty payload is refused");
	ok(mysql_command_packet_size_ok(HDR + 1), "command packet with just the command byte is accepted");

	return exit_status();
}
