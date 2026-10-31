/** Regression for #6430: binary rows use payload lengths, not framed lengths. */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "MySQL_Protocol.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Thread.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {
constexpr size_t packet_limit = 16777215;
constexpr size_t guard_size = 32;
// Literal sizes independently pin every affected size, both controls, and an
// exact multiple needing two full packets plus an empty terminal packet.
const size_t lengths[] = {0, 1, 12582911, 12582912, 16777214, 16777215, 16777216,
	16777217, 16777218, 16777219, 33554430};

size_t framed_size(size_t length) {
	return length + 4 * (length / packet_limit + 1);
}

std::vector<unsigned char> pattern(size_t length) {
	std::vector<unsigned char> data(length);
	for (size_t i = 0; i < length; ++i) data[i] = 1 + i % 127;
	return data;
}

// Decode bytes rather than mysql_hdr's bitfields. Compare every payload byte
// and require the short terminal packet, including a zero-length terminator.
bool check_row(const unsigned char* wire, size_t available,
	const std::vector<unsigned char>& data, uint8_t first_sid, size_t* consumed) {
	size_t offset = 0, copied = 0;
	unsigned int packet = 0;
	for (;;) {
		if (available - offset < 4) return false;
		const size_t length = wire[offset] | (size_t(wire[offset + 1]) << 8)
			| (size_t(wire[offset + 2]) << 16);
		const size_t expected = std::min(packet_limit, data.size() - copied);
		if (length != expected || wire[offset + 3] != uint8_t(first_sid + packet)) return false;
		offset += 4;
		if (length > available - offset) return false;
		if (length && memcmp(wire + offset, data.data() + copied, length)) return false;
		offset += length;
		copied += length;
		++packet;
		if (length < packet_limit) break;
	}
	*consumed = offset;
	return copied == data.size();
}

void test_add_row2(size_t length) {
	auto data = pattern(length);
	unsigned char empty_payload = 0;
	MYSQL_ROWS row {};
	row.length = length;
	row.data = reinterpret_cast<MYSQL_ROW>(length ? data.data() : &empty_payload);
	const size_t size = framed_size(length);
	std::vector<unsigned char> guarded(size + 2 * guard_size, 0xAA);
	MySQL_ResultSet rs;
	rs.sid = 254; // Multi-packet rows must wrap 255 -> 0.
	rs.num_rows = 0;
	const unsigned int returned = rs.add_row2(&row, guarded.data() + guard_size);
	size_t consumed = 0;
	ok(check_row(guarded.data() + guard_size, size, data, 254, &consumed)
		&& consumed == size, "add_row2 payload=%zu: complete framing, sequence and payload; no unwritten tail", length);
	ok(std::all_of(guarded.begin(), guarded.begin() + guard_size,
		[](unsigned char c) { return c == 0xAA; })
		&& std::all_of(guarded.end() - guard_size, guarded.end(),
		[](unsigned char c) { return c == 0xAA; }),
		"add_row2 payload=%zu: both allocation canaries intact", length);
	ok(returned == length && rs.num_rows == 1
		&& rs.sid == uint8_t(254 + length / packet_limit + 1),
		"add_row2 payload=%zu: returned payload length, row count and next sequence", length);
}

void test_init_with_stmt(size_t length) {
	// Mix small and large rows to exercise allocation and offset calculations in
	// both the aggregate buffer and the large-result batching paths.
	std::vector<std::vector<unsigned char>> data {pattern(3), pattern(length), pattern(7)};
	unsigned char empty_payload = 0;
	MYSQL_ROWS rows[3] {};
	for (size_t i = 0; i < 3; ++i) {
		rows[i].length = data[i].size();
		rows[i].data = reinterpret_cast<MYSQL_ROW>(data[i].empty() ? &empty_payload : data[i].data());
		rows[i].next = i < 2 ? &rows[i + 1] : nullptr;
	}
	MYSQL* mysql = mysql_init(nullptr);
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	MYSQL_RES metadata {};
	MySQL_Thread worker;
	worker.atomic_curtime = 0;
	MySQL_Session session;
	session.thread = &worker;
	session.connections_handler = true; // No hostgroup client-counter registration.
	MySQL_Data_Stream stream;
	MySQL_Data_Stream* stream_ptr = &stream;
	stream.sess = &session;
	stream.myds_type = MYDS_FRONTEND;
	stream.com_field_list = false;
	stream.pkt_sid = 250;
	stream.myprot.init(&stream_ptr, nullptr, &session);
	{
		MySQL_ResultSet rs;
		rs.init(&stream.myprot, &metadata, mysql, stmt);
		rs.buffer_to_PSarrayOut();
		const unsigned int first_entry = rs.PSarrayOUT.len;
		const uint8_t first_sid = rs.sid;
		const auto initial_size = rs.resultset_size;
		stmt->result.data = rows;
		rs.init_with_stmt(nullptr); // errno=0: no backend connection is required.
		stmt->result.data = nullptr; // Stack rows remain owned by this fixture.
		std::vector<unsigned char> wire;
		for (unsigned int i = first_entry; i + 1 < rs.PSarrayOUT.len; ++i) {
			const PtrSize_t* pkt = rs.PSarrayOUT.index(i);
			const auto* p = static_cast<const unsigned char*>(pkt->ptr);
			wire.insert(wire.end(), p, p + pkt->size);
		}
		size_t offset = 0;
		uint8_t sid = first_sid;
		bool valid = true;
		for (const auto& payload : data) {
			size_t consumed = 0;
			if (!check_row(wire.data() + offset, wire.size() - offset, payload, sid, &consumed)) {
				valid = false;
				break;
			}
			offset += consumed;
			sid += payload.size() / packet_limit + 1;
		}
		const size_t expected = framed_size(3) + framed_size(length) + framed_size(7);
		ok(valid && offset == wire.size() && wire.size() == expected,
			"init_with_stmt payload=%zu: advertised allocations contain precisely all three framed rows", length);
		const PtrSize_t* eof = rs.PSarrayOUT.index(rs.PSarrayOUT.len - 1);
		const auto* p = static_cast<const unsigned char*>(eof->ptr);
		ok(eof->size == 9 && p[0] == 5 && p[3] == sid && p[4] == 0xFE
			&& rs.sid == uint8_t(sid + 1) && rs.num_rows == 3
			&& rs.resultset_completed && rs.resultset_size == initial_size + expected + 9,
			"init_with_stmt payload=%zu: EOF follows complete rows with exact size and sequence accounting", length);
		if (length == 33554430) {
			ok(worker.atomic_curtime.load() != 0,
				"init_with_stmt refreshes the worker heartbeat after 32 MiB of output");
		}
	}
	mysql_stmt_close(stmt);
	mysql_close(mysql);
}
} // namespace

int main() {
	plan(5 * (sizeof(lengths) / sizeof(lengths[0])) + 1);
	test_init_minimal();
	for (size_t length : lengths) {
		test_add_row2(length);
		test_init_with_stmt(length);
	}
	test_cleanup_minimal();
	return exit_status();
}
