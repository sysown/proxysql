/**
 * @file stmt_execute_short_packet_unit-t.cpp
 * @brief Unit tests for MySQL_Protocol::get_binds_from_pkt() on a truncated
 *   COM_STMT_EXECUTE packet.
 *
 * get_binds_from_pkt() stores the packet in stmt_execute_metadata_t::pkt, and
 * the metadata destructor frees it. When the packet was too short to hold the
 * NULL bitmap and the new-params-bound flag, the function deleted the metadata
 * without detaching the packet, while its caller frees the packet too
 * (double-free). If the metadata came from the per-session cache
 * (sess_STMTs_meta), the cache was also left with a dangling pointer.
 *
 * The session-level check on the parameter types rejects these packets before
 * bind decoding, so the path is not reachable through the protocol anymore;
 * this test exercises the function directly.
 *
 * @see https://github.com/sysown/proxysql/issues/6233
 * @see https://github.com/sysown/proxysql/issues/6229
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Protocol.h"
#include "MySQL_PreparedStatement.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

// Fill freed memory with 0x5a, so that a packet or cached metadata wrongly
// freed by get_binds_from_pkt() is detected by the checks below instead of
// silently passing (with the old code, the destructor sets 'pkt' to NULL right
// before freeing the metadata, and the packet contents may survive the free).
extern "C" const char* malloc_conf;
const char* malloc_conf = "junk:true";

namespace {

constexpr uint32_t kStmtId = 6233;

/**
 * @brief Builds a COM_STMT_EXECUTE packet that stops right after the
 *   iteration count: 4 bytes header + command + stmt_id + flags + iterations.
 *   With at least one parameter, the NULL bitmap and the new-params-bound flag
 *   are missing.
 */
constexpr size_t kTruncatedPktSize = 14;

void fill_truncated_execute_pkt(unsigned char* p) {
	memset(p, 0, kTruncatedPktSize);
	p[0] = kTruncatedPktSize - 4; // payload length
	p[4] = 0x17;                  // COM_STMT_EXECUTE
	memcpy(p + 5, &kStmtId, sizeof(kStmtId));
	p[9] = 0;                     // flags: CURSOR_TYPE_NO_CURSOR
	p[10] = 1;                    // iteration count
}

PtrSize_t build_truncated_execute_pkt() {
	PtrSize_t pkt;
	pkt.size = kTruncatedPktSize;
	pkt.ptr = malloc(pkt.size);
	fill_truncated_execute_pkt(static_cast<unsigned char*>(pkt.ptr));
	return pkt;
}

/**
 * @brief Tells whether the packet still holds what build_truncated_execute_pkt()
 *   wrote, i.e. it was not freed (and junk-filled) by get_binds_from_pkt().
 */
bool packet_intact(const PtrSize_t& pkt) {
	// Not heap-allocated: a malloc() of the same size could get the chunk just
	// freed by get_binds_from_pkt() back, and rewrite the expected bytes in it.
	unsigned char expected[kTruncatedPktSize];
	fill_truncated_execute_pkt(expected);
	return pkt.size == kTruncatedPktSize && memcmp(expected, pkt.ptr, kTruncatedPktSize) == 0;
}

/**
 * @brief Creates the global statement info of 'SELECT ?, ?' (two parameters,
 *   no columns), without contacting any backend.
 */
MySQL_STMT_Global_info* make_stmt_info(MYSQL** mysql, MYSQL_STMT** stmt) {
	*mysql = mysql_init(nullptr);
	*stmt = *mysql ? mysql_stmt_init(*mysql) : nullptr;
	if (*stmt == nullptr) {
		return nullptr;
	}
	(*stmt)->param_count = 2;
	(*stmt)->field_count = 0;
	char user[] = "user";
	char schema[] = "schema";
	char query[] = "SELECT ?, ?";
	return new MySQL_STMT_Global_info(1, user, schema, query, strlen(query), nullptr, *stmt, 1);
}

void test_first_execute(MySQL_STMT_Global_info* stmt_info) {
	MySQL_Protocol protocol;
	PtrSize_t pkt = build_truncated_execute_pkt();
	stmt_execute_metadata_t* stmt_meta = nullptr;

	stmt_execute_metadata_t* ret = protocol.get_binds_from_pkt(pkt, stmt_info, &stmt_meta, nullptr);
	ok(ret == nullptr, "first execute: truncated packet is rejected");
	ok(stmt_meta == nullptr, "first execute: no metadata is handed back to the caller");

	// The caller still owns the packet and frees it, as the session does.
	ok(packet_intact(pkt), "first execute: packet left to the caller, not freed by get_binds_from_pkt()");
	l_free(pkt.size, pkt.ptr);
}

void test_cached_metadata(MySQL_STMT_Global_info* stmt_info) {
	MySQL_Protocol protocol;
	PtrSize_t pkt = build_truncated_execute_pkt();
	// Metadata of a previous execution, as stored in sess_STMTs_meta.
	stmt_execute_metadata_t* cached = new stmt_execute_metadata_t();
	stmt_execute_metadata_t* stmt_meta = cached;

	stmt_execute_metadata_t* ret = protocol.get_binds_from_pkt(pkt, stmt_info, &stmt_meta, nullptr);
	ok(ret == nullptr, "cached metadata: truncated packet is rejected");
	// The cached metadata must still be alive (it is still referenced by the
	// cache) and must not keep a pointer to the packet the caller frees.
	ok(cached->pkt == nullptr, "cached metadata: packet detached from the cached metadata");

	ok(packet_intact(pkt), "cached metadata: packet left to the caller, not freed by get_binds_from_pkt()");
	l_free(pkt.size, pkt.ptr);
	delete cached;
}

} // namespace

int main() {
	plan(7);

	test_init_minimal();

	MYSQL* mysql = nullptr;
	MYSQL_STMT* stmt = nullptr;
	MySQL_STMT_Global_info* stmt_info = make_stmt_info(&mysql, &stmt);
	ok(stmt_info != nullptr && stmt_info->num_params == 2, "Created statement info with 2 parameters");

	if (stmt_info != nullptr) {
		test_first_execute(stmt_info);   // 3 tests
		test_cached_metadata(stmt_info); // 3 tests
		delete stmt_info;
	}
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	if (mysql) {
		mysql_close(mysql);
	}

	test_cleanup_minimal();

	return exit_status();
}
