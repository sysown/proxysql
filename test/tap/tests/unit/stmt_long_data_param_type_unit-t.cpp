/**
 * @file stmt_long_data_param_type_unit-t.cpp
 * @brief Empty long-data entries must retain their parameter-type semantics.
 * @see https://github.com/sysown/proxysql/issues/6406
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_Protocol.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"

#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

constexpr uint32_t kStmtId = 6406;

/** @brief Builds a single-parameter execution, optionally with an inline INT. */
PtrSize_t execute_packet(enum enum_field_types type, bool inline_value) {
	PtrSize_t pkt;
	pkt.size = 18 + (inline_value ? 4 : 0);
	pkt.ptr = calloc(1, pkt.size);
	auto* p = static_cast<unsigned char*>(pkt.ptr);
	p[0] = pkt.size - 4;
	p[4] = 0x17;
	memcpy(p + 5, &kStmtId, sizeof(kStmtId));
	p[10] = 1; // iteration count
	p[15] = 1; // new_params_bound_flag
	p[16] = type;
	if (inline_value) p[18] = 42;
	return pkt;
}

/** @brief Exercises empty long data on fresh and previously used metadata. */
void test_empty_long_data(MySQL_STMT_Global_info* info, bool cached) {
	MySQL_Session session;
	session.connections_handler = true; // No hostgroup manager in this decoder-only test.
	MySQL_Data_Stream stream;
	MySQL_Data_Stream* stream_ptr = &stream;
	stream.sess = &session;
	stream.myprot.init(&stream_ptr, nullptr, &session);
	stmt_execute_metadata_t* meta = nullptr;
	if (cached) {
		PtrSize_t pkt = execute_packet(MYSQL_TYPE_LONG, true);
		meta = stream.myprot.get_binds_from_pkt(pkt, info, &meta, nullptr);
		ok(meta != nullptr, "ordinary INT initializes cached metadata");
		if (!meta) { free(pkt.ptr); return; }
		free(meta->pkt);
		meta->pkt = nullptr;
	}

	char empty = 0;
	session.SLDH->add(kStmtId, 0, &empty, 0);
	session.SLDH->add(kStmtId, 0, &empty, 0);
	unsigned long* length = nullptr;
	my_bool* is_null = nullptr;
	void* data = session.SLDH->get(kStmtId, 0, &length, &is_null);
	ok(length && *length == 0,
		"%s metadata: two empty chunks retain a zero-length entry", cached ? "cached" : "fresh");
	diag("Empty long-data buffer is %s", data ? "non-null on this allocator" : "null");

	// Extra inline bytes must not bypass the rejection of a non-string type.
	PtrSize_t pkt = execute_packet(MYSQL_TYPE_LONG, true);
	stmt_execute_metadata_t* ret = stream.myprot.get_binds_from_pkt(pkt, info, &meta, nullptr);
	ok(ret == nullptr, "%s metadata: empty long data for INT is rejected", cached ? "cached" : "fresh");
	if (ret) {
		ret->pkt = nullptr;
		if (ret != meta) delete ret;
	}
	free(pkt.ptr);

	// The same empty entry is valid for a string, with no inline value bytes.
	pkt = execute_packet(MYSQL_TYPE_STRING, false);
	ret = stream.myprot.get_binds_from_pkt(pkt, info, &meta, nullptr);
	ok(ret && ret->binds[0].buffer && *ret->binds[0].length == 0 && !*ret->binds[0].is_null,
		"%s metadata: empty string long data is accepted", cached ? "cached" : "fresh");
	if (ret) {
		ret->pkt = nullptr;
		if (ret != meta) delete ret;
	}
	free(pkt.ptr);
	delete meta;
}

} // namespace

int main() {
	plan(13);
	test_init_minimal();
	MYSQL* mysql = mysql_init(nullptr);
	MYSQL_STMT* stmt = mysql ? mysql_stmt_init(mysql) : nullptr;
	ok(stmt != nullptr, "created statement handle");
	if (stmt) {
		stmt->param_count = 1;
		char user[] = "user", schema[] = "schema", query[] = "SELECT ?";
		MySQL_STMT_Global_info info(1, user, schema, query, strlen(query), nullptr, stmt, 1);
		test_empty_long_data(&info, false);
		test_empty_long_data(&info, true);
		mysql_stmt_close(stmt);
	}
 {
  StmtLongDataHandler data;
  bool appended = true;
  ok(data.add_checked(7, 0, nullptr, 0, &appended) && !appended, "checked empty chunk creates a non-null entry");
  const char bytes[] = {'a', 0, 'b'};
  ok(data.add_checked(7, 0, bytes, sizeof(bytes), &appended) && appended, "checked append preserves binary bytes");
  ok(!data.add_checked(7, 0, bytes, std::numeric_limits<unsigned long>::max()), "overflowing append is refused");
  unsigned long *length = nullptr; my_bool *is_null = nullptr;
  void *stored = data.get(7, 0, &length, &is_null);
  ok(stored && length && *length == sizeof(bytes) && !memcmp(stored, bytes, sizeof(bytes)), "failed append leaves original value intact");
  ok(!data.add_checked(7, 1, nullptr, 1), "nonempty null input is refused");
 }
	if (mysql) mysql_close(mysql);
	test_cleanup_minimal();
	return exit_status();
}
