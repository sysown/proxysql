/**
 * @file mysql_replication_pipeline_unit-t.cpp
 * @brief Exercise replication rejection with a deterministically queued packet (#6494).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#define private public
#include "cpp.h"
#undef private
#include "MySQL_Data_Stream.h"

#include <cstdint>
#include <cstring>

namespace {

void check_rejection(uint8_t command, uint32_t payload_size, uint8_t expected_sequence) {
	MySQL_Session* session = new MySQL_Session();
	session->connections_handler = true;
	session->set_status(WAITING_CLIENT_DATA);
	MySQL_Data_Stream* stream = new MySQL_Data_Stream();
	stream->init(MYDS_FRONTEND, session, -1);
	stream->DSS = STATE_SLEEP;
	session->client_myds = stream;
	stream->myprot.init(&session->client_myds, nullptr, session);

	// This packet is already queued before the real handler is called: no TCP
	// segmentation or scheduler timing is involved in reaching the guard.
	unsigned char* ping = static_cast<unsigned char*>(l_alloc(5));
	const unsigned char ping_bytes[] = {1, 0, 0, 0, 0x0e};
	memcpy(ping, ping_bytes, sizeof(ping_bytes));
	stream->PSarrayIN->add(ping, sizeof(ping_bytes));

	PtrSize_t pkt {};
	pkt.size = sizeof(mysql_hdr) + payload_size;
	pkt.ptr = l_alloc(pkt.size);
	memset(pkt.ptr, 0, sizeof(mysql_hdr) + 1);
	static_cast<unsigned char*>(pkt.ptr)[4] = command;
	// A later pipelined packet can overwrite this stream-wide sequence ID.
	stream->pkt_sid = 0;
	const int rc = session->GPFC_Replication_SwitchToFastForward(pkt, command);
	ok(rc == 0 && !pkt.ptr && session->status == WAITING_CLIENT_DATA && stream->DSS == STATE_SLEEP &&
		session->session_fast_forward == SESSION_FORWARD_TYPE_NONE && session->mybe == nullptr,
		"command 0x%02x: rejected without switching session state", command);
	ok(stream->PSarrayIN->len == 1 && stream->PSarrayIN->index(0)->ptr == ping,
		"command 0x%02x: following packet remains queued", command);
	bool reply_ok = false;
	if (stream->PSarrayOUT->len == 1) {
		const PtrSize_t* reply = stream->PSarrayOUT->index(0);
		const unsigned char* p = static_cast<const unsigned char*>(reply->ptr);
		reply_ok = reply->size >= 13 && p[3] == expected_sequence && p[4] == 0xff &&
			p[5] == 0x17 && p[6] == 0x07 && memcmp(p + 7, "#HY000", 6) == 0;
	}
	ok(reply_ok, "command 0x%02x: ERR 1815/HY000 has sequence %u", command, expected_sequence);
	delete session;
}

} // namespace

int main() {
	plan(12);
	if (test_init_minimal()) BAIL_OUT("failed to initialize test globals");
	check_rejection(0x15, 1, 1);
	check_rejection(0x12, 1, 1);
	check_rejection(0x1e, 1, 1);
	check_rejection(0x1e, 0x1000000, 2);
	test_cleanup_minimal();
	return exit_status();
}
