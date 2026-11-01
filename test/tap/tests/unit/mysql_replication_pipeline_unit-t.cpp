/**
 * @file mysql_replication_pipeline_unit-t.cpp
 * @brief A queued command must close a replication client before fast-forward (#6494).
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

void check_close(uint8_t command) {
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
	pkt.size = sizeof(mysql_hdr) + 1;
	pkt.ptr = l_alloc(pkt.size);
	memset(pkt.ptr, 0, sizeof(mysql_hdr) + 1);
	static_cast<unsigned char*>(pkt.ptr)[4] = command;
	// The close path must not generate a response or consume another command.
	stream->pkt_sid = 0;
	const int rc = session->GPFC_Replication_SwitchToFastForward(pkt, command);
	ok(rc == -1, "command 0x%02x: handler requests client connection closure", command);
	ok(!pkt.ptr && session->status == WAITING_CLIENT_DATA && stream->DSS == STATE_SLEEP &&
		session->session_fast_forward == SESSION_FORWARD_TYPE_NONE && session->mybe == nullptr,
		"command 0x%02x: command freed before any fast-forward state change", command);
	ok(stream->PSarrayIN->len == 1 && stream->PSarrayIN->index(0)->ptr == ping,
		"command 0x%02x: queued command is left for session teardown, not replayed", command);
	ok(stream->PSarrayOUT->len == 0,
		"command 0x%02x: no protocol reply is queued for the closing client", command);
	delete session;
}

} // namespace

int main() {
	plan(12);
	if (test_init_minimal()) BAIL_OUT("failed to initialize test globals");
	check_close(0x15);
	check_close(0x12);
	check_close(0x1e);
	test_cleanup_minimal();
	return exit_status();
}
