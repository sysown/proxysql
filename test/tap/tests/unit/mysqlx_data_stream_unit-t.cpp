#include "mysqlx_data_stream.h"
#include "tap.h"

#include <cstring>

static void test_frame_header_parse() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t frame[] = {
		0x0a, 0x00, 0x00, 0x00,
		0x01,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	};
	ds.feed_bytes(frame, sizeof(frame));
	ok(ds.has_complete_frame(), "complete frame detected");
	if (ds.has_complete_frame()) {
		auto& pkt = ds.front_frame();
		ok(pkt.size() == 14, "frame total size is 14 (4 header + 10 payload)");
		ok(pkt[4] == 0x01, "message type is 1");
	}
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "no more frames after pop");
}

static void test_partial_frame() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t hdr[] = {0x0a, 0x00, 0x00, 0x00, 0x01};
	ds.feed_bytes(hdr, 5);
	ok(!ds.has_complete_frame(), "no complete frame with header only");
	uint8_t body[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	ds.feed_bytes(body, 9);
	ok(ds.has_complete_frame(), "frame complete after body arrives");
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "empty after pop");
}

static void test_multiple_frames() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t f1[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0xAA};
	uint8_t f2[] = {0x02, 0x00, 0x00, 0x00, 0x02, 0xBB};
	uint8_t both[12];
	memcpy(both, f1, 6);
	memcpy(both + 6, f2, 6);
	ds.feed_bytes(both, 12);
	ok(ds.has_complete_frame(), "first frame ready");
	ok(ds.front_frame()[4] == 0x01, "first frame type is 1");
	ds.pop_frame();
	ok(ds.has_complete_frame(), "second frame ready");
	ok(ds.front_frame()[4] == 0x02, "second frame type is 2");
	ds.pop_frame();
	ok(!ds.has_complete_frame(), "empty after both popped");
}

static void test_frame_enqueue_write() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t body[] = {0x01, 0x02, 0x03};
	ds.enqueue_frame(0x0E, body, 3);
	ok(ds.write_buffer_size() == 8, "write buffer has 4 header + 1 msg_type + 3 body = 8 bytes");
	const auto& wb = ds.write_buffer_raw();
	ok(wb[0] == 0x04, "payload_size byte 0 is 4");
	ok(wb[4] == 0x0E, "message type is 0x0E");
}

static void test_parse_error_zero_payload() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t bad[] = {0x00, 0x00, 0x00, 0x00, 0x01};
	ds.feed_bytes(bad, 5);
	ok(ds.has_parse_error(), "zero payload_size sets parse error");
	ok(!ds.has_complete_frame(), "no frame produced after parse error");
}

static void test_parse_error_oversized_payload() {
	diag(">>> %s", __func__);
	MysqlxDataStream ds;
	uint8_t big[] = {0x01, 0x00, 0x00, 0x01, 0x01};
	ds.feed_bytes(big, 5);
	ok(ds.has_parse_error(), "oversized payload (>16MB) sets parse error");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(18);
	diag("=== mysqlx_data_stream_unit-t starting ===");

	test_frame_header_parse();
	test_partial_frame();
	test_multiple_frames();
	test_frame_enqueue_write();
	test_parse_error_zero_payload();
	test_parse_error_oversized_payload();

	return exit_status();
}
