/**
 * mysqlx_protocol_socket_unit-t.cpp
 *
 * Socket-based I/O roundtrip tests for X Protocol frame handling.
 */

#include "mysqlx_protocol.h"
#include "ProxySQL_PluginListenerGate.h"
#include "tap.h"

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(23);
	diag("=== mysqlx_protocol_socket_unit-t starting ===");
	signal(SIGPIPE, SIG_IGN);

	// --- Frame I/O roundtrip (8 tests) ---

	// Test 1: write_all + read_exact roundtrip
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		uint8_t write_buf[10] = {0,1,2,3,4,5,6,7,8,9};
		mysqlx_write_all(fds[0], write_buf, 10);
		uint8_t read_buf[10] = {};
		bool ok_read = mysqlx_read_exact(fds[1], read_buf, 10);
		ok(ok_read && memcmp(write_buf, read_buf, 10) == 0,
		   "write_all + read_exact roundtrip preserves data");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 2: build_frame + write_all → read_frame roundtrip
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string payload = "test payload";
		auto frame = mysqlx_build_frame(42, payload);
		mysqlx_write_all(fds[0], frame.data(), frame.size());
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> recv_payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, recv_payload);
		ok(ok_read && hdr.message_type == 42 &&
		   recv_payload.size() == payload.size() &&
		   memcmp(recv_payload.data(), payload.data(), payload.size()) == 0,
		   "build_frame + write_all → read_frame roundtrip matches");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 3: Two frames in FIFO order
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string p1 = "first";
		std::string p2 = "second";
		auto f1 = mysqlx_build_frame(1, p1);
		auto f2 = mysqlx_build_frame(2, p2);
		mysqlx_write_all(fds[0], f1.data(), f1.size());
		mysqlx_write_all(fds[0], f2.data(), f2.size());

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok1 = mysqlx_read_frame(fds[1], hdr, payload);
		bool match1 = ok1 && hdr.message_type == 1 &&
		              payload.size() == p1.size() &&
		              memcmp(payload.data(), p1.data(), p1.size()) == 0;
		bool ok2 = mysqlx_read_frame(fds[1], hdr, payload);
		bool match2 = ok2 && hdr.message_type == 2 &&
		              payload.size() == p2.size() &&
		              memcmp(payload.data(), p2.data(), p2.size()) == 0;
		ok(match1 && match2, "two frames read in FIFO order with correct payloads");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 4: Close peer, read_frame returns false (EOF)
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		close(fds[1]);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		ok(!mysqlx_read_frame(fds[0], hdr, payload),
		   "read_frame returns false after peer closed");
		close(fds[0]);
	}

	// Test 5: Close peer, write_all returns false (EPIPE)
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		close(fds[0]);
		uint8_t buf[5] = {};
		ok(!mysqlx_write_all(fds[1], buf, 5),
		   "write_all returns false after peer closed (EPIPE)");
		close(fds[1]);
	}

	// Test 6: read_exact with len=0 returns true
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		uint8_t buf[1];
		ok(mysqlx_read_exact(fds[0], buf, 0),
		   "read_exact with len=0 returns true immediately");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 7: Frame with payload_size=1 (just message_type)
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string empty_payload;
		auto frame = mysqlx_build_frame(7, empty_payload);
		mysqlx_write_all(fds[0], frame.data(), frame.size());
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read && payload.empty() && hdr.message_type == 7,
		   "frame with payload_size=1 reads with empty payload");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 8: read_frame rejects payload_size > MYSQLX_MAX_PAYLOAD_SIZE
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		uint32_t huge = MYSQLX_MAX_PAYLOAD_SIZE + 1;
		uint8_t hdr_buf[5];
		hdr_buf[0] = static_cast<uint8_t>(huge & 0xFF);
		hdr_buf[1] = static_cast<uint8_t>((huge >> 8) & 0xFF);
		hdr_buf[2] = static_cast<uint8_t>((huge >> 16) & 0xFF);
		hdr_buf[3] = static_cast<uint8_t>((huge >> 24) & 0xFF);
		hdr_buf[4] = 1;
		mysqlx_write_all(fds[0], hdr_buf, 5);
		close(fds[0]);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		ok(!mysqlx_read_frame(fds[1], hdr, payload),
		   "read_frame rejects payload_size > MYSQLX_MAX_PAYLOAD_SIZE");
		close(fds[1]);
	}

	// --- Error/OK send+receive (6 tests) ---

	// Test 9: send_error → read_frame succeeds
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1045, "Access denied", "28000");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		ok(mysqlx_read_frame(fds[1], hdr, payload),
		   "send_error → read_frame succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 10: send_ok → read_frame succeeds
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_ok(fds[0]);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		ok(mysqlx_read_frame(fds[1], hdr, payload),
		   "send_ok → read_frame succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 11: send_error(1045, "Access denied") → payload non-empty
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1045, "Access denied", "28000");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read && !payload.empty(),
		   "send_error(1045, \"Access denied\") → payload non-empty");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 12: send_ok with 256-char message → payload > 256
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string long_msg(256, 'A');
		mysqlx_send_ok(fds[0], long_msg);
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok_read && payload.size() > 256,
		   "send_ok with 256-char message → payload > 256");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 13: Multiple interleaved send_error + send_ok
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1001, "first", "HY000");
		mysqlx_send_ok(fds[0], "second");
		mysqlx_send_error(fds[0], 1002, "third", "HY000");

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok1 = mysqlx_read_frame(fds[1], hdr, payload);
		bool ok2 = mysqlx_read_frame(fds[1], hdr, payload);
		bool ok3 = mysqlx_read_frame(fds[1], hdr, payload);
		ok(ok1 && ok2 && ok3, "interleaved error/ok → all reads succeed");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 14: send_error with default sql_state
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		mysqlx_send_error(fds[0], 1045, "test error");
		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		ok(mysqlx_read_frame(fds[1], hdr, payload),
		   "send_error with default sql_state → read succeeds");
		close(fds[0]);
		close(fds[1]);
	}

	// --- Large frames (6 tests) ---

	// Test 15: 64KB payload roundtrip
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string payload_64k(64 * 1024, 'X');
		auto frame = mysqlx_build_frame(1, payload_64k);

		std::thread writer([fd0 = fds[0], &frame]() {
			mysqlx_write_all(fd0, frame.data(), frame.size());
			close(fd0);
		});

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> recv_payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, recv_payload);
		writer.join();

		bool match = ok_read && recv_payload.size() == payload_64k.size() &&
		             memcmp(recv_payload.data(), payload_64k.data(), payload_64k.size()) == 0;
		ok(match, "64KB payload frame roundtrip succeeds, payload matches");
		close(fds[1]);
	}

	// Test 16: 1MB payload roundtrip
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string payload_1m(1024 * 1024, 'Y');
		auto frame = mysqlx_build_frame(2, payload_1m);

		std::thread writer([fd0 = fds[0], &frame]() {
			mysqlx_write_all(fd0, frame.data(), frame.size());
			close(fd0);
		});

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> recv_payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, recv_payload);
		writer.join();

		bool match = ok_read && recv_payload.size() == payload_1m.size() &&
		             memcmp(recv_payload.data(), payload_1m.data(), payload_1m.size()) == 0;
		ok(match, "1MB payload frame roundtrip succeeds, payload matches");
		close(fds[1]);
	}

	// Test 17: MYSQLX_MAX_PAYLOAD_SIZE - 1 payload boundary
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string payload_boundary(static_cast<size_t>(MYSQLX_MAX_PAYLOAD_SIZE) - 1, 'Z');
		auto frame = mysqlx_build_frame(3, payload_boundary);

		std::thread writer([fd0 = fds[0], &frame]() {
			mysqlx_write_all(fd0, frame.data(), frame.size());
			close(fd0);
		});

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> recv_payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, recv_payload);
		writer.join();

		ok(ok_read, "MYSQLX_MAX_PAYLOAD_SIZE-1 payload boundary roundtrip succeeds");
		close(fds[1]);
	}

	// Test 18: 10 small frames rapidly
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		const int N = 10;
		std::string payloads[N];
		for (int i = 0; i < N; i++) {
			payloads[i] = "frame_" + std::to_string(i);
			auto f = mysqlx_build_frame(static_cast<uint8_t>(i), payloads[i]);
			mysqlx_write_all(fds[0], f.data(), f.size());
		}

		bool all_ok = true;
		for (int i = 0; i < N; i++) {
			MysqlxFrameHeader hdr;
			std::vector<uint8_t> payload;
			if (!mysqlx_read_frame(fds[1], hdr, payload)) { all_ok = false; break; }
			if (payload.size() != payloads[i].size() ||
			    memcmp(payload.data(), payloads[i].data(), payloads[i].size()) != 0) {
				all_ok = false; break;
			}
		}
		ok(all_ok, "10 small frames written rapidly all read correctly in order");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 19: Binary data with null bytes
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string binary_payload("\x00\x01\x02\x00\xFF\xFE", 6);
		auto frame = mysqlx_build_frame(10, binary_payload);
		mysqlx_write_all(fds[0], frame.data(), frame.size());

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		bool match = ok_read && payload.size() == binary_payload.size() &&
		             memcmp(payload.data(), binary_payload.data(), binary_payload.size()) == 0;
		ok(match, "binary data with null bytes preserved in roundtrip");
		close(fds[0]);
		close(fds[1]);
	}

	// Test 20: All-0xFF payload
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		std::string ff_payload(256, '\xFF');
		auto frame = mysqlx_build_frame(11, ff_payload);
		mysqlx_write_all(fds[0], frame.data(), frame.size());

		MysqlxFrameHeader hdr;
		std::vector<uint8_t> payload;
		bool ok_read = mysqlx_read_frame(fds[1], hdr, payload);
		bool match = ok_read && payload.size() == ff_payload.size() &&
		             memcmp(payload.data(), ff_payload.data(), ff_payload.size()) == 0;
		ok(match, "all-0xFF payload preserved in roundtrip");
		close(fds[0]);
		close(fds[1]);
	}

	// Tests 21-23: listener readiness decisions happen before protocol setup.
	// A closed gate must close the accepted socket without producing any
	// handshake; ready and unrelated listeners leave the socket untouched.
	{
		const ProxySQL_PluginListenerGate closed {
			"socket-test", "127.0.0.1", 6450,
			ProxySQL_PluginListenerState::closed, "initial reconcile pending"
		};
		proxysql_plugin_set_listener_gate(closed);
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		const auto decision = proxysql_plugin_listener_gate_close_if_closed(
			"127.0.0.1", 6450, fds[0], 1);
		char byte = '\0';
		ok(decision && decision->reject && recv(fds[1], &byte, 1, 0) == 0,
			"closed listener gate closes accepted socket before a handshake");
		close(fds[1]);

		const ProxySQL_PluginListenerGate ready {
			"socket-test", "127.0.0.1", 6451,
			ProxySQL_PluginListenerState::ready, "reconciled"
		};
		proxysql_plugin_set_listener_gate(ready);
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		const auto ready_decision = proxysql_plugin_listener_gate_close_if_closed(
			"127.0.0.1", 6451, fds[0], 2);
		const char ready_byte = 'R';
		write(fds[0], &ready_byte, 1);
		ok(!ready_decision && recv(fds[1], &byte, 1, 0) == 1 && byte == ready_byte,
			"ready listener gate leaves the normal handshake socket path unchanged");
		close(fds[0]);
		close(fds[1]);

		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		const auto unrelated_decision = proxysql_plugin_listener_gate_close_if_closed(
			"127.0.0.1", 6452, fds[0], 3);
		const char unrelated_byte = 'U';
		write(fds[0], &unrelated_byte, 1);
		ok(!unrelated_decision && recv(fds[1], &byte, 1, 0) == 1 && byte == unrelated_byte,
			"unrelated listener leaves the normal handshake socket path unchanged");
		close(fds[0]);
		close(fds[1]);
	}

	return exit_status();
}
