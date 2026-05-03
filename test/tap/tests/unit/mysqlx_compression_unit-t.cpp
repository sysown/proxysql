// X Protocol compression unit tests.
//
// Phase 1 (capability negotiation):
//   - send_capabilities() advertises a `compression` capability listing the
//     algorithms we support (zstd_stream, lz4_message).
//   - handler_capabilities_set() accepts a supported algorithm and stores it
//     on the session, plus the optional combine_* hints.
//   - handler_capabilities_set() rejects an unknown algorithm with
//     X-Protocol error 5052 and leaves the session healthy (capability
//     failures are non-fatal — the client may retry or proceed without
//     compression).
//
// These tests drive MysqlxSession through a socketpair the same way the
// existing mysqlx_session_unit-t tests do — there is no plugin loader / IO
// thread involvement, just direct frame bytes pushed through handler().

#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_sql.pb.h"

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <vector>

#include <zstd.h>
#include <lz4.h>

static void write_x_frame(int fd, uint8_t msg_type, const uint8_t* payload, size_t payload_len) {
	uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	uint8_t header[5];
	header[0] = size & 0xFF;
	header[1] = (size >> 8) & 0xFF;
	header[2] = (size >> 16) & 0xFF;
	header[3] = (size >> 24) & 0xFF;
	header[4] = msg_type;
	(void)!write(fd, header, 5);
	if (payload_len > 0) {
		(void)!write(fd, payload, payload_len);
	}
}

static ssize_t read_x_frame(int fd, uint8_t* buf, size_t buf_size) {
	uint8_t header[5];
	ssize_t r = read(fd, header, 5);
	if (r != 5) return -1;
	uint32_t payload_size = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
	if (5 + payload_size > buf_size) return -1;
	memcpy(buf, header, 5);
	if (payload_size > 1) {
		r = read(fd, buf + 5, payload_size - 1);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return 4 + payload_size;
}

// Non-blocking read variant for the Phase 2/3 tests where the session may
// legitimately not produce any output (because the dispatched message goes
// to a backend the test doesn't fake out). Returns -1 immediately if no
// data is available; -1 + errno EAGAIN should be treated as "no response".
static ssize_t try_read_x_frame_nonblocking(int fd, uint8_t* buf, size_t buf_size) {
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	ssize_t r = read_x_frame(fd, buf, buf_size);
	fcntl(fd, F_SETFL, flags);
	return r;
}

// Helper: build a CapabilitiesSet message that tries to set the `compression`
// capability with the given algorithm name. Returns the serialized protobuf
// payload (not the X frame — caller wraps that).
static std::string build_compression_capset(const char* algorithm,
                                            bool with_combine_mixed = false,
                                            bool combine_mixed_value = true,
                                            bool with_max_combine = false,
                                            uint64_t max_combine_value = 0) {
	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* caps = cap_set.mutable_capabilities();
	auto* cap = caps->add_capabilities();
	cap->set_name("compression");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::OBJECT);
	auto* obj = val->mutable_obj();

	auto* algo_field = obj->add_fld();
	algo_field->set_key("algorithm");
	auto* algo_any = algo_field->mutable_value();
	algo_any->set_type(Mysqlx::Datatypes::Any::SCALAR);
	algo_any->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	algo_any->mutable_scalar()->mutable_v_string()->set_value(algorithm);

	if (with_combine_mixed) {
		auto* f = obj->add_fld();
		f->set_key("server_combine_mixed_messages");
		auto* a = f->mutable_value();
		a->set_type(Mysqlx::Datatypes::Any::SCALAR);
		a->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_BOOL);
		a->mutable_scalar()->set_v_bool(combine_mixed_value);
	}
	if (with_max_combine) {
		auto* f = obj->add_fld();
		f->set_key("server_max_combine_messages");
		auto* a = f->mutable_value();
		a->set_type(Mysqlx::Datatypes::Any::SCALAR);
		a->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_UINT);
		a->mutable_scalar()->set_v_unsigned_int(max_combine_value);
	}

	std::string out;
	cap_set.SerializeToString(&out);
	return out;
}

static void test_capabilities_advertise_compression() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);
	sess.handler();

	uint8_t buf[8192];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5, "got CapGet response frame");

	Mysqlx::Connection::Capabilities caps;
	bool parsed = (r > 5) && caps.ParseFromArray(buf + 5, static_cast<int>(r - 5));
	ok(parsed, "parsed Capabilities protobuf");

	bool found_compression = false;
	bool has_zstd = false;
	bool has_lz4 = false;
	if (parsed) {
		for (int i = 0; i < caps.capabilities_size(); i++) {
			const auto& c = caps.capabilities(i);
			if (c.name() == "compression") {
				found_compression = true;
				const auto& any = c.value();
				if (any.type() == Mysqlx::Datatypes::Any::OBJECT) {
					for (const auto& fld : any.obj().fld()) {
						if (fld.key() == "algorithm" &&
						    fld.value().type() == Mysqlx::Datatypes::Any::ARRAY) {
							for (const auto& av : fld.value().array().value()) {
								if (av.type() == Mysqlx::Datatypes::Any::SCALAR &&
								    av.scalar().type() == Mysqlx::Datatypes::Scalar::V_STRING) {
									const auto& s = av.scalar().v_string().value();
									if (s == "zstd_stream") has_zstd = true;
									if (s == "lz4_message") has_lz4 = true;
								}
							}
						}
					}
				}
			}
		}
	}
	ok(found_compression, "Capabilities advertise `compression`");
	ok(has_zstd, "advertised algorithms include zstd_stream");
	ok(has_lz4, "advertised algorithms include lz4_message");

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_set_zstd_accepted() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	std::string payload = build_compression_capset("zstd_stream",
	                                               true, true,
	                                               true, 64);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got CapSet response (zstd_stream)");
	ok(r > 0 && buf[4] == Mysqlx::ServerMessages_Type_OK,
	   "CapSet zstd_stream returned Ok");
	ok(sess.is_healthy(), "session healthy after accepting zstd_stream");
	ok(sess.compression_algo_for_test() == MYSQLX_COMPR_ZSTD_STREAM,
	   "session stored ZSTD_STREAM algorithm");
	ok(sess.compression_combine_mixed_for_test() == true,
	   "stored combine_mixed_messages=true");
	ok(sess.compression_max_combine_for_test() == 64,
	   "stored max_combine_messages=64");

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_set_lz4_accepted() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	std::string payload = build_compression_capset("lz4_message");
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0 && buf[4] == Mysqlx::ServerMessages_Type_OK,
	   "CapSet lz4_message returned Ok");
	ok(sess.compression_algo_for_test() == MYSQLX_COMPR_LZ4_MESSAGE,
	   "session stored LZ4_MESSAGE algorithm");

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_set_unsupported_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	// deflate_stream is part of the X Protocol spec but we do not implement
	// it; it must be rejected with 5052 like any other unknown algorithm.
	std::string payload = build_compression_capset("deflate_stream");
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got CapSet response (unsupported algo)");
	ok(r > 0 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "CapSet unsupported algo returns Error frame");
	if (r > 0 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		bool parsed = err.ParseFromArray(buf + 5, static_cast<int>(r - 5));
		ok(parsed, "parsed Error protobuf");
		if (parsed) {
			ok(err.code() == 5052, "error code is 5052");
			ok(err.severity() == Mysqlx::Error::ERROR,
			   "compression rejection severity is non-fatal ERROR");
		} else {
			ok(false, "code 5052 (could not parse)");
			ok(false, "severity ERROR (could not parse)");
		}
	} else {
		ok(false, "code 5052 (no error frame)");
		ok(false, "severity ERROR (no error frame)");
	}
	ok(sess.compression_algo_for_test() == MYSQLX_COMPR_NONE,
	   "session has no compression algorithm after rejection");
	ok(sess.is_healthy(),
	   "session remains healthy after non-fatal capability rejection");

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_set_garbage_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	// Wrong-shape value: scalar string instead of OBJECT { algorithm: ... }.
	// Must also be rejected with 5052.
	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* caps = cap_set.mutable_capabilities();
	auto* cap = caps->add_capabilities();
	cap->set_name("compression");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::SCALAR);
	val->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	val->mutable_scalar()->mutable_v_string()->set_value("zstd_stream");
	std::string payload;
	cap_set.SerializeToString(&payload);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "wrong-shape compression value returns Error");
	if (r > 0 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.code() == 5052,
			   "wrong-shape compression value rejected with 5052");
		} else {
			ok(false, "wrong-shape rejected with 5052 (could not parse)");
		}
	} else {
		ok(false, "wrong-shape rejected with 5052 (no error frame)");
	}

	close(fds[0]);
	close(fds[1]);
}

// ---------------------------------------------------------------------------
// Phase 2: end-to-end decompression on the client→server path.
//
// Each of these tests:
//   1. Drives the session through the CapabilitiesSet handshake to negotiate
//      a specific compression algorithm (zstd_stream or lz4_message).
//   2. Builds a fully-framed Mysqlx.Sql.StmtExecute message body.
//   3. Compresses it with the matching algorithm.
//   4. Wraps the compressed bytes in a Mysqlx.Connection.Compression message
//      with `client_messages = SQL_STMT_EXECUTE` and feeds that frame to the
//      session.
//   5. Asserts the session reaches a state consistent with having dispatched
//      a real StmtExecute (CONNECTING_SERVER — backend lookup happens before
//      the test's fake connection cache returns nullptr).
//
// We don't have a backend, so the session legitimately can't complete the
// query; we just verify the COMPRESSION envelope was unwrapped and the
// inner message reached dispatch. The "decompressed but malformed" case is
// covered separately and asserts the session emits 5174 (bad compressed
// frame) — see test_decompress_oversize_rejected / _garbage_rejected.
// ---------------------------------------------------------------------------

static std::string compress_zstd(const std::vector<uint8_t>& src) {
	size_t bound = ZSTD_compressBound(src.size());
	std::string out;
	out.resize(bound);
	size_t produced = ZSTD_compress(out.data(), out.size(),
	                                src.data(), src.size(), 3);
	if (ZSTD_isError(produced)) {
		out.clear();
		return out;
	}
	out.resize(produced);
	return out;
}

static std::string compress_lz4(const std::vector<uint8_t>& src) {
	int bound = LZ4_compressBound(static_cast<int>(src.size()));
	std::string out;
	out.resize(static_cast<size_t>(bound));
	int produced = LZ4_compress_default(reinterpret_cast<const char*>(src.data()),
	                                    out.data(),
	                                    static_cast<int>(src.size()),
	                                    bound);
	if (produced <= 0) {
		out.clear();
		return out;
	}
	out.resize(static_cast<size_t>(produced));
	return out;
}

// Drive `sess` through a capabilities-set handshake that enables `algo`.
// Returns true on success. Leaves the session in WAITING_CLIENT_XMSG-equivalent
// state (CONNECTING_CLIENT, since we don't go through full auth) with the
// algorithm member populated.
static bool negotiate_compression(MysqlxSession& sess, int peer_fd, const char* algo) {
	std::string payload = build_compression_capset(algo);
	write_x_frame(peer_fd, Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	sess.to_process = true;
	sess.handler();
	uint8_t buf[4096];
	usleep(10000);
	read_x_frame(peer_fd, buf, sizeof(buf)); // drain Ok response
	return sess.compression_algo_for_test() != MYSQLX_COMPR_NONE;
}

// Build a Mysqlx.Sql.StmtExecute body — small, fits well under any cap.
static std::vector<uint8_t> build_stmt_execute_body(const char* sql) {
	Mysqlx::Sql::StmtExecute msg;
	msg.set_namespace_("sql");
	msg.set_stmt(sql);
	std::string s;
	msg.SerializeToString(&s);
	return std::vector<uint8_t>(s.begin(), s.end());
}

// Wrap (msg_type, body) in a Compression message that says
// "the decompressed payload is one client_messages of msg_type". Returns
// the protobuf-serialized Compression message bytes (caller will frame).
static std::string build_compression_envelope(uint8_t msg_type,
                                              const std::string& compressed,
                                              uint64_t uncompressed_size) {
	Mysqlx::Connection::Compression c;
	c.set_uncompressed_size(uncompressed_size);
	c.set_client_messages(static_cast<Mysqlx::ClientMessages::Type>(msg_type));
	c.set_payload(compressed);
	std::string s;
	c.SerializeToString(&s);
	return s;
}

static void test_decompress_zstd_single_message() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;
	// Skip auth: jump straight to the post-auth state and enable
	// compression directly so we don't have to wire a fake backend.
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);

	ok(negotiate_compression(sess, fds[1], "zstd_stream"),
	   "negotiated zstd_stream pre-decompression test");

	// Build a small StmtExecute, compress it, wrap in Compression.
	auto body = build_stmt_execute_body("SELECT 42");
	std::string compressed = compress_zstd(body);
	ok(!compressed.empty(), "zstd compressed sample body");
	std::string envelope = build_compression_envelope(
		Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		compressed, body.size());

	// Move session back to WAITING_CLIENT_XMSG (negotiate left it in
	// CONNECTING_CLIENT / no auth) so the COMPRESSION dispatch runs.
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(envelope.data()), envelope.size());
	sess.handler();

	// On a successful unwrap the inner StmtExecute will be dispatched;
	// without a backend the session transitions to CONNECTING_SERVER (it
	// expects the next handler tick to materialize a backend). It must
	// NOT have emitted a compression-related error frame (5170/5171/5174
	// in upstream code-space; previously 5008 before the parity-cleanup
	// pass in #5696). The backend's connect() returns EINPROGRESS so the
	// session may not have written anything yet — use a non-blocking
	// read so we don't deadlock.
	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = try_read_x_frame_nonblocking(fds[1], buf, sizeof(buf));
	bool got_compression_err = false;
	if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			int c = err.code();
			if (c == 5170 || c == 5171 || c == 5174) got_compression_err = true;
		}
	}
	ok(!got_compression_err,
	   "decompressed StmtExecute was dispatched (no compression error from session)");
	// Also assert the session moved past WAITING_CLIENT_XMSG — proves we
	// actually reached forward_to_backend on the unwrapped message.
	ok(sess.get_status() != MysqlxSession::WAITING_CLIENT_XMSG,
	   "session moved past WAITING_CLIENT_XMSG after unwrapping COMPRESSION");

	close(fds[0]);
	close(fds[1]);
}

static void test_decompress_lz4_single_message() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);

	ok(negotiate_compression(sess, fds[1], "lz4_message"),
	   "negotiated lz4_message pre-decompression test");

	auto body = build_stmt_execute_body("SHOW DATABASES");
	std::string compressed = compress_lz4(body);
	ok(!compressed.empty(), "lz4 compressed sample body");
	std::string envelope = build_compression_envelope(
		Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		compressed, body.size());

	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(envelope.data()), envelope.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = try_read_x_frame_nonblocking(fds[1], buf, sizeof(buf));
	bool got_compression_err = false;
	if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			int c = err.code();
			if (c == 5170 || c == 5171 || c == 5174) got_compression_err = true;
		}
	}
	ok(!got_compression_err,
	   "decompressed lz4 StmtExecute was dispatched (no compression error from session)");
	ok(sess.get_status() != MysqlxSession::WAITING_CLIENT_XMSG,
	   "lz4 path: session moved past WAITING_CLIENT_XMSG after unwrap");

	close(fds[0]);
	close(fds[1]);
}

static void test_decompress_oversize_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);

	ok(negotiate_compression(sess, fds[1], "zstd_stream"),
	   "negotiated zstd_stream pre-oversize test");

	// Compress 1 MiB of zeros (super-cheap to compress; payload is tiny).
	std::vector<uint8_t> body(1 * 1024 * 1024, 0);
	std::string compressed = compress_zstd(body);
	ok(!compressed.empty(), "compressed 1 MiB of zeros");

	// Lie about uncompressed_size: claim only 100 bytes. Decompressor
	// should bail when the actual output would exceed the cap.
	std::string envelope = build_compression_envelope(
		Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		compressed, /*uncompressed_size=*/100);

	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(envelope.data()), envelope.size());
	sess.handler();

	uint8_t buf[8192];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "oversize-vs-hint message produced an Error frame");
	if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			// 5171 = ER_X_DECOMPRESSION_FAILED (upstream MySQL
			// plugin/x/src/xpl_error.h) — decompressed payload exceeds
			// cap is treated as a decompression failure. Aligned with
			// upstream in #5696.
			ok(err.code() == 5171, "oversize rejected with 5171 (ER_X_DECOMPRESSION_FAILED)");
		} else {
			ok(false, "oversize rejected with 5171 (parse failed)");
		}
	} else {
		ok(false, "oversize rejected with 5171 (no error frame)");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_decompress_garbage_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);

	ok(negotiate_compression(sess, fds[1], "zstd_stream"),
	   "negotiated zstd_stream pre-garbage test");

	// Send a Compression message whose payload isn't valid zstd.
	std::string garbage = "not zstd compressed data at all xxxxxxxx";
	std::string envelope = build_compression_envelope(
		Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE,
		garbage, /*uncompressed_size=*/100);

	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION,
		reinterpret_cast<const uint8_t*>(envelope.data()), envelope.size());
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "garbage compressed payload produced an Error frame");
	if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			// 5171 = ER_X_DECOMPRESSION_FAILED (upstream).
			ok(err.code() == 5171, "garbage rejected with 5171 (ER_X_DECOMPRESSION_FAILED)");
		} else {
			ok(false, "garbage rejected with 5171 (parse failed)");
		}
	} else {
		ok(false, "garbage rejected with 5171 (no error frame)");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_compression_without_negotiation_still_5170() {
	diag(">>> %s", __func__);
	// Sanity: if the client tries to send a Compression message before
	// (or without) having set the compression capability, the dispatcher
	// must reject with 5170 (ER_X_FRAME_COMPRESSION_DISABLED — upstream
	// MySQL plugin/x/src/xpl_error.h). Aligned with upstream in #5696.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION, nullptr, 0);
	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR,
	   "compression without negotiation rejected");
	if (r > 5 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.code() == 5170,
			   "compression without negotiation rejected with 5170 (ER_X_FRAME_COMPRESSION_DISABLED)");
		} else {
			ok(false,
			   "compression without negotiation rejected with 5170 (parse fail)");
		}
	} else {
		ok(false,
		   "compression without negotiation rejected with 5170 (no err frame)");
	}

	close(fds[0]);
	close(fds[1]);
}

// ---------------------------------------------------------------------------
// Phase 3: outbound compression — wrap server messages bound for the client
// in Mysqlx.Connection.Compression frames when negotiated.
// ---------------------------------------------------------------------------

// Decompress a single zstd payload to a fresh vector. Returns empty on error.
static std::vector<uint8_t> decompress_zstd(const std::string& payload) {
	std::vector<uint8_t> out;
	out.resize(1 * 1024 * 1024);
	size_t r = ZSTD_decompress(out.data(), out.size(),
	                           payload.data(), payload.size());
	if (ZSTD_isError(r)) {
		out.clear();
		return out;
	}
	out.resize(r);
	return out;
}

static std::vector<uint8_t> decompress_lz4(const std::string& payload, size_t expected) {
	std::vector<uint8_t> out;
	out.resize(expected ? expected : 64 * 1024);
	int r = LZ4_decompress_safe(payload.data(),
	                            reinterpret_cast<char*>(out.data()),
	                            static_cast<int>(payload.size()),
	                            static_cast<int>(out.size()));
	if (r < 0) {
		out.clear();
		return out;
	}
	out.resize(static_cast<size_t>(r));
	return out;
}

// Read everything currently in the session's write buffer back as a single
// frame (assumes the test wrote exactly one frame). Returns the body bytes.
static bool extract_one_frame_from_buffer(const std::vector<uint8_t>& buf,
                                          uint8_t* out_msg_type,
                                          std::vector<uint8_t>* out_body) {
	if (buf.size() < 5) return false;
	uint32_t payload_size = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	if (payload_size < 1 || 4 + payload_size > buf.size()) return false;
	*out_msg_type = buf[4];
	if (payload_size > 1) {
		out_body->assign(buf.begin() + 5, buf.begin() + 4 + payload_size);
	} else {
		out_body->clear();
	}
	return true;
}

static void test_compress_zstd_single_message() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	ok(negotiate_compression(sess, fds[1], "zstd_stream"),
	   "Phase 3 zstd: negotiated zstd_stream");

	// Build a body large enough to compress (>= COMPRESSION_MIN_OUTPUT_BYTES).
	// 200 bytes of 'A' compresses to a tiny zstd frame.
	std::vector<uint8_t> body(200, 'A');
	// (negotiate_compression() already drained the Ok response from the
	// wire; the session's outbound write buffer is empty here.)

	// Drive send_to_client_compressed() via the test hook. With
	// combine_mixed_messages = false (the negotiate_compression helper
	// doesn't set it), this should emit ONE compressed frame.
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body.data(), body.size());

	const std::vector<uint8_t>& wb = sess.client_write_buffer_for_test();
	uint8_t mt;
	std::vector<uint8_t> frame_body;
	bool got = extract_one_frame_from_buffer(wb, &mt, &frame_body);
	ok(got, "Phase 3 zstd: write buffer holds one frame after send");
	ok(got && mt == Mysqlx::ServerMessages_Type_COMPRESSION,
	   "Phase 3 zstd: frame is a COMPRESSION message");

	if (got && mt == Mysqlx::ServerMessages_Type_COMPRESSION) {
		Mysqlx::Connection::Compression cmsg;
		bool parsed = cmsg.ParseFromArray(frame_body.data(),
		                                  static_cast<int>(frame_body.size()));
		ok(parsed, "Phase 3 zstd: Compression protobuf parses");
		ok(parsed && cmsg.has_server_messages(),
		   "Phase 3 zstd: server_messages set on outbound Compression");
		ok(parsed && cmsg.server_messages() == Mysqlx::ServerMessages_Type_NOTICE,
		   "Phase 3 zstd: server_messages is NOTICE");
		ok(parsed && cmsg.uncompressed_size() == body.size(),
		   "Phase 3 zstd: uncompressed_size matches body");

		auto decoded = decompress_zstd(cmsg.payload());
		ok(decoded.size() == body.size() && decoded == body,
		   "Phase 3 zstd: payload round-trips back to original body");
	} else {
		ok(false, "Phase 3 zstd: Compression protobuf parses (skipped)");
		ok(false, "Phase 3 zstd: server_messages set (skipped)");
		ok(false, "Phase 3 zstd: server_messages is NOTICE (skipped)");
		ok(false, "Phase 3 zstd: uncompressed_size matches body (skipped)");
		ok(false, "Phase 3 zstd: payload round-trips (skipped)");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_compress_lz4_single_message() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	ok(negotiate_compression(sess, fds[1], "lz4_message"),
	   "Phase 3 lz4: negotiated lz4_message");

	// (negotiate_compression already drained the Ok response.)

	std::vector<uint8_t> body(200, 'B');
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body.data(), body.size());

	const std::vector<uint8_t>& wb = sess.client_write_buffer_for_test();
	uint8_t mt;
	std::vector<uint8_t> frame_body;
	bool got = extract_one_frame_from_buffer(wb, &mt, &frame_body);
	ok(got && mt == Mysqlx::ServerMessages_Type_COMPRESSION,
	   "Phase 3 lz4: frame is a COMPRESSION message");

	if (got && mt == Mysqlx::ServerMessages_Type_COMPRESSION) {
		Mysqlx::Connection::Compression cmsg;
		bool parsed = cmsg.ParseFromArray(frame_body.data(),
		                                  static_cast<int>(frame_body.size()));
		ok(parsed && cmsg.server_messages() == Mysqlx::ServerMessages_Type_NOTICE,
		   "Phase 3 lz4: server_messages is NOTICE");
		auto decoded = decompress_lz4(cmsg.payload(), cmsg.uncompressed_size());
		ok(decoded.size() == body.size() && decoded == body,
		   "Phase 3 lz4: payload round-trips back to original body");
	} else {
		ok(false, "Phase 3 lz4: server_messages is NOTICE (skipped)");
		ok(false, "Phase 3 lz4: payload round-trips (skipped)");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_compress_below_threshold_passthrough() {
	diag(">>> %s", __func__);
	// Payload smaller than COMPRESSION_MIN_OUTPUT_BYTES (50) must be sent
	// uncompressed even when compression is negotiated — the wrap
	// overhead would dwarf any savings. We assert the frame on the wire
	// is plain (msg type matches what the caller passed, NOT
	// COMPRESSION) and the body is identical.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;
	negotiate_compression(sess, fds[1], "zstd_stream");

	// (negotiate_compression already drained the Ok response.)

	std::vector<uint8_t> body(20, 'x'); // below 50-byte threshold
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body.data(), body.size());

	const std::vector<uint8_t>& wb = sess.client_write_buffer_for_test();
	uint8_t mt = 0;
	std::vector<uint8_t> frame_body;
	bool got = extract_one_frame_from_buffer(wb, &mt, &frame_body);
	ok(got && mt == Mysqlx::ServerMessages_Type_NOTICE,
	   "Phase 3 below-threshold: frame is sent uncompressed (NOTICE, not COMPRESSION)");
	ok(got && frame_body == body,
	   "Phase 3 below-threshold: body is unmodified");

	close(fds[0]);
	close(fds[1]);
}

static void test_compress_combine_mixed_batches() {
	diag(">>> %s", __func__);
	// With combine_mixed_messages=true and max_combine_messages=3, three
	// successive sends should buffer the first two and emit ONE
	// Compression message containing both after the third triggers the
	// flush-on-cap path. We assert exactly one frame on the wire and
	// that decompressing its payload yields three concatenated framed
	// messages.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	// Send a CapabilitiesSet that opts into combine_mixed_messages with
	// a tight cap so we can hit the flush deterministically.
	std::string payload = build_compression_capset("zstd_stream",
	                                               /*with_combine_mixed=*/true,
	                                               /*combine_mixed_value=*/true,
	                                               /*with_max_combine=*/true,
	                                               /*max_combine_value=*/3);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	sess.handler();
	// (negotiate_compression already drained the Ok response.)

	ok(sess.compression_combine_mixed_for_test() == true,
	   "Phase 3 batch: combine_mixed_messages enabled");
	ok(sess.compression_max_combine_for_test() == 3,
	   "Phase 3 batch: max_combine_messages = 3");

	std::vector<uint8_t> body1(80, '1');
	std::vector<uint8_t> body2(80, '2');
	std::vector<uint8_t> body3(80, '3');
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body1.data(), body1.size());
	ok(sess.compression_batch_count_for_test() == 1,
	   "Phase 3 batch: 1 frame buffered after first send");
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body2.data(), body2.size());
	ok(sess.compression_batch_count_for_test() == 2,
	   "Phase 3 batch: 2 frames buffered after second send");
	// Third send should trigger flush_compression_batch() inside.
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body3.data(), body3.size());
	ok(sess.compression_batch_count_for_test() == 0,
	   "Phase 3 batch: batch drained after hitting cap");

	const std::vector<uint8_t>& wb = sess.client_write_buffer_for_test();
	uint8_t mt;
	std::vector<uint8_t> frame_body;
	bool got = extract_one_frame_from_buffer(wb, &mt, &frame_body);
	ok(got && mt == Mysqlx::ServerMessages_Type_COMPRESSION,
	   "Phase 3 batch: emitted one COMPRESSION frame");

	if (got && mt == Mysqlx::ServerMessages_Type_COMPRESSION) {
		Mysqlx::Connection::Compression cmsg;
		bool parsed = cmsg.ParseFromArray(frame_body.data(),
		                                  static_cast<int>(frame_body.size()));
		ok(parsed && !cmsg.has_server_messages() && !cmsg.has_client_messages(),
		   "Phase 3 batch: neither server_messages nor client_messages set "
		   "(=multi-frame payload)");
		auto decoded = decompress_zstd(cmsg.payload());
		// Decoded buffer should contain three back-to-back fully-framed
		// X messages of body1, body2, body3.
		ok(!decoded.empty(),
		   "Phase 3 batch: payload decompresses");
		size_t off = 0;
		int seen = 0;
		bool match = true;
		std::vector<std::vector<uint8_t>> expected = {body1, body2, body3};
		while (off + 5 <= decoded.size() && seen < 3) {
			uint32_t ps = decoded[off] | (decoded[off+1] << 8) |
			              (decoded[off+2] << 16) | (decoded[off+3] << 24);
			if (off + 4 + ps > decoded.size()) { match = false; break; }
			if (decoded[off+4] != Mysqlx::ServerMessages_Type_NOTICE) {
				match = false;
				break;
			}
			std::vector<uint8_t> b(decoded.begin() + off + 5,
			                       decoded.begin() + off + 4 + ps);
			if (b != expected[seen]) { match = false; break; }
			off += 4 + ps;
			seen++;
		}
		ok(match && seen == 3,
		   "Phase 3 batch: payload contains three framed NOTICE messages "
		   "in order");
	} else {
		ok(false, "Phase 3 batch: payload neither flag set (skipped)");
		ok(false, "Phase 3 batch: payload decompresses (skipped)");
		ok(false, "Phase 3 batch: payload contains three framed NOTICE messages (skipped)");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_compress_passthrough_when_disabled() {
	diag(">>> %s", __func__);
	// Sanity: when compression hasn't been negotiated, the helper must
	// just enqueue verbatim — the .so MUST work fine for clients that
	// never opt in to compression.
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	std::vector<uint8_t> body(200, 'C');
	sess.send_to_client_compressed_for_test(
		Mysqlx::ServerMessages_Type_NOTICE, body.data(), body.size());

	const std::vector<uint8_t>& wb = sess.client_write_buffer_for_test();
	uint8_t mt;
	std::vector<uint8_t> frame_body;
	bool got = extract_one_frame_from_buffer(wb, &mt, &frame_body);
	ok(got && mt == Mysqlx::ServerMessages_Type_NOTICE,
	   "Phase 3 disabled: frame is plain NOTICE (not COMPRESSION)");
	ok(got && frame_body == body,
	   "Phase 3 disabled: body unmodified when compression off");

	close(fds[0]);
	close(fds[1]);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(64);
	diag("=== mysqlx_compression_unit-t starting ===");

	test_capabilities_advertise_compression();
	test_capabilities_set_zstd_accepted();
	test_capabilities_set_lz4_accepted();
	test_capabilities_set_unsupported_rejected();
	test_capabilities_set_garbage_rejected();

	test_decompress_zstd_single_message();
	test_decompress_lz4_single_message();
	test_decompress_oversize_rejected();
	test_decompress_garbage_rejected();
	test_compression_without_negotiation_still_5170();

	test_compress_zstd_single_message();
	test_compress_lz4_single_message();
	test_compress_below_threshold_passthrough();
	test_compress_combine_mixed_batches();
	test_compress_passthrough_when_disabled();

	return exit_status();
}
