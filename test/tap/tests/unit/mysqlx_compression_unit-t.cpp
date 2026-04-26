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

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <vector>

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

int main() {
	plan(22);

	test_capabilities_advertise_compression();
	test_capabilities_set_zstd_accepted();
	test_capabilities_set_lz4_accepted();
	test_capabilities_set_unsupported_rejected();
	test_capabilities_set_garbage_rejected();

	return exit_status();
}
