/**
 * @file reg_test_compressed_split_header-t.cpp
 * @brief Regression test for GHSA-qg2m-q3ch-cg9v.
 *
 * @details When reassembling packets from the MySQL compressed protocol, ProxySQL asserted that
 *   every compressed frame held at least a whole inner packet header. A frame ending with 1-3
 *   bytes of an inner header, sent by any authenticated client, aborted the process. The
 *   compressed protocol is a byte stream, so a header split across frames is legitimate: the
 *   test splits the header of a COM_QUERY across two (uncompressed-payload) frames, and checks
 *   that ProxySQL reassembles it and returns the resultset, for every split point.
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

namespace {

bool send_all(int fd, const std::vector<uint8_t>& buf) {
	size_t sent = 0;
	while (sent < buf.size()) {
		ssize_t n = send(fd, buf.data() + sent, buf.size() - sent, MSG_NOSIGNAL);
		if (n <= 0) return false;
		sent += n;
	}
	return true;
}

bool recv_all(int fd, uint8_t* buf, size_t len) {
	size_t got = 0;
	while (got < len) {
		struct pollfd pfd { fd, POLLIN, 0 };
		if (poll(&pfd, 1, 5000) != 1) return false;
		ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) return false;
		got += n;
	}
	return true;
}

/**
 * @brief Wraps 'data' in a compressed-protocol frame with an uncompressed payload.
 */
std::vector<uint8_t> comp_frame(uint8_t seq, const std::vector<uint8_t>& data) {
	std::vector<uint8_t> f {
		uint8_t(data.size()), uint8_t(data.size() >> 8), uint8_t(data.size() >> 16),
		seq,
		0x00, 0x00, 0x00, // uncompressed length 0: payload not compressed
	};
	f.insert(f.end(), data.begin(), data.end());
	return f;
}

/**
 * @brief Reads one compressed frame and returns its (decompressed) payload. Empty on failure.
 */
std::vector<uint8_t> read_comp_frame(int fd) {
	uint8_t hdr[7];
	if (!recv_all(fd, hdr, 7)) return {};
	size_t clen = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
	size_t ulen = hdr[4] | (hdr[5] << 8) | (hdr[6] << 16);
	std::vector<uint8_t> body(clen);
	if (clen && !recv_all(fd, body.data(), clen)) return {};
	if (ulen == 0) return body;
	std::vector<uint8_t> out(ulen);
	uLongf dlen = ulen;
	if (uncompress(out.data(), &dlen, body.data(), clen) != Z_OK || dlen != ulen) return {};
	return out;
}

/**
 * @brief Sends 'SELECT 1' with its inner header split after 'split' bytes, and checks that the
 *   reply starts with a resultset holding one column.
 */
bool split_query_works(const CommandLine& cl, size_t split) {
	MYSQL* mysql = mysql_init(nullptr);
	mysql_options(mysql, MYSQL_OPT_COMPRESS, nullptr);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return false;
	}
	const std::string q = "SELECT 1";
	std::vector<uint8_t> inner { uint8_t(q.size() + 1), 0x00, 0x00, 0x00, 0x03 /* COM_QUERY */ };
	inner.insert(inner.end(), q.begin(), q.end());

	const std::vector<uint8_t> first(inner.begin(), inner.begin() + split);
	const std::vector<uint8_t> second(inner.begin() + split, inner.end());
	bool res = false;
	if (send_all(mysql->net.fd, comp_frame(0, first))) {
		usleep(100000); // make sure ProxySQL processes the frames separately
		if (send_all(mysql->net.fd, comp_frame(1, second))) {
			std::vector<uint8_t> reply = read_comp_frame(mysql->net.fd);
			// First inner packet of the reply: 4 bytes header + column count
			res = reply.size() > 4 && reply[4] == 0x01;
			if (!res) diag("Unexpected reply of %zu bytes", reply.size());
		}
	}
	mysql_close(mysql);
	return res;
}

bool query_returns_one(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	bool ok = false;
	if (mysql_real_connect(mysql, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)
		&& mysql_query(mysql, "SELECT 1") == 0) {
		MYSQL_RES* res = mysql_store_result(mysql);
		MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
		ok = row && row[0] && strcmp(row[0], "1") == 0;
		if (res) mysql_free_result(res);
	} else {
		diag("Query failed: %s", mysql_error(mysql));
	}
	mysql_close(mysql);
	return ok;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(5);

	for (size_t split = 1; split <= 3; split++) {
		ok(split_query_works(cl, split), "Inner header split after %zu byte(s) is reassembled", split);
	}
	ok(split_query_works(cl, 4), "Inner header complete in the first frame (body split) works");
	ok(query_returns_one(cl), "ProxySQL is still operational");

	return exit_status();
}
