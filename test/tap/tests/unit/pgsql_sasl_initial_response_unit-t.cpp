/**
 * @file pgsql_sasl_initial_response_unit-t.cpp
 * @brief Unit tests for pgsql_parse_sasl_initial_response() (GHSA-5xv5-24pg-gmq8).
 *
 * The SASLInitialResponse body is a NUL-terminated mechanism name, a 4-byte big-endian length,
 * and that many bytes of initial response. ProxySQL read the length field without checking that
 * 4 bytes were left in the message, so a body ending right after the mechanism NUL made it read 4
 * bytes past the packet buffer, before authentication. The follow-up bounds check then wrapped
 * around (unsigned) and let the out-of-bounds value through as the length of a second, larger
 * out-of-bounds read in scram_handle_client_first().
 *
 * Every message is copied into a heap buffer of exactly its size, so a build with
 * AddressSanitizer also reports any read past the end.
 */

#include "tap.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Defined in libproxysql.a (lib/PgSQL_Protocol.cpp), declared in include/PgSQL_Protocol.h.
bool pgsql_parse_sasl_initial_response(const unsigned char* data, uint32_t size, const char** mech,
	const unsigned char** response, uint32_t* response_len);

namespace {

const std::string kMech = "SCRAM-SHA-256";

std::vector<unsigned char> mech_body() {
	std::vector<unsigned char> b(kMech.begin(), kMech.end());
	b.push_back(0);
	return b;
}

void append_be32(std::vector<unsigned char>& b, uint32_t v) {
	b.push_back(uint8_t(v >> 24));
	b.push_back(uint8_t(v >> 16));
	b.push_back(uint8_t(v >> 8));
	b.push_back(uint8_t(v));
}

struct parse_result {
	bool ok;
	std::string mech;
	size_t response_offset;
	uint32_t response_len;
};

/** @brief Parses a copy of 'msg' held in a heap buffer of exactly msg.size() bytes. */
parse_result parse(const std::vector<unsigned char>& msg) {
	parse_result r { false, "", 0, 0 };
	unsigned char* buf = static_cast<unsigned char*>(malloc(msg.empty() ? 1 : msg.size()));
	if (!msg.empty()) {
		memcpy(buf, msg.data(), msg.size());
	}
	const char* mech = nullptr;
	const unsigned char* resp = nullptr;
	uint32_t resp_len = 0;
	r.ok = pgsql_parse_sasl_initial_response(buf, msg.size(), &mech, &resp, &resp_len);
	if (r.ok) {
		r.mech = mech;
		r.response_offset = resp - buf;
		r.response_len = resp_len;
	}
	free(buf);
	return r;
}

} // namespace

int main() {
	plan(12);

	{
		auto m = mech_body();
		append_be32(m, 5);
		m.insert(m.end(), { 'a', 'b', 'c', 'd', 'e' });
		auto r = parse(m);
		ok(r.ok && r.mech == kMech && r.response_offset == kMech.size() + 1 + 4 && r.response_len == 5,
			"well-formed message is parsed (mech='%s', offset=%zu, len=%u)",
			r.mech.c_str(), r.response_offset, r.response_len);
	}
	{
		auto m = mech_body();
		append_be32(m, 0);
		auto r = parse(m);
		ok(r.ok && r.response_len == 0, "zero-length initial response ending the message is accepted");
	}
	{
		auto m = mech_body();
		append_be32(m, 2);
		m.insert(m.end(), { 'a', 'b', 'c', 'd' });
		auto r = parse(m);
		ok(r.ok && r.response_len == 2, "initial response shorter than the remaining bytes is accepted");
	}

	// GHSA-5xv5-24pg-gmq8: the body ends right after the mechanism NUL.
	ok(!parse(mech_body()).ok, "mechanism only, no length field: rejected");

	for (size_t partial = 1; partial <= 3; partial++) {
		auto m = mech_body();
		m.insert(m.end(), partial, 0);
		ok(!parse(m).ok, "mechanism + %zu of the 4 length bytes: rejected", partial);
	}

	{
		auto m = mech_body();
		append_be32(m, 6);
		m.insert(m.end(), { 'a', 'b', 'c', 'd', 'e' });
		ok(!parse(m).ok, "length one byte larger than the remaining bytes: rejected");
	}
	{
		auto m = mech_body();
		append_be32(m, 0xFFFFFFFF);
		ok(!parse(m).ok, "length -1 (no initial response): rejected");
	}
	{
		auto m = mech_body();
		append_be32(m, 0xFFFFFFFC);
		m.insert(m.end(), { 'a', 'b' });
		ok(!parse(m).ok, "length 0xFFFFFFFC (the value the old unsigned check let through): rejected");
	}
	{
		std::vector<unsigned char> m(kMech.begin(), kMech.end());
		ok(!parse(m).ok, "mechanism without NUL terminator: rejected");
	}
	ok(!parse({}).ok, "empty message: rejected");

	return exit_status();
}
