/**
 * @file mysql_decompress_payload_unit-t.cpp
 * @brief Regression test for GHSA-fvch-fpgq-pwfx: uninitialized heap read in
 *        MySQL compressed-packet decompression (zlib path).
 *
 * Background:
 *   A compressed MySQL packet carries, in its 7-byte header, the claimed
 *   pre-compression ("uncompressed") length. decompress_mysql_payload() is
 *   handed a malloc'd buffer of that claimed length and asked to inflate the
 *   zlib stream into it. Before the fix, the zlib branch returned success on
 *   Z_OK alone, discarding the actual number of bytes uncompress() wrote
 *   (destLen is passed by value). A client could therefore declare a large
 *   uncompressed length while sending a stream that inflates to far fewer
 *   bytes; the caller (buffer2array) then walked the full claimed length,
 *   parsing the uninitialized tail of the buffer as MySQL packet headers and
 *   forwarding it to the backend -> heap information disclosure. The zstd
 *   branch already guarded against this by requiring rc == destLen.
 *
 *   The fix makes the zlib branch require the actual decompressed size to
 *   equal the claimed length, mirroring the zstd branch.
 *
 * This test calls decompress_mysql_payload() directly. The zlib path is
 * selected by passing myconn == nullptr (use_zstd_compression(nullptr) is
 * false). It asserts:
 *   1. A correctly-sized claim decompresses successfully and yields the exact
 *      original bytes (non-regression: valid compression still works).
 *   2. An over-declared claim (claimed length > actual decompressed size) is
 *      REJECTED. This is the security invariant; pre-fix code accepted it and
 *      left the tail of the buffer uninitialized.
 *   3. An under-declared claim (buffer smaller than the real payload) is
 *      rejected (zlib returns Z_BUF_ERROR; no overflow).
 *   4. Corrupt / non-zlib input is rejected.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <zlib.h>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

// decompress_mysql_payload() is declared in MySQL_Data_Stream.h and defined in
// lib/mysql_data_stream.cpp. Forward-declare it here to keep this unit light,
// avoiding the full protocol/mariadb include chain. Signature must match.
class MySQL_Connection;
bool decompress_mysql_payload(
	const MySQL_Connection* myconn, unsigned char* dest, unsigned long destLen,
	const unsigned char* source, size_t sourceLen
);

int main() {
	plan(6);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	// Build a deterministic plaintext payload and zlib-compress it. This
	// mimics a legitimate compressed MySQL sub-packet stream on the wire.
	const size_t original_len = 512;
	std::vector<unsigned char> original(original_len);
	for (size_t i = 0; i < original_len; i++) {
		original[i] = static_cast<unsigned char>((i * 31 + 7) & 0xff);
	}

	uLongf comp_cap = compressBound(original_len);
	std::vector<unsigned char> comp(comp_cap);
	uLongf comp_len = comp_cap;
	int crc = compress(comp.data(), &comp_len, original.data(), original_len);
	ok(crc == Z_OK && comp_len > 0,
	   "zlib compress() of %zu-byte payload succeeded (%lu compressed bytes)",
	   original_len, static_cast<unsigned long>(comp_len));

	// --- Case 1: correctly-sized claim -> success + exact bytes ------------
	// This is the legitimate path; the fix must not break it.
	{
		std::vector<unsigned char> dest(original_len);
		bool decompressed = decompress_mysql_payload(
			nullptr, dest.data(), original_len, comp.data(), comp_len);
		ok(decompressed && memcmp(dest.data(), original.data(), original_len) == 0,
		   "valid compressed payload with exact claimed length decompresses correctly");
	}

	// --- Case 2: over-declared claim -> MUST be rejected (the fix) ---------
	// Claimed length (20000) far exceeds the real decompressed size (512).
	// uncompress() writes only 512 bytes and returns Z_OK; the remaining
	// 19488 bytes of `dest` are uninitialized. Pre-fix this returned true,
	// leaking that uninitialized tail. The fix rejects it.
	{
		const unsigned long claimed = 20000;
		std::vector<unsigned char> dest(claimed);
		bool decompressed = decompress_mysql_payload(
			nullptr, dest.data(), claimed, comp.data(), comp_len);
		ok(!decompressed,
		   "over-declared payload (claimed=%lu, actual=%zu) is rejected [GHSA-fvch-fpgq-pwfx]",
		   claimed, original_len);
	}

	// --- Case 3: under-declared claim (buffer too small) -> rejected -------
	// The destination buffer is smaller than the real payload; zlib returns
	// Z_BUF_ERROR without overflowing it.
	{
		const unsigned long claimed = 100;
		std::vector<unsigned char> dest(claimed);
		bool decompressed = decompress_mysql_payload(
			nullptr, dest.data(), claimed, comp.data(), comp_len);
		ok(!decompressed,
		   "under-declared payload (claimed=%lu < actual=%zu) is rejected",
		   claimed, original_len);
	}

	// --- Case 4: corrupt / non-zlib input -> rejected ----------------------
	{
		std::vector<unsigned char> junk(64);
		for (size_t i = 0; i < junk.size(); i++) {
			junk[i] = static_cast<unsigned char>(0xA5 ^ (i & 0xff));
		}
		std::vector<unsigned char> dest(original_len);
		bool decompressed = decompress_mysql_payload(
			nullptr, dest.data(), original_len, junk.data(), junk.size());
		ok(!decompressed, "corrupt (non-zlib) input is rejected");
	}

	test_cleanup_minimal();
	return exit_status();
}
