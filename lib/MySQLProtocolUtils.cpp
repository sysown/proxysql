/**
 * @file MySQLProtocolUtils.cpp
 * @brief Implementation of MySQL protocol utility functions.
 *
 * @see MySQLProtocolUtils.h
 */

#include "MySQLProtocolUtils.h"
#include <cstring>

uint64_t mysql_read_lenenc_int(const unsigned char* &buf, size_t &len) {
	if (len == 0) return 0;
	uint8_t first_byte = buf[0];
	buf++; len--;
	if (first_byte < 0xFB) return first_byte;
	if (first_byte == 0xFC) {
		if (len < 2) return 0;
		uint64_t value = buf[0] | (static_cast<uint64_t>(buf[1]) << 8);
		buf += 2; len -= 2;
		return value;
	}
	if (first_byte == 0xFD) {
		if (len < 3) return 0;
		uint64_t value = buf[0] | (static_cast<uint64_t>(buf[1]) << 8)
			| (static_cast<uint64_t>(buf[2]) << 16);
		buf += 3; len -= 3;
		return value;
	}
	if (first_byte == 0xFE) {
		if (len < 8) return 0;
		uint64_t value = buf[0] | (static_cast<uint64_t>(buf[1]) << 8)
			| (static_cast<uint64_t>(buf[2]) << 16)
			| (static_cast<uint64_t>(buf[3]) << 24)
			| (static_cast<uint64_t>(buf[4]) << 32)
			| (static_cast<uint64_t>(buf[5]) << 40)
			| (static_cast<uint64_t>(buf[6]) << 48)
			| (static_cast<uint64_t>(buf[7]) << 56);
		buf += 8; len -= 8;
		return value;
	}
	return 0;
}

size_t mysql_build_packet(
	const unsigned char *payload,
	uint32_t payload_len,
	uint8_t seq_id,
	unsigned char *out_buf)
{
	// 3-byte length (little-endian) + 1-byte sequence
	out_buf[0] = payload_len & 0xFF;
	out_buf[1] = (payload_len >> 8) & 0xFF;
	out_buf[2] = (payload_len >> 16) & 0xFF;
	out_buf[3] = seq_id;
	if (payload && payload_len > 0) {
		memcpy(out_buf + 4, payload, payload_len);
	}
	return payload_len + 4;
}
