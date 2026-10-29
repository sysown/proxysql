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

bool mysql_parse_err_packet(
    const unsigned char* payload, size_t len,
    uint16_t* out_errno, const char** out_msg, size_t* out_msg_len
) {
    // Minimum: 0xFF + 2 bytes errno = 3 bytes
    if (!payload || len < 3 || payload[0] != 0xFF) return false;

    *out_errno = payload[1] | (static_cast<uint16_t>(payload[2]) << 8);

    if (len >= 9 && payload[3] == '#') {
        // sqlstate at [4..8], message at [9..]
        *out_msg = reinterpret_cast<const char*>(payload + 9);
        *out_msg_len = len - 9;
    } else {
        // no sqlstate marker — message starts at [3]
        *out_msg = reinterpret_cast<const char*>(payload + 3);
        *out_msg_len = len - 3;
    }
    return true;
}

bool mysql_is_eof_payload(const unsigned char* p, size_t n) {
	return p && n >= 1 && n < 9 && p[0] == 0xFE;
}

bool mysql_is_ok_header(const unsigned char* p, size_t n) {
	return p && n >= 1 && p[0] == 0x00;
}

bool mysql_parse_ok_payload(const unsigned char* p, size_t n, MySQLOkFields* out) {
	if (!p || !out || n < 1 || p[0] != 0x00) return false;
	const unsigned char* cur = p + 1;
	size_t rem = n - 1;
	out->affected_rows = mysql_read_lenenc_int(cur, rem);
	out->last_insert_id = mysql_read_lenenc_int(cur, rem);
	if (rem < 4) return false;
	out->status_flags = (uint16_t)(cur[0] | (cur[1] << 8));
	out->warnings = (uint16_t)(cur[2] | (cur[3] << 8));
	return true;
}

bool mysql_parse_eof_payload(const unsigned char* p, size_t n, uint16_t* warnings, uint16_t* status_flags) {
	if (!mysql_is_eof_payload(p, n) || n < 5) return false;
	if (warnings) *warnings = (uint16_t)(p[1] | (p[2] << 8));
	if (status_flags) *status_flags = (uint16_t)(p[3] | (p[4] << 8));
	return true;
}
