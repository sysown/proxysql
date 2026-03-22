/**
 * @file MySQLProtocolUtils.h
 * @brief Pure MySQL protocol utility functions for unit testability.
 *
 * Extracted from MySQLFFTO for testing. These are low-level protocol
 * parsing helpers that operate on raw byte buffers.
 *
 * @see FFTO unit testing (GitHub issue #5499)
 */

#ifndef MYSQL_PROTOCOL_UTILS_H
#define MYSQL_PROTOCOL_UTILS_H

#include <cstdint>
#include <cstddef>

/**
 * @brief Read a MySQL length-encoded integer from a buffer.
 *
 * MySQL length-encoded integers use 1-9 bytes:
 *   - 0x00-0xFA: 1 byte (value itself)
 *   - 0xFC: 2 bytes follow (uint16)
 *   - 0xFD: 3 bytes follow (uint24)
 *   - 0xFE: 8 bytes follow (uint64)
 *
 * @param buf  [in/out] Pointer to current position; advanced past the integer.
 * @param len  [in/out] Remaining buffer length; decremented.
 * @return Decoded 64-bit integer value (0 on error/truncation).
 */
uint64_t mysql_read_lenenc_int(const unsigned char* &buf, size_t &len);

/**
 * @brief Build a MySQL protocol packet header + payload.
 *
 * Constructs a complete MySQL wire-format packet: 3-byte length +
 * 1-byte sequence number + payload.
 *
 * @param payload      Payload data.
 * @param payload_len  Length of payload.
 * @param seq_id       Packet sequence number.
 * @param out_buf      Output buffer (must be at least payload_len + 4).
 * @return Total packet size (payload_len + 4).
 */
size_t mysql_build_packet(
	const unsigned char *payload,
	uint32_t payload_len,
	uint8_t seq_id,
	unsigned char *out_buf
);

#endif // MYSQL_PROTOCOL_UTILS_H
