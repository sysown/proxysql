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

/**
 * @brief Parse a MySQL ERR packet payload to extract errno and error message.
 *
 * ERR packet format: 0xFF + errno(2) + ['#' + sqlstate(5)] + message
 *
 * @param payload    Full ERR packet payload (starting with 0xFF).
 * @param len        Length of payload.
 * @param out_errno  [out] MySQL error number.
 * @param out_msg    [out] Pointer into payload where error message starts.
 * @param out_msg_len [out] Length of error message.
 * @return true if parsed successfully, false if payload too short.
 */
bool mysql_parse_err_packet(
    const unsigned char* payload, size_t len,
    uint16_t* out_errno, const char** out_msg, size_t* out_msg_len
);

struct MySQLOkFields {
	uint64_t affected_rows;
	uint64_t last_insert_id;
	uint16_t status_flags;
	uint16_t warnings;
};

bool mysql_is_eof_payload(const unsigned char* p, size_t n);
bool mysql_is_ok_header(const unsigned char* p, size_t n);
bool mysql_parse_ok_payload(const unsigned char* p, size_t n, MySQLOkFields* out);
bool mysql_parse_eof_payload(const unsigned char* p, size_t n, uint16_t* warnings, uint16_t* status_flags);

#endif // MYSQL_PROTOCOL_UTILS_H
