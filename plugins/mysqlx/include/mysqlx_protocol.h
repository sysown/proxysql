#ifndef PROXYSQL_MYSQLX_PROTOCOL_H
#define PROXYSQL_MYSQLX_PROTOCOL_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// X Protocol frame header: 4-byte payload_size (LE) + 1-byte message_type.
// payload_size includes the message_type byte.
struct MysqlxFrameHeader {
	uint32_t payload_size { 0 };
	uint8_t message_type { 0 };
};

static constexpr size_t MYSQLX_FRAME_HEADER_SIZE = 5; // 4 + 1

// Maximum allowed X Protocol frame payload (16 MB).  Protects against
// OOM from a malicious client claiming a multi-GB payload.
static constexpr uint32_t MYSQLX_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

// Encode a frame header into a 5-byte buffer.
std::vector<uint8_t> mysqlx_encode_frame_header(const MysqlxFrameHeader& hdr);

// Decode a frame header from raw bytes.  Returns nullopt if len < 5.
std::optional<MysqlxFrameHeader> mysqlx_decode_frame_header(const uint8_t* data, size_t len);

// Check if an auth method name is supported by our plugin (Phase 1).
bool mysqlx_is_supported_auth_method(const std::string& method);

// Build a complete X Protocol frame: header + serialized protobuf payload.
std::vector<uint8_t> mysqlx_build_frame(uint8_t message_type, const std::string& serialized_payload);

// Read exactly `len` bytes from fd into buf.  Returns false on error/EOF.
bool mysqlx_read_exact(int fd, uint8_t* buf, size_t len);

// Read one complete X Protocol frame from fd.  Fills header and payload.
bool mysqlx_read_frame(int fd, MysqlxFrameHeader& header, std::vector<uint8_t>& payload);

// Write a complete buffer to fd.  Returns false on error.
bool mysqlx_write_all(int fd, const uint8_t* data, size_t len);

// Build and send an X Protocol Error frame.
bool mysqlx_send_error(int fd, uint16_t code, const std::string& msg, const std::string& sql_state = "HY000");

// Build and send an X Protocol Ok frame.
bool mysqlx_send_ok(int fd, const std::string& msg = "");

// MYSQL41 auth helpers
std::vector<uint8_t> mysqlx_mysql41_hash(const std::string& password);
std::vector<uint8_t> mysqlx_mysql41_scramble(const std::vector<uint8_t>& challenge,
                                              const std::string& password);
bool mysqlx_mysql41_verify(const std::vector<uint8_t>& challenge,
                            const std::vector<uint8_t>& client_response,
                            const std::string& password);

#endif /* PROXYSQL_MYSQLX_PROTOCOL_H */
