#include "proxysql.h"
#include "cpp.h"

#include "PgSQL_Extended_Query_Message.h"
#include "PgSQL_Protocol.h"

template<typename DATA, typename DERIVED>
Base_Extended_Query_Message<DATA,DERIVED>::~Base_Extended_Query_Message() noexcept {
	if (_pkt.ptr) {
		free(_pkt.ptr);
		_pkt = {};
	}
}

template<typename DATA, typename DERIVED>
PtrSize_t Base_Extended_Query_Message<DATA, DERIVED>::detach() noexcept {
	PtrSize_t result = _pkt;
	_data = {}; 
	_pkt = {};
	return result;
}

template<typename DATA, typename DERIVED>
DERIVED* Base_Extended_Query_Message<DATA,DERIVED>::release() noexcept {
	std::unique_ptr<DERIVED> msg = std::make_unique<DERIVED>();
	msg->_data = _data;
	msg->_pkt = _pkt;
	_data = {};
	_pkt = {};
	return msg.release();
}

bool PgSQL_Parse_Message::parse(PtrSize_t& pkt) {

	if (pkt.ptr == nullptr || pkt.size == 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "No packet to parse\n");
		return false;
	}

	if (pkt.size < 5) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet too short for parsing: %u bytes\n", pkt.size);
		return false;
	}

	auto packet = (unsigned char*)pkt.ptr;
	uint32_t pkt_len = pkt.size;
	uint32_t payload_len = 0;
	uint32_t offset = 0;
	PgSQL_Parse_Data& data = mutable_data();

	if (packet[offset++] != 'P') { // 'P' is the packet type for Parse
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid packet type: expected 'P'\n");
		return false;
	}

	// Read the length of the packet (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &payload_len)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(uint32_t);

	// Check if the reported packet length matches the provided length
	if (payload_len != pkt_len - 1) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size too small: %u bytes\n", pkt.size);
		return false;
	}

	// Validate remaining length for statement name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for statement name
	}

	// Read the statement name (null-terminated string)
	data.stmt_name = reinterpret_cast<char*>(packet + offset);
	size_t stmt_name_len = strnlen(data.stmt_name, pkt_len - offset);

	// Ensure there is a null-terminator within the packet length
	if (offset + stmt_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}

	offset += stmt_name_len + 1; // Move past the null-terminated statement name

	// Validate remaining length for query string (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for query string
	}

	// Read the query string (null-terminated string)
	data.query_string = reinterpret_cast<char*>(packet + offset);
	size_t query_string_len = strnlen(data.query_string, pkt_len - offset);

	// Ensure there is a null-terminator within the packet length
	if (offset + query_string_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}

	offset += query_string_len + 1;  // Move past the null-terminated query string

	// Validate remaining length for number of parameter types (2 bytes)
	if (offset + sizeof(int16_t) > pkt_len) {
		return false;  // Not enough data for numParameterTypes
	}

	// Read the length of the parameter types (2 bytes, big-endian)
	if (!get_uint16be(packet + offset, &data.num_param_types)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(int16_t);

	// If there are parameter types, ensure there's enough data for all of them
	if (data.num_param_types > 0) {
		if (offset + data.num_param_types * sizeof(uint32_t) > pkt_len) {
			return false;  // Not enough data for all parameter types
		}

		// Read the parameter types array (each is 4 bytes, big-endian)
		data.param_types_start_ptr = (packet + offset);

		// Move past the parameter types
		offset += data.num_param_types * sizeof(uint32_t);
	}

	if (offset != pkt_len) {
		return false;
	}

	// take "ownership"
	move_pkt(std::move(pkt));

	// If we reach here, the packet is valid and fully parsed
	return true;
}

PgSQL_Field_Reader<uint32_t> PgSQL_Parse_Message::get_param_types_reader() const {
	const PgSQL_Parse_Data& parse_data = data();
	return PgSQL_Field_Reader<uint32_t>(parse_data.param_types_start_ptr, parse_data.num_param_types);
}

bool PgSQL_Describe_Message::parse(PtrSize_t& pkt) {

	if (pkt.ptr == nullptr || pkt.size == 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "No packet to parse\n");
		return false;
	}

	if (pkt.size < 5) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet too short for parsing: %u bytes\n", pkt.size);
		return false;
	}

	auto packet = (unsigned char*)pkt.ptr;
	uint32_t pkt_len = pkt.size;
	uint32_t payload_len = 0;
	uint32_t offset = 0;
	PgSQL_Describe_Data& data = mutable_data();

	if (packet[offset++] != 'D') { // 'D' is the packet type for Describe
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid packet type: expected 'D'\n");
		return false;
	}

	// Read the length of the packet (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &payload_len)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(uint32_t);

	// Check if the reported packet length matches the provided length
	if (payload_len != pkt_len - 1) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size too small: %u bytes\n", pkt.size);
		return false;
	}

	// Validate remaining length for statement name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for statement name
	}

	// Read the statement type (1 byte)
	data.stmt_type = *(packet + offset);
	offset += sizeof(uint8_t);

	// Validate that the statement type is either 'S' (statement) or 'P' (portal)
	if (data.stmt_type != 'S' && data.stmt_type != 'P') {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid statement type: expected 'S' or 'P', got '%c'\n", data.stmt_type);
		return false;
	}

	// Validate remaining length for statement name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for statement name
	}

	// Read the statement name (null-terminated string)
	data.stmt_name = reinterpret_cast<char*>(packet + offset);
	size_t stmt_name_len = strnlen(data.stmt_name, pkt_len - offset);

	// Ensure there is a null-terminator within the packet length
	if (offset + stmt_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}

	offset += stmt_name_len + 1; // Move past the null-terminated statement name

	// Validate remaining length for query string (at least 1 byte for null-terminated string)
	if (offset != pkt_len) {
		return false;
	}

	// take "ownership"
	move_pkt(std::move(pkt));

	// If we reach here, the packet is valid and fully parsed
	return true;
}

// write definition of pgsql_close_message
bool PgSQL_Close_Message::parse(PtrSize_t& pkt) {
	if (pkt.ptr == nullptr || pkt.size == 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "No packet to parse\n");
		return false;
	}
	if (pkt.size < 5) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet too short for parsing: %u bytes\n", pkt.size);
		return false;
	}
	auto packet = (unsigned char*)pkt.ptr;
	uint32_t pkt_len = pkt.size;
	uint32_t payload_len = 0;
	uint32_t offset = 0;
	PgSQL_Close_Data& data = mutable_data();

	// Check the packet type
	if (packet[offset++] != 'C') { // 'C' is the packet type for Close
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid packet type: expected 'C'\n");
		return false;
	}
	// Read the length of the packet (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &payload_len)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(uint32_t);
	// Check if the reported packet length matches the provided length
	if (payload_len != pkt_len - 1) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size too small: %u bytes\n", pkt.size);
		return false;
	}
	// Read the statement type (1 byte)
	data.stmt_type = *(packet + offset);
	offset += sizeof(uint8_t);
	// Validate that the statement type is either 'S' (statement) or 'P' (portal)
	if (data.stmt_type != 'S' && data.stmt_type != 'P') {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid statement type: expected 'S' or 'P', got '%c'\n", data.stmt_type);
		return false;
	}
	// Validate remaining length for statement name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for statement name
	}
	// Read the statement name (null-terminated string)
	data.stmt_name = reinterpret_cast<char*>(packet + offset);
	size_t stmt_name_len = strnlen(data.stmt_name, pkt_len - offset);
	// Ensure there is a null-terminator within the packet length
	if (offset + stmt_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}
	offset += stmt_name_len + 1; // Move past the null-terminated statement name

	if (offset != pkt_len) {
		return false;
	}
	// take "ownership"
	move_pkt(std::move(pkt));
	// If we reach here, the packet is valid and fully parsed
	return true;
}

// implement PgSQLBind_Message 
bool PgSQL_Bind_Message::parse(PtrSize_t& pkt) {
	if (pkt.ptr == nullptr || pkt.size == 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "No packet to parse\n");
		return false;
	}
	if (pkt.size < 5) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet too short for parsing: %u bytes\n", pkt.size);
		return false;
	}
	auto packet = (unsigned char*)pkt.ptr;
	uint32_t pkt_len = pkt.size;
	uint32_t payload_len = 0;
	uint32_t offset = 0;
	PgSQL_Bind_Data& data = mutable_data();
	// Check the packet type
	if (packet[offset++] != 'B') { // 'B' is the packet type for Bind
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid packet type: expected 'B'\n");
		return false;
	}
	// Read the length of the packet (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &payload_len)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(uint32_t);
	// Check if the reported packet length matches the provided length
	if (payload_len != pkt_len - 1) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size too small: %u bytes\n", pkt.size);
		return false;
	}
	// Validate remaining length for portal name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for portal name
	}
	// Read the portal name (null-terminated string)
	data.portal_name = reinterpret_cast<char*>(packet + offset);
	size_t portal_name_len = strnlen(data.portal_name, pkt_len - offset);
	// Ensure there is a null-terminator within the packet length
	if (offset + portal_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}
	offset += portal_name_len + 1; // Move past the null-terminated portal name
	// Validate remaining length for statement name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for statement name
	}
	// Read the statement name (null-terminated string)
	data.stmt_name = reinterpret_cast<char*>(packet + offset);
	size_t stmt_name_len = strnlen(data.stmt_name, pkt_len - offset);
	// Ensure there is a null-terminator within the packet length
	if (offset + stmt_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}
	offset += stmt_name_len + 1; // Move past the null-terminated statement name
	// Validate remaining length for number of parameter formats (2 bytes)
	if (offset + sizeof(int16_t) > pkt_len) {
		return false;  // Not enough data for numParameterFormats
	}
	// Read the length of the parameter formats (2 bytes, big-endian)
	if (!get_uint16be(packet + offset, &data.num_param_formats)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(int16_t);
	// If there are parameter formats, ensure there's enough data for all of them
	if (data.num_param_formats > 0) {
		if (offset + data.num_param_formats * sizeof(uint16_t) > pkt_len) {
			return false;  // Not enough data for all parameter formats
		}
		// Read the parameter formats array (each is 2 bytes, big-endian)
		data.param_formats_start_ptr = (packet + offset);
		// Move past the parameter formats
		offset += data.num_param_formats * sizeof(uint16_t);
	}
	// Validate remaining length for number of parameter values (2 bytes)
	if (offset + sizeof(int16_t) > pkt_len) {
		return false;  // Not enough data for numParameters
	}
	// Read the length of the parameter values (2 bytes, big-endian)
	if (!get_uint16be(packet + offset, &data.num_param_values)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(int16_t);
	// If there are parameter values, ensure there's enough data for all of them
	if (data.num_param_values > 0) {
		data.param_values_start_ptr = (packet + offset);
		// Calculate the size of the parameter values array
		for (uint16_t i = 0; i < data.num_param_values; ++i) {
			if (offset + sizeof(uint32_t) > pkt_len) {
				return false;  // Not enough data for parameter value
			}
			uint32_t param_value_len;
			if (!get_uint32be(packet + offset, &param_value_len)) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read parameter value size\n");
				return false;
			}
			offset += sizeof(uint32_t);
			if (param_value_len != PGSQL_PARAM_NULL) {
				// Ensure the parameter value size is valid
				if (offset + param_value_len > pkt_len)
					return false;
				offset += param_value_len;
			}
		}
	}
	// Validate remaining length for number of result formats (2 bytes)
	if (offset + sizeof(int16_t) > pkt_len) {
		return false;  // Not enough data for numResultFormats
	}
	// Read the length of the result formats (2 bytes, big-endian)
	if (!get_uint16be(packet + offset, &data.num_result_formats)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(int16_t);
	// If there are result formats, ensure there's enough data for all of them
	if (data.num_result_formats > 0) {
		if (offset + data.num_result_formats * sizeof(uint16_t) > pkt_len) {
			return false;  // Not enough data for all result formats
		}
		// Read the result formats array (each is 2 bytes, big-endian)
		data.result_formats_start_ptr = (packet + offset);
		// Move past the result formats
		offset += data.num_result_formats * sizeof(uint16_t);
	}

	if (offset != pkt_len) {
		return false;
	}

	// take "ownership"
	move_pkt(std::move(pkt));
	// If we reach here, the packet is valid and fully parsed
	return true;
}

PgSQL_Field_Reader<uint16_t> PgSQL_Bind_Message::get_param_format_reader() const {
	const PgSQL_Bind_Data& bind_data = data();
	return PgSQL_Field_Reader<uint16_t>(bind_data.param_formats_start_ptr, bind_data.num_param_formats);
}

PgSQL_Field_Reader<uint16_t> PgSQL_Bind_Message::get_result_format_reader() const {
	const PgSQL_Bind_Data& bind_data = data();
	return PgSQL_Field_Reader<uint16_t>(bind_data.result_formats_start_ptr, bind_data.num_result_formats);
}

PgSQL_Field_Reader<PgSQL_Param_Value> PgSQL_Bind_Message::get_param_value_reader() const {
	const PgSQL_Bind_Data& bind_data = data();
	return PgSQL_Field_Reader<PgSQL_Param_Value>(bind_data.param_values_start_ptr, bind_data.num_param_values);
}

// implement PgSQL_Execute_Message
bool PgSQL_Execute_Message::parse(PtrSize_t& pkt) {
	if (pkt.ptr == nullptr || pkt.size == 0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "No packet to parse\n");
		return false;
	}
	if (pkt.size < 5) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet too short for parsing: %u bytes\n", pkt.size);
		return false;
	}
	auto packet = (unsigned char*)pkt.ptr;
	uint32_t pkt_len = pkt.size;
	uint32_t payload_len = 0;
	uint32_t offset = 0;
	PgSQL_Execute_Data& data = mutable_data();
	// Check the packet type
	if (packet[offset++] != 'E') { // 'E' is the packet type for Execute
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Invalid packet type: expected 'E'\n");
		return false;
	}
	// Read the length of the packet (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &payload_len)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read packet size\n");
		return false;
	}
	offset += sizeof(uint32_t);
	// Check if the reported packet length matches the provided length
	if (payload_len != pkt_len - 1) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size too small: %u bytes\n", pkt.size);
		return false;
	}
	// Validate remaining length for portal name (at least 1 byte for null-terminated string)
	if (offset >= pkt_len) {
		return false;  // Not enough data for portal name
	}
	// Read the portal name (null-terminated string)
	data.portal_name = reinterpret_cast<char*>(packet + offset);
	size_t portal_name_len = strnlen(data.portal_name, pkt_len - offset);
	// Ensure there is a null-terminator within the packet length
	if (offset + portal_name_len >= pkt_len) {
		return false;  // No null-terminator found within the packet bounds
	}
	offset += portal_name_len + 1; // Move past the null-terminated portal name
	// Validate remaining length for max rows (4 bytes)
	if (offset + sizeof(uint32_t) > pkt_len) {
		return false;  // Not enough data for max rows
	}
	// Read the maximum number of rows to return (4 bytes, big-endian)
	if (!get_uint32be(packet + offset, &data.max_rows)) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Failed to read max rows size\n");
		return false;
	}
	offset += sizeof(uint32_t);
	// Validate that we have consumed the entire packet
	if (offset != pkt_len) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 1, "Packet size mismatch: expected %u bytes, got %u bytes\n", pkt_len, offset);
		return false;
	}
	// take "ownership"
	move_pkt(std::move(pkt));
	// If we reach here, the packet is valid and fully parsed
	return true;
}

template class Base_Extended_Query_Message<PgSQL_Parse_Data, PgSQL_Parse_Message>;
template class Base_Extended_Query_Message<PgSQL_Describe_Data, PgSQL_Describe_Message>;
template class Base_Extended_Query_Message<PgSQL_Close_Data, PgSQL_Close_Message>;
template class Base_Extended_Query_Message<PgSQL_Bind_Data, PgSQL_Bind_Message>;
template class Base_Extended_Query_Message<PgSQL_Execute_Data, PgSQL_Execute_Message>;
