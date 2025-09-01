#ifndef CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H
#define CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H

#include "proxysql.h"
#include "cpp.h"


/**
 * @brief Base class for handling PostgreSQL extended query messages.
 *
 * @tparam DATA    The structure type holding parsed message data.
 * @tparam DERIVED The derived message class type.
 */
template<typename DATA, typename DERIVED>
class Base_Extended_Query_Message {

public:
	Base_Extended_Query_Message() noexcept = default;
	~Base_Extended_Query_Message() noexcept;

	// Disable copy and move operations to prevent slicing and ensure proper ownership semantics
	Base_Extended_Query_Message(const Base_Extended_Query_Message&) = delete;
	Base_Extended_Query_Message& operator=(const Base_Extended_Query_Message&) = delete;
	Base_Extended_Query_Message(Base_Extended_Query_Message&&) = delete;
	Base_Extended_Query_Message& operator=(Base_Extended_Query_Message&&) = delete;

	/**
	  * @brief Releases the ownership of the packet and returns a new message object.
	  *
	  * This method transfers ownership of the packet data to a new message object
	  * and resets the current message's internal state.
	  *
	  * @return A pointer to the newly created message object with transferred data.
	  */
	DERIVED* release() noexcept;

	/**
	  * @brief Detaches the packet data from the message.
	  *
	  * @return The detached packet data as a PtrSize_t structure.
	  */
	PtrSize_t detach() noexcept;

	/**
	 * @brief Returns a const reference to the parsed data.
	 *
	 * @return Const reference to the DATA structure.
	 */
	inline const DATA& data() const noexcept {
		return _data;
	}

	/**
	 * @brief Returns a reference to the internal packet data.
	 *
	 * @return Reference to the PtrSize_t structure containing packet data.
	 */
	inline const PtrSize_t& get_raw_pkt() const noexcept {
		return _pkt;
	}

	inline PtrSize_t& get_raw_pkt() noexcept {
		return _pkt;
	}

protected:
	/**
	 * @brief Provides mutable access to the internal data.
	 *
	 * @return Reference to the DATA structure.
	 */
	inline DATA& mutable_data() noexcept {
		return _data;
	}

	/**
	 * @brief Moves ownership of packet data from source to internal storage.
	 *
	 * @param src Rvalue reference to the source PtrSize_t.
	 */
	inline void move_pkt(PtrSize_t&& src) noexcept {
		_pkt = { src.size, src.ptr };
		src = PtrSize_t{ 0, nullptr };
	}

private:
	DATA _data = {};		///< Parsed message data.
	PtrSize_t _pkt = {};	///< Packet data pointer.
};

struct PgSQL_Param_Value {
	int32_t len;         ///< Length of value (-1 for NULL)
	const unsigned char* value;  ///< Pointer to value data
};


/**
 * @brief Reads fields from a PostgreSQL extended query message.
 *
 * This template class provides an iterator-like interface for reading a sequence of fields
 * from a buffer, converting each field from network byte order (big-endian) to host byte order.
 * It supports reading different field types such as uint32_t, uint16_t, and PgSQL_Param_Value.
 *
 * Note: The buffer pointer passed to this reader may be nullptr if count is zero (valid case).
 * If count is non-zero but the buffer is invalid (malformed packet), this is detected and handled
 * during parsing before constructing the reader.
 *
 * @tparam T The type of field to read (e.g., uint32_t, uint16_t, PgSQL_Param_Value).
 */
template<class T>
class PgSQL_Field_Reader {
public:
	/**
	  * @brief Constructs a field reader.
	  * @param start Pointer to the start of the field array.
	  * @param count Number of fields to read.
	  */
	PgSQL_Field_Reader(const unsigned char* start, uint16_t count) : current(start), remaining(count) {}
	~PgSQL_Field_Reader() = default;
	PgSQL_Field_Reader() = delete;
	PgSQL_Field_Reader(const PgSQL_Field_Reader&) = default;
	PgSQL_Field_Reader& operator=(const PgSQL_Field_Reader&) = default;
	PgSQL_Field_Reader(PgSQL_Field_Reader&&) = default;
	PgSQL_Field_Reader& operator=(PgSQL_Field_Reader&&) = default;

	/**
	  * @brief Checks if there are more fields to read.
	  * @return True if more fields are available, false otherwise.
	  */
	bool has_next() const { return remaining > 0; }

	/**
	  * @brief Reads the next field from the buffer.
	  * @param out Pointer to the output variable to store the field value.
	  * @return True if the field was successfully read, false otherwise.
	  *
	  * For uint32_t and uint16_t, reads the value in big-endian order.
	  * For PgSQL_Param_Value, reads the length and value pointer, handling NULL values.
	  */
	bool next(T* out) {
		if (remaining == 0) return false;

		if constexpr (std::is_same_v<T, uint32_t>) {
			if (!get_uint32be(current, out)) {
				return false;
			}
			current += sizeof(uint32_t);
		} else if constexpr (std::is_same_v<T, uint16_t>) {
			if (!get_uint16be(current, out)) {
				return false;
			}
			current += sizeof(uint16_t);
		} else if constexpr (std::is_same_v<T, PgSQL_Param_Value>) {
			// Read length (big-endian)
			uint32_t len;
			if (!get_uint32be(current, &len)) {
				return false;
			}
			current += sizeof(uint32_t);

			out->len = (len == 0xFFFFFFFF) ? -1 : static_cast<int32_t>(len);
			out->value = (len == 0xFFFFFFFF) ? nullptr : current;

			// Advance pointer if not NULL
			if (out->len > 0) {
				current += len;
			}
		}
		remaining--;
		return true;
	}
private:
	const unsigned char* current;   ///< Current position in the buffer.
	uint16_t remaining;				///< Number of fields remaining to read.
};

struct PgSQL_Parse_Data {
	const char* stmt_name;		// The name of the prepared statement
	const char* query_string;	// The query string to be prepared
	uint16_t num_param_types;		// Number of parameter types specified

private:
	const unsigned char* param_types_start_ptr;	// Array of parameter types (can be nullptr if none)

	friend class PgSQL_Parse_Message;
	friend class PgSQL_Session; // need it for void PgSQL_Session::handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t* pkt);
};

class PgSQL_Parse_Message : public Base_Extended_Query_Message<PgSQL_Parse_Data,PgSQL_Parse_Message> {
public:

	/**
	 * @brief Parses the PgSQL_Parse_Message from the provided packet.
	 *
	 * This method extracts the statement name, query string, parameter types,
	 * and initializes the internal state of the PgSQL_Parse_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Parse_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);

	// Initialize param type iterator
	PgSQL_Field_Reader<uint32_t> get_param_types_reader() const;
};

struct PgSQL_Describe_Data {
	const char* stmt_name;		// The name of the prepared statement or portal
	uint8_t stmt_type;			// 'S' for statement, 'P' for portal
};

class PgSQL_Describe_Message : public Base_Extended_Query_Message<PgSQL_Describe_Data, PgSQL_Describe_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Describe_Message from the provided packet.
	 *
	 * This method extracts the statement type and name from the packet and
	 * initializes the internal state of the PgSQL_Describe_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Describe_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

struct PgSQL_Close_Data {
	uint8_t stmt_type;		// 'S' for statement, 'P' for portal
	const char* stmt_name;	// The name of the prepared statement or portal
};

// Class for handling Close messages for prepared statements and portals
class PgSQL_Close_Message : public Base_Extended_Query_Message<PgSQL_Close_Data,PgSQL_Close_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Close_Message from the provided packet.
	 *
	 * This method extracts the statement type and name from the packet and
	 * initializes the internal state of the PgSQL_Close_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Close_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

struct PgSQL_Bind_Data {
	const char* portal_name;		// The name of the portal to bind
	const char* stmt_name;			// The name of the prepared statement to bind
	uint16_t num_param_formats;		// Number of parameter formats
	uint16_t num_param_values;		// Number of parameter values
	uint16_t num_result_formats;	// Number of result format codes

private:
	const unsigned char* param_formats_start_ptr; // Pointer to the start of parameter formats (can be nullptr if none)
	const unsigned char* param_values_start_ptr; // Pointer to the start of parameter values (can be nullptr if none)
	const unsigned char* result_formats_start_ptr; // Pointer to the start of result formats (can be nullptr if none)

	friend class PgSQL_Bind_Message;
};

class PgSQL_Bind_Message : public Base_Extended_Query_Message<PgSQL_Bind_Data,PgSQL_Bind_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Bind_Message from the provided packet.
	 *
	 * This method extracts the portal name, statement name, parameter formats,
	 * parameter values, and result formats from the packet and initializes the
	 * internal state of the PgSQL_Bind_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Bind_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);

	// Initialize param type iterator
	PgSQL_Field_Reader<uint16_t> get_param_format_reader() const;
	// Initialize result format iterator
	PgSQL_Field_Reader<uint16_t> get_result_format_reader() const;
	// Initialize parameter value iterator
	PgSQL_Field_Reader<PgSQL_Param_Value> get_param_value_reader() const;
};

struct PgSQL_Execute_Data {
	const char* portal_name;	// The name of the portal to execute
	uint32_t max_rows;			// Maximum number of rows to return (0 for no limit)
};

class PgSQL_Execute_Message : public Base_Extended_Query_Message<PgSQL_Execute_Data,PgSQL_Execute_Message> {
public:
	/**
	 * @brief Parses the PgSQL_Execute_Message from the provided packet.
	 *
	 * This method extracts the portal name and maximum rows from the packet
	 * and initializes the internal state of the PgSQL_Execute_Message object.
	 *
	 * @param pkt The packet containing the PgSQL_Execute_Message data.
	 *
	 * @return True if parsing was successful, false otherwise.
	 */
	bool parse(PtrSize_t& pkt);
};

#endif /* CLASS_PGSQL_EXTENDED_QUERY_MESSAGE_H */
