#ifndef __POSTGRES_PROTOCOL_H
#define __POSTGRES_PROTOCOL_H

#include "proxysql.h"
#include "gen_utils.h"
#include "MySQL_Protocol.h"


/* no-auth modes */
#define PG_PKT_AUTH_ANY        -1	/* same as trust but without username check */
#define PG_PKT_AUTH_TRUST      AUTH_OK

/* protocol codes in Authentication* 'R' messages from server */
#define PG_PKT_AUTH_OK         0
#define PG_PKT_AUTH_KRB4       1	/* not supported */
#define PG_PKT_AUTH_KRB5       2	/* not supported */
#define PG_PKT_AUTH_PLAIN      3
#define PG_PKT_AUTH_CRYPT      4	/* not supported */
#define PG_PKT_AUTH_MD5        5
#define PG_PKT_AUTH_SCM_CREDS  6	/* not supported */
#define PG_PKT_AUTH_GSS        7	/* not supported */
#define PG_PKT_AUTH_GSS_CONT   8	/* not supported */
#define PG_PKT_AUTH_SSPI       9	/* not supported */
#define PG_PKT_AUTH_SASL       10
#define PG_PKT_AUTH_SASL_CONT  11
#define PG_PKT_AUTH_SASL_FIN   12

/* internal codes */
#define AUTH_CERT       107
#define AUTH_PEER       108
#define AUTH_HBA        109
#define AUTH_REJECT     110
#define AUTH_PAM        111
#define AUTH_SCRAM_SHA_256      112

#define PG_PKT_STARTUP_V2  0x20000
#define PG_PKT_STARTUP     0x30000
#define PG_PKT_CANCEL      80877102
#define PG_PKT_SSLREQ      80877103
#define PG_PKT_GSSENCREQ   80877104

#define PG_PKT_DEFAULT_SIZE	64


/* old style V2 header: len:4b code:4b */
#define OLD_HEADER_LEN  8
/* new style V3 packet header len - type:1b, len:4b */
#define NEW_HEADER_LEN  5

#define PGSQL_RESULTSET_BUFLEN		(16 * 1024)

class ProxySQL_Admin;
struct PgCredentials;
struct ScramState;

enum class EXECUTION_STATE {
	FAILED = 0,
	SUCCESSFUL,
	PENDING
};

struct pgsql_hdr {
	uint32_t type;
	uint32_t len;
	PtrSize_t data;
};

struct PG_Field {
	char*	 name;
	uint32_t tbl_oid;
	uint16_t col_idx;
	uint32_t type_oid;
	uint16_t col_len;
	uint32_t type_mod;
	uint16_t fmt;
};

using PG_Fields = std::vector<PG_Field>;

class PG_pkt 
{
public:
	PG_pkt(unsigned c = PG_PKT_DEFAULT_SIZE) {
		ownership = true;
		capacity = l_near_pow_2(c);
		size = 0;
		ptr = (char*)malloc(capacity);
		multiple_pkt_mode = false;
	}
	PG_pkt(void* _ptr, unsigned int _capacity) {
		ownership = false;
		ptr = (char*)_ptr;
		capacity = _capacity;
		size = 0;
	}
	~PG_pkt() {
		reset();
	}

	void reset() {
		if (ptr) {
			if (ownership == true)
				free(ptr);
			else
				assert(size == capacity); // just to check if we are not passing buffer boundaries
		}
		ptr = nullptr;
		size = 0;
		capacity = 0;
		multiple_pkt_mode = false;
		pkt_offset.clear();
	}

	std::pair<char*, unsigned int> detach() {
		std::pair<char*, unsigned int> result(ptr, size);
		ptr = nullptr;
		size = 0;
		capacity = 0;
		multiple_pkt_mode = false;
		pkt_offset.clear();
		return result;
	}

	PtrSize_t* get_PtrSize(unsigned c = PG_PKT_DEFAULT_SIZE);

	/**
	 * @brief Moves the current packet data to a PtrSizeArray.
	 *
	 * This function adds the current `ptr` and `size` to the provided
	 * `PtrSizeArray` (`psa`). It then resets the internal buffer (`ptr` and
	 * `size`) to a new buffer with a capacity of `c` if `c` is not zero.
	 *
	 * @param psa The PtrSizeArray where the current packet data will be added.
	 * @param c The desired capacity of the new internal buffer.
	 */
	void to_PtrSizeArray(PtrSizeArray* psa, unsigned c = PG_PKT_DEFAULT_SIZE);

	void set_multi_pkt_mode(bool mode) {
		multiple_pkt_mode = mode;

		if (mode == false)
			pkt_offset.clear();
	}
	/**
	 * @brief Resizes the internal buffer if needed to accommodate additional data.
	 *
	 * If the current size of the internal buffer (`size`) plus the requested length
	 * (`len`) exceeds the buffer's capacity (`capacity`), this function reallocates
	 * the buffer to a new size that's the nearest power of 2 greater than or equal
	 * to `size + len`.
	 *
	 * If the buffer already has enough space, this function does nothing.
	 *
	 * @param len The number of bytes of additional space required.
	 *
	 * @note This function only resizes the buffer if the `ownership` flag is true,
	 *       indicating that the buffer is owned by the `PG_pkt` object.
	 */
	void make_space(unsigned int len);

	/**
	 * @brief Appends a single character to the internal buffer.
	 *
	 * This function ensures there's enough space in the buffer and then appends
	 * the given character (`val`) to the end of the buffer.
	 *
	 * @param val The character to append.
	 */
	void put_char(char val);

	/**
	 * @brief Appends a 16-bit unsigned integer to the internal buffer.
	 *
	 * This function ensures there's enough space in the buffer and then appends
	 * the given 16-bit unsigned integer (`val`) in big-endian byte order.
	 *
	 * @param val The 16-bit unsigned integer to append.
	 */
	void put_uint16(uint16_t val);

	/**
	 * @brief Appends a 32-bit unsigned integer to the internal buffer.
	 *
	 * This function ensures there's enough space in the buffer and then appends
	 * the given 32-bit unsigned integer (`val`) in big-endian byte order.
	 *
	 * @param val The 32-bit unsigned integer to append.
	 */
	void put_uint32(uint32_t val);

	/**
	 * @brief Appends a 64-bit unsigned integer to the internal buffer.
	 *
	 * This function appends the given 64-bit unsigned integer (`val`) to the
	 * internal buffer in big-endian byte order.
	 *
	 * @param val The 64-bit unsigned integer to append.
	 */
	void put_uint64(uint64_t val);

	/**
	 * @brief Appends a block of bytes to the internal buffer.
	 *
	 * This function ensures there's enough space in the buffer and then copies
	 * `len` bytes from the provided data pointer (`data`) to the end of the buffer.
	 *
	 * @param data A pointer to the beginning of the data to append.
	 * @param len The number of bytes to append.
	 */
	void put_bytes(const void* data, int len);

	/**
	 * @brief Appends a null-terminated string to the internal buffer.
	 *
	 * This function appends the given null-terminated string (`str`) to the
	 * internal buffer, including the null terminator.
	 *
	 * @param str The null-terminated string to append.
	 */
	void put_string(const char* str);
	
	void write_generic(int type, const char* pktdesc, ...);

	void write_ParameterStatus(const char* key, const char* val) {
		write_generic('S', "ss", key, val);
	}
	void write_AuthenticationOk() {
		write_generic('R', "i", 0);
	}
	void write_AuthenticationRequest(uint32_t auth_type, const uint8_t* data, int len) {
		write_generic('R', "ib", auth_type, data, len);
	}
	void write_ReadyForQuery(char txn_state = 'I') {
		write_generic('Z', "c", txn_state);
	}
	void write_CommandComplete(const char* desc) {
		write_generic('C', "s", desc);
	}
	void write_BackendKeyData(const uint8_t* key) {
		write_generic('K', "b", key, 8);
	}
	void write_StartupMessage(const char* user, const char* parms, int parms_len) {
		write_generic(PG_PKT_STARTUP, "bsss", parms, parms_len, "user", user, "");
	}
	void write_PasswordMessage(const char* psw) {
		write_generic('p', "s", psw);
	}

	void write_RowDescription(const char* tupdesc, ...);
	void write_DataRow(const char* tupdesc, ...);

private:
	/**
	 * @brief Initializes a new packet with a specified type.
	 *
	 * This function sets the first byte of the packet to the given `type` and
	 * reserves space for the packet length (which will be filled in later).
	 *
	 * @param type The type of the packet (must be a value between 0 and 255).
	 */
	void start_packet(int type);

	/**
	 * @brief Completes a packet by filling in the length field.
	 *
	 * This function calculates the length of the packet (excluding the type
	 * byte) and writes it to the appropriate position in the packet buffer.
	 *
	 * @note If the `multiple_pkt_mode` flag is set to true, the length is
	 *       calculated and written based on the last recorded packet offset.
	 */
	void finish_packet();

	char* ptr;
	unsigned int size;
	unsigned int capacity;

	// currently for debug only. will replace this with a single variable that will contain last pkt offset
	std::vector<unsigned int> pkt_offset;
	bool multiple_pkt_mode = false;
	bool ownership = true;
	friend void SQLite3_to_Postgres(PtrSizeArray* psa, SQLite3_result* result, char* error, int affected_rows, const char* query_type);
};

class PgSQL_Protocol;

#define PGSQL_QUERY_RESULT_NO_DATA	0x00
#define PGSQL_QUERY_RESULT_TUPLE	0x01
#define PGSQL_QUERY_RESULT_COMMAND	0x02
#define PGSQL_QUERY_RESULT_READY	0x04
#define PGSQL_QUERY_RESULT_ERROR	0x08
#define PGSQL_QUERY_RESULT_EMPTY	0x10

class PgSQL_Query_Result {
public:
	PgSQL_Query_Result();
	~PgSQL_Query_Result();

	/**
	 * @brief Initializes the PgSQL_Query_Result object.
	 *
	 * This method initializes the `PgSQL_Query_Result` object with the
	 * provided `PgSQL_Protocol`, `PgSQL_Data_Stream`, and `PgSQL_Connection`
	 * objects. It also initializes the internal buffer using the
	 * `buffer_init` method and resets any internal state.
	 *
	 * @param _proto A pointer to the `PgSQL_Protocol` object associated with
	 *               this query result.
	 * @param _myds A pointer to the `PgSQL_Data_Stream` object associated with
	 *              this query result.
	 * @param _conn A pointer to the `PgSQL_Connection` object associated with
	 *              this query result.
	 *
	 * @note This method is typically called when a new query is executed.
	 */
	void init(PgSQL_Protocol* _proto, PgSQL_Data_Stream* _myds, PgSQL_Connection* _conn);

	/**
	 * @brief Adds a row description to the query result.
	 *
	 * This method adds a row description (from a `PGresult` object) to the
	 * query result. It copies the row description data to the internal buffer
	 * or to the `PSarrayOUT` if the buffer is full.
	 *
	 * @param result A pointer to a `PGresult` object containing the row
	 *               description to add.
	 *
	 * @return The number of bytes added to the query result.
	 *
	 * @note This method is used to prepare the client for receiving rows
	 *       with the corresponding data types and column names.
	 */
	unsigned int add_row_description(const PGresult* result);

	/**
	 * @brief Adds a row of data to the query result.
	 *
	 * This method adds a row of data (from a `PGresult` object) to the query
	 * result. It copies the row data to the internal buffer or to the
	 * `PSarrayOUT` if the buffer is full.
	 *
	 * @param result A pointer to a `PGresult` object containing the row data
	 *               to add.
	 *
	 * @return The number of bytes added to the query result.
	 */
	unsigned int add_row(const PGresult* result);

	/**
	 * @brief Adds a row of data to the query result from a PSresult.
	 *
	 * This method adds a row of data (from a `PSresult` object) to the query
	 * result. It copies the row data to the internal buffer or to the
	 * `PSarrayOUT` if the buffer is full.
	 *
	 * @param result A pointer to a `PSresult` object containing the row data
	 *               to add.
	 *
	 * @return The number of bytes added to the query result.
	 */
	unsigned int add_row(const PSresult* result);

	/**
	 * @brief Adds a command completion message to the query result.
	 *
	 * This method adds a command completion message (from a `PGresult`
	 * object) to the query result. It extracts the command tag and affected
	 * rows count (if requested) and adds them to the internal buffer or the
	 * `PSarrayOUT` if the buffer is full.
	 *
	 * @param result A pointer to a `PGresult` object containing the command
	 *               completion message.
	 * @param extract_affected_rows A boolean flag indicating whether to
	 *                             extract the affected rows count from the
	 *                             `PGresult` object.
	 *
	 * @return The number of bytes added to the query result.
	 *
	 * @note This method is used to signal the completion of a command
	 *       (e.g., INSERT, UPDATE, DELETE) and to send the appropriate
	 *       response to the client.
	 */
	unsigned int add_command_completion(const PGresult* result, bool extract_affected_rows = true);

	/**
	 * @brief Adds an error message to the query result.
	 *
	 * This method adds an error message (from a `PGresult` object) to the
	 * query result. It copies the error data to the internal buffer or to the
	 * `PSarrayOUT` if the buffer is full.
	 *
	 * @param result A pointer to a `PGresult` object containing the error
	 *               message to add.
	 *
	 * @return The number of bytes added to the query result.
	 *
	 * @note This method is used to handle errors that occur during query
	 *       execution and to send the error information to the client.
	 */
	unsigned int add_error(const PGresult* result);

	/**
	 * @brief Adds an empty query response to the query result.
	 *
	 * This method adds an empty query response (for example from query
	 * returning no rows) to the query result. It copies the empty query
	 * response data to the internal buffer or to the `PSarrayOUT` if the
	 * buffer is full.
	 *
	 * @param result A pointer to a `PGresult` object representing the empty
	 *               response.
	 *
	 * @return The number of bytes added to the query result.
	 *
	 * @note This method is used to handle cases where a query does not
	 *       return any rows or data, and to send the appropriate response
	 *       to the client.
	 */
	unsigned int add_empty_query_response(const PGresult* result);

	/**
	 * @brief Adds a ready status message to the query result.
	 *
	 * This method adds a ready status message to the query result, indicating
	 * that the server is ready for a new query. The status reflects the
	 * transaction state.
	 *
	 * @param txn_status The transaction status type, indicating whether a
	 *                   transaction is in progress or not.
	 *
	 * @return The number of bytes added to the query result.
	 *
	 * @note This method is used to signal to the client that the server is
	 *       ready for a new query and that any previous query has completed.
	 */
	unsigned int add_ready_status(PGTransactionStatusType txn_status);

	/**
	 * @brief Retrieves the query result set and copies it to a PtrSizeArray.
	 *
	 * This method retrieves the accumulated query result, including row
	 * descriptions, rows, errors, etc., and copies it to the provided
	 * `PtrSizeArray`. It also resets the internal state of the
	 * `PgSQL_Query_Result` object after the result set is copied.
	 *
	 * @param PSarrayFinal The `PtrSizeArray` where the query result will be
	 *                    copied.
	 *
	 * @return `true` if the result set is complete (i.e., a ready status
	 *         packet has been added), `false` otherwise.
	 *
	 * @note This method is typically called when all query results have been
	 *       accumulated and are ready to be sent to the client.
	 */
	bool get_resultset(PtrSizeArray* PSarrayFinal); // this also calls reset 

	/**
	 * @brief Calculates the current size of the PgSQL_Query_Result object.
	 *
	 * This method calculates the total size of the `PgSQL_Query_Result`
	 * object in bytes, including the size of the object itself, the internal
	 * buffer, and any packets stored in the `PSarrayOUT`.
	 *
	 * @return The current size of the `PgSQL_Query_Result` object in bytes.
	 */
	unsigned long long current_size();

	inline bool is_transfer_started() const { return transfer_started; }
	inline unsigned long long get_num_rows() const { return num_rows; }
	inline unsigned long long get_affected_rows() const { return affected_rows; }
	inline unsigned int get_num_fields() const { return num_fields; }
	inline unsigned long long get_resultset_size() const { return resultset_size; }
	inline uint8_t get_result_packet_type() const { return result_packet_type; }

private:
	/**
	 * @brief Initializes the internal buffer for storing query results.
	 *
	 * If the `buffer` pointer is null, this function allocates a new buffer
	 * of size `PGSQL_RESULTSET_BUFLEN` and assigns it to the `buffer` pointer.
	 * It also resets the `buffer_used` counter to 0, indicating that the
	 * buffer is currently empty.
	 *
	 * @note This method is called by the `init` method to ensure that the
	 *       buffer is properly initialized before any query results are added.
	 */
	void buffer_init();

	inline unsigned int buffer_available_capacity() const { return (PGSQL_RESULTSET_BUFLEN - buffer_used); }

	/**
	 * @brief Reserves space in the internal buffer and returns a pointer.
	 *
	 * This method checks if there is enough space in the internal `buffer`
	 * to store the requested `size` of data. If there is space, it returns
	 * a pointer to the available location and updates `buffer_used`.
	 * Otherwise, it flushes the buffer to `PSarrayOUT`, allocates a new
	 * buffer, and returns a pointer to the available location.
	 *
	 * @param size The number of bytes of space to reserve.
	 *
	 * @return A pointer to the reserved space in the buffer, or `NULL` if
	 *         there is not enough space.
	 *
	 * @note This method is used to efficiently manage the internal buffer
	 *       and avoid unnecessary memory allocations.
	 */
	unsigned char* buffer_reserve_space(unsigned int size);

	/**
	 * @brief Flushes the internal buffer to the PSarrayOUT.
	 *
	 * This method moves the data currently stored in the internal `buffer`
	 * to the `PSarrayOUT` (a `PtrSizeArray`). It then resizes the
	 * `buffer` to the default size `PGSQL_RESULTSET_BUFLEN` and resets
	 * `buffer_used` to 0.
	 *
	 * @note This method is used when the internal `buffer` is full and
	 *       needs to be flushed to release the memory and continue adding
	 *       more data.
	 */
	void buffer_to_PSarrayOut();

	/**
	 * @brief Resets the internal state of the PgSQL_Query_Result object.
	 *
	 * This method resets the internal state of the `PgSQL_Query_Result`
	 * object to its initial state, including clearing the result set data,
	 * resetting counters, and preparing for a new query result.
	 *
	 * @note This method is typically called after the query result has been
	 *       sent to the client and the object is ready to handle a new query.
	 */
	void reset();

	PtrSizeArray PSarrayOUT;
	unsigned long long resultset_size;
	unsigned long long num_rows;
	unsigned long long pkt_count;
	unsigned long long affected_rows;
	unsigned int num_fields;
	unsigned int buffer_used;
	unsigned char* buffer;
	PgSQL_Protocol* proto;
	PgSQL_Data_Stream* myds;
	PgSQL_Connection* conn;
	bool transfer_started;
	uint8_t result_packet_type;

	friend class PgSQL_Protocol;
	friend class PgSQL_Connection;
};

class PgSQL_Protocol : public MySQL_Protocol {
public:
	void init(PgSQL_Data_Stream** __myds, PgSQL_Connection_userinfo* __userinfo, PgSQL_Session* __sess) {
		myds = __myds;
		userinfo = __userinfo;
		sess = __sess;
		current_PreStmt = NULL;
	}
	PgSQL_Data_Stream* get_myds() { return *myds; }

	/**
	 * @brief Generates the initial handshake packet for the PostgreSQL protocol.
	 *
	 * This function generates the initial handshake packet that is sent to the
	 * PostgreSQL client.  It includes an authentication request based on the
	 * configured authentication method (`pgsql_thread___authentication_method`).
	 *
	 * @param send A boolean flag indicating whether to send the packet immediately
	 *             or just generate it.
	 * @param _ptr A pointer to a pointer where the generated packet data will be
	 *            stored (if `send` is false).
	 * @param len A pointer to an unsigned integer where the length of the
	 *           generated packet will be stored (if `send` is false).
	 * @param _thread_id A pointer to a 32-bit unsigned integer where the thread ID
	 *                  will be stored.
	 * @param deprecate_eof_active A boolean flag to control deprecation of EOF
	 *                            active behavior.
	 *
	 * @return `true` if the packet was successfully generated, `false` otherwise.
	 *
	 * @note This function updates the authentication method and next packet type
	 *       in the `PgSQL_Data_Stream` object. If `send` is true, it also adds
	 *       the generated packet to the output buffer and updates the data stream
	 *       state.
	 */
	bool generate_pkt_initial_handshake(bool send, void** ptr, unsigned int* len, uint32_t* thread_id, bool deprecate_eof_active) override;

	/**
	 * @brief Processes a PostgreSQL startup packet.
	 *
	 * This function processes a PostgreSQL startup packet received from the
	 * client. It extracts the connection parameters, checks for SSL requests,
	 * and validates the user name.
	 *
	 * @param pkt A pointer to the beginning of the packet buffer.
	 * @param len The length of the packet buffer in bytes.
	 * @param ssl_request A boolean variable that is set to `true` if the client
	 *                   requests an SSL connection.
	 *
	 * @return `true` if the startup packet was successfully processed, `false`
	 *         otherwise.
	 *
	 * @note This function updates the data stream state to `STATE_SERVER_HANDSHAKE`
	 *       after successfully processing the startup packet. It also handles
	 *       SSL requests and generates an error packet if the user name is
	 *       missing.
	 */
	bool process_startup_packet(unsigned char* pkt, unsigned int len, bool& ssl_request);

	/**
	 * @brief Processes a PostgreSQL handshake response packet.
	 *
	 * This function processes a handshake response packet received from the
	 * PostgreSQL client. It handles authentication based on the selected
	 * authentication method (e.g., clear text password, SCRAM-SHA-256) and
	 * updates the session state.
	 *
	 * @param pkt A pointer to the beginning of the packet buffer.
	 * @param len The length of the packet buffer in bytes.
	 *
	 * @return The execution state after processing the handshake response
	 *         packet.
	 *
	 * @note This function validates the packet type, retrieves user credentials
	 *       from the database, performs authentication, and updates the session
	 *       state. It also handles errors related to authentication and invalid
	 *       packets.
	 */
	EXECUTION_STATE process_handshake_response_packet(unsigned char* pkt, unsigned int len);

	/**
	 * @brief Sends a welcome message to the PostgreSQL client.
	 *
	 * This function sends a welcome message to the PostgreSQL client after a
	 * successful authentication. The welcome message includes parameter status
	 * messages and a ready-for-query message.
	 *
	 * @note This function updates the output buffer with the welcome message
	 *       data. It also sets the session state to `STATE_CLIENT_AUTH_OK`.
	 */
	void welcome_client();

	/**
	 * @brief Generates an error packet for the PostgreSQL protocol.
	 *
	 * This function generates an error packet that is sent to the PostgreSQL
	 * client in case of an error. It includes the error severity, code, and
	 * message.
	 *
	 * @param send A boolean flag indicating whether to send the packet
	 *            immediately or just generate it.
	 * @param ready A boolean flag indicating whether to generate a ready-for-query
	 *             packet after the error.
	 * @param msg The error message to be included in the packet.
	 * @param code The error code.
	 * @param fatal A boolean flag indicating whether the error is fatal.
	 * @param track A boolean flag to control whether to track the error count.
	 * @param _ptr A pointer to a `PtrSize_t` structure (if `send` is false)
	 *            where the generated packet data will be stored.
	 *
	 * @note This function updates the output buffer with the generated error
	 *       packet. It also updates the data stream state to `STATE_ERR` if
	 *       necessary.
	 */
	void generate_error_packet(bool send, bool ready, const char* msg, PGSQL_ERROR_CODES code, bool fatal, bool track = false, PtrSize_t* _ptr = NULL);

	/**
	 * @brief Generates an "OK" packet for the PostgreSQL protocol.
	 * 
	 * This function generates an "OK" packet, which is sent to the PostgreSQL 
	 * client after a successful command execution (e.g., INSERT, UPDATE, DELETE, 
	 * SELECT). It includes a command tag (e.g., "INSERT 0 10" for an INSERT 
	 * command that affected 10 rows) and a ready-for-query message if `ready` 
	 * is true.
	 * 
	 * @param send A boolean flag indicating whether to send the packet 
	 *            immediately or just generate it.
	 * @param ready A boolean flag indicating whether to generate a ready-for-query 
	 *             packet after the "OK" packet.
	 * @param msg An optional message to be included in the "OK" packet.
	 * @param rows The number of rows affected by the command (used for 
	 *            INSERT, UPDATE, DELETE, and SELECT).
	 * @param query The original query string that was executed.
	 * @param _ptr A pointer to a `PtrSize_t` structure (if `send` is false) 
	 *            where the generated packet data will be stored.
	 *
	 * @return `true` if the packet was successfully generated, `false` otherwise.
	 *
	 * @note This function extracts the appropriate command tag based on the 
	 *       `query` string and constructs the "OK" packet accordingly. It also 
	 *       updates the output buffer with the generated packet. If `ready` is 
	 *       true, it also generates and sends a ready-for-query packet.
	 */
	bool generate_ok_packet(bool send, bool ready, const char* msg, int rows, const char* query, char trx_state = 'I', PtrSize_t* _ptr = NULL);

	// temporary overriding generate_pkt_OK to avoid crash. FIXME remove this
	bool generate_pkt_OK(bool send, void** ptr, unsigned int* len, uint8_t sequence_id, unsigned int affected_rows, 
		uint64_t last_insert_id, uint16_t status, uint16_t warnings, char* msg, bool eof_identifier = false) {
		char txn_state = 'I';
		if (status & SERVER_STATUS_IN_TRANS) {
			txn_state = 'T';
		}
		return generate_ok_packet(send, true, msg, affected_rows, "OK 1", txn_state);
	}

	// temporary overriding generate_pkt_EOF to avoid crash. FIXME remove this
	bool generate_pkt_EOF(bool send, void** ptr, unsigned int* len, uint8_t sequence_id, uint16_t warnings, 
		uint16_t status, MySQL_ResultSet* myrs = NULL) {
		char txn_state = 'I';
		if (status & SERVER_STATUS_IN_TRANS) {
			txn_state = 'T';
		}
		return generate_ok_packet(send, true, NULL, 0, "OK 1", txn_state);
	}

	// temporary overriding generate_pkt_ERR to avoid crash. FIXME remove this
	bool generate_pkt_ERR(bool send, void** ptr, unsigned int* len, uint8_t sequence_id, uint16_t error_code, 
		char* sql_state, const char* sql_message, bool track = false) {
			
		generate_error_packet(send, true, sql_message, PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, false, track);
		return true;
	}

	//bool generate_row_description(bool send, PgSQL_Query_Result* rs, const PG_Fields& fields, unsigned int size);

	/**
	 * @brief Copies a row description from a PGresult to a PgSQL_Query_Result.
	 *
	 * This function copies the row description from a `PGresult` object (typically
	 * obtained from libpq) to a `PgSQL_Query_Result` object. The row description
	 * contains information about the columns returned by a query, such as column
	 * names, data types, and other metadata.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       row description will be copied.
	 * @param result A pointer to the `PGresult` object containing the row
	 *              description to be copied.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 *
	 * @note This function is used to prepare the client for receiving rows
	 *       with the corresponding data types and column names.
	 */
	unsigned int copy_row_description_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);

	/**
	 * @brief Copies a row of data from a PGresult to a PgSQL_Query_Result.
	 *
	 * This function copies a row of data from a `PGresult` object (typically
	 * obtained from libpq) to a `PgSQL_Query_Result` object. The row data
	 * represents a single row from the result set of a query.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       row data will be copied.
	 * @param result A pointer to the `PGresult` object containing the row data
	 *              to be copied.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_row_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);

	/**
	 * @brief Copies a command completion message from a PGresult to a
	 *        PgSQL_Query_Result.
	 *
	 * This function copies a command completion message from a `PGresult` object
	 * (typically obtained from libpq) to a `PgSQL_Query_Result` object. The
	 * command completion message indicates that a command (e.g., INSERT, UPDATE,
	 * DELETE) has finished executing.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       command completion message will be copied.
	 * @param result A pointer to the `PGresult` object containing the command
	 *              completion message to be copied.
	 * @param extract_affected_rows A boolean flag indicating whether to extract
	 *                             the affected rows count from the `PGresult`
	 *                             object.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 *
	 * @note This function extracts the command tag and affected rows count (if
	 *       requested) and copies them to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_command_completion_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result, bool extract_affected_rows);

	/**
	 * @brief Copies an error message from a PGresult to a PgSQL_Query_Result.
	 *
	 * This function copies an error message from a `PGresult` object (typically
	 * obtained from libpq) to a `PgSQL_Query_Result` object. The error message
	 * contains information about an error that occurred during query execution.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       error message will be copied.
	 * @param result A pointer to the `PGresult` object containing the error
	 *              message to be copied.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 *
	 * @note This function extracts the various error fields (severity, code,
	 *       message, detail, etc.) from the `PGresult` object and copies them
	 *       to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_error_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);

	/**
	 * @brief Copies an empty query response from a PGresult to a
	 *        PgSQL_Query_Result.
	 *
	 * This function copies an empty query response from a `PGresult` object
	 * (typically obtained from libpq) to a `PgSQL_Query_Result` object. The
	 * empty query response indicates that a query did not return any rows.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       empty query response will be copied.
	 * @param result A pointer to the `PGresult` object containing the empty query
	 *              response to be copied.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_empty_query_response_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);

	/**
	 * @brief Copies a ready status message from a PGresult to a
	 *        PgSQL_Query_Result.
	 *
	 * This function copies a ready status message from a `PGresult` object
	 * (typically obtained from libpq) to a `PgSQL_Query_Result` object. The
	 * ready status indicates that the server is ready for a new query.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       ready status message will be copied.
	 * @param txn_status The transaction status type, indicating whether a
	 *                   transaction is in progress or not.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_ready_status_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, PGTransactionStatusType txn_status);

	/**
	 * @brief Copies a buffer from a PSresult to a PgSQL_Query_Result.
	 *
	 * This function copies a buffer of data from a `PSresult` object to a
	 * `PgSQL_Query_Result` object. The buffer can contain various types of
	 * data, including row data or other results.
	 *
	 * @param send A boolean flag indicating whether to send the generated packet
	 *            immediately or just generate it. (Currently not supported).
	 * @param pg_query_result A pointer to the `PgSQL_Query_Result` object where the
	 *                       buffer will be copied.
	 * @param result A pointer to the `PSresult` object containing the buffer to
	 *              be copied.
	 *
	 * @return The number of bytes copied to the `PgSQL_Query_Result` object.
	 */
	unsigned int copy_buffer_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PSresult* result);

private:

	/**
	 * @brief Extracts the header information from a PostgreSQL packet.
	 *
	 * This function reads the header information from a received PostgreSQL
	 * packet and populates the `pgsql_hdr` structure with the packet type and
	 * length. It handles both the new (v3) and old (v2) packet formats.
	 *
	 * @param pkt A pointer to the beginning of the packet buffer.
	 * @param pkt_len The length of the packet buffer in bytes.
	 * @param hdr A pointer to a `pgsql_hdr` structure where the extracted header
	 *           information will be stored.
	 *
	 * @return `true` if the header was successfully parsed, `false` otherwise.
	 *
	 * @note This function performs basic validation on the packet length and
	 *       header fields to ensure that the packet is valid.
	 */
	bool get_header(unsigned char* pkt, unsigned int len, pgsql_hdr* hdr);

	/**
	 * @brief Loads the connection parameters from a PostgreSQL startup packet.
	 *
	 * This function extracts the connection parameters (e.g., user, database,
	 * client encoding) from a PostgreSQL startup packet and stores them in the
	 * connection parameters object (`myconn->conn_params`).
	 *
	 * @param pkt A pointer to a `pgsql_hdr` structure containing the startup
	 *            packet data.
	 * @param startup A boolean flag indicating whether this is a startup packet.
	 *
	 * @note This function iterates through the key-value pairs in the startup
	 *       packet and stores them in the connection parameters object.
	 */
	void load_conn_parameters(pgsql_hdr* pkt, bool startup);

	/**
	 * @brief Handles the client's first message in a SCRAM-SHA-256
	 *        authentication exchange.
	 *
	 * This function receives the client's first message during the SCRAM-SHA-256
	 * authentication process. It parses the message, generates the server's
	 * first message, and sends it back to the client.
	 *
	 * @param scram_state A pointer to the `ScramState` structure that maintains
	 *                   the state of the SCRAM exchange.
	 * @param user A pointer to the `PgCredentials` structure containing the user
	 *            credentials.
	 * @param data A pointer to the buffer containing the client's first message.
	 * @param datalen The length of the client's first message in bytes.
	 *
	 * @return `true` if the client's first message was successfully handled,
	 *         `false` otherwise.
	 *
	 * @note This function performs the following steps:
	 *       1. Parses the client's first message to extract the authentication
	 *          mechanism and client nonce.
	 *       2. Generates the server's first message, which includes the server
	 *          nonce and salt.
	 *       3. Sends the server's first message to the client.
	 */
	bool scram_handle_client_first(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen);

	/**
	 * @brief Handles the client's final message in a SCRAM-SHA-256
	 *        authentication exchange.
	 *
	 * This function receives the client's final message during the SCRAM-SHA-256
	 * authentication process. It validates the client's proof, generates the
	 * server's final message, and sends it back to the client.
	 *
	 * @param scram_state A pointer to the `ScramState` structure that maintains
	 *                   the state of the SCRAM exchange.
	 * @param user A pointer to the `PgCredentials` structure containing the user
	 *            credentials.
	 * @param data A pointer to the buffer containing the client's final message.
	 * @param datalen The length of the client's final message in bytes.
	 *
	 * @return `true` if the client's final message was successfully handled,
	 *         `false` otherwise.
	 *
	 * @note This function performs the following steps:
	 *       1. Parses the client's final message to extract the client proof.
	 *       2. Verifies the client's proof against the expected value.
	 *       3. Generates the server's final message.
	 *       4. Sends the server's final message to the client.
	 */
	bool scram_handle_client_final(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen);

	PgSQL_Data_Stream** myds;
	PgSQL_Connection_userinfo* userinfo;
	PgSQL_Session* sess;
	
	template<typename S>
	friend void admin_session_handler(S* sess, void* _pa, PtrSize_t* pkt);
};

void SQLite3_to_Postgres(PtrSizeArray* psa, SQLite3_result* result, char* error, int affected_rows, const char* query_type);

#endif // __POSTGRES_PROTOCOL_H
