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
	void to_PtrSizeArray(PtrSizeArray* psa, unsigned c = PG_PKT_DEFAULT_SIZE);

	void set_multi_pkt_mode(bool mode) {
		multiple_pkt_mode = mode;

		if (mode == false)
			pkt_offset.clear();
	}
	void make_space(unsigned int len);
	void put_char(char val);
	void put_uint16(uint16_t val);
	void put_uint32(uint32_t val);
	void put_uint64(uint64_t val);
	void put_bytes(const void* data, int len);
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
	void write_ReadyForQuery() {
		write_generic('Z', "c", 'I');
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
	void start_packet(int type);
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

#define PGSQL_QUERY_RESULT_EMPTY	0x00
#define PGSQL_QUERY_RESULT_TUPLE	0x01
#define PGSQL_QUERY_RESULT_COMMAND  0x02
#define PGSQL_QUERY_RESULT_READY	0x04
#define PGSQL_QUERY_RESULT_ERROR	0x08
#define PGSQL_QUERY_RESULT_WARNING	0x10

class PgSQL_Query_Result {
public:
	PgSQL_Query_Result();
	~PgSQL_Query_Result();

	void init(PgSQL_Protocol* _proto, PgSQL_Data_Stream* _myds, PgSQL_Connection* _conn);
	unsigned int add_row_description(const PGresult* result);
	unsigned int add_row(const PGresult* result);
	unsigned int add_command_completion(const PGresult* result);
	unsigned int add_error(const PGresult* result);
	unsigned int add_ready_status(PGTransactionStatusType txn_status);
	bool get_resultset(PtrSizeArray* PSarrayFinal);
	
	unsigned long long current_size();
	inline bool is_transfer_started() const { return transfer_started; }
	inline unsigned long long get_num_rows() const { return num_rows; }
	inline unsigned int get_num_fields() const { return num_fields; }
	inline unsigned long long get_resultset_size() const { return resultset_size; }
	inline uint8_t get_result_packet_type() const { return result_packet_type; }

private:
	void buffer_init();
	inline unsigned int buffer_available_capacity() const { return (RESULTSET_BUFLEN - buffer_used); }
	unsigned char* buffer_reserve_space(unsigned int size);
	void buffer_to_PSarrayOut();
	void reset();

	PtrSizeArray PSarrayOUT;
	unsigned long long resultset_size;
	unsigned long long num_rows;
	unsigned long long pkt_count;
	unsigned int num_fields;
	unsigned int buffer_used;
	unsigned char* buffer;
	PgSQL_Protocol* proto;
	PgSQL_Data_Stream* myds;
	PgSQL_Connection* conn;
	bool transfer_started;
	uint8_t result_packet_type;

	friend class PgSQL_Protocol;
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

	bool generate_pkt_initial_handshake(bool send, void** ptr, unsigned int* len, uint32_t* thread_id, bool deprecate_eof_active) override;
	bool process_startup_packet(unsigned char* pkt, unsigned int len, bool& ssl_request);
	EXECUTION_STATE process_handshake_response_packet(unsigned char* pkt, unsigned int len);
	void welcome_client();

	void generate_error_packet(bool send, bool ready, const char* msg, PGSQL_ERROR_CODES code, bool fatal, bool track = false, PtrSize_t* _ptr = NULL);
	bool generate_ok_packet(bool send, bool ready, const char* msg, int rows, const char* query, PtrSize_t* _ptr = NULL);

	//bool generate_row_description(bool send, PgSQL_Query_Result* rs, const PG_Fields& fields, unsigned int size);
	
	unsigned int copy_row_description_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);
	unsigned int copy_row_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);
	unsigned int copy_command_completion_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);
	unsigned int copy_error_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result);
	unsigned int copy_ready_status_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, PGTransactionStatusType txn_status);
private:
	bool get_header(unsigned char* pkt, unsigned int len, pgsql_hdr* hdr);
	void load_conn_parameters(pgsql_hdr* pkt, bool startup);
	bool scram_handle_client_first(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen);
	bool scram_handle_client_final(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen);

	PgSQL_Data_Stream** myds;
	PgSQL_Connection_userinfo* userinfo;
	PgSQL_Session* sess;
	
	template<class T>
	friend void admin_session_handler(Client_Session<T> sess, void* _pa, PtrSize_t* pkt);
};

void SQLite3_to_Postgres(PtrSizeArray* psa, SQLite3_result* result, char* error, int affected_rows, const char* query_type);

#endif // __POSTGRES_PROTOCOL_H
