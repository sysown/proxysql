#ifndef __CLASS_MYSQL_PROTOCOL_H
#define __CLASS_MYSQL_PROTOCOL_H

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"

#define RESULTSET_BUFLEN 16300

extern MySQL_Variables mysql_variables;

/* The default mariadb-connecter 3.1.4 does not yet implement CLIENT_DEPRECATE_EOF
 * flag.
 */
#ifndef CLIENT_DEPRECATE_EOF
#define CLIENT_DEPRECATE_EOF     (1UL << 24)
#endif

class MySQL_ResultSet {
	private:
	bool deprecate_eof_active;
	public:
	bool transfer_started;
	bool resultset_completed;
	//bool reset_pid;
	uint8_t sid;
	MySQL_Data_Stream *myds;
	MySQL_Protocol *myprot;
	MYSQL *mysql;
	MYSQL_RES *result;
	MYSQL_STMT *stmt;
	unsigned int num_fields;
	unsigned long long num_rows;
	unsigned long long resultset_size;
	PtrSizeArray PSarrayOUT;
	//PtrSizeArray *PSarrayOUT;
	MySQL_ResultSet();
	void init(MySQL_Protocol *_myprot, MYSQL_RES *_res, MYSQL *_my, MYSQL_STMT *_stmt=NULL);
	void init_with_stmt(MySQL_Connection *myconn);
	/**
	 * @brief Simple initialization of resulset of 'MySQL_ResultSet' without a resulset.
	 * @details This initialization allows to reuse the logic from function 'generate_pkt_row3' for filling
	 *   the resulset for later extracting the generated 'PtrSizeArray' via 'buffer_to_PSarrayOut' and
	 *   'get_resultset'.
	 *
	 *   IMPORTANT-NOTE: Other member functions are not safe to be used after this initialization.
	 * @param myproto Used to initialize internal 'MySQL_Protocol' field.
	 */
	void buffer_init(MySQL_Protocol* myproto);
	~MySQL_ResultSet();
	unsigned int add_row(MYSQL_ROWS *rows);
	unsigned int add_row(MYSQL_ROW row);
	unsigned int add_row2(MYSQL_ROWS *row, unsigned char *offset);
	void add_eof();
	void remove_last_eof();
	void add_err(MySQL_Data_Stream *_myds);
	bool get_resultset(PtrSizeArray *PSarrayFinal);
	//bool generate_COM_FIELD_LIST_response(PtrSizeArray *PSarrayFinal);
	unsigned char *buffer;
	unsigned int buffer_used;
	void buffer_to_PSarrayOut(bool _last=false);
	unsigned long long current_size();
};

class MySQL_Prepared_Stmt_info {
	public:
	uint32_t statement_id;
	uint16_t num_columns;
	uint16_t num_params;
	uint16_t warning_count;
	uint16_t pending_num_columns;
	uint16_t pending_num_params;
	MySQL_Prepared_Stmt_info(unsigned char *, unsigned int);
};

uint8_t mysql_decode_length(unsigned char *ptr, uint64_t *len);

/**
 * @brief ProxySQL replacement function for 'mysql_stmt_close'. Closes a
 *   MYSQL_STMT avoiding any blocking commands that are sent by default
 *   'mysql_stmt_close'.
 *
 *   NOTE: This function is not safe, caller must check that the supplied
 *   argument is not NULL.
 *
 * @param mysql_stmt An already initialized 'MYSQL_STMT'. Caller must ensure
 *   that the supplied argument is not NULL.
 *
 * @return The result of calling 'mysql_stmt_close' function over the internally
 *   modified 'MYSQL_STMT'.
 */
my_bool proxy_mysql_stmt_close(MYSQL_STMT* mysql_stmt);

class MySQL_Protocol {
	private:
	MySQL_Connection_userinfo *userinfo;
	MySQL_Session *sess;
	public:
	MySQL_Data_Stream **myds;
#ifdef DEBUG
	bool dump_pkt;
#endif
	MySQL_Prepared_Stmt_info *current_PreStmt;
	uint16_t prot_status;
	MySQL_Data_Stream *get_myds() { return *myds; }
	MySQL_Protocol() {
		prot_status=0;
	}
	void init(MySQL_Data_Stream **, MySQL_Connection_userinfo *, MySQL_Session *);

	// members get as arguments:
	// - a data stream (optionally NULL for some)
	// - a boolean variable to indicate whatever the packet needs to be sent directly in the data stream
	// - a pointer to void pointer, used to return the packet if not NULL
	// - a pointer to unsigned int, used to return the size of the packet if not NULL 
	// for now,  they all return true
	bool generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings, char *msg, bool eof_identifier=false);
	bool generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, const char *sql_message, bool track=false);
	bool generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status, MySQL_ResultSet *myrs=NULL);
//	bool generate_COM_INIT_DB(bool send, void **ptr, unsigned int *len, char *schema);
	//bool generate_COM_PING(bool send, void **ptr, unsigned int *len);

	bool generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len);
	bool process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len);

//	bool generate_pkt_column_count(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count);
	bool generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count, MySQL_ResultSet *myrs=NULL);
//	bool generate_pkt_field(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue);
	bool generate_pkt_field2(void **ptr, unsigned int *len, uint8_t sequence_id, MYSQL_FIELD *field, MySQL_ResultSet *myrs);
	bool generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue, MySQL_ResultSet *myrs=NULL);
	bool generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt);
	uint8_t generate_pkt_row3(MySQL_ResultSet *myrs, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt, unsigned long rl);
	bool generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len, uint32_t *thread_id, bool deprecate_eof_active);
//	bool generate_statistics_response(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len);
	bool generate_statistics_response(bool send, void **ptr, unsigned int *len);

	// process_* members get a arguments:
	// - a data stream (optionally NULL for some)
	// - pointer to the packet
	// - size of the packet 
	bool process_pkt_handshake_response(unsigned char *pkt, unsigned int len);
	bool process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len);
	void * Query_String_to_packet(uint8_t sid, std::string *s, unsigned int *l);
	/**
	 * @brief Verifies the supplied 'user' and 'password' in order to authenticate an user. For
	 *  doing so, it takes into account:
	 *     * Current session type.
	 *     * Current 'sha1' password for the user, reported by 'GloMyAuth' or 'GloClickHouseAuth'.
	 *     * Current 'auth_plugin' being used for the session.
	 *     * Username received sent by the client.
	 *     * Password received sent by the client.
	 *
	 * @param session_type The session type inn which the authentication is taking place.
	 * @param password Pointer to the stored password for the supplied user.
	 * @param user Pointer to the user supplied by the client.
	 * @param pass Pointer to the password supplied by the client.
	 * @param pass_len Length of the supplied password received from the client.
	 * @param sha1_pass Pointer to sha1_pass returned by auth cache.
	 * @param auth_plugin Auth plugin supplied by client in the COM_CHANGE_USER packet. If
	 *   the packet doesn't hold any, 'mysql_native_password' should be supplied
	 *   as default.
	 *
	 * @details TODO: This function holds the same authentication block that can be seen in
	 *   "MySQL_Protocol::process_pkt_handshake_response". That portion of the function should be
	 *   refactored into using this very same function.
	 * @return Returns 'true' if the user password was correctly verified, 'false' otherwise.
	 */
	bool verify_user_pass(enum proxysql_session_type session_type, const char* password, const char* user, const char* pass, int pass_len, const char* sha1_pass, const char* auth_plugin);

	// prepared statements
	bool generate_STMT_PREPARE_RESPONSE(uint8_t sequence_id, MySQL_STMT_Global_info *stmt_info, uint32_t _stmt_id=0);
	void generate_STMT_PREPARE_RESPONSE_OK(uint8_t sequence_id, uint32_t stmt_id);

	stmt_execute_metadata_t * get_binds_from_pkt(void *ptr, unsigned int size, MySQL_STMT_Global_info *stmt_info, stmt_execute_metadata_t **stmt_meta);

	bool generate_COM_QUERY_from_COM_FIELD_LIST(PtrSize_t *pkt);

	bool verify_user_attributes(int calling_line, const char *calling_func, const unsigned char *user);
	bool user_attributes_has_spiffe(int calling_line, const char *calling_func, const unsigned char *user);
};
#endif /* __CLASS_MYSQL_PROTOCOL_H */
