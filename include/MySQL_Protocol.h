#ifndef __CLASS_MYSQL_PROTOCOL_H
#define __CLASS_MYSQL_PROTOCOL_H

#include "proxysql.h"
#include "cpp.h"

#define RESULTSET_BUFLEN 16300

class MySQL_ResultSet {
	private:
	public:
	bool transfer_started;
	bool resultset_completed;
	uint8_t sid;
	MySQL_Data_Stream *myds;
	MySQL_Protocol *myprot;
	MYSQL *mysql;
	MYSQL_RES *result;
	unsigned int num_fields;
	unsigned int num_rows;
	unsigned long long resultset_size;
	PtrSizeArray *PSarrayOUT;
	MySQL_ResultSet(MySQL_Protocol *_myprot, MYSQL_RES *_res, MYSQL *_my, MYSQL_STMT *_stmt=NULL);
	~MySQL_ResultSet();
	unsigned int add_row(MYSQL_ROW row);
	unsigned int add_row2(MYSQL_ROWS *row, unsigned char *offset);
	void add_eof();
	void add_err(MySQL_Data_Stream *_myds);
	bool get_resultset(PtrSizeArray *PSarrayFinal);
	unsigned char *buffer;
	unsigned int buffer_used;
	void buffer_to_PSarrayOut();
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


class MySQL_Protocol {
	private:
	MySQL_Data_Stream **myds;
	MySQL_Connection_userinfo *userinfo;
	MySQL_Session *sess;
	public:
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
	int parse_mysql_pkt(PtrSize_t *, MySQL_Data_Stream *);

	// members get as arguments:
	// - a data stream (optionally NULL for some)
	// - a boolean variable to indicate whatever the packet needs to be sent directly in the data stream
	// - a pointer to void pointer, used to return the packet if not NULL
	// - a pointer to unsigned int, used to return the size of the packet if not NULL 
	// for now,  they all return true
	bool generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings, char *msg);
	bool generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, char *sql_message);
	bool generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status, MySQL_ResultSet *myrs=NULL);
//	bool generate_COM_INIT_DB(bool send, void **ptr, unsigned int *len, char *schema);
	//bool generate_COM_PING(bool send, void **ptr, unsigned int *len);

	bool generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len);
	bool process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len);

//	bool generate_pkt_column_count(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count);
	bool generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count, MySQL_ResultSet *myrs=NULL);
//	bool generate_pkt_field(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue);
	bool generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue, MySQL_ResultSet *myrs=NULL);
	bool generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt);
	uint8_t generate_pkt_row3(MySQL_ResultSet *myrs, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt);
//	bool generate_pkt_initial_handshake(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len);
	bool generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len, uint32_t *thread_id);
//	bool generate_statistics_response(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len);
	bool generate_statistics_response(bool send, void **ptr, unsigned int *len);

	// process_* members get a arguments:
	// - a data stream (optionally NULL for some)
	// - pointer to the packet
	// - size of the packet 
	bool process_pkt_OK(unsigned char *pkt, unsigned int len);
	bool process_pkt_EOF(unsigned char *pkt, unsigned int len);
	bool process_pkt_handshake_response(unsigned char *pkt, unsigned int len);
	bool process_pkt_COM_QUERY(unsigned char *pkt, unsigned int len);
	bool process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len);
	void * Query_String_to_packet(uint8_t sid, std::string *s, unsigned int *l);

	// prepared statements
	bool generate_STMT_PREPARE_RESPONSE(uint8_t sequence_id, MySQL_STMT_Global_info *stmt_info, uint32_t _stmt_id=0);
	void generate_STMT_PREPARE_RESPONSE_OK(uint8_t sequence_id, uint32_t stmt_id);

	stmt_execute_metadata_t * get_binds_from_pkt(void *ptr, unsigned int size, MySQL_STMT_Global_info *stmt_info, stmt_execute_metadata_t **stmt_meta);
};
#endif /* __CLASS_MYSQL_PROTOCOL_H */
