#ifndef __CLASS_MYSQL_PROTOCOL_H
#define __CLASS_MYSQL_PROTOCOL_H

#include "proxysql.h"
#include "cpp.h"


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
	void init(MySQL_Data_Stream **, MySQL_Connection_userinfo *, MySQL_Session *);
	int pkt_handshake_client(unsigned char *, unsigned int);

	// ----------------- //
	// Packet generation //
	// ----------------- //
	bool generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, unsigned int last_insert_id, uint16_t status, uint16_t warnings, char *msg);
	bool generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, char *sql_message);
	bool generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status);
	bool generate_COM_QUIT(bool send, void **ptr, unsigned int *len);
	bool generate_COM_INIT_DB(bool send, void **ptr, unsigned int *len, char *schema);
	bool generate_COM_PING(bool send, void **ptr, unsigned int *len);
	bool generate_COM_QUERY(bool send, void **ptr, unsigned int *len, char *query);
	bool generate_COM_RESET_CONNECTION(bool send, void **ptr, unsigned int *len);
	bool generate_COM_CHANGE_USER(bool send, void **ptr, unsigned int *len);
	bool generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len);
	bool process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len);
	bool generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count);
	bool generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue);
	bool generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, int *fieldslen, char **fieldstxt);
	bool generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len);
	bool generate_pkt_handshake_response(bool send, void **ptr, unsigned int *len);
	bool generate_statistics_response(bool send, void **ptr, unsigned int *len);

	// ----------------- //
	// Packet processing //
	// ----------------- //
	//
	// These routines are used to react to certain types of packets that are
	// incoming. MySQL_Session class will call these as part of the state machine
	//
	bool process_pkt_OK(unsigned char *pkt, unsigned int len);
	bool process_pkt_EOF(unsigned char *pkt, unsigned int len);
	bool process_pkt_handshake_response(unsigned char *pkt, unsigned int len);
	bool process_pkt_initial_handshake(unsigned char *pkt, unsigned int len);
	bool process_pkt_COM_QUERY(unsigned char *pkt, unsigned int len);
	bool process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len);

	// ----------------- //
	// Packet asserting //
	// ---------------- //
	bool is_pkt_EOF(unsigned char *pkt, unsigned int len);
	bool is_pkt_OK(unsigned char *pkt, unsigned int len);
	bool is_pkt_ERR(unsigned char *pkt, unsigned int len);
};
#endif /* __CLASS_MYSQL_PROTOCOL_H */
