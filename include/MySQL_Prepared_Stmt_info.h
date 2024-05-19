#ifndef CLASS_MySQL_Prepared_Stmt_info_H
#define CLASS_MySQL_Prepared_Stmt_info_H
class MySQL_Prepared_Stmt_info {
	public:
	uint32_t statement_id;
	uint16_t num_columns;
	uint16_t num_params;
	uint16_t warning_count;
	uint16_t pending_num_columns;
	uint16_t pending_num_params;
	MySQL_Prepared_Stmt_info(unsigned char *pkt, unsigned int length) {
		pkt += 5;
		statement_id = CPY4(pkt);
		pkt += sizeof(uint32_t);
		num_columns = CPY2(pkt);
		pkt += sizeof(uint16_t);
		num_params = CPY2(pkt);
		pkt += sizeof(uint16_t);
		pkt++; // reserved_1
		warning_count = CPY2(pkt);
		pending_num_columns=num_columns;
		pending_num_params=num_params;
	}
};
#endif // CLASS_MySQL_Prepared_Stmt_info_H
