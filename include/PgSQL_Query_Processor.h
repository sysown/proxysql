#ifndef __CLASS_PGSQL_QUERY_PROCESSOR_H
#define __CLASS_PGSQL_QUERY_PROCESSOR_H
#include "proxysql.h"
#include "cpp.h"
#include "QP_rule_text.h"
#include "query_processor.h"

class Command_Counter;
struct PgSQL_Query_Processor_Rule_t : public QP_rule_t {};
class PgSQL_Query_Processor_Output : public Query_Processor_Output {};

class PgSQL_Rule_Text : public QP_rule_text {
public:
	PgSQL_Rule_Text(const PgSQL_Query_Processor_Rule_t* pqr);
	~PgSQL_Rule_Text() = default;
};

class PgSQL_Query_Processor : public Query_Processor<PgSQL_Query_Processor> {
public:
	PgSQL_Query_Processor();
	~PgSQL_Query_Processor();

	void init_thread();
	void end_thread();
	void update_query_processor_stats();
	SQLite3_result* get_stats_commands_counters();
	SQLite3_result* get_current_query_rules();
	PgSQL_Query_Processor_Output* process_query(PgSQL_Session* sess, void* ptr, unsigned int size, PgSQL_Query_Info* qi);
	unsigned long long query_parser_update_counters(PgSQL_Session* sess, enum PGSQL_QUERY_command c, SQP_par_t* qp, unsigned long long t);
	static enum PGSQL_QUERY_command query_parser_command_type(SQP_par_t* qp);
	static PgSQL_Query_Processor_Rule_t* new_query_rule(int rule_id, bool active, const char* username, const char* schemaname, int flagIN, const char* client_addr,
		const char* proxy_addr, int proxy_port, const char* digest, const char* match_digest, const char* match_pattern, bool negate_match_pattern,
		const char* re_modifiers, int flagOUT, const char* replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result,
		int cache_timeout, int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_hostgroup,
		int mirror_flagOUT, const char* error_msg, const char* OK_msg, int sticky_conn, int multiplex, int log,
		bool apply, const char* attributes, const char* comment);

private:
	Command_Counter* commands_counters[PGSQL_QUERY___NONE];
	static PgSQL_Query_Processor_Rule_t* new_query_rule(const PgSQL_Query_Processor_Rule_t* mqr);

	friend class Query_Processor;
};

#endif /* __CLASS_PGSQL_QUERY_PROCESSOR_H */
