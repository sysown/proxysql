#ifndef __CLASS_MYSQL_QUERY_PROCESSOR_H
#define __CLASS_MYSQL_QUERY_PROCESSOR_H
#include "proxysql.h"
#include "cpp.h"
#include "QP_rule_text.h"
#include "query_processor.h"

class Command_Counter;
typedef struct _MySQL_Query_processor_Rule_t : public QP_rule_t { 
	int gtid_from_hostgroup;
} MySQL_Query_Processor_Rule_t;

class MySQL_Query_Processor_Output : public Query_Processor_Output {
public:
	MySQL_Query_Processor_Output() = default;
	~MySQL_Query_Processor_Output() = default;

	void init() {
		Query_Processor_Output::init();
		min_gtid = NULL;
		gtid_from_hostgroup = -1;
	}
	void destroy() {
		Query_Processor_Output::destroy();
		if (min_gtid) {
			free(min_gtid);
			min_gtid = NULL;
		}
	}

	char* min_gtid;
	int gtid_from_hostgroup;
};

class MySQL_Rule_Text : public QP_rule_text {
public:
	MySQL_Rule_Text(const MySQL_Query_Processor_Rule_t* mqr);
	~MySQL_Rule_Text() = default;
};

class MySQL_Query_Processor : public Query_Processor<MySQL_Query_Processor> {
public:
	MySQL_Query_Processor();
	~MySQL_Query_Processor();

	void init_thread();
	void end_thread();
	void update_query_processor_stats();
	SQLite3_result* get_current_query_rules();
	SQLite3_result* get_stats_commands_counters();
	MySQL_Query_Processor_Output* process_query(MySQL_Session* sess, void* ptr, unsigned int size, Query_Info* qi);
	unsigned long long query_parser_update_counters(MySQL_Session* sess, enum MYSQL_COM_QUERY_command c, SQP_par_t* qp, unsigned long long t);
	static enum MYSQL_COM_QUERY_command query_parser_command_type(SQP_par_t* qp);
	static MySQL_Query_Processor_Rule_t* new_query_rule(int rule_id, bool active, const char* username, const char* schemaname, int flagIN, const char* client_addr,
		const char* proxy_addr, int proxy_port, const char* digest, const char* match_digest, const char* match_pattern, bool negate_match_pattern,
		const char* re_modifiers, int flagOUT, const char* replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result,
		int cache_timeout, int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_hostgroup,
		int mirror_flagOUT, const char* error_msg, const char* OK_msg, int sticky_conn, int multiplex, int gtid_from_hostgroup, int log,
		bool apply, const char* attributes, const char* comment);

private:
	Command_Counter* commands_counters[MYSQL_COM_QUERY___NONE];
	static bool _is_valid_gtid(char* gtid, size_t gtid_len);
	static MySQL_Query_Processor_Rule_t* new_query_rule(const MySQL_Query_Processor_Rule_t* mqr);

	inline
	void process_query_extended(MySQL_Query_Processor_Output* ret, const MySQL_Query_Processor_Rule_t* mqr) {
		if (mqr->gtid_from_hostgroup >= 0) {
			// Note: negative gtid_from_hostgroup means this rule doesn't change the gtid_from_hostgroup
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set gtid from hostgroup: %d. A new session will be created\n", mqr->rule_id, mqr->gtid_from_hostgroup);
			ret->gtid_from_hostgroup = mqr->gtid_from_hostgroup;
		}
	}

	inline
	void query_parser_first_comment_extended(const char* key, const char* value, MySQL_Query_Processor_Output* qpo) {
		if (!strcasecmp(key, "min_gtid")) {
			size_t l = strlen(value);
			if (_is_valid_gtid((char*)value, l)) {
				char* buf = (char*)malloc(l + 1);
				strncpy(buf, value, l);
				buf[l + 1] = '\0';
				qpo->min_gtid = buf;
			} else {
				proxy_warning("Invalid gtid value=%s\n", value);
			}
		}
	}

	friend class Query_Processor;
};

#endif /* __CLASS_MYSQL_QUERY_PROCESSOR_H */
