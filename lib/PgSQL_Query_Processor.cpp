#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "proxysql.h"
#include "cpp.h"
#include "Command_Counter.h"
#include "PgSQL_Query_Processor.h"

extern PgSQL_Threads_Handler* GloPTH;
extern ProxySQL_Admin *GloAdmin;

static __thread Command_Counter* _thr_commands_counters[PGSQL_QUERY___NONE];

static char* commands_counters_desc[PGSQL_QUERY___NONE] = {
	[PGSQL_QUERY_SELECT] = (char*)"SELECT",
	[PGSQL_QUERY_INSERT] = (char*)"INSERT",
	[PGSQL_QUERY_UPDATE] = (char*)"UPDATE",
	[PGSQL_QUERY_DELETE] = (char*)"DELETE",
	[PGSQL_QUERY_MERGE] = (char*)"MERGE",
	[PGSQL_QUERY_CREATE_TABLE] = (char*)"CREATE_TABLE",
	[PGSQL_QUERY_ALTER_TABLE] = (char*)"ALTER_TABLE",
	[PGSQL_QUERY_DROP_TABLE] = (char*)"DROP_TABLE",
	[PGSQL_QUERY_TRUNCATE] = (char*)"TRUNCATE",
	[PGSQL_QUERY_COPY] = (char*)"COPY",
	[PGSQL_QUERY_CREATE_INDEX] = (char*)"CREATE_INDEX",
	[PGSQL_QUERY_DROP_INDEX] = (char*)"DROP_INDEX",
	[PGSQL_QUERY_ALTER_INDEX] = (char*)"ALTER_INDEX",
	[PGSQL_QUERY_CREATE_VIEW] = (char*)"CREATE_VIEW",
	[PGSQL_QUERY_DROP_VIEW] = (char*)"DROP_VIEW",
	[PGSQL_QUERY_ALTER_VIEW] = (char*)"ALTER_VIEW",
	[PGSQL_QUERY_CREATE_MATERIALIZED_VIEW] = (char*)"CREATE_MATERIALIZED_VIEW",
	[PGSQL_QUERY_ALTER_MATERIALIZED_VIEW] = (char*)"ALTER_MATERIALIZED_VIEW",
	[PGSQL_QUERY_REFRESH_MATERIALIZED_VIEW] = (char*)"REFRESH_MATERIALIZED_VIEW",
	[PGSQL_QUERY_DROP_MATERIALIZED_VIEW] = (char*)"DROP_MATERIALIZED_VIEW",
	[PGSQL_QUERY_CREATE_SEQUENCE] = (char*)"CREATE_SEQUENCE",
	[PGSQL_QUERY_ALTER_SEQUENCE] = (char*)"ALTER_SEQUENCE",
	[PGSQL_QUERY_DROP_SEQUENCE] = (char*)"DROP_SEQUENCE",
	[PGSQL_QUERY_CREATE_SCHEMA] = (char*)"CREATE_SCHEMA",
	[PGSQL_QUERY_DROP_SCHEMA] = (char*)"DROP_SCHEMA",
	[PGSQL_QUERY_ALTER_SCHEMA] = (char*)"ALTER_SCHEMA",
	[PGSQL_QUERY_CREATE_FUNCTION] = (char*)"CREATE_FUNCTION",
	[PGSQL_QUERY_ALTER_FUNCTION] = (char*)"ALTER_FUNCTION",
	[PGSQL_QUERY_DROP_FUNCTION] = (char*)"DROP_FUNCTION",
	[PGSQL_QUERY_CREATE_PROCEDURE] = (char*)"CREATE_PROCEDURE",
	[PGSQL_QUERY_ALTER_PROCEDURE] = (char*)"ALTER_PROCEDURE",
	[PGSQL_QUERY_CALL] = (char*)"CALL",
	[PGSQL_QUERY_DROP_PROCEDURE] = (char*)"DROP_PROCEDURE",
	[PGSQL_QUERY_CREATE_AGGREGATE] = (char*)"CREATE_AGGREGATE",
	[PGSQL_QUERY_ALTER_AGGREGATE] = (char*)"ALTER_AGGREGATE",
	[PGSQL_QUERY_DROP_AGGREGATE] = (char*)"DROP_AGGREGATE",
	[PGSQL_QUERY_CREATE_OPERATOR] = (char*)"CREATE_OPERATOR",
	[PGSQL_QUERY_ALTER_OPERATOR] = (char*)"ALTER_OPERATOR",
	[PGSQL_QUERY_DROP_OPERATOR] = (char*)"DROP_OPERATOR",
	[PGSQL_QUERY_CREATE_TYPE] = (char*)"CREATE_TYPE",
	[PGSQL_QUERY_ALTER_TYPE] = (char*)"ALTER_TYPE",
	[PGSQL_QUERY_DROP_TYPE] = (char*)"DROP_TYPE",
	[PGSQL_QUERY_CREATE_DOMAIN] = (char*)"CREATE_DOMAIN",
	[PGSQL_QUERY_ALTER_DOMAIN] = (char*)"ALTER_DOMAIN",
	[PGSQL_QUERY_DROP_DOMAIN] = (char*)"DROP_DOMAIN",
	[PGSQL_QUERY_CREATE_TRIGGER] = (char*)"CREATE_TRIGGER",
	[PGSQL_QUERY_ALTER_TRIGGER] = (char*)"ALTER_TRIGGER",
	[PGSQL_QUERY_DROP_TRIGGER] = (char*)"DROP_TRIGGER",
	[PGSQL_QUERY_CREATE_RULE] = (char*)"CREATE_RULE",
	[PGSQL_QUERY_ALTER_RULE] = (char*)"ALTER_RULE",
	[PGSQL_QUERY_DROP_RULE] = (char*)"DROP_RULE",
	[PGSQL_QUERY_CREATE_EXTENSION] = (char*)"CREATE_EXTENSION",
	[PGSQL_QUERY_ALTER_EXTENSION] = (char*)"ALTER_EXTENSION",
	[PGSQL_QUERY_DROP_EXTENSION] = (char*)"DROP_EXTENSION",
	[PGSQL_QUERY_CREATE_POLICY] = (char*)"CREATE_POLICY",
	[PGSQL_QUERY_ALTER_POLICY] = (char*)"ALTER_POLICY",
	[PGSQL_QUERY_DROP_POLICY] = (char*)"DROP_POLICY",
	[PGSQL_QUERY_CREATE_ROLE] = (char*)"CREATE_ROLE",
	[PGSQL_QUERY_ALTER_ROLE] = (char*)"ALTER_ROLE",
	[PGSQL_QUERY_DROP_ROLE] = (char*)"DROP_ROLE",
	[PGSQL_QUERY_CREATE_USER] = (char*)"CREATE_USER",
	[PGSQL_QUERY_ALTER_USER] = (char*)"ALTER_USER",
	[PGSQL_QUERY_DROP_USER] = (char*)"DROP_USER",
	[PGSQL_QUERY_GRANT] = (char*)"GRANT",
	[PGSQL_QUERY_REVOKE] = (char*)"REVOKE",
	[PGSQL_QUERY_COMMENT] = (char*)"COMMENT",
	[PGSQL_QUERY_NOTIFY] = (char*)"NOTIFY",
	[PGSQL_QUERY_LISTEN] = (char*)"LISTEN",
	[PGSQL_QUERY_UNLISTEN] = (char*)"UNLISTEN",
	[PGSQL_QUERY_LOCK] = (char*)"LOCK",
	[PGSQL_QUERY_CHECKPOINT] = (char*)"CHECKPOINT",
	[PGSQL_QUERY_REINDEX] = (char*)"REINDEX",
	[PGSQL_QUERY_VACUUM] = (char*)"VACUUM",
	[PGSQL_QUERY_ANALYZE] = (char*)"ANALYZE",
	[PGSQL_QUERY_EXPLAIN] = (char*)"EXPLAIN",
	[PGSQL_QUERY_EXECUTE] = (char*)"EXECUTE",
	[PGSQL_QUERY_PREPARE] = (char*)"PREPARE",
	[PGSQL_QUERY_DEALLOCATE] = (char*)"DEALLOCATE",
	[PGSQL_QUERY_FETCH] = (char*)"FETCH",
	[PGSQL_QUERY_MOVE] = (char*)"MOVE",
	[PGSQL_QUERY_SAVEPOINT] = (char*)"SAVEPOINT",
	[PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT] = (char*)"ROLLBACK_TO_SAVEPOINT",
	[PGSQL_QUERY_RELEASE_SAVEPOINT] = (char*)"RELEASE_SAVEPOINT",
	[PGSQL_QUERY_BEGIN] = (char*)"BEGIN",
	[PGSQL_QUERY_COMMIT] = (char*)"COMMIT",
	[PGSQL_QUERY_ROLLBACK] = (char*)"ROLLBACK",
	[PGSQL_QUERY_DECLARE_CURSOR] = (char*)"DECLARE_CURSOR",
	[PGSQL_QUERY_CLOSE_CURSOR] = (char*)"CLOSE_CURSOR",
	[PGSQL_QUERY_DISCARD] = (char*)"DISCARD",
	[PGSQL_QUERY_SHOW] = (char*)"SHOW",
	[PGSQL_QUERY_SET] = (char*)"SET",
	[PGSQL_QUERY_RESET] = (char*)"RESET",
	[PGSQL_QUERY_ALTER_DATABASE] = (char*)"ALTER_DATABASE",
	[PGSQL_QUERY_CREATE_DATABASE] = (char*)"CREATE_DATABASE",
	[PGSQL_QUERY_DROP_DATABASE] = (char*)"DROP_DATABASE",
	[PGSQL_QUERY_CREATE_COLLATION] = (char*)"CREATE_COLLATION",
	[PGSQL_QUERY_ALTER_COLLATION] = (char*)"ALTER_COLLATION",
	[PGSQL_QUERY_DROP_COLLATION] = (char*)"DROP_COLLATION",
	[PGSQL_QUERY_CREATE_TEXT_SEARCH_CONFIGURATION] = (char*)"CREATE_TEXT_SEARCH_CONFIGURATION",
	[PGSQL_QUERY_ALTER_TEXT_SEARCH_CONFIGURATION] = (char*)"ALTER_TEXT_SEARCH_CONFIGURATION",
	[PGSQL_QUERY_DROP_TEXT_SEARCH_CONFIGURATION] = (char*)"DROP_TEXT_SEARCH_CONFIGURATION",
	[PGSQL_QUERY_CREATE_TEXT_SEARCH_DICTIONARY] = (char*)"CREATE_TEXT_SEARCH_DICTIONARY",
	[PGSQL_QUERY_ALTER_TEXT_SEARCH_DICTIONARY] = (char*)"ALTER_TEXT_SEARCH_DICTIONARY",
	[PGSQL_QUERY_DROP_TEXT_SEARCH_DICTIONARY] = (char*)"DROP_TEXT_SEARCH_DICTIONARY",
	[PGSQL_QUERY_CREATE_TEXT_SEARCH_TEMPLATE] = (char*)"CREATE_TEXT_SEARCH_TEMPLATE",
	[PGSQL_QUERY_ALTER_TEXT_SEARCH_TEMPLATE] = (char*)"ALTER_TEXT_SEARCH_TEMPLATE",
	[PGSQL_QUERY_DROP_TEXT_SEARCH_TEMPLATE] = (char*)"DROP_TEXT_SEARCH_TEMPLATE",
	[PGSQL_QUERY_CREATE_TEXT_SEARCH_PARSER] = (char*)"CREATE_TEXT_SEARCH_PARSER",
	[PGSQL_QUERY_ALTER_TEXT_SEARCH_PARSER] = (char*)"ALTER_TEXT_SEARCH_PARSER",
	[PGSQL_QUERY_DROP_TEXT_SEARCH_PARSER] = (char*)"DROP_TEXT_SEARCH_PARSER",
	[PGSQL_QUERY_CREATE_FOREIGN_TABLE] = (char*)"CREATE_FOREIGN_TABLE",
	[PGSQL_QUERY_ALTER_FOREIGN_TABLE] = (char*)"ALTER_FOREIGN_TABLE",
	[PGSQL_QUERY_DROP_FOREIGN_TABLE] = (char*)"DROP_FOREIGN_TABLE",
	[PGSQL_QUERY_IMPORT_FOREIGN_SCHEMA] = (char*)"IMPORT_FOREIGN_SCHEMA",
	[PGSQL_QUERY_CREATE_SERVER] = (char*)"CREATE_SERVER",
	[PGSQL_QUERY_ALTER_SERVER] = (char*)"ALTER_SERVER",
	[PGSQL_QUERY_DROP_SERVER] = (char*)"DROP_SERVER",
	[PGSQL_QUERY_CREATE_USER_MAPPING] = (char*)"CREATE_USER_MAPPING",
	[PGSQL_QUERY_ALTER_USER_MAPPING] = (char*)"ALTER_USER_MAPPING",
	[PGSQL_QUERY_DROP_USER_MAPPING] = (char*)"DROP_USER_MAPPING",
	[PGSQL_QUERY_CREATE_PUBLICATION] = (char*)"CREATE_PUBLICATION",
	[PGSQL_QUERY_ALTER_PUBLICATION] = (char*)"ALTER_PUBLICATION",
	[PGSQL_QUERY_DROP_PUBLICATION] = (char*)"DROP_PUBLICATION",
	[PGSQL_QUERY_CREATE_SUBSCRIPTION] = (char*)"CREATE_SUBSCRIPTION",
	[PGSQL_QUERY_ALTER_SUBSCRIPTION] = (char*)"ALTER_SUBSCRIPTION",
	[PGSQL_QUERY_DROP_SUBSCRIPTION] = (char*)"DROP_SUBSCRIPTION",
	[PGSQL_QUERY_CREATE_ACCESS_METHOD] = (char*)"CREATE_ACCESS_METHOD",
	[PGSQL_QUERY_ALTER_ACCESS_METHOD] = (char*)"ALTER_ACCESS_METHOD",
	[PGSQL_QUERY_DROP_ACCESS_METHOD] = (char*)"DROP_ACCESS_METHOD",
	[PGSQL_QUERY_CREATE_EVENT_TRIGGER] = (char*)"CREATE_EVENT_TRIGGER",
	[PGSQL_QUERY_ALTER_EVENT_TRIGGER] = (char*)"ALTER_EVENT_TRIGGER",
	[PGSQL_QUERY_DROP_EVENT_TRIGGER] = (char*)"DROP_EVENT_TRIGGER",
	[PGSQL_QUERY_CREATE_TRANSFORM] = (char*)"CREATE_TRANSFORM",
	[PGSQL_QUERY_ALTER_TRANSFORM] = (char*)"ALTER_TRANSFORM",
	[PGSQL_QUERY_DROP_TRANSFORM] = (char*)"DROP_TRANSFORM",
	[PGSQL_QUERY_CREATE_CAST] = (char*)"CREATE_CAST",
	[PGSQL_QUERY_ALTER_CAST] = (char*)"ALTER_CAST",
	[PGSQL_QUERY_DROP_CAST] = (char*)"DROP_CAST",
	[PGSQL_QUERY_CREATE_OPERATOR_CLASS] = (char*)"CREATE_OPERATOR_CLASS",
	[PGSQL_QUERY_ALTER_OPERATOR_CLASS] = (char*)"ALTER_OPERATOR_CLASS",
	[PGSQL_QUERY_DROP_OPERATOR_CLASS] = (char*)"DROP_OPERATOR_CLASS",
	[PGSQL_QUERY_CREATE_OPERATOR_FAMILY] = (char*)"CREATE_OPERATOR_FAMILY",
	[PGSQL_QUERY_ALTER_OPERATOR_FAMILY] = (char*)"ALTER_OPERATOR_FAMILY",
	[PGSQL_QUERY_DROP_OPERATOR_FAMILY] = (char*)"DROP_OPERATOR_FAMILY",
	[PGSQL_QUERY_CREATE_TABLESPACE] = (char*)"CREATE_TABLESPACE",
	[PGSQL_QUERY_ALTER_TABLESPACE] = (char*)"ALTER_TABLESPACE",
	[PGSQL_QUERY_DROP_TABLESPACE] = (char*)"DROP_TABLESPACE",
	[PGSQL_QUERY_CLUSTER] = (char*)"PGSQL_QUERY_CLUSTER",
	[PGSQL_QUERY_UNKNOWN] = (char*)"UNKNOWN",
};

PgSQL_Rule_Text::PgSQL_Rule_Text(const PgSQL_Query_Processor_Rule_t* pqr) {
	num_fields = 35; // this count the number of fields
	pta = NULL;
	pta = (char**)malloc(sizeof(char*) * num_fields);
	itostr(pta[0], (long long)pqr->rule_id);
	itostr(pta[1], (long long)pqr->active);
	pta[2] = strdup_null(pqr->username);
	pta[3] = strdup_null(pqr->schemaname);
	itostr(pta[4], (long long)pqr->flagIN);

	pta[5] = strdup_null(pqr->client_addr);
	pta[6] = strdup_null(pqr->proxy_addr);
	itostr(pta[7], (long long)pqr->proxy_port);

	char buf[20];
	if (pqr->digest) {
		sprintf(buf, "0x%016llX", (long long unsigned int)pqr->digest);
		pta[8] = strdup(buf);
	}
	else {
		pta[8] = NULL;
	}

	pta[9] = strdup_null(pqr->match_digest);
	pta[10] = strdup_null(pqr->match_pattern);
	itostr(pta[11], (long long)pqr->negate_match_pattern);
	std::string re_mod;
	re_mod = "";
	if ((pqr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
	if ((pqr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
		if (re_mod.length()) {
			re_mod = re_mod + ",";
		}
		re_mod = re_mod + "GLOBAL";
	}
	pta[12] = strdup_null((char*)re_mod.c_str()); // re_modifiers
	itostr(pta[13], (long long)pqr->flagOUT);
	pta[14] = strdup_null(pqr->replace_pattern);
	itostr(pta[15], (long long)pqr->destination_hostgroup);
	itostr(pta[16], (long long)pqr->cache_ttl);
	itostr(pta[17], (long long)pqr->cache_empty_result);
	itostr(pta[18], (long long)pqr->cache_timeout);
	itostr(pta[19], (long long)pqr->reconnect);
	itostr(pta[20], (long long)pqr->timeout);
	itostr(pta[21], (long long)pqr->retries);
	itostr(pta[22], (long long)pqr->delay);
	itostr(pta[23], (long long)pqr->next_query_flagIN);
	itostr(pta[24], (long long)pqr->mirror_flagOUT);
	itostr(pta[25], (long long)pqr->mirror_hostgroup);
	pta[26] = strdup_null(pqr->error_msg);
	pta[27] = strdup_null(pqr->OK_msg);
	itostr(pta[28], (long long)pqr->sticky_conn);
	itostr(pta[29], (long long)pqr->multiplex);

	itostr(pta[30], (long long)pqr->log);
	itostr(pta[31], (long long)pqr->apply);
	pta[32] = strdup_null(pqr->attributes);
	pta[33] = strdup_null(pqr->comment); // issue #643
	itostr(pta[34], (long long)pqr->hits);
}

PgSQL_Query_Processor::PgSQL_Query_Processor() : 
	Query_Processor<PgSQL_Query_Processor>(GloPTH->get_variable_int("query_rules_fast_routing_algorithm")) {

	for (int i = 0; i < PGSQL_QUERY___NONE; i++) commands_counters[i] = new Command_Counter(i,15,commands_counters_desc);
}

PgSQL_Query_Processor::~PgSQL_Query_Processor() {
	for (int i = 0; i < PGSQL_QUERY___NONE; i++) delete commands_counters[i];
}

void PgSQL_Query_Processor::update_query_processor_stats() {
	Query_Processor::update_query_processor_stats();
	for (int i = 0; i < PGSQL_QUERY___NONE; i++) commands_counters[i]->add_and_reset(_thr_commands_counters[i]);
}

void PgSQL_Query_Processor::init_thread() {
	Query_Processor::init_thread();
	for (int i = 0; i < PGSQL_QUERY___NONE; i++) _thr_commands_counters[i] = new Command_Counter(i,15,commands_counters_desc);
}

void PgSQL_Query_Processor::end_thread() {
	Query_Processor::end_thread();
	for (int i = 0; i < PGSQL_QUERY___NONE; i++) delete _thr_commands_counters[i];
};

unsigned long long PgSQL_Query_Processor::query_parser_update_counters(PgSQL_Session* sess, enum PGSQL_QUERY_command c, SQP_par_t* qp, unsigned long long t) {
	if (c >= PGSQL_QUERY___NONE) return 0;
	unsigned long long ret = _thr_commands_counters[c]->add_time(t);
	Query_Processor::query_parser_update_counters(sess, qp->digest_total, qp->digest, qp->digest_text, t);
	return ret;
}

PgSQL_Query_Processor_Output* PgSQL_Query_Processor::process_query(PgSQL_Session* sess, void* ptr, unsigned int size, PgSQL_Query_Info* qi) {
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	// to avoid unnecssary deallocation/allocation, we initialize qpo witout new allocation
	PgSQL_Query_Processor_Output* ret = sess->qpo;
	ret->init();

	SQP_par_t stmt_exec_qp;
	SQP_par_t* qp = NULL;
	if (qi) {
		// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
		if (ptr) {
			qp = (SQP_par_t*)&qi->QueryParserArgs;
		} else {
			qp = &stmt_exec_qp;
			//qp->digest = qi->stmt_info->digest;
			//qp->digest_text = qi->stmt_info->digest_text;
			//qp->first_comment = qi->stmt_info->first_comment;
		}
	}
#define stackbuffer_size 128
	char stackbuffer[stackbuffer_size];
	unsigned int len = 0;
	char* query = NULL;
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	if (ptr) {
		len = size - sizeof(mysql_hdr) - 1;
		if (len < stackbuffer_size) {
			query = stackbuffer;
		} else {
			query = (char*)l_alloc(len + 1);
		}
		memcpy(query, (char*)ptr + sizeof(mysql_hdr) + 1, len);
		query[len] = 0;
	}
	else {
		//query = qi->stmt_info->query;
		//len = qi->stmt_info->query_length;
	}

	Query_Processor::process_query(sess, ptr == NULL, query, len, ret, qp);

	// FIXME : there is too much data being copied around
	if (len < stackbuffer_size) {
		// query is in the stack
	} else {
		if (ptr) {
			l_free(len + 1, query);
		}
	}

	return ret;
}

PgSQL_Query_Processor_Rule_t* PgSQL_Query_Processor::new_query_rule(int rule_id, bool active, const char* username, const char* schemaname, int flagIN, const char* client_addr,
	const char* proxy_addr, int proxy_port, const char* digest, const char* match_digest, const char* match_pattern, bool negate_match_pattern,
	const char* re_modifiers, int flagOUT, const char* replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result,
	int cache_timeout, int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_hostgroup,
	int mirror_flagOUT, const char* error_msg, const char* OK_msg, int sticky_conn, int multiplex, int log,
	bool apply, const char* attributes, const char* comment) {

	PgSQL_Query_Processor_Rule_t* newQR = (PgSQL_Query_Processor_Rule_t*)malloc(sizeof(PgSQL_Query_Processor_Rule_t));
	newQR->rule_id = rule_id;
	newQR->active = active;
	newQR->username = (username ? strdup(username) : NULL);
	newQR->schemaname = (schemaname ? strdup(schemaname) : NULL);
	newQR->flagIN = flagIN;
	newQR->match_digest = (match_digest ? strdup(match_digest) : NULL);
	newQR->match_pattern = (match_pattern ? strdup(match_pattern) : NULL);
	newQR->negate_match_pattern = negate_match_pattern;
	newQR->re_modifiers = 0;
	{
		tokenizer_t tok;
		tokenizer(&tok, re_modifiers, ",", TOKENIZER_NO_EMPTIES);
		const char* token;
		for (token = tokenize(&tok); token; token = tokenize(&tok)) {
			if (strncasecmp(token, (char*)"CASELESS", strlen((char*)"CASELESS")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_CASELESS;
			}
			if (strncasecmp(token, (char*)"GLOBAL", strlen((char*)"GLOBAL")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_GLOBAL;
			}
		}
		free_tokenizer(&tok);
	}
	newQR->flagOUT = flagOUT;
	newQR->replace_pattern = (replace_pattern ? strdup(replace_pattern) : NULL);
	newQR->destination_hostgroup = destination_hostgroup;
	newQR->cache_ttl = cache_ttl;
	newQR->cache_empty_result = cache_empty_result;
	newQR->cache_timeout = cache_timeout;
	newQR->reconnect = reconnect;
	newQR->timeout = timeout;
	newQR->retries = retries;
	newQR->delay = delay;
	newQR->next_query_flagIN = next_query_flagIN;
	newQR->mirror_flagOUT = mirror_flagOUT;
	newQR->mirror_hostgroup = mirror_hostgroup;
	newQR->error_msg = (error_msg ? strdup(error_msg) : NULL);
	newQR->OK_msg = (OK_msg ? strdup(OK_msg) : NULL);
	newQR->sticky_conn = sticky_conn;
	newQR->multiplex = multiplex;
	newQR->apply = apply;
	newQR->attributes = (attributes ? strdup(attributes) : NULL);
	newQR->comment = (comment ? strdup(comment) : NULL); // see issue #643
	newQR->regex_engine1 = NULL;
	newQR->regex_engine2 = NULL;
	newQR->hits = 0;

	newQR->client_addr_wildcard_position = -1; // not existing by default
	newQR->client_addr = (client_addr ? strdup(client_addr) : NULL);
	if (newQR->client_addr) {
		char* pct = strchr(newQR->client_addr, '%');
		if (pct) { // there is a wildcard . We assume Admin did already all the input validation
			if (pct == newQR->client_addr) {
				// client_addr == '%'
				// % is at the end of the string, but also at the beginning
				// becoming a catch all
				newQR->client_addr_wildcard_position = 0;
			}
			else {
				// this math is valid also if (pct == newQR->client_addr)
				// but we separate it to clarify that client_addr_wildcard_position is a match all
				newQR->client_addr_wildcard_position = strlen(newQR->client_addr) - strlen(pct);
			}
		}
	}
	newQR->proxy_addr = (proxy_addr ? strdup(proxy_addr) : NULL);
	newQR->proxy_port = proxy_port;
	newQR->log = log;
	newQR->digest = 0;
	if (digest) {
		unsigned long long num = strtoull(digest, NULL, 0);
		if (num != ULLONG_MAX && num != 0) {
			newQR->digest = num;
		}
		else {
			proxy_error("Incorrect digest for rule_id %d : %s\n", rule_id, digest);
		}
	}
	newQR->flagOUT_weights_total = 0;
	newQR->flagOUT_ids = NULL;
	newQR->flagOUT_weights = NULL;
	if (newQR->attributes != NULL) {
		if (strlen(newQR->attributes)) {
			nlohmann::json j_attributes = nlohmann::json::parse(newQR->attributes);
			if (j_attributes.find("flagOUTs") != j_attributes.end()) {
				newQR->flagOUT_ids = new vector<int>;
				newQR->flagOUT_weights = new vector<int>;
				const nlohmann::json& flagOUTs = j_attributes["flagOUTs"];
				if (flagOUTs.type() == nlohmann::json::value_t::array) {
					for (auto it = flagOUTs.begin(); it != flagOUTs.end(); it++) {
						bool parsed = false;
						const nlohmann::json& j = *it;
						if (j.find("id") != j.end() && j.find("weight") != j.end()) {
							if (j["id"].type() == nlohmann::json::value_t::number_unsigned && j["weight"].type() == nlohmann::json::value_t::number_unsigned) {
								int id = j["id"];
								int weight = j["weight"];
								newQR->flagOUT_ids->push_back(id);
								newQR->flagOUT_weights->push_back(weight);
								newQR->flagOUT_weights_total += weight;
								parsed = true;
							}
						}
						if (parsed == false) {
							proxy_error("Failed to parse flagOUTs in JSON on attributes for rule_id %d : %s\n", newQR->rule_id, j.dump().c_str());
						}
					}
				}
				else {
					proxy_error("Failed to parse flagOUTs attributes for rule_id %d : %s\n", newQR->rule_id, flagOUTs.dump().c_str());
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_digest=\"%s\", %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_digest, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
	return newQR;
}

PgSQL_Query_Processor_Rule_t* PgSQL_Query_Processor::new_query_rule(const PgSQL_Query_Processor_Rule_t* pqr) {

	char buf[20];
	if (pqr->digest) { // not 0
		sprintf(buf, "0x%016llX", (long long unsigned int)pqr->digest);
	}

	std::string re_mod;
	re_mod = "";
	if ((pqr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
	if ((pqr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
		if (re_mod.length()) {
			re_mod = re_mod + ",";
		}
		re_mod = re_mod + "GLOBAL";
	}

	PgSQL_Query_Processor_Rule_t* newQR = (PgSQL_Query_Processor_Rule_t*)malloc(sizeof(PgSQL_Query_Processor_Rule_t));
	newQR->rule_id = pqr->rule_id;
	newQR->active = pqr->active;
	newQR->username = (pqr->username ? strdup(pqr->username) : NULL);
	newQR->schemaname = (pqr->schemaname ? strdup(pqr->schemaname) : NULL);
	newQR->flagIN = pqr->flagIN;
	newQR->match_digest = (pqr->match_digest ? strdup(pqr->match_digest) : NULL);
	newQR->match_pattern = (pqr->match_pattern ? strdup(pqr->match_pattern) : NULL);
	newQR->negate_match_pattern = pqr->negate_match_pattern;
	newQR->re_modifiers = 0;
	{
		tokenizer_t tok;
		tokenizer(&tok, re_mod.c_str(), ",", TOKENIZER_NO_EMPTIES);
		const char* token;
		for (token = tokenize(&tok); token; token = tokenize(&tok)) {
			if (strncasecmp(token, (char*)"CASELESS", strlen((char*)"CASELESS")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_CASELESS;
			}
			if (strncasecmp(token, (char*)"GLOBAL", strlen((char*)"GLOBAL")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_GLOBAL;
			}
		}
		free_tokenizer(&tok);
	}
	newQR->flagOUT = pqr->flagOUT;
	newQR->replace_pattern = (pqr->replace_pattern ? strdup(pqr->replace_pattern) : NULL);
	newQR->destination_hostgroup = pqr->destination_hostgroup;
	newQR->cache_ttl = pqr->cache_ttl;
	newQR->cache_empty_result = pqr->cache_empty_result;
	newQR->cache_timeout = pqr->cache_timeout;
	newQR->reconnect = pqr->reconnect;
	newQR->timeout = pqr->timeout;
	newQR->retries = pqr->retries;
	newQR->delay = pqr->delay;
	newQR->next_query_flagIN = pqr->next_query_flagIN;
	newQR->mirror_flagOUT = pqr->mirror_flagOUT;
	newQR->mirror_hostgroup = pqr->mirror_hostgroup;
	newQR->error_msg = (pqr->error_msg ? strdup(pqr->error_msg) : NULL);
	newQR->OK_msg = (pqr->OK_msg ? strdup(pqr->OK_msg) : NULL);
	newQR->sticky_conn = pqr->sticky_conn;
	newQR->multiplex = pqr->multiplex;
	newQR->apply = pqr->apply;
	newQR->attributes = (pqr->attributes ? strdup(pqr->attributes) : NULL);
	newQR->comment = (pqr->comment ? strdup(pqr->comment) : NULL); // see issue #643
	newQR->regex_engine1 = NULL;
	newQR->regex_engine2 = NULL;
	newQR->hits = 0;

	newQR->client_addr_wildcard_position = -1; // not existing by default
	newQR->client_addr = (pqr->client_addr ? strdup(pqr->client_addr) : NULL);
	if (newQR->client_addr) {
		char* pct = strchr(newQR->client_addr, '%');
		if (pct) { // there is a wildcard . We assume Admin did already all the input validation
			if (pct == newQR->client_addr) {
				// client_addr == '%'
				// % is at the end of the string, but also at the beginning
				// becoming a catch all
				newQR->client_addr_wildcard_position = 0;
			}
			else {
				// this math is valid also if (pct == newQR->client_addr)
				// but we separate it to clarify that client_addr_wildcard_position is a match all
				newQR->client_addr_wildcard_position = strlen(newQR->client_addr) - strlen(pct);
			}
		}
	}
	newQR->proxy_addr = (pqr->proxy_addr ? strdup(pqr->proxy_addr) : NULL);
	newQR->proxy_port = pqr->proxy_port;
	newQR->log = pqr->log;
	newQR->digest = 0;
	if (pqr->digest) {
		unsigned long long num = strtoull(buf, NULL, 0);
		if (num != ULLONG_MAX && num != 0) {
			newQR->digest = num;
		}
		else {
			proxy_error("Incorrect digest for rule_id %d : %s\n", pqr->rule_id, buf);
		}
	}
	newQR->flagOUT_weights_total = 0;
	newQR->flagOUT_ids = NULL;
	newQR->flagOUT_weights = NULL;
	if (newQR->attributes != NULL) {
		if (strlen(newQR->attributes)) {
			nlohmann::json j_attributes = nlohmann::json::parse(newQR->attributes);
			if (j_attributes.find("flagOUTs") != j_attributes.end()) {
				newQR->flagOUT_ids = new vector<int>;
				newQR->flagOUT_weights = new vector<int>;
				const nlohmann::json& flagOUTs = j_attributes["flagOUTs"];
				if (flagOUTs.type() == nlohmann::json::value_t::array) {
					for (auto it = flagOUTs.begin(); it != flagOUTs.end(); it++) {
						bool parsed = false;
						const nlohmann::json& j = *it;
						if (j.find("id") != j.end() && j.find("weight") != j.end()) {
							if (j["id"].type() == nlohmann::json::value_t::number_unsigned && j["weight"].type() == nlohmann::json::value_t::number_unsigned) {
								int id = j["id"];
								int weight = j["weight"];
								newQR->flagOUT_ids->push_back(id);
								newQR->flagOUT_weights->push_back(weight);
								newQR->flagOUT_weights_total += weight;
								parsed = true;
							}
						}
						if (parsed == false) {
							proxy_error("Failed to parse flagOUTs in JSON on attributes for rule_id %d : %s\n", newQR->rule_id, j.dump().c_str());
						}
					}
				}
				else {
					proxy_error("Failed to parse flagOUTs attributes for rule_id %d : %s\n", newQR->rule_id, flagOUTs.dump().c_str());
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_digest=\"%s\", %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_digest, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
	return newQR;
}

SQLite3_result* PgSQL_Query_Processor::get_current_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules, using Global version %d\n", version);
	SQLite3_result* result = new SQLite3_result(34);
	PgSQL_Query_Processor_Rule_t* qr1;
	rdlock();
	result->add_column_definition(SQLITE_TEXT, "rule_id");
	result->add_column_definition(SQLITE_TEXT, "active");
	result->add_column_definition(SQLITE_TEXT, "username");
	result->add_column_definition(SQLITE_TEXT, "database");
	result->add_column_definition(SQLITE_TEXT, "flagIN");
	result->add_column_definition(SQLITE_TEXT, "client_addr");
	result->add_column_definition(SQLITE_TEXT, "proxy_addr");
	result->add_column_definition(SQLITE_TEXT, "proxy_port");
	result->add_column_definition(SQLITE_TEXT, "digest");
	result->add_column_definition(SQLITE_TEXT, "match_digest");
	result->add_column_definition(SQLITE_TEXT, "match_pattern");
	result->add_column_definition(SQLITE_TEXT, "negate_match_pattern");
	result->add_column_definition(SQLITE_TEXT, "re_modifiers");
	result->add_column_definition(SQLITE_TEXT, "flagOUT");
	result->add_column_definition(SQLITE_TEXT, "replace_pattern");
	result->add_column_definition(SQLITE_TEXT, "destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT, "cache_ttl");
	result->add_column_definition(SQLITE_TEXT, "cache_empty_result");
	result->add_column_definition(SQLITE_TEXT, "cache_timeout");
	result->add_column_definition(SQLITE_TEXT, "reconnect");
	result->add_column_definition(SQLITE_TEXT, "timeout");
	result->add_column_definition(SQLITE_TEXT, "retries");
	result->add_column_definition(SQLITE_TEXT, "delay");
	result->add_column_definition(SQLITE_TEXT, "next_query_flagIN");
	result->add_column_definition(SQLITE_TEXT, "mirror_flagOUT");
	result->add_column_definition(SQLITE_TEXT, "mirror_hostgroup");
	result->add_column_definition(SQLITE_TEXT, "error_msg");
	result->add_column_definition(SQLITE_TEXT, "OK_msg");
	result->add_column_definition(SQLITE_TEXT, "sticky_conn");
	result->add_column_definition(SQLITE_TEXT, "multiplex");
	result->add_column_definition(SQLITE_TEXT, "log");
	result->add_column_definition(SQLITE_TEXT, "apply");
	result->add_column_definition(SQLITE_TEXT, "attributes");
	result->add_column_definition(SQLITE_TEXT, "comment"); // issue #643
	result->add_column_definition(SQLITE_TEXT, "hits");
	for (std::vector<QP_rule_t*>::iterator it = rules.begin(); it != rules.end(); ++it) {
		qr1 = static_cast<PgSQL_Query_Processor_Rule_t*>(*it);
		PgSQL_Rule_Text* qt = new PgSQL_Rule_Text(qr1);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
		result->add_row(qt->pta);
		delete qt;
	}
	wrunlock();
	return result;
}

SQLite3_result* PgSQL_Query_Processor::get_stats_commands_counters() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping commands counters\n");
	SQLite3_result* result = new SQLite3_result(15);
	result->add_column_definition(SQLITE_TEXT, "Command");
	result->add_column_definition(SQLITE_TEXT, "Total_Cnt");
	result->add_column_definition(SQLITE_TEXT, "Total_Time_us");
	result->add_column_definition(SQLITE_TEXT, "cnt_100us");
	result->add_column_definition(SQLITE_TEXT, "cnt_500us");
	result->add_column_definition(SQLITE_TEXT, "cnt_1ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_5ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_10ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_50ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_100ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_500ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_1s");
	result->add_column_definition(SQLITE_TEXT, "cnt_5s");
	result->add_column_definition(SQLITE_TEXT, "cnt_10s");
	result->add_column_definition(SQLITE_TEXT, "cnt_INFs");
	for (int i = 0; i < PGSQL_QUERY__UNINITIALIZED; i++) {
		char** pta = commands_counters[i]->get_row();
		result->add_row(pta);
		commands_counters[i]->free_row(pta);
	}
	return result;
}

enum PGSQL_QUERY_command PgSQL_Query_Processor::query_parser_command_type(SQP_par_t* qp) {
	char* text = NULL;
	if (qp->digest_text) {
		text = qp->digest_text;
	}
	else {
		text = qp->query_prefix;
	}

	enum PGSQL_QUERY_command ret = PGSQL_QUERY_UNKNOWN;
	char c1;

	tokenizer_t tok;
	tokenizer(&tok, text, " ", TOKENIZER_NO_EMPTIES);
	char* token = NULL;
__get_token:
	token = (char*)tokenize(&tok);
	if (token == NULL) {
		goto __exit__query_parser_command_type;
	}
__remove_parenthesis:
	if (token[0] == '(') {
		if (strlen(token) > 1) {
			token++;
			goto __remove_parenthesis;
		}
		else {
			goto __get_token;
		}
	}
	c1 = token[0];
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%s Prefix:%c\n", token, c1);
	switch (c1) {
	case 'a':
	case 'A':
		if (!strcasecmp("ALTER", token)) {
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) ret = PGSQL_QUERY_ALTER_TABLE;
			else if (!strcasecmp("INDEX", token)) ret = PGSQL_QUERY_ALTER_INDEX;
			else if (!strcasecmp("VIEW", token)) ret = PGSQL_QUERY_ALTER_VIEW;
			else if (!strcasecmp("MATERIALIZED", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("VIEW", token)) ret = PGSQL_QUERY_ALTER_MATERIALIZED_VIEW;
			}
			else if (!strcasecmp("SEQUENCE", token)) ret = PGSQL_QUERY_ALTER_SEQUENCE;
			else if (!strcasecmp("SCHEMA", token)) ret = PGSQL_QUERY_ALTER_SCHEMA;
			else if (!strcasecmp("FUNCTION", token)) ret = PGSQL_QUERY_ALTER_FUNCTION;
			else if (!strcasecmp("PROCEDURE", token)) ret = PGSQL_QUERY_ALTER_PROCEDURE;
			else if (!strcasecmp("AGGREGATE", token)) ret = PGSQL_QUERY_ALTER_AGGREGATE;
			else if (!strcasecmp("OPERATOR", token)) ret = PGSQL_QUERY_ALTER_OPERATOR;
			else if (!strcasecmp("TYPE", token)) ret = PGSQL_QUERY_ALTER_TYPE;
			else if (!strcasecmp("DOMAIN", token)) ret = PGSQL_QUERY_ALTER_DOMAIN;
			else if (!strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_ALTER_TRIGGER;
			else if (!strcasecmp("RULE", token)) ret = PGSQL_QUERY_ALTER_RULE;
			else if (!strcasecmp("EXTENSION", token)) ret = PGSQL_QUERY_ALTER_EXTENSION;
			else if (!strcasecmp("POLICY", token)) ret = PGSQL_QUERY_ALTER_POLICY;
			else if (!strcasecmp("ROLE", token)) ret = PGSQL_QUERY_ALTER_ROLE;
			else if (!strcasecmp("USER", token)) ret = PGSQL_QUERY_ALTER_USER;
			else if (!strcasecmp("DATABASE", token)) ret = PGSQL_QUERY_ALTER_DATABASE;
			else if (!strcasecmp("COLLATION", token)) ret = PGSQL_QUERY_ALTER_COLLATION;
			else if (!strcasecmp("TEXT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("SEARCH", token)) {
						token = (char*)tokenize(&tok);
						if (token != NULL) {
							if (!strcasecmp("CONFIGURATION", token)) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_CONFIGURATION;
							else if (!strcasecmp("DICTIONARY", token)) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_DICTIONARY;
							else if (!strcasecmp("TEMPLATE", token)) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_TEMPLATE;
							else if (!strcasecmp("PARSER", token)) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (!strcasecmp("FOREIGN", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TABLE", token)) ret = PGSQL_QUERY_ALTER_FOREIGN_TABLE;
			}
			else if (!strcasecmp("SERVER", token)) ret = PGSQL_QUERY_ALTER_SERVER;
			else if (!strcasecmp("USER", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("MAPPING", token)) ret = PGSQL_QUERY_ALTER_USER_MAPPING;
			}
			else if (!strcasecmp("PUBLICATION", token)) ret = PGSQL_QUERY_ALTER_PUBLICATION;
			else if (!strcasecmp("SUBSCRIPTION", token)) ret = PGSQL_QUERY_ALTER_SUBSCRIPTION;
			else if (!strcasecmp("ACCESS", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("METHOD", token)) ret = PGSQL_QUERY_ALTER_ACCESS_METHOD;
			}
			else if (!strcasecmp("EVENT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_ALTER_EVENT_TRIGGER;
			}
			else if (!strcasecmp("TRANSFORM", token)) ret = PGSQL_QUERY_ALTER_TRANSFORM;
			else if (!strcasecmp("CAST", token)) ret = PGSQL_QUERY_ALTER_CAST;
			else if (!strcasecmp("OPERATOR", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("CLASS", token)) ret = PGSQL_QUERY_ALTER_OPERATOR_CLASS;
					else if (!strcasecmp("FAMILY", token)) ret = PGSQL_QUERY_ALTER_OPERATOR_FAMILY;
				}
			}
			else if (!strcasecmp("TABLESPACE", token)) ret = PGSQL_QUERY_ALTER_TABLESPACE;
			break;
		}
		if (!strcasecmp("ANALYZE", token)) {
			ret = PGSQL_QUERY_ANALYZE;
			break;
		}
		break;
	case 'b':
	case 'B':
		if (!strcasecmp("BEGIN", token)) {
			ret = PGSQL_QUERY_BEGIN;
			break;
		}
		break;
	case 'c':
	case 'C':
		if (!strcasecmp("CALL", token)) {
			ret = PGSQL_QUERY_CALL;
			break;
		}
		if (!strcasecmp("CHECKPOINT", token)) {
			ret = PGSQL_QUERY_CHECKPOINT;
			break;
		}
		if (!strcasecmp("CLOSE", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("CURSOR", token)) ret = PGSQL_QUERY_CLOSE_CURSOR;
			break;
		}
		if (!strcasecmp("CLUSTER", token)) {
			ret = PGSQL_QUERY_CLUSTER; 
			break;
		}
		if (!strcasecmp("COMMENT", token)) {
			ret = PGSQL_QUERY_COMMENT;
			break;
		}
		if (!strcasecmp("COMMIT", token)) {
			ret = PGSQL_QUERY_COMMIT;
			break;
		}
		if (!strcasecmp("COPY", token)) {
			ret = PGSQL_QUERY_COPY;
			break;
		}
		if (!strcasecmp("CREATE", token)) {
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) ret = PGSQL_QUERY_CREATE_TABLE;
			else if (!strcasecmp("INDEX", token)) ret = PGSQL_QUERY_CREATE_INDEX;
			else if (!strcasecmp("VIEW", token)) ret = PGSQL_QUERY_CREATE_VIEW;
			else if (!strcasecmp("MATERIALIZED", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("VIEW", token)) ret = PGSQL_QUERY_CREATE_MATERIALIZED_VIEW;
			}
			else if (!strcasecmp("SEQUENCE", token)) ret = PGSQL_QUERY_CREATE_SEQUENCE;
			else if (!strcasecmp("SCHEMA", token)) ret = PGSQL_QUERY_CREATE_SCHEMA;
			else if (!strcasecmp("FUNCTION", token)) ret = PGSQL_QUERY_CREATE_FUNCTION;
			else if (!strcasecmp("PROCEDURE", token)) ret = PGSQL_QUERY_CREATE_PROCEDURE;
			else if (!strcasecmp("AGGREGATE", token)) ret = PGSQL_QUERY_CREATE_AGGREGATE;
			else if (!strcasecmp("OPERATOR", token)) ret = PGSQL_QUERY_CREATE_OPERATOR;
			else if (!strcasecmp("TYPE", token)) ret = PGSQL_QUERY_CREATE_TYPE;
			else if (!strcasecmp("DOMAIN", token)) ret = PGSQL_QUERY_CREATE_DOMAIN;
			else if (!strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_CREATE_TRIGGER;
			else if (!strcasecmp("RULE", token)) ret = PGSQL_QUERY_CREATE_RULE;
			else if (!strcasecmp("EXTENSION", token)) ret = PGSQL_QUERY_CREATE_EXTENSION;
			else if (!strcasecmp("POLICY", token)) ret = PGSQL_QUERY_CREATE_POLICY;
			else if (!strcasecmp("ROLE", token)) ret = PGSQL_QUERY_CREATE_ROLE;
			else if (!strcasecmp("USER", token)) ret = PGSQL_QUERY_CREATE_USER;
			else if (!strcasecmp("DATABASE", token)) ret = PGSQL_QUERY_CREATE_DATABASE;
			else if (!strcasecmp("COLLATION", token)) ret = PGSQL_QUERY_CREATE_COLLATION;
			else if (!strcasecmp("TEXT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("SEARCH", token)) {
						token = (char*)tokenize(&tok);
						if (token != NULL) {
							if (!strcasecmp("CONFIGURATION", token)) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_CONFIGURATION;
							else if (!strcasecmp("DICTIONARY", token)) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_DICTIONARY;
							else if (!strcasecmp("TEMPLATE", token)) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_TEMPLATE;
							else if (!strcasecmp("PARSER", token)) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (!strcasecmp("FOREIGN", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TABLE", token)) ret = PGSQL_QUERY_CREATE_FOREIGN_TABLE;
			}
			else if (!strcasecmp("SERVER", token)) ret = PGSQL_QUERY_CREATE_SERVER;
			else if (!strcasecmp("USER", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("MAPPING", token)) ret = PGSQL_QUERY_CREATE_USER_MAPPING;
			}
			else if (!strcasecmp("PUBLICATION", token)) ret = PGSQL_QUERY_CREATE_PUBLICATION;
			else if (!strcasecmp("SUBSCRIPTION", token)) ret = PGSQL_QUERY_CREATE_SUBSCRIPTION;
			else if (!strcasecmp("ACCESS", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("METHOD", token)) ret = PGSQL_QUERY_CREATE_ACCESS_METHOD;
			}
			else if (!strcasecmp("EVENT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_CREATE_EVENT_TRIGGER;
			}
			else if (!strcasecmp("TRANSFORM", token)) ret = PGSQL_QUERY_CREATE_TRANSFORM;
			else if (!strcasecmp("CAST", token)) ret = PGSQL_QUERY_CREATE_CAST;
			else if (!strcasecmp("OPERATOR", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("CLASS", token)) ret = PGSQL_QUERY_CREATE_OPERATOR_CLASS;
					else if (!strcasecmp("FAMILY", token)) ret = PGSQL_QUERY_CREATE_OPERATOR_FAMILY;
				}
			}
			else if (!strcasecmp("TABLESPACE", token)) ret = PGSQL_QUERY_CREATE_TABLESPACE;
			break;
		}
		break;
	case 'd':
	case 'D':
		if (!strcasecmp("DEALLOCATE", token)) {
			ret = PGSQL_QUERY_DEALLOCATE;
			break;
		}
		if (!strcasecmp("DECLARE", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("CURSOR", token)) ret = PGSQL_QUERY_DECLARE_CURSOR;
			break;
		}
		if (!strcasecmp("DELETE", token)) {
			ret = PGSQL_QUERY_DELETE;
			break;
		}
		if (!strcasecmp("DISCARD", token)) {
			ret = PGSQL_QUERY_DISCARD;
			break;
		}
		if (!strcasecmp("DROP", token)) {
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) ret = PGSQL_QUERY_DROP_TABLE;
			else if (!strcasecmp("INDEX", token)) ret = PGSQL_QUERY_DROP_INDEX;
			else if (!strcasecmp("VIEW", token)) ret = PGSQL_QUERY_DROP_VIEW;
			else if (!strcasecmp("MATERIALIZED", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("VIEW", token)) ret = PGSQL_QUERY_DROP_MATERIALIZED_VIEW;
			}
			else if (!strcasecmp("SEQUENCE", token)) ret = PGSQL_QUERY_DROP_SEQUENCE;
			else if (!strcasecmp("SCHEMA", token)) ret = PGSQL_QUERY_DROP_SCHEMA;
			else if (!strcasecmp("FUNCTION", token)) ret = PGSQL_QUERY_DROP_FUNCTION;
			else if (!strcasecmp("PROCEDURE", token)) ret = PGSQL_QUERY_DROP_PROCEDURE;
			else if (!strcasecmp("AGGREGATE", token)) ret = PGSQL_QUERY_DROP_AGGREGATE;
			else if (!strcasecmp("OPERATOR", token)) ret = PGSQL_QUERY_DROP_OPERATOR;
			else if (!strcasecmp("TYPE", token)) ret = PGSQL_QUERY_DROP_TYPE;
			else if (!strcasecmp("DOMAIN", token)) ret = PGSQL_QUERY_DROP_DOMAIN;
			else if (!strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_DROP_TRIGGER;
			else if (!strcasecmp("RULE", token)) ret = PGSQL_QUERY_DROP_RULE;
			else if (!strcasecmp("EXTENSION", token)) ret = PGSQL_QUERY_DROP_EXTENSION;
			else if (!strcasecmp("POLICY", token)) ret = PGSQL_QUERY_DROP_POLICY;
			else if (!strcasecmp("ROLE", token)) ret = PGSQL_QUERY_DROP_ROLE;
			else if (!strcasecmp("USER", token)) ret = PGSQL_QUERY_DROP_USER;
			else if (!strcasecmp("DATABASE", token)) ret = PGSQL_QUERY_DROP_DATABASE;
			else if (!strcasecmp("COLLATION", token)) ret = PGSQL_QUERY_DROP_COLLATION;
			else if (!strcasecmp("TEXT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("SEARCH", token)) {
						token = (char*)tokenize(&tok);
						if (token != NULL) {
							if (!strcasecmp("CONFIGURATION", token)) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_CONFIGURATION;
							else if (!strcasecmp("DICTIONARY", token)) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_DICTIONARY;
							else if (!strcasecmp("TEMPLATE", token)) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_TEMPLATE;
							else if (!strcasecmp("PARSER", token)) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (!strcasecmp("FOREIGN", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TABLE", token)) ret = PGSQL_QUERY_DROP_FOREIGN_TABLE;
			}
			else if (!strcasecmp("SERVER", token)) ret = PGSQL_QUERY_DROP_SERVER;
			else if (!strcasecmp("USER", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("MAPPING", token)) ret = PGSQL_QUERY_DROP_USER_MAPPING;
			}
			else if (!strcasecmp("PUBLICATION", token)) ret = PGSQL_QUERY_DROP_PUBLICATION;
			else if (!strcasecmp("SUBSCRIPTION", token)) ret = PGSQL_QUERY_DROP_SUBSCRIPTION;
			else if (!strcasecmp("ACCESS", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("METHOD", token)) ret = PGSQL_QUERY_DROP_ACCESS_METHOD;
			}
			else if (!strcasecmp("EVENT", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("TRIGGER", token)) ret = PGSQL_QUERY_DROP_EVENT_TRIGGER;
			}
			else if (!strcasecmp("TRANSFORM", token)) ret = PGSQL_QUERY_DROP_TRANSFORM;
			else if (!strcasecmp("CAST", token)) ret = PGSQL_QUERY_DROP_CAST;
			else if (!strcasecmp("OPERATOR", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL) {
					if (!strcasecmp("CLASS", token)) ret = PGSQL_QUERY_DROP_OPERATOR_CLASS;
					else if (!strcasecmp("FAMILY", token)) ret = PGSQL_QUERY_DROP_OPERATOR_FAMILY;
				}
			}
			else if (!strcasecmp("TABLESPACE", token)) ret = PGSQL_QUERY_DROP_TABLESPACE;
			break;
		}
		break;
	case 'e':
	case 'E':
		if (!strcasecmp("EXECUTE", token)) {
			ret = PGSQL_QUERY_EXECUTE;
			break;
		}
		if (!strcasecmp("EXPLAIN", token)) {
			ret = PGSQL_QUERY_EXPLAIN;
			break;
		}
		break;
	case 'f':
	case 'F':
		if (!strcasecmp("FETCH", token)) {
			ret = PGSQL_QUERY_FETCH;
			break;
		}
		break;
	case 'g':
	case 'G':
		if (!strcasecmp("GRANT", token)) {
			ret = PGSQL_QUERY_GRANT;
			break;
		}
		break;
	case 'i':
	case 'I':
		if (!strcasecmp("INSERT", token)) {
			ret = PGSQL_QUERY_INSERT;
			break;
		}
		if (!strcasecmp("IMPORT", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("FOREIGN", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("SCHEMA", token)) ret = PGSQL_QUERY_IMPORT_FOREIGN_SCHEMA;
			}
			break;
		}
		break;
	case 'l':
	case 'L':
		if (!strcasecmp("LISTEN", token)) {
			ret = PGSQL_QUERY_LISTEN;
			break;
		}
		if (!strcasecmp("LOAD", token)) {
			ret = PGSQL_QUERY_UNKNOWN; // Not in the enum, but exists in PostgreSQL
			break;
		}
		if (!strcasecmp("LOCK", token)) {
			ret = PGSQL_QUERY_LOCK;
			break;
		}
		break;
	case 'm':
	case 'M':
		if (!strcasecmp("MERGE", token)) {
			ret = PGSQL_QUERY_MERGE;
			break;
		}
		if (!strcasecmp("MOVE", token)) {
			ret = PGSQL_QUERY_MOVE;
			break;
		}
		break;
	case 'n':
	case 'N':
		if (!strcasecmp("NOTIFY", token)) {
			ret = PGSQL_QUERY_NOTIFY;
			break;
		}
		break;
	case 'p':
	case 'P':
		if (!strcasecmp("PREPARE", token)) {
			ret = PGSQL_QUERY_PREPARE;
			break;
		}
		break;
	case 'r':
	case 'R':
		if (!strcasecmp("REFRESH", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("MATERIALIZED", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("VIEW", token)) ret = PGSQL_QUERY_REFRESH_MATERIALIZED_VIEW;
			}
			break;
		}
		if (!strcasecmp("REINDEX", token)) {
			ret = PGSQL_QUERY_REINDEX;
			break;
		}
		if (!strcasecmp("RELEASE", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("SAVEPOINT", token)) ret = PGSQL_QUERY_RELEASE_SAVEPOINT;
			break;
		}
		if (!strcasecmp("RESET", token)) {
			ret = PGSQL_QUERY_RESET;
			break;
		}
		if (!strcasecmp("REVOKE", token)) {
			ret = PGSQL_QUERY_REVOKE;
			break;
		}
		if (!strcasecmp("ROLLBACK", token)) {
			token = (char*)tokenize(&tok);
			if (token == NULL) {
				ret = PGSQL_QUERY_ROLLBACK;
			}
			else if (!strcasecmp("TO", token)) {
				token = (char*)tokenize(&tok);
				if (token != NULL && !strcasecmp("SAVEPOINT", token)) ret = PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT;
			}
			break;
		}
		break;
	case 's':
	case 'S':
		if (!strcasecmp("SAVEPOINT", token)) {
			ret = PGSQL_QUERY_SAVEPOINT;
			break;
		}
		if (!strcasecmp("SELECT", token)) {
			ret = PGSQL_QUERY_SELECT;
			break;
		}
		if (!strcasecmp("SET", token)) {
			ret = PGSQL_QUERY_SET;
			break;
		}
		if (!strcasecmp("SHOW", token)) {
			ret = PGSQL_QUERY_SHOW;
			break;
		}
		if (!strcasecmp("START", token)) {
			token = (char*)tokenize(&tok);
			if (token != NULL && !strcasecmp("TRANSACTION", token)) ret = PGSQL_QUERY_BEGIN;
			break;
		}
		break;
	case 't':
	case 'T':
		if (!strcasecmp("TRUNCATE", token)) {
			ret = PGSQL_QUERY_TRUNCATE;
			break;
		}
		break;
	case 'u':
	case 'U':
		if (!strcasecmp("UNLISTEN", token)) {
			ret = PGSQL_QUERY_UNLISTEN;
			break;
		}
		if (!strcasecmp("UPDATE", token)) {
			ret = PGSQL_QUERY_UPDATE;
			break;
		}
		break;
	case 'v':
	case 'V':
		if (!strcasecmp("VACUUM", token)) {
			ret = PGSQL_QUERY_VACUUM;
			break;
		}
		break;
	default:
		break;
	}

__exit__query_parser_command_type:
	free_tokenizer(&tok);
	if (qp->query_prefix) {
		free(qp->query_prefix);
		qp->query_prefix = NULL;
	}
	return ret;
}
