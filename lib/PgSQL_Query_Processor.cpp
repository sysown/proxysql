#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include <climits>      // INT_MAX for bounded debug output
#include "proxysql.h"
#include "cpp.h"
#include "Command_Counter.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Query_Processor.h"
#include "Query_Processor_ParserSQL.h"

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
	[PGSQL_QUERY_ABORT] = (char*)"ABORT",
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
	[PGSQL_QUERY_START_REPLICATION] = (char*)"START_REPLICATION",
	[PGSQL_QUERY_CANCEL_BACKEND] = (char*)"CANCEL_BACKEND",
	[PGSQL_QUERY_TERMINATE_BACKEND] = (char*)"TERMINATE_BACKEND",
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
		snprintf(buf, sizeof(buf), "0x%016llX", (long long unsigned int)pqr->digest);
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
	for (int i = 0; i < PGSQL_QUERY___NONE; i++) {
		commands_counters[i]->add_and_reset(_thr_commands_counters[i]);
	}
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
		// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE or STMT_DESCRIBE
		if (ptr) {
			qp = &qi->QueryParserArgs;
		} else {
			qp = &stmt_exec_qp;
			qp->digest = qi->extended_query_info.stmt_info->digest;
			qp->digest_text = qi->extended_query_info.stmt_info->digest_text;
			qp->first_comment = qi->extended_query_info.stmt_info->first_comment;
		}
	}
#define stackbuffer_size 128
	char stackbuffer[stackbuffer_size];
	unsigned int len = size;
	char* query = NULL;
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	if (ptr) {
		//len = size - sizeof(mysql_hdr) - 1;
		if (len < stackbuffer_size) {
			query = stackbuffer;
		} else {
			query = (char*)l_alloc(len);
		}
		memcpy(query, ptr, len);
		query[len-1] = 0;
	} else {
		query = qi->extended_query_info.stmt_info->query;
		len = qi->extended_query_info.stmt_info->query_length;
	}

	Query_Processor::process_query(sess, ptr == NULL, query, len, ret, qp);

	// FIXME : there is too much data being copied around
	if (len < stackbuffer_size) {
		// query is in the stack
	} else {
		if (ptr) {
			l_free(len, query);
		}
	}

	return ret;
}

PgSQL_Query_Processor_Rule_t* PgSQL_Query_Processor::new_query_rule(int rule_id, bool active, const char* username, const char* schemaname, int flagIN, const char* client_addr,
	const char* proxy_addr, int proxy_port, const char* digest, const char* match_digest, const char* match_pattern, bool negate_match_pattern,
	const char* re_modifiers, int flagOUT, const char* replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result,
	int cache_timeout, int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_flagOUT,
	int mirror_hostgroup, const char* error_msg, const char* OK_msg, int sticky_conn, int multiplex, int log,
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

	newQR->client_addr = (client_addr ? strdup(client_addr) : NULL);
	if (qp_addr_predicate_init(&newQR->client_addr_pred, newQR->client_addr, QP_ADDR_FIELD_CLIENT) == false) {
		// Admin rejects a malformed value before we get here, so this only
		// fires on a rule that bypassed validation. Keep the address but leave
		// the predicate inert rather than matching on a partial parse.
		proxy_error("Query rule with rule_id %d has an invalid client_addr, address matching disabled: %s\n",
			newQR->rule_id, newQR->client_addr);
	}
	newQR->proxy_addr = (proxy_addr ? strdup(proxy_addr) : NULL);
	if (qp_addr_predicate_init(&newQR->proxy_addr_pred, newQR->proxy_addr, QP_ADDR_FIELD_PROXY) == false) {
		// Same reasoning as the client_addr case above: the predicate is left
		// inert and the failure is reported, not silently ignored.
		proxy_error("Query rule with rule_id %d has an invalid proxy_addr, address matching disabled: %s\n",
			newQR->rule_id, newQR->proxy_addr);
	}
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
		snprintf(buf, sizeof(buf), "0x%016llX", (long long unsigned int)pqr->digest);
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

	newQR->client_addr = (pqr->client_addr ? strdup(pqr->client_addr) : NULL);
	if (qp_addr_predicate_init(&newQR->client_addr_pred, newQR->client_addr, QP_ADDR_FIELD_CLIENT) == false) {
		proxy_error("Query rule with rule_id %d has an invalid client_addr, address matching disabled: %s\n",
			newQR->rule_id, newQR->client_addr);
	}
	newQR->proxy_addr = (pqr->proxy_addr ? strdup(pqr->proxy_addr) : NULL);
	if (qp_addr_predicate_init(&newQR->proxy_addr_pred, newQR->proxy_addr, QP_ADDR_FIELD_PROXY) == false) {
		proxy_error("Query rule with rule_id %d has an invalid proxy_addr, address matching disabled: %s\n",
			newQR->rule_id, newQR->proxy_addr);
	}
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
	SQLite3_result* result = new SQLite3_result(35);
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

/**
 * @brief Classifies what follows a leading SELECT.
 *
 * ProxySQL intercepts pg_cancel_backend() and pg_terminate_backend() itself, because the
 * PID a client passes is the ProxySQL session id that SELECT pg_backend_pid() returned.
 * The function name must be complete and followed by '(' (whitespace and comments allowed
 * in between) or by the end of the text, which is where a 32-byte query prefix or a legacy token can stop: a longer
 * identifier such as pg_cancel_backend_count() or a column named pg_cancel_backend stays a
 * SELECT.
 *
 * @param p Text right after SELECT and the spaces that follow it. Must not be NULL.
 */
static enum PGSQL_QUERY_command select_target_command_type(const char* p) {
	enum PGSQL_QUERY_command cmd = PGSQL_QUERY_SELECT;
	size_t len = 0;
	if (pgsql_stmt_first_keyword_is(p, "pg_cancel_backend")) {
		cmd = PGSQL_QUERY_CANCEL_BACKEND;
		len = sizeof("pg_cancel_backend") - 1;
	} else if (pgsql_stmt_first_keyword_is(p, "pg_terminate_backend")) {
		cmd = PGSQL_QUERY_TERMINATE_BACKEND;
		len = sizeof("pg_terminate_backend") - 1;
	} else {
		return PGSQL_QUERY_SELECT;
	}
	// PostgreSQL takes a comment for whitespace, so "pg_cancel_backend/*x*/(1)" is a call too.
	// Nothing after the name, or a comment the text ends inside (a cut prefix), counts like
	// the end of the text.
	p = pgsql_stmt_skip_lead(p + len, NULL);
	return (p == NULL || *p == '(') ? cmd : PGSQL_QUERY_SELECT;
}

static enum PGSQL_QUERY_command legacy_command_type(const char* text);

/**
 * @brief Where the first keyword of @p text starts: past whitespace of any kind, comments,
 * '(' and ';'. NULL when there is no keyword.
 */
static const char* first_keyword(const char* text) {
	const char* p = pgsql_stmt_skip_lead(text, NULL);
	while (p != NULL && (*p == '(' || *p == ';')) {
		p = pgsql_stmt_skip_lead(p + 1, NULL);
	}
	return p;
}

/**
 * @brief Refines a SELECT or UNKNOWN reported by ParserSQL with the legacy classification (#6422).
 *
 * ParserSQL reports SELECT for "SELECT pg_cancel_backend(N)" and for data-modifying CTEs
 * ("WITH d AS (DELETE ... RETURNING *) SELECT ..."). The session must still intercept
 * cancel/terminate, and a CTE must not be treated as a read. ParserSQL reports UNKNOWN when
 * it cannot parse the text, as with "SELECT pg_terminate_backend(1234" from the 32-byte
 * query prefix used without digests.
 *
 * Leading whitespace of any kind, comments (kept in the digest by
 * pgsql-query_digests_keep_comment, always present in a raw query prefix), '(' and ';' are
 * skipped first, in place, so that the text is not copied. When the first keyword is SELECT
 * the result is promoted to CANCEL_BACKEND / TERMINATE_BACKEND if it is one of the
 * intercepted calls, and is a SELECT otherwise: the digest tokenizer turns PostgreSQL
 * arguments into '?' placeholders, which ParserSQL cannot parse, so its UNKNOWN must not
 * demote a plain SELECT. Any other text reported as SELECT gets the legacy classification,
 * which is what tells a CTE apart.
 *
 * @param ret Classification from ParserSQL: PGSQL_QUERY_SELECT or PGSQL_QUERY_UNKNOWN.
 * @param text Digest text or query prefix. Must not be NULL.
 */
static enum PGSQL_QUERY_command parser_refine_command_type(enum PGSQL_QUERY_command ret, const char* text) {
	const char* p = first_keyword(text);
	if (p == NULL) return ret;
	if (pgsql_stmt_first_keyword_is(p, "SELECT") == false) {
		return ret == PGSQL_QUERY_SELECT ? legacy_command_type(p) : ret;
	}
	p = pgsql_stmt_skip_lead(p + sizeof("SELECT") - 1, NULL);
	if (p == NULL) return PGSQL_QUERY_SELECT;
	const enum PGSQL_QUERY_command target = select_target_command_type(p);
	// A SELECT the digest parser could not classify (e.g. the tokenizer turned its
	// arguments into '?', which is not PostgreSQL syntax) is still a SELECT once the
	// first keyword says so. Only the two intercepted calls are promoted.
	return target != PGSQL_QUERY_SELECT ? target : PGSQL_QUERY_SELECT;
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

	if (pgsql_thread___query_processor_parser == 1) {
#ifndef PROXYSQL31
		if (qp->parsersql_command_type >= 0) {
			ret = static_cast<PGSQL_QUERY_command>(qp->parsersql_command_type);
		} else
		{
			// Prefix-only callers have no digest parse to reuse.
			if (text) {
				ret = parsersql_command_type_pgsql(text, strlen(text)); // NOSONAR
			}
		}
		if (text && (ret == PGSQL_QUERY_SELECT || ret == PGSQL_QUERY_UNKNOWN)) {
			ret = parser_refine_command_type(ret, text);
		}
#else
		// ParserSQL is asked only where its answer can differ: a SELECT is decided by
		// parser_refine_command_type(), and the legacy classifier names the rest the same way except
		// CREATE/ALTER/DROP (no subtypes in ParserSQL) and ROLLBACK (ROLLBACK TO SAVEPOINT).
		// pgsql_parser_command_type_unit-t fails if a ParserSQL change breaks that.
		if (text) {
			ret = parser_refine_command_type(PGSQL_QUERY_UNKNOWN, text);
			if (ret == PGSQL_QUERY_UNKNOWN) {
				const char* p = first_keyword(text);
				if (pgsql_stmt_first_keyword_is(p, "CREATE") == false && pgsql_stmt_first_keyword_is(p, "ALTER") == false &&
					pgsql_stmt_first_keyword_is(p, "DROP") == false && pgsql_stmt_first_keyword_is(p, "ROLLBACK") == false) {
					ret = legacy_command_type(text);
				}
			}
			if (ret == PGSQL_QUERY_UNKNOWN) {
				ret = parsersql_command_type_pgsql(text, strlen(text)); // NOSONAR
				if (ret == PGSQL_QUERY_SELECT || ret == PGSQL_QUERY_UNKNOWN) {
					ret = parser_refine_command_type(ret, text);
				}
			}
		}
#endif
		// ParserSQL cannot parse the tokenizer digest when it holds '?' placeholders or
		// statements outside its grammar. Fall back to the legacy classifier, as MySQL
		// does, so the command counters keep a meaningful value (#6454).
		if (ret == PGSQL_QUERY_UNKNOWN) {
			ret = legacy_command_type(text);
		}
	} else {
		ret = legacy_command_type(text);
	}

	// query_prefix is only set when digests are disabled; it is owned here in both modes
	if (qp->query_prefix) {
		free(qp->query_prefix);
		qp->query_prefix = NULL;
	}
	return ret;
}

// A legacy classifier token borrows the digest/prefix storage. SQL whitespace,
// comments and semicolons separate command keywords, including in raw prefixes.
struct PgSQL_Command_Token {
	const char* data = NULL;
	size_t length = 0;

	template<size_t N>
	bool is(const char (&keyword)[N]) const {
		return length == N - 1 && strncasecmp(data, keyword, N - 1) == 0;
	}

	template<size_t N>
	bool starts_keyword(const char (&keyword)[N]) const {
		if (length < N - 1 || strncasecmp(data, keyword, N - 1) != 0) return false;
		if (length == N - 1) return true;
		const unsigned char c = (unsigned char)data[N - 1];
		return !(isalnum(c) || c == '_' || c == '$');
	}

	void remove_prefix(size_t n) { data += n; length -= n; }
};

class PgSQL_Command_Cursor {
	const char* next;
public:
	explicit PgSQL_Command_Cursor(const char* text) : next(text) {}
	PgSQL_Command_Token take(bool split_comments = true) {
		next = pgsql_stmt_skip_lead(next, NULL);
		while (next != NULL && *next == ';') next = pgsql_stmt_skip_lead(next + 1, NULL);
		if (next == NULL) return {};
		const char* start = next;
		while (*next != '\0' && !isspace((unsigned char)*next) && *next != ';') {
			if (split_comments && ((next[0] == '/' && next[1] == '*') ||
				(next[0] == '-' && next[1] == '-'))) break;
			++next;
		}
		return {start, (size_t)(next - start)};
	}
};

// The token ends at a delimiter in the original text, not necessarily at NUL.
// Keep the old SELECT refinement semantics without reading beyond that end,
// including comments cut short by a token/prefix boundary and nested comments.
static enum PGSQL_QUERY_command select_target_command_type(PgSQL_Command_Token token) {
	enum PGSQL_QUERY_command cmd;
	if (token.starts_keyword("pg_cancel_backend")) {
		cmd = PGSQL_QUERY_CANCEL_BACKEND;
		token.remove_prefix(sizeof("pg_cancel_backend") - 1);
	} else if (token.starts_keyword("pg_terminate_backend")) {
		cmd = PGSQL_QUERY_TERMINATE_BACKEND;
		token.remove_prefix(sizeof("pg_terminate_backend") - 1);
	} else {
		return PGSQL_QUERY_SELECT;
	}
	for (;;) {
		while (token.length && isspace((unsigned char)token.data[0])) token.remove_prefix(1);
		if (token.length >= 2 && token.data[0] == '/' && token.data[1] == '*') {
			size_t depth = 1;
			token.remove_prefix(2);
			while (depth && token.length) {
				if (token.length >= 2 && token.data[0] == '/' && token.data[1] == '*') {
					++depth;
					token.remove_prefix(2);
				} else if (token.length >= 2 && token.data[0] == '*' && token.data[1] == '/') {
					--depth;
					token.remove_prefix(2);
				} else {
					token.remove_prefix(1);
				}
			}
			if (depth) return cmd;
		} else if (token.length >= 2 && token.data[0] == '-' && token.data[1] == '-') {
			while (token.length && token.data[0] != '\n') token.remove_prefix(1);
		} else {
			return (!token.length || token.data[0] == '(') ? cmd : PGSQL_QUERY_SELECT;
		}
	}
}

/**
 * @brief Read-only token classification used when pgsql-query_processor_parser=0.
 *
 * @param text Digest text, or the query prefix when digests are disabled. May be NULL.
 */
static enum PGSQL_QUERY_command legacy_command_type(const char* text) {
	enum PGSQL_QUERY_command ret = PGSQL_QUERY_UNKNOWN;
	char c1;

	PgSQL_Command_Cursor cursor(text);
	PgSQL_Command_Token token;
__get_token:
	token = cursor.take();
	if (token.data == NULL) {
		goto __exit__query_parser_command_type;
	}
__remove_parenthesis:
	if (token.data[0] == '(') {
		if (token.length > 1) {
			token.remove_prefix(1);
			goto __remove_parenthesis;
		}
		else {
			goto __get_token;
		}
	}
	c1 = token.data[0];
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%.*s Prefix:%c\n", (int)std::min(token.length, (size_t)INT_MAX), token.data, c1);
	switch (c1) {
	case 'a':
	case 'A':
		if (token.is("ALTER")) {
			token = cursor.take();
			if (token.data == NULL) break;
			if (token.is("TABLE")) ret = PGSQL_QUERY_ALTER_TABLE;
			else if (token.is("INDEX")) ret = PGSQL_QUERY_ALTER_INDEX;
			else if (token.is("VIEW")) ret = PGSQL_QUERY_ALTER_VIEW;
			else if (token.is("MATERIALIZED")) {
				token = cursor.take();
				if (token.data != NULL && token.is("VIEW")) ret = PGSQL_QUERY_ALTER_MATERIALIZED_VIEW;
			}
			else if (token.is("SEQUENCE")) ret = PGSQL_QUERY_ALTER_SEQUENCE;
			else if (token.is("SCHEMA")) ret = PGSQL_QUERY_ALTER_SCHEMA;
			else if (token.is("FUNCTION")) ret = PGSQL_QUERY_ALTER_FUNCTION;
			else if (token.is("PROCEDURE")) ret = PGSQL_QUERY_ALTER_PROCEDURE;
			else if (token.is("AGGREGATE")) ret = PGSQL_QUERY_ALTER_AGGREGATE;
			else if (token.is("OPERATOR")) ret = PGSQL_QUERY_ALTER_OPERATOR;
			else if (token.is("TYPE")) ret = PGSQL_QUERY_ALTER_TYPE;
			else if (token.is("DOMAIN")) ret = PGSQL_QUERY_ALTER_DOMAIN;
			else if (token.is("TRIGGER")) ret = PGSQL_QUERY_ALTER_TRIGGER;
			else if (token.is("RULE")) ret = PGSQL_QUERY_ALTER_RULE;
			else if (token.is("EXTENSION")) ret = PGSQL_QUERY_ALTER_EXTENSION;
			else if (token.is("POLICY")) ret = PGSQL_QUERY_ALTER_POLICY;
			else if (token.is("ROLE")) ret = PGSQL_QUERY_ALTER_ROLE;
			else if (token.is("USER")) ret = PGSQL_QUERY_ALTER_USER;
			else if (token.is("DATABASE")) ret = PGSQL_QUERY_ALTER_DATABASE;
			else if (token.is("COLLATION")) ret = PGSQL_QUERY_ALTER_COLLATION;
			else if (token.is("TEXT")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("SEARCH")) {
						token = cursor.take();
						if (token.data != NULL) {
							if (token.is("CONFIGURATION")) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_CONFIGURATION;
							else if (token.is("DICTIONARY")) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_DICTIONARY;
							else if (token.is("TEMPLATE")) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_TEMPLATE;
							else if (token.is("PARSER")) ret = PGSQL_QUERY_ALTER_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (token.is("FOREIGN")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TABLE")) ret = PGSQL_QUERY_ALTER_FOREIGN_TABLE;
			}
			else if (token.is("SERVER")) ret = PGSQL_QUERY_ALTER_SERVER;
			else if (token.is("USER")) {
				token = cursor.take();
				if (token.data != NULL && token.is("MAPPING")) ret = PGSQL_QUERY_ALTER_USER_MAPPING;
			}
			else if (token.is("PUBLICATION")) ret = PGSQL_QUERY_ALTER_PUBLICATION;
			else if (token.is("SUBSCRIPTION")) ret = PGSQL_QUERY_ALTER_SUBSCRIPTION;
			else if (token.is("ACCESS")) {
				token = cursor.take();
				if (token.data != NULL && token.is("METHOD")) ret = PGSQL_QUERY_ALTER_ACCESS_METHOD;
			}
			else if (token.is("EVENT")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TRIGGER")) ret = PGSQL_QUERY_ALTER_EVENT_TRIGGER;
			}
			else if (token.is("TRANSFORM")) ret = PGSQL_QUERY_ALTER_TRANSFORM;
			else if (token.is("CAST")) ret = PGSQL_QUERY_ALTER_CAST;
			else if (token.is("OPERATOR")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("CLASS")) ret = PGSQL_QUERY_ALTER_OPERATOR_CLASS;
					else if (token.is("FAMILY")) ret = PGSQL_QUERY_ALTER_OPERATOR_FAMILY;
				}
			}
			else if (token.is("TABLESPACE")) ret = PGSQL_QUERY_ALTER_TABLESPACE;
			break;
		}
		if (token.is("ANALYZE")) {
			ret = PGSQL_QUERY_ANALYZE;
			break;
		}
		if (token.is("ABORT")) {
			ret = PGSQL_QUERY_ROLLBACK;
			break;
		}
		break;
	case 'b':
	case 'B':
		if (token.is("BEGIN")) {
			ret = PGSQL_QUERY_BEGIN;
			break;
		}
		break;
	case 'c':
	case 'C':
		if (token.is("CALL")) {
			ret = PGSQL_QUERY_CALL;
			break;
		}
		if (token.is("CHECKPOINT")) {
			ret = PGSQL_QUERY_CHECKPOINT;
			break;
		}
		if (token.is("CLOSE")) {
			token = cursor.take();
			if (token.data != NULL && token.is("CURSOR")) ret = PGSQL_QUERY_CLOSE_CURSOR;
			break;
		}
		if (token.is("CLUSTER")) {
			ret = PGSQL_QUERY_CLUSTER; 
			break;
		}
		if (token.is("COMMENT")) {
			ret = PGSQL_QUERY_COMMENT;
			break;
		}
		if (token.is("COMMIT")) {
			ret = PGSQL_QUERY_COMMIT;
			break;
		}
		if (token.is("COPY")) {
			ret = PGSQL_QUERY_COPY;
			break;
		}
		if (token.is("CREATE")) {
			token = cursor.take();
			if (token.data == NULL) break;
			if (token.is("TABLE")) ret = PGSQL_QUERY_CREATE_TABLE;
			else if (token.is("INDEX")) ret = PGSQL_QUERY_CREATE_INDEX;
			else if (token.is("VIEW")) ret = PGSQL_QUERY_CREATE_VIEW;
			else if (token.is("MATERIALIZED")) {
				token = cursor.take();
				if (token.data != NULL && token.is("VIEW")) ret = PGSQL_QUERY_CREATE_MATERIALIZED_VIEW;
			}
			else if (token.is("SEQUENCE")) ret = PGSQL_QUERY_CREATE_SEQUENCE;
			else if (token.is("SCHEMA")) ret = PGSQL_QUERY_CREATE_SCHEMA;
			else if (token.is("FUNCTION")) ret = PGSQL_QUERY_CREATE_FUNCTION;
			else if (token.is("PROCEDURE")) ret = PGSQL_QUERY_CREATE_PROCEDURE;
			else if (token.is("AGGREGATE")) ret = PGSQL_QUERY_CREATE_AGGREGATE;
			else if (token.is("OPERATOR")) ret = PGSQL_QUERY_CREATE_OPERATOR;
			else if (token.is("TYPE")) ret = PGSQL_QUERY_CREATE_TYPE;
			else if (token.is("DOMAIN")) ret = PGSQL_QUERY_CREATE_DOMAIN;
			else if (token.is("TRIGGER")) ret = PGSQL_QUERY_CREATE_TRIGGER;
			else if (token.is("RULE")) ret = PGSQL_QUERY_CREATE_RULE;
			else if (token.is("EXTENSION")) ret = PGSQL_QUERY_CREATE_EXTENSION;
			else if (token.is("POLICY")) ret = PGSQL_QUERY_CREATE_POLICY;
			else if (token.is("ROLE")) ret = PGSQL_QUERY_CREATE_ROLE;
			else if (token.is("USER")) ret = PGSQL_QUERY_CREATE_USER;
			else if (token.is("DATABASE")) ret = PGSQL_QUERY_CREATE_DATABASE;
			else if (token.is("COLLATION")) ret = PGSQL_QUERY_CREATE_COLLATION;
			else if (token.is("TEXT")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("SEARCH")) {
						token = cursor.take();
						if (token.data != NULL) {
							if (token.is("CONFIGURATION")) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_CONFIGURATION;
							else if (token.is("DICTIONARY")) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_DICTIONARY;
							else if (token.is("TEMPLATE")) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_TEMPLATE;
							else if (token.is("PARSER")) ret = PGSQL_QUERY_CREATE_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (token.is("FOREIGN")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TABLE")) ret = PGSQL_QUERY_CREATE_FOREIGN_TABLE;
			}
			else if (token.is("SERVER")) ret = PGSQL_QUERY_CREATE_SERVER;
			else if (token.is("USER")) {
				token = cursor.take();
				if (token.data != NULL && token.is("MAPPING")) ret = PGSQL_QUERY_CREATE_USER_MAPPING;
			}
			else if (token.is("PUBLICATION")) ret = PGSQL_QUERY_CREATE_PUBLICATION;
			else if (token.is("SUBSCRIPTION")) ret = PGSQL_QUERY_CREATE_SUBSCRIPTION;
			else if (token.is("ACCESS")) {
				token = cursor.take();
				if (token.data != NULL && token.is("METHOD")) ret = PGSQL_QUERY_CREATE_ACCESS_METHOD;
			}
			else if (token.is("EVENT")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TRIGGER")) ret = PGSQL_QUERY_CREATE_EVENT_TRIGGER;
			}
			else if (token.is("TRANSFORM")) ret = PGSQL_QUERY_CREATE_TRANSFORM;
			else if (token.is("CAST")) ret = PGSQL_QUERY_CREATE_CAST;
			else if (token.is("OPERATOR")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("CLASS")) ret = PGSQL_QUERY_CREATE_OPERATOR_CLASS;
					else if (token.is("FAMILY")) ret = PGSQL_QUERY_CREATE_OPERATOR_FAMILY;
				}
			}
			else if (token.is("TABLESPACE")) ret = PGSQL_QUERY_CREATE_TABLESPACE;
			break;
		}
		break;
	case 'd':
	case 'D':
		if (token.is("DEALLOCATE")) {
			ret = PGSQL_QUERY_DEALLOCATE;
			break;
		}
		if (token.is("DECLARE")) {
			token = cursor.take();
			if (token.data != NULL && token.is("CURSOR")) ret = PGSQL_QUERY_DECLARE_CURSOR;
			break;
		}
		if (token.is("DELETE")) {
			ret = PGSQL_QUERY_DELETE;
			break;
		}
		if (token.is("DISCARD")) {
			ret = PGSQL_QUERY_DISCARD;
			break;
		}
		if (token.is("DROP")) {
			token = cursor.take();
			if (token.data == NULL) break;
			if (token.is("TABLE")) ret = PGSQL_QUERY_DROP_TABLE;
			else if (token.is("INDEX")) ret = PGSQL_QUERY_DROP_INDEX;
			else if (token.is("VIEW")) ret = PGSQL_QUERY_DROP_VIEW;
			else if (token.is("MATERIALIZED")) {
				token = cursor.take();
				if (token.data != NULL && token.is("VIEW")) ret = PGSQL_QUERY_DROP_MATERIALIZED_VIEW;
			}
			else if (token.is("SEQUENCE")) ret = PGSQL_QUERY_DROP_SEQUENCE;
			else if (token.is("SCHEMA")) ret = PGSQL_QUERY_DROP_SCHEMA;
			else if (token.is("FUNCTION")) ret = PGSQL_QUERY_DROP_FUNCTION;
			else if (token.is("PROCEDURE")) ret = PGSQL_QUERY_DROP_PROCEDURE;
			else if (token.is("AGGREGATE")) ret = PGSQL_QUERY_DROP_AGGREGATE;
			else if (token.is("OPERATOR")) ret = PGSQL_QUERY_DROP_OPERATOR;
			else if (token.is("TYPE")) ret = PGSQL_QUERY_DROP_TYPE;
			else if (token.is("DOMAIN")) ret = PGSQL_QUERY_DROP_DOMAIN;
			else if (token.is("TRIGGER")) ret = PGSQL_QUERY_DROP_TRIGGER;
			else if (token.is("RULE")) ret = PGSQL_QUERY_DROP_RULE;
			else if (token.is("EXTENSION")) ret = PGSQL_QUERY_DROP_EXTENSION;
			else if (token.is("POLICY")) ret = PGSQL_QUERY_DROP_POLICY;
			else if (token.is("ROLE")) ret = PGSQL_QUERY_DROP_ROLE;
			else if (token.is("USER")) ret = PGSQL_QUERY_DROP_USER;
			else if (token.is("DATABASE")) ret = PGSQL_QUERY_DROP_DATABASE;
			else if (token.is("COLLATION")) ret = PGSQL_QUERY_DROP_COLLATION;
			else if (token.is("TEXT")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("SEARCH")) {
						token = cursor.take();
						if (token.data != NULL) {
							if (token.is("CONFIGURATION")) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_CONFIGURATION;
							else if (token.is("DICTIONARY")) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_DICTIONARY;
							else if (token.is("TEMPLATE")) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_TEMPLATE;
							else if (token.is("PARSER")) ret = PGSQL_QUERY_DROP_TEXT_SEARCH_PARSER;
						}
					}
				}
			}
			else if (token.is("FOREIGN")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TABLE")) ret = PGSQL_QUERY_DROP_FOREIGN_TABLE;
			}
			else if (token.is("SERVER")) ret = PGSQL_QUERY_DROP_SERVER;
			else if (token.is("USER")) {
				token = cursor.take();
				if (token.data != NULL && token.is("MAPPING")) ret = PGSQL_QUERY_DROP_USER_MAPPING;
			}
			else if (token.is("PUBLICATION")) ret = PGSQL_QUERY_DROP_PUBLICATION;
			else if (token.is("SUBSCRIPTION")) ret = PGSQL_QUERY_DROP_SUBSCRIPTION;
			else if (token.is("ACCESS")) {
				token = cursor.take();
				if (token.data != NULL && token.is("METHOD")) ret = PGSQL_QUERY_DROP_ACCESS_METHOD;
			}
			else if (token.is("EVENT")) {
				token = cursor.take();
				if (token.data != NULL && token.is("TRIGGER")) ret = PGSQL_QUERY_DROP_EVENT_TRIGGER;
			}
			else if (token.is("TRANSFORM")) ret = PGSQL_QUERY_DROP_TRANSFORM;
			else if (token.is("CAST")) ret = PGSQL_QUERY_DROP_CAST;
			else if (token.is("OPERATOR")) {
				token = cursor.take();
				if (token.data != NULL) {
					if (token.is("CLASS")) ret = PGSQL_QUERY_DROP_OPERATOR_CLASS;
					else if (token.is("FAMILY")) ret = PGSQL_QUERY_DROP_OPERATOR_FAMILY;
				}
			}
			else if (token.is("TABLESPACE")) ret = PGSQL_QUERY_DROP_TABLESPACE;
			break;
		}
		break;
	case 'e':
	case 'E':
		if (token.is("EXECUTE")) {
			ret = PGSQL_QUERY_EXECUTE;
			break;
		}
		if (token.is("EXPLAIN")) {
			ret = PGSQL_QUERY_EXPLAIN;
			break;
		}
		break;
	case 'f':
	case 'F':
		if (token.is("FETCH")) {
			ret = PGSQL_QUERY_FETCH;
			break;
		}
		break;
	case 'g':
	case 'G':
		if (token.is("GRANT")) {
			ret = PGSQL_QUERY_GRANT;
			break;
		}
		break;
	case 'i':
	case 'I':
		if (token.is("INSERT")) {
			ret = PGSQL_QUERY_INSERT;
			break;
		}
		if (token.is("IMPORT")) {
			token = cursor.take();
			if (token.data != NULL && token.is("FOREIGN")) {
				token = cursor.take();
				if (token.data != NULL && token.is("SCHEMA")) ret = PGSQL_QUERY_IMPORT_FOREIGN_SCHEMA;
			}
			break;
		}
		break;
	case 'l':
	case 'L':
		if (token.is("LISTEN")) {
			ret = PGSQL_QUERY_LISTEN;
			break;
		}
		if (token.is("LOAD")) {
			ret = PGSQL_QUERY_UNKNOWN; // Not in the enum, but exists in PostgreSQL
			break;
		}
		if (token.is("LOCK")) {
			ret = PGSQL_QUERY_LOCK;
			break;
		}
		break;
	case 'm':
	case 'M':
		if (token.is("MERGE")) {
			ret = PGSQL_QUERY_MERGE;
			break;
		}
		if (token.is("MOVE")) {
			ret = PGSQL_QUERY_MOVE;
			break;
		}
		break;
	case 'n':
	case 'N':
		if (token.is("NOTIFY")) {
			ret = PGSQL_QUERY_NOTIFY;
			break;
		}
		break;
	case 'p':
	case 'P':
		if (token.is("PREPARE")) {
			ret = PGSQL_QUERY_PREPARE;
			break;
		}
		break;
	case 'r':
	case 'R':
		if (token.is("REFRESH")) {
			token = cursor.take();
			if (token.data != NULL && token.is("MATERIALIZED")) {
				token = cursor.take();
				if (token.data != NULL && token.is("VIEW")) ret = PGSQL_QUERY_REFRESH_MATERIALIZED_VIEW;
			}
			break;
		}
		if (token.is("REINDEX")) {
			ret = PGSQL_QUERY_REINDEX;
			break;
		}
		if (token.is("RELEASE")) {
			token = cursor.take();
			if (token.data != NULL && token.is("SAVEPOINT")) ret = PGSQL_QUERY_RELEASE_SAVEPOINT;
			break;
		}
		if (token.is("RESET")) {
			ret = PGSQL_QUERY_RESET;
			break;
		}
		if (token.is("REVOKE")) {
			ret = PGSQL_QUERY_REVOKE;
			break;
		}
		if (token.is("ROLLBACK")) {
			token = cursor.take();
			if (token.data == NULL) {
				ret = PGSQL_QUERY_ROLLBACK;
			}
			else if (token.is("TO")) {
				token = cursor.take();
				if (token.data != NULL && token.is("SAVEPOINT")) ret = PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT;
			}
			break;
		}
		break;
	case 's':
	case 'S':
		if (token.is("SAVEPOINT")) {
			ret = PGSQL_QUERY_SAVEPOINT;
			break;
		}
		if (token.is("SELECT")) {
			// Retain inline comments for the bounded function-call refinement: a
			// suffix such as "pg_cancel_backend/**/.x" must remain a SELECT.
			token = cursor.take(false);
			if (token.data == NULL) break;
			ret = select_target_command_type(token);
			break;
		}
		if (token.is("SET")) {
			ret = PGSQL_QUERY_SET;
			break;
		}
		if (token.is("SHOW")) {
			ret = PGSQL_QUERY_SHOW;
			break;
		}
		if (token.is("START")) {
			token = cursor.take();
			if (token.data != NULL && token.is("TRANSACTION")) ret = PGSQL_QUERY_BEGIN;
			break;
		}
		if (token.is("START_REPLICATION")) {
			ret = PGSQL_QUERY_START_REPLICATION;
			break;
		}
		break;
	case 't':
	case 'T':
		if (token.is("TRUNCATE")) {
			ret = PGSQL_QUERY_TRUNCATE;
			break;
		}
		break;
	case 'u':
	case 'U':
		if (token.is("UNLISTEN")) {
			ret = PGSQL_QUERY_UNLISTEN;
			break;
		}
		if (token.is("UPDATE")) {
			ret = PGSQL_QUERY_UPDATE;
			break;
		}
		break;
	case 'v':
	case 'V':
		if (token.is("VACUUM")) {
			ret = PGSQL_QUERY_VACUUM;
			break;
		}
		break;
	default:
		break;
	}

__exit__query_parser_command_type:
	return ret;
}
