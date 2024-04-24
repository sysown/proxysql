/*
#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
*/
#include "query_processor.h"
#include <stdlib.h>
#include "proxysql_macros.h"

#include "QP_rule_text.h"


QP_rule_text_hitsonly::QP_rule_text_hitsonly(QP_rule_t *QPr) {
	pta=NULL;
	pta=(char **)malloc(sizeof(char *)*2);
	itostr(pta[0], (long long)QPr->rule_id);
	itostr(pta[1], (long long)QPr->hits);
}

QP_rule_text_hitsonly::~QP_rule_text_hitsonly() {
	for(int i=0; i<2; i++) {
		free_null(pta[i]);
	}
	free(pta);
}

QP_rule_text::QP_rule_text(QP_rule_t *QPr) {
	num_fields=36; // this count the number of fields
	pta=NULL;
	pta=(char **)malloc(sizeof(char *)*num_fields);
	itostr(pta[0], (long long)QPr->rule_id);
	itostr(pta[1], (long long)QPr->active);
	pta[2]=strdup_null(QPr->username);
	pta[3]=strdup_null(QPr->schemaname);
	itostr(pta[4], (long long)QPr->flagIN);

	pta[5]=strdup_null(QPr->client_addr);
	pta[6]=strdup_null(QPr->proxy_addr);
	itostr(pta[7], (long long)QPr->proxy_port);

	char buf[20];
	if (QPr->digest) {
		sprintf(buf,"0x%016llX", (long long unsigned int)QPr->digest);
		pta[8]=strdup(buf);
	} else {
		pta[8]=NULL;
	}

	pta[9]=strdup_null(QPr->match_digest);
	pta[10]=strdup_null(QPr->match_pattern);
	itostr(pta[11], (long long)QPr->negate_match_pattern);
	std::string re_mod;
	re_mod="";
	if ((QPr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
		if ((QPr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
			if (re_mod.length()) {
				re_mod = re_mod + ",";
			}
		re_mod = re_mod + "GLOBAL";
	}
	pta[12]=strdup_null((char *)re_mod.c_str()); // re_modifiers
	itostr(pta[13], (long long)QPr->flagOUT);
	pta[14]=strdup_null(QPr->replace_pattern);
	itostr(pta[15], (long long)QPr->destination_hostgroup);
	itostr(pta[16], (long long)QPr->cache_ttl);
	itostr(pta[17], (long long)QPr->cache_empty_result);
	itostr(pta[18], (long long)QPr->cache_timeout);
	itostr(pta[19], (long long)QPr->reconnect);
	itostr(pta[20], (long long)QPr->timeout);
	itostr(pta[21], (long long)QPr->retries);
	itostr(pta[22], (long long)QPr->delay);
	itostr(pta[23], (long long)QPr->next_query_flagIN);
	itostr(pta[24], (long long)QPr->mirror_flagOUT);
	itostr(pta[25], (long long)QPr->mirror_hostgroup);
	pta[26]=strdup_null(QPr->error_msg);
	pta[27]=strdup_null(QPr->OK_msg);
	itostr(pta[28], (long long)QPr->sticky_conn);
	itostr(pta[29], (long long)QPr->multiplex);
	itostr(pta[30], (long long)QPr->gtid_from_hostgroup);
	itostr(pta[31], (long long)QPr->log);
	itostr(pta[32], (long long)QPr->apply);
	pta[33]=strdup_null(QPr->attributes);
	pta[34]=strdup_null(QPr->comment); // issue #643
	itostr(pta[35], (long long)QPr->hits);
}

QP_rule_text::~QP_rule_text() {
	for(int i=0; i<num_fields; i++) {
		free_null(pta[i]);
	}
	free(pta);
}
