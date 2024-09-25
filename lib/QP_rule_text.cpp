
#include <stdlib.h>
#include "proxysql_macros.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
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

QP_rule_text::QP_rule_text() :  pta(NULL), num_fields(0) {

}
QP_rule_text::~QP_rule_text() {
	for (int i = 0; i < num_fields; i++) {
		free_null(pta[i]);
	}
	free(pta);
};
