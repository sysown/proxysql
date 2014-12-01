#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"



#define QUERY_PROCESSOR_VERSION "0.1.728"



struct __RE2_objects_t {
	re2::RE2::Options *opt;
	RE2 *re;
};

typedef struct __RE2_objects_t re2_t;

static bool rules_sort_comp_function (QP_rule_t * a, QP_rule_t * b) { return (a->rule_id < b->rule_id); }

static re2_t * compile_query_rule(QP_rule_t *qr) {
	re2_t *r=(re2_t *)malloc(sizeof(re2_t));
	r->opt=new re2::RE2::Options(RE2::Quiet);
	r->opt->set_case_sensitive(false);
	r->re=new RE2(qr->match_pattern, *r->opt);
	return r;
};

static void __delete_query_rule(QP_rule_t *qr) {
	if (qr->username)
		free(qr->username);
	if (qr->schemaname)
		free(qr->schemaname);
	if (qr->match_pattern)
		free(qr->match_pattern);
	if (qr->replace_pattern)
		free(qr->replace_pattern);
	if (qr->regex_engine) {
		re2_t *r=(re2_t *)qr->regex_engine;
		delete r->opt;
		delete r->re;
		free(qr->regex_engine);
	}
	free(qr);
};

static void __reset_rules(std::vector<QP_rule_t *> * qrs) {
	if (qrs==NULL) return;
	QP_rule_t *qr;
	for (std::vector<QP_rule_t *>::iterator it=qrs->begin(); it!=qrs->end(); ++it) {
		qr=*it;
		__delete_query_rule(qr);
	}
	qrs->clear();
}


__thread unsigned int _thr_SQP_version;
__thread std::vector<QP_rule_t *> * _thr_SQP_rules;

class Standard_Query_Processor: public Query_Processor {

private:
rwlock_t rwlock;
std::vector<QP_rule_t *> rules;

volatile unsigned int version;
protected:

public:
Standard_Query_Processor() {
	spinlock_rwlock_init(&rwlock);
	version=0;
};

virtual ~Standard_Query_Processor() {
	__reset_rules(&rules);
};

virtual void init_thread() {
	_thr_SQP_version=0;
	_thr_SQP_rules=new std::vector<QP_rule_t *>;
};


virtual void end_thread() {
	__reset_rules(_thr_SQP_rules);
	delete _thr_SQP_rules;
};

virtual void print_version() {
	fprintf(stderr,"Standard Query Processor rev. %s -- %s -- %s\n", QUERY_PROCESSOR_VERSION, __FILE__, __TIMESTAMP__);
};

virtual void wrlock() {
	spin_wrlock(&rwlock);
};

virtual void wrunlock() {
	spin_wrunlock(&rwlock);
};



virtual QP_rule_t * new_query_rule(int rule_id, bool active, char *username, char *schemaname, int flagIN, char *match_pattern, bool negate_match_pattern, int flagOUT, char *replace_pattern, int destination_hostgroup, int cache_ttl, bool apply) {
	QP_rule_t * newQR=(QP_rule_t *)malloc(sizeof(QP_rule_t));
	newQR->rule_id=rule_id;
	newQR->active=active;
	newQR->username=(username ? strdup(username) : NULL);
	newQR->schemaname=(schemaname ? strdup(schemaname) : NULL);
	newQR->flagIN=flagIN;
	newQR->match_pattern=(match_pattern ? strdup(match_pattern) : NULL);
	newQR->negate_match_pattern=negate_match_pattern;
	newQR->flagOUT=flagOUT;
	newQR->replace_pattern=(replace_pattern ? strdup(replace_pattern) : NULL);
	newQR->destination_hostgroup=destination_hostgroup;
	newQR->cache_ttl=cache_ttl;
	newQR->apply=apply;
	newQR->regex_engine=NULL;
	return newQR;
};


virtual void delete_query_rule(QP_rule_t *qr) {
	__delete_query_rule(qr);
/*
	if (qr->username)
		free(qr->username);
	if (qr->schemaname)
		free(qr->schemaname);
	if (qr->match_pattern)
		free(qr->match_pattern);
	if (qr->replace_pattern)
		free(qr->replace_pattern);
	free(qr);
*/
};

virtual void reset_all(bool lock) {
	if (lock) spin_wrlock(&rwlock);
/*
	QP_rule_t *qr;
	for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
		qr=*it;
		__delete_query_rule(qr);
	}
	rules.clear();
*/
	__reset_rules(&rules);
	if (lock) spin_wrunlock(&rwlock);
};

virtual bool insert(QP_rule_t *qr, bool lock) {
	bool ret=true;
	if (lock) spin_wrlock(&rwlock);
	rules.push_back(qr);
	if (lock) spin_wrunlock(&rwlock);
	return ret;
};


virtual void sort(bool lock) {
	if (lock) spin_wrlock(&rwlock);
	std::sort (rules.begin(), rules.end(), rules_sort_comp_function);
	if (lock) spin_wrunlock(&rwlock);
};

virtual void commit() {
	spin_wrlock(&rwlock);
	__sync_add_and_fetch(&version,1);
	spin_wrunlock(&rwlock);
};


virtual QP_out_t * process_mysql_query(MySQL_Session *sess, void *ptr, unsigned int size, bool delete_original) {
	QP_out_t *ret=NULL;
	unsigned int len=size-sizeof(mysql_hdr)-1;
	char *query=(char *)l_alloc(len+1);
	memcpy(query,(char *)ptr+sizeof(mysql_hdr)+1,len);
	query[len]=0;
	if (__sync_add_and_fetch(&version,0) > _thr_SQP_version) {
		// update local rules;
		spin_rdlock(&rwlock);
		_thr_SQP_version=__sync_add_and_fetch(&version,0);
		__reset_rules(_thr_SQP_rules);
		spin_rdunlock(&rwlock);
		QP_rule_t *qr1;
		QP_rule_t *qr2;
		for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
			qr1=*it;
			if (qr1->active) {
				qr2=new_query_rule(qr1->rule_id, qr1->active, qr1->username, qr1->schemaname, qr1->flagIN, qr1->match_pattern, qr1->negate_match_pattern, qr1->flagOUT, qr1->replace_pattern, qr1->destination_hostgroup, qr1->cache_ttl, qr1->apply);
				if (qr2->match_pattern) {
					qr2->regex_engine=(void *)compile_query_rule(qr2);
				}
				_thr_SQP_rules->push_back(qr2);
			}
		}
	}
	QP_rule_t *qr;
	re2_t *re2p;
	for (std::vector<QP_rule_t *>::iterator it=_thr_SQP_rules->begin(); it!=_thr_SQP_rules->end(); ++it) {
		qr=*it;
		re2p=(re2_t *)qr->regex_engine;
		if (qr->match_pattern && RE2::PartialMatch(query,*re2p->re)==true) {
			//ret=(QP_out_t *)malloc(sizeof(QP_out_t));
			ret=(QP_out_t *)l_alloc(sizeof(QP_out_t));
			ret->cache_ttl=qr->cache_ttl;
			goto __exit_process_mysql_query;
		}
	}
	
__exit_process_mysql_query:
	l_free(len+1,query);
	return ret;
};

virtual void delete_QP_out(QP_out_t *o) {
	l_free(sizeof(QP_out_t),o);
};

};

extern "C" Query_Processor * create_Query_Processor_func() {
    return new Standard_Query_Processor();
}

extern "C" void destroy_Query_Processor(Query_Processor * qp) {
    delete qp;
}
