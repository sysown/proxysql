#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"
#include "../deps/libinjection/libinjection.h"
#include "../deps/libinjection/libinjection_sqli.h"


#define QUERY_PROCESSOR_VERSION "0.1.728"


#define strdup_null(__c) ( __c ? strdup(__c) : __c )
#define char_malloc (char *)malloc
#define free_null(__c) { if(__c) { free(__c); __c=NULL; } }

#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }

class QP_rule_text_hitsonly {
	public:
	char **pta;
	QP_rule_text_hitsonly(QP_rule_t *QPr) {
		pta=NULL;
		pta=(char **)malloc(sizeof(char *)*2);
		itostr(pta[0], (long long)QPr->rule_id);
		itostr(pta[1], (long long)QPr->hits);
	}
	~QP_rule_text_hitsonly() {
		for(int i=0; i<2; i++) {
			free_null(pta[i]);
		}
		free(pta);
	}
};

class QP_rule_text {
	public:
	char **pta;
/*
	char * rule_id;
	char * active;
	char * username;
	char * schemaname;
	char * flagIN;
	char * match_pattern;
	char * negate_match_pattern;
	char * flagOUT;
	char * replace_pattern;
	char * destination_hostgroup;
	char * cache_ttl;
	char * apply;
	char * hits;
*/
	QP_rule_text(QP_rule_t *QPr) {
		pta=NULL;
		pta=(char **)malloc(sizeof(char *)*13);
		itostr(pta[0], (long long)QPr->rule_id);
		itostr(pta[1], (long long)QPr->active);
		pta[2]=strdup_null(QPr->username);
		pta[3]=strdup_null(QPr->schemaname);
		itostr(pta[4], (long long)QPr->flagIN);
		pta[5]=strdup_null(QPr->match_pattern);
		itostr(pta[6], (long long)QPr->negate_match_pattern);
		itostr(pta[7], (long long)QPr->flagOUT);
		pta[8]=strdup_null(QPr->replace_pattern);
		itostr(pta[9], (long long)QPr->destination_hostgroup);
		itostr(pta[10], (long long)QPr->cache_ttl);
		itostr(pta[11], (long long)QPr->apply);
		itostr(pta[12], (long long)QPr->hits);
/*
		itostr(rule_id, QPr->rule_id);
		itostr(active, QPr->active);
		username=strdup_null(QPr->username);
		schemaname=strdup_null(QPr->schemaname);
		itostr(flagIN, QPr->flagIN);
		match_pattern=strdup_null(QPr->match_pattern);
		itostr(negate_match_pattern, QPr->negate_match_pattern);
		itostr(flagOUT, QPr->flagOUT);
		replace_pattern=strdup_null(QPr->replace_pattern);
		itostr(destination_hostgroup, QPr->destination_hostgroup);
		itostr(cache_ttl, QPr->cache_ttl);
		itostr(apply, QPr->apply);
		itostr(hits, QPr->hits);
*/
	}
	~QP_rule_text() {
		for(int i=0; i<13; i++) {
			free_null(pta[i]);
		}
		free(pta);
/*
		free_null(rule_id);
		free_null(active);
		free_null(username);
		free_null(schemaname);
		free_null(flagIN);
		free_null(match_pattern);
		free_null(negate_match_pattern);
		free_null(flagOUT);
		free_null(replace_pattern);
  	free_null(destination_hostgroup);
		free_null(cache_ttl);
		free_null(apply);
		free_null(hits);
*/
	}
};


struct __SQP_query_parser_t {
	sfilter sf;
};

typedef struct __SQP_query_parser_t SQP_par_t;

static char *commands_counters_desc[MYSQL_COM_QUERY___NONE];



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
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Deleting rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", qr, qr->rule_id, qr->active, qr->username, qr->schemaname, qr->flagIN, (qr->negate_match_pattern ? "(!)" : "") , qr->match_pattern, qr->flagOUT, qr->replace_pattern, qr->destination_hostgroup, qr->apply);
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

// delete all the query rules in a Query Processor Table
// Note that this function is called by GloQPro with &rules (generic table)
//     and is called by each mysql thread with _thr_SQP_rules (per thread table)
static void __reset_rules(std::vector<QP_rule_t *> * qrs) {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Resetting rules in Query Processor Table %p\n", qrs);
	if (qrs==NULL) return;
	QP_rule_t *qr;
	for (std::vector<QP_rule_t *>::iterator it=qrs->begin(); it!=qrs->end(); ++it) {
		qr=*it;
		__delete_query_rule(qr);
	}
	qrs->clear();
}


class Command_Counter {
	private:
	int cmd_idx;
	int _add_idx(unsigned long long t) {
		if (t<=100) return 0;
		if (t<=500) return 1;
		if (t<=1000) return 2;
		if (t<=5000) return 3;
		if (t<=10000) return 4;
		if (t<=50000) return 5;
		if (t<=100000) return 6;
		if (t<=500000) return 7;
		if (t<=1000000) return 8;
		if (t<=5000000) return 9;
		if (t<=10000000) return 10;
		return 11;
	}
	public:
	unsigned long long total_time;
	unsigned long long counters[13];
	Command_Counter(int a) {
		total_time=0;
		cmd_idx=a;
		total_time=0;
		for (int i=0; i<13; i++) {
			counters[i]=0;
		}
	}
	unsigned long long add_time(unsigned long long t) {
		total_time+=t;
		counters[0]++;
		int i=_add_idx(t);
		counters[i+1]++;
		return total_time;
	}
	char **get_row() {
		char **pta=(char **)malloc(sizeof(char *)*15);
		pta[0]=commands_counters_desc[cmd_idx];
		itostr(pta[1],total_time);
		for (int i=0;i<13;i++) itostr(pta[i+2], counters[i]);
		return pta;
	}
	void free_row(char **pta) {
		for (int i=1;i<15;i++) free(pta[i]);
		free(pta);
	}
};

// per thread variables
__thread unsigned int _thr_SQP_version;
__thread std::vector<QP_rule_t *> * _thr_SQP_rules;
//__thread unsigned int _thr_commands_counters[MYSQL_COM_QUERY___NONE];
__thread Command_Counter * _thr_commands_counters[MYSQL_COM_QUERY___NONE];


class Standard_Query_Processor: public Query_Processor {

private:
rwlock_t rwlock;
std::vector<QP_rule_t *> rules;
//unsigned int commands_counters[MYSQL_COM_QUERY___NONE];
Command_Counter * commands_counters[MYSQL_COM_QUERY___NONE];

volatile unsigned int version;
protected:

public:
Standard_Query_Processor() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Query Processor with version=0\n");
	spinlock_rwlock_init(&rwlock);
	version=0;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) commands_counters[i]=new Command_Counter(i);

	commands_counters_desc[MYSQL_COM_QUERY_ALTER_TABLE]=(char *)"ALTER_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_ANALYZE_TABLE]=(char *)"ANALYZE_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_BEGIN]=(char *)"BEGIN";
  commands_counters_desc[MYSQL_COM_QUERY_CHANGE_MASTER]=(char *)"CHANGE_MASTER";
  commands_counters_desc[MYSQL_COM_QUERY_COMMIT]=(char *)"COMMIT";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_DATABASE]=(char *)"CREATE_DATABASE";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_INDEX]=(char *)"CREATE_INDEX";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TABLE]=(char *)"CREATE_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TEMPORARY]=(char *)"CREATE_TEMPORARY";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TRIGGER]=(char *)"CREATE_TRIGGER";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_USER]=(char *)"CREATE_USER";
  commands_counters_desc[MYSQL_COM_QUERY_DELETE]=(char *)"DELETE";
  commands_counters_desc[MYSQL_COM_QUERY_DESCRIBE]=(char *)"DESCRIBE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_DATABASE]=(char *)"DROP_DATABASE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_INDEX]=(char *)"DROP_INDEX";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_TABLE]=(char *)"DROP_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_TRIGGER]=(char *)"DROP_TRIGGER";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_USER]=(char *)"DROP_USER";
  commands_counters_desc[MYSQL_COM_QUERY_GRANT]=(char *)"GRANT";
  commands_counters_desc[MYSQL_COM_QUERY_EXPLAIN]=(char *)"EXPLAIN";
  commands_counters_desc[MYSQL_COM_QUERY_FLUSH]=(char *)"FLUSH";
  commands_counters_desc[MYSQL_COM_QUERY_INSERT]=(char *)"INSERT";
  commands_counters_desc[MYSQL_COM_QUERY_KILL]=(char *)"KILL";
  commands_counters_desc[MYSQL_COM_QUERY_LOAD]=(char *)"LOAD";
  commands_counters_desc[MYSQL_COM_QUERY_LOCK_TABLE]=(char *)"LOCK_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_OPTIMIZE]=(char *)"OPTIMIZE";
  commands_counters_desc[MYSQL_COM_QUERY_PREPARE]=(char *)"PREPARE";
  commands_counters_desc[MYSQL_COM_QUERY_PURGE]=(char *)"PURGE";
  commands_counters_desc[MYSQL_COM_QUERY_RENAME_TABLE]=(char *)"RENAME_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_RESET_MASTER]=(char *)"RESET_MASTER";
  commands_counters_desc[MYSQL_COM_QUERY_RESET_SLAVE]=(char *)"RESET_SLAVE";
  commands_counters_desc[MYSQL_COM_QUERY_REPLACE]=(char *)"REPLACE";
  commands_counters_desc[MYSQL_COM_QUERY_REVOKE]=(char *)"REVOKE";
  commands_counters_desc[MYSQL_COM_QUERY_ROLLBACK]=(char *)"ROLLBACK";
  commands_counters_desc[MYSQL_COM_QUERY_SAVEPOINT]=(char *)"SAVEPOINT";
  commands_counters_desc[MYSQL_COM_QUERY_SELECT]=(char *)"SELECT";
  commands_counters_desc[MYSQL_COM_QUERY_SELECT_FOR_UPDATE]=(char *)"SELECT_FOR_UPDATE";
  commands_counters_desc[MYSQL_COM_QUERY_SET]=(char *)"SET";
  commands_counters_desc[MYSQL_COM_QUERY_SHOW_TABLE_STATUS]=(char *)"SHOW_TABLE_STATUS";
  commands_counters_desc[MYSQL_COM_QUERY_START_TRANSACTION]=(char *)"START_TRANSACTION";
  commands_counters_desc[MYSQL_COM_QUERY_UNLOCK_TABLES]=(char *)"UNLOCK_TABLES";
  commands_counters_desc[MYSQL_COM_QUERY_UPDATE]=(char *)"UPDATE";
  commands_counters_desc[MYSQL_COM_QUERY_USE]=(char *)"USE";
  commands_counters_desc[MYSQL_COM_QUERY_UNKNOWN]=(char *)"UNKNOWN";
};

virtual ~Standard_Query_Processor() {
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete commands_counters[i];
	__reset_rules(&rules);
};

// This function is called by each thread when it starts. It create a Query Processor Table for each thread
virtual void init_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Per-Thread Query Processor Table with version=0\n");
	_thr_SQP_version=0;
	_thr_SQP_rules=new std::vector<QP_rule_t *>;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) _thr_commands_counters[i] = new Command_Counter(i);
};


virtual void end_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Destroying Per-Thread Query Processor Table with version=%d\n", _thr_SQP_version);
	__reset_rules(_thr_SQP_rules);
	delete _thr_SQP_rules;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete _thr_commands_counters[i];
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
	newQR->hits=0;
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : "") , newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
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
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Sorting rules\n");
	std::sort (rules.begin(), rules.end(), rules_sort_comp_function);
	if (lock) spin_wrunlock(&rwlock);
};

// when commit is called, the version number is increased and the this will trigger the mysql threads to get a new Query Processor Table
// The operation is asynchronous
virtual void commit() {
	spin_wrlock(&rwlock);
	__sync_add_and_fetch(&version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Increasing version number to %d - all threads will notice this and refresh their rules\n", version);
	spin_wrunlock(&rwlock);
};


virtual SQLite3_result * get_stats_commands_counters() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping commands counters%d\n");
	SQLite3_result *result=new SQLite3_result(15);
	result->add_column_definition(SQLITE_TEXT,"Command");
	result->add_column_definition(SQLITE_TEXT,"Total_Cnt");
	result->add_column_definition(SQLITE_TEXT,"Total_Time_us");
	result->add_column_definition(SQLITE_TEXT,"cnt_100us");
	result->add_column_definition(SQLITE_TEXT,"cnt_500us");
	result->add_column_definition(SQLITE_TEXT,"cnt_1ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_5ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_10ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_50ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_100ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_500ms");
	result->add_column_definition(SQLITE_TEXT,"cnt_1s");
	result->add_column_definition(SQLITE_TEXT,"cnt_5s");
	result->add_column_definition(SQLITE_TEXT,"cnt_10s");
	result->add_column_definition(SQLITE_TEXT,"cnt_INFs");
	for (int i=0;i<MYSQL_COM_QUERY___NONE;i++) {
		char **pta=commands_counters[i]->get_row();
		result->add_row(pta);
		commands_counters[i]->free_row(pta);
/*
		char **pta=(char **)malloc(sizeof(char *)*2);
		pta[0]=commands_counters_desc[i];
		itostr(pta[1], (long long)commands_counters[i]);
		result->add_row(pta);
		free(pta[1]);
		free(pta);
*/
	}
	return result;
}
virtual SQLite3_result * get_stats_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping query rules statistics, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(2);
	spin_rdlock(&rwlock);
	QP_rule_t *qr1;
	result->add_column_definition(SQLITE_TEXT,"rule_id");
	result->add_column_definition(SQLITE_TEXT,"hits");
	for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
		qr1=*it;
		if (qr1->active) {
			QP_rule_text_hitsonly *qt=new QP_rule_text_hitsonly(qr1);
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
			result->add_row(qt->pta);
			delete qt;
		}
	}
	spin_rdunlock(&rwlock);
	return result;
}

virtual SQLite3_result * get_current_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(13);
	spin_rdlock(&rwlock);
	QP_rule_t *qr1;
	result->add_column_definition(SQLITE_TEXT,"rule_id");
	result->add_column_definition(SQLITE_TEXT,"active");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"flagIN");
	result->add_column_definition(SQLITE_TEXT,"match_pattern");
	result->add_column_definition(SQLITE_TEXT,"negate_match_pattern");
	result->add_column_definition(SQLITE_TEXT,"flagOUT");
	result->add_column_definition(SQLITE_TEXT,"replace_pattern");
	result->add_column_definition(SQLITE_TEXT,"destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"cache_ttl");
	result->add_column_definition(SQLITE_TEXT,"apply");
	result->add_column_definition(SQLITE_TEXT,"hits");
	for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
		qr1=*it;
		QP_rule_text *qt=new QP_rule_text(qr1);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
		result->add_row(qt->pta);
		delete qt;
	}
	spin_rdunlock(&rwlock);
	return result;
}


virtual QP_out_t * process_mysql_query(MySQL_Session *sess, void *ptr, unsigned int size, bool delete_original) {
	QP_out_t *ret=NULL;
	unsigned int len=size-sizeof(mysql_hdr)-1;
	char *query=(char *)l_alloc(len+1);
	memcpy(query,(char *)ptr+sizeof(mysql_hdr)+1,len);
	query[len]=0;
	if (__sync_add_and_fetch(&version,0) > _thr_SQP_version) {
		// update local rules;
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Detected a changed in version. Global:%d , local:%d . Refreshing...\n", version, _thr_SQP_version);
		spin_rdlock(&rwlock);
		_thr_SQP_version=__sync_add_and_fetch(&version,0);
		__reset_rules(_thr_SQP_rules);
		QP_rule_t *qr1;
		QP_rule_t *qr2;
		for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
			qr1=*it;
			if (qr1->active) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Copying Query Rule id: %d\n", qr1->rule_id);
				qr2=new_query_rule(qr1->rule_id, qr1->active, qr1->username, qr1->schemaname, qr1->flagIN, qr1->match_pattern, qr1->negate_match_pattern, qr1->flagOUT, qr1->replace_pattern, qr1->destination_hostgroup, qr1->cache_ttl, qr1->apply);
				qr2->parent=qr1;	// pointer to parent to speed up parent update (hits)
				if (qr2->match_pattern) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_pattern: \n", qr2->rule_id, qr2->match_pattern);
					qr2->regex_engine=(void *)compile_query_rule(qr2);
				}
				_thr_SQP_rules->push_back(qr2);
			}
		}
		spin_rdunlock(&rwlock); // unlock should be after the copy
	}
	QP_rule_t *qr;
	re2_t *re2p;
	int flagIN=0;
	for (std::vector<QP_rule_t *>::iterator it=_thr_SQP_rules->begin(); it!=_thr_SQP_rules->end(); ++it) {
		qr=*it;
		if (qr->flagIN != flagIN) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 6, "query rule %d has no matching flagIN\n", qr->rule_id);
			continue;
		}
		if (qr->username) {
			if (strcmp(qr->username,sess->client_myds->myconn->userinfo->username)!=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching username\n", qr->rule_id);
				continue;
			}
		}
		if (qr->schemaname) {
			if (strcmp(qr->schemaname,sess->client_myds->myconn->userinfo->schemaname)!=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching schemaname\n", qr->rule_id);
				continue;
			}
		}

		re2p=(re2_t *)qr->regex_engine;
		if (qr->match_pattern) {
			bool rc;
			if (ret && ret->new_query) {
				// if we already rewrote the query, process the new query
				//std::string *s=ret->new_query;
				rc=RE2::PartialMatch(ret->new_query->c_str(),*re2p->re);
			} else {
				// we never rewrote the query
				rc=RE2::PartialMatch(query,*re2p->re);
			}
			if ((rc==true && qr->negate_match_pattern==true) || ( rc==false && qr->negate_match_pattern==false )) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching pattern\n", qr->rule_id);
				continue;
			}
		}
		// if we arrived here, we have a match
		if (ret==NULL) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "this is the first time we find a match\n");
			// create struct
			ret=(QP_out_t *)l_alloc(sizeof(QP_out_t));
			// initalized all values
			ret->ptr=NULL;
			ret->size=0;
			ret->destination_hostgroup=-1;
			ret->cache_ttl=-1;
			ret->new_query=NULL;
		}
		//__sync_fetch_and	_add(&qr->hits,1);
		qr->hits++; // this is done without atomic function because it updates only the local variables
			//ret=(QP_out_t *)malloc(sizeof(QP_out_t));

/*
{
		// FIXME: this block of code is only for testing
		if ((qr->hits%20)==0) {
			spin_rdlock(&rwlock);
			if (__sync_add_and_fetch(&version,0) == _thr_SQP_version) { // extra safety check to avoid race conditions
				__sync_fetch_and_add(&qr->parent->hits,20);
			}
*/
/*
			QP_rule_t *qrg;
			for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
				qrg=*it;
				if (qrg->rule_id==qr->rule_id) {
					__sync_fetch_and_add(&qrg->hits,20);
					break;
				}
			}
*/
/*
			spin_rdunlock(&rwlock);
		}
}
*/
		if (qr->flagOUT >= 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has changed flagOUT\n", qr->rule_id);
			flagIN=qr->flagOUT;
			//sess->query_info.flagOUT=flagIN;
    }
    if (qr->cache_ttl >= 0) {
			// Note: negative TTL means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set cache_ttl: %d. Query will%s hit the cache\n", qr->rule_id, qr->cache_ttl, (qr->cache_ttl == 0 ? " NOT" : "" ));
      ret->cache_ttl=qr->cache_ttl;
    }
    if (qr->destination_hostgroup >= 0) {
			// Note: negative TTL means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set destination hostgroup: %d\n", qr->rule_id, qr->destination_hostgroup);
      ret->destination_hostgroup=qr->destination_hostgroup;
    }

		if (qr->replace_pattern) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d on match_pattern \"%s\" has a replace_pattern \"%s\" to apply\n", qr->rule_id, qr->match_pattern, qr->replace_pattern);
			if (ret->new_query==NULL) ret->new_query=new std::string(query);
			RE2::Replace(ret->new_query,qr->match_pattern,qr->replace_pattern);
		}

		if (qr->apply==true) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d is the last one to apply: exit!\n", qr->rule_id);
			goto __exit_process_mysql_query;
		}
	}
	
__exit_process_mysql_query:
	// FIXME : there is too much data being copied around
	l_free(len+1,query);
	return ret;
};

// this function is called by mysql_session to free the result generated by process_mysql_query()
virtual void delete_QP_out(QP_out_t *o) {
	l_free(sizeof(QP_out_t),o);
};

virtual void update_query_processor_stats() {
	// Note:
	// this function is called by each thread to update global query statistics
	//
	// As an extra safety, it checks that the version didn't change
	// Yet, if version changed doesn't perfomr any rules update
	//
	// It acquires a read lock to ensure that the rules table doesn't change
	// Yet, because it has to update vales, it uses atomic operations
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Updating query rules statistics\n");
	spin_rdlock(&rwlock);
	if (__sync_add_and_fetch(&version,0) == _thr_SQP_version) {
		QP_rule_t *qr;
		for (std::vector<QP_rule_t *>::iterator it=_thr_SQP_rules->begin(); it!=_thr_SQP_rules->end(); ++it) {
			qr=*it;
			if (qr->active && qr->hits) {
				__sync_fetch_and_add(&qr->parent->hits,qr->hits);
				qr->hits=0;
			}
		}
	}
	spin_rdunlock(&rwlock);
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) {
		for (int j=0; j<13; j++) {
			__sync_fetch_and_add(&commands_counters[i]->counters[j],_thr_commands_counters[i]->counters[j]);
			_thr_commands_counters[i]->counters[j]=0;
		}
		__sync_fetch_and_add(&commands_counters[i]->total_time,_thr_commands_counters[i]->total_time);
		_thr_commands_counters[i]->total_time=0;
	}
};

virtual void * query_parser_init(char *query, int query_length, int flags) {
	SQP_par_t *qp=(SQP_par_t *)malloc(sizeof(SQP_par_t));
	libinjection_sqli_init(&qp->sf, query, query_length, FLAG_SQL_MYSQL);
	return (void *)qp;
};

virtual enum MYSQL_COM_QUERY_command query_parser_command_type(void *args) {
	enum MYSQL_COM_QUERY_command ret=__query_parser_command_type(args);
	//_thr_commands_counters[ret]++;
	return ret;
}

virtual unsigned long long query_parser_update_counters(enum MYSQL_COM_QUERY_command c, unsigned long long t) {
	if (c>=MYSQL_COM_QUERY___NONE) return 0;
	unsigned long long ret=_thr_commands_counters[c]->add_time(t);
	return ret;
}


enum MYSQL_COM_QUERY_command __query_parser_command_type(void *args) {
	SQP_par_t *qp=(SQP_par_t *)args;
	while (libinjection_sqli_tokenize(&qp->sf)) {
		if (qp->sf.current->type=='E' || qp->sf.current->type=='k' || qp->sf.current->type=='T')	{
			char c1=toupper(qp->sf.current->val[0]);
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%s Prefix:%c\n", c1, qp->sf.current->val, c1);
			switch (c1) {
				case 'A':
					if (!strcasecmp("ALTER",qp->sf.current->val)) { // ALTER [ONLINE | OFFLINE] [IGNORE] TABLE
						while (libinjection_sqli_tokenize(&qp->sf)) {
							if (qp->sf.current->type=='c') continue;
							if (qp->sf.current->type=='n') {
								if (!strcasecmp("OFFLINE",qp->sf.current->val)) continue;
								if (!strcasecmp("ONLINE",qp->sf.current->val)) continue;
							}
							if (qp->sf.current->type=='k') {
								if (!strcasecmp("IGNORE",qp->sf.current->val)) continue;
								if (!strcasecmp("TABLE",qp->sf.current->val))
									return MYSQL_COM_QUERY_ALTER_TABLE;
							}
							return MYSQL_COM_QUERY_UNKNOWN;
						}
					}
					if (!strcasecmp("ANALYZE",qp->sf.current->val)) { // ANALYZE [NO_WRITE_TO_BINLOG | LOCAL] TABLE
						while (libinjection_sqli_tokenize(&qp->sf)) {
							if (qp->sf.current->type=='c') continue;
							if (qp->sf.current->type=='n') {
								if (!strcasecmp("LOCAL",qp->sf.current->val)) continue;
							}
							if (qp->sf.current->type=='k') {
								if (!strcasecmp("NO_WRITE_TO_BINLOG",qp->sf.current->val)) continue;
								if (!strcasecmp("TABLE",qp->sf.current->val))
									return MYSQL_COM_QUERY_ANALYZE_TABLE;
							}
							return MYSQL_COM_QUERY_UNKNOWN;
						}
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'B':
					if (!strcasecmp("BEGIN",qp->sf.current->val)) { // BEGIN
						return MYSQL_COM_QUERY_BEGIN;
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'C':
					if (!strcasecmp("COMMIT",qp->sf.current->val)) { // COMMIT
						return MYSQL_COM_QUERY_COMMIT;
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'D':
					if (!strcasecmp("DELETE",qp->sf.current->val)) { // DELETE
						return MYSQL_COM_QUERY_DELETE;
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'I':
					if (!strcasecmp("INSERT",qp->sf.current->val)) { // INSERT
						return MYSQL_COM_QUERY_INSERT;
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'S':
					if (!strcasecmp("SELECT",qp->sf.current->val)) { // SELECT
						return MYSQL_COM_QUERY_SELECT;
					}
					if (!strcasecmp("SET",qp->sf.current->val)) { // SET
						return MYSQL_COM_QUERY_SET;
					}
					if (!strcasecmp("SHOW",qp->sf.current->val)) { // SHOW
						while (libinjection_sqli_tokenize(&qp->sf)) {
							if (qp->sf.current->type=='c') continue;
/*
							if (qp->sf.current->type=='n') {
								if (!strcasecmp("OFFLINE",qp->sf.current->val)) continue;
								if (!strcasecmp("ONLINE",qp->sf.current->val)) continue;
							}
*/
							if (qp->sf.current->type=='k') {
								if (!strcasecmp("TABLE",qp->sf.current->val)) {
									while (libinjection_sqli_tokenize(&qp->sf)) {
										if (qp->sf.current->type=='c') continue;
										if (qp->sf.current->type=='n') {
											if (!strcasecmp("STATUS",qp->sf.current->val))
												return MYSQL_COM_QUERY_SHOW_TABLE_STATUS;
										}
									}
								}
							}
							return MYSQL_COM_QUERY_UNKNOWN;
						}
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				case 'U':
					if (!strcasecmp("UPDATE",qp->sf.current->val)) { // UPDATE
						return MYSQL_COM_QUERY_UPDATE;
					}
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
				default:
					return MYSQL_COM_QUERY_UNKNOWN;
					break;
			}
		}
	}
	return MYSQL_COM_QUERY_UNKNOWN;
}

virtual char * query_parser_first_comment(void *args) { return NULL; }

virtual void query_parser_free(void *args) {
	SQP_par_t *qp=(SQP_par_t *)args;
	free(qp);	
};

};

extern "C" Query_Processor * create_Query_Processor_func() {
    return new Standard_Query_Processor();
}

extern "C" void destroy_Query_Processor(Query_Processor * qp) {
    delete qp;
}
