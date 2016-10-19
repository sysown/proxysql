#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include "SpookyV2.h"

#include <pcrecpp.h>

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_PROCESSOR_VERSION "0.2.0902" DEB

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
	int num_fields;
	QP_rule_text(QP_rule_t *QPr) {
		num_fields=27;
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
		//uint32_t d32[2];
		//memcpy(&d32,&QPr->digest,sizeof(QPr->digest));
		//sprintf(buf,"0x%X%X", d32[0], d32[1]);
		if (QPr->digest) {
			sprintf(buf,"0x%016llX", (long long unsigned int)QPr->digest);
			pta[8]=strdup(buf);
		} else {
			pta[8]=NULL;
		}

		pta[9]=strdup_null(QPr->match_digest);
		pta[10]=strdup_null(QPr->match_pattern);
		itostr(pta[11], (long long)QPr->negate_match_pattern);
		itostr(pta[12], (long long)QPr->flagOUT);
		pta[13]=strdup_null(QPr->replace_pattern);
		itostr(pta[14], (long long)QPr->destination_hostgroup);
		itostr(pta[15], (long long)QPr->cache_ttl);
		itostr(pta[16], (long long)QPr->reconnect);
		itostr(pta[17], (long long)QPr->timeout);
		itostr(pta[18], (long long)QPr->retries);
		itostr(pta[19], (long long)QPr->delay);
		itostr(pta[20], (long long)QPr->mirror_flagOUT);
		itostr(pta[21], (long long)QPr->mirror_hostgroup);
		pta[22]=strdup_null(QPr->error_msg);
		itostr(pta[23], (long long)QPr->log);
		itostr(pta[24], (long long)QPr->apply);
		pta[25]=strdup_null(QPr->comment); // issue #643
		itostr(pta[26], (long long)QPr->hits);
	}
	~QP_rule_text() {
		for(int i=0; i<num_fields; i++) {
			free_null(pta[i]);
		}
		free(pta);
	}
};

/*
struct __SQP_query_parser_t {
	sfilter sf;
	uint64_t digest;
	char *digest_text;
	char *first_comment;
	uint64_t digest_total;
};

typedef struct __SQP_query_parser_t SQP_par_t;
*/
class QP_query_digest_stats {
	public:
	uint64_t digest;
	char *digest_text;
	char *username;
	char *schemaname;
	time_t first_seen;
	time_t last_seen;
	unsigned int count_star;
	unsigned long long sum_time;
	unsigned long long min_time;
	unsigned long long max_time;
	int hid;
	QP_query_digest_stats(char *u, char *s, uint64_t d, char *dt, int h) {
		digest=d;
		digest_text=strdup(dt);
		username=strdup(u);
		schemaname=strdup(s);
		count_star=0;
		first_seen=0;
		last_seen=0;
		sum_time=0;
		min_time=0;
		max_time=0;
		hid=h;
	}
	void add_time(unsigned long long t, unsigned long long n) {
		count_star++;
		sum_time+=t;
		if (t < min_time || min_time==0) {
			if (t) min_time = t;
		}
		if (t > max_time) {
			max_time = t;
		}
		if (first_seen==0) {
			first_seen=n;
		}
		last_seen=n;
	}
	~QP_query_digest_stats() {
		if (digest_text) {
			free(digest_text);
			digest_text=NULL;
		}
		if (username) {
			free(username);
			username=NULL;
		}
		if (schemaname) {
			free(schemaname);
			schemaname=NULL;
		}
	}
	char **get_row() {
		char buf[128];
		char **pta=(char **)malloc(sizeof(char *)*11);
		assert(schemaname);
		pta[0]=strdup(schemaname);
		assert(username);
		pta[1]=strdup(username);

		//uint32_t d32[2];
		//memcpy(&d32,&digest,sizeof(digest));
		//sprintf(buf,"0x%X%X", d32[0], d32[1]);
		sprintf(buf,"0x%016llX", (long long unsigned int)digest);
		pta[2]=strdup(buf);

		assert(digest_text);
		pta[3]=strdup(digest_text);
		sprintf(buf,"%u",count_star);
		pta[4]=strdup(buf);

		time_t __now;
    //char __buffer[25];
//    struct tm *__tm_info;
    time(&__now);
		
		unsigned long long curtime=monotonic_time();

		time_t seen_time;

		seen_time= __now - curtime/1000000 + first_seen/1000000;
//    __tm_info = localtime(&seen_time);
//    strftime(buf, 25, "%Y-%m-%d %H:%M:%S", __tm_info);
		sprintf(buf,"%ld", seen_time);
		pta[5]=strdup(buf);

		seen_time= __now - curtime/1000000 + last_seen/1000000;
//    __tm_info = localtime(&seen_time);
//    strftime(buf, 25, "%Y-%m-%d %H:%M:%S", __tm_info);
		sprintf(buf,"%ld", seen_time);
		pta[6]=strdup(buf);

		sprintf(buf,"%llu",sum_time);
		pta[7]=strdup(buf);
		sprintf(buf,"%llu",min_time);
		pta[8]=strdup(buf);
		sprintf(buf,"%llu",max_time);
		pta[9]=strdup(buf);
		sprintf(buf,"%d",hid);
		pta[10]=strdup(buf);
		return pta;
	}
	void free_row(char **pta) {
		int i;
		for (i=0;i<11;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};


//static char *commands_counters_desc[MYSQL_COM_QUERY___NONE];



struct __RE2_objects_t {
	pcrecpp::RE_Options *opt1;
	pcrecpp::RE *re1;
	re2::RE2::Options *opt2;
	RE2 *re2;
};

typedef struct __RE2_objects_t re2_t;

static bool rules_sort_comp_function (QP_rule_t * a, QP_rule_t * b) { return (a->rule_id < b->rule_id); }

static re2_t * compile_query_rule(QP_rule_t *qr, int i) {
	re2_t *r=(re2_t *)malloc(sizeof(re2_t));
	r->opt1=NULL;
	r->re1=NULL;
	r->opt2=NULL;
	r->re2=NULL;
	if (mysql_thread___query_processor_regex==2) {
		r->opt2=new re2::RE2::Options(RE2::Quiet);
		r->opt2->set_case_sensitive(false);
		if (i==1) {
			r->re2=new RE2(qr->match_digest, *r->opt2);
		} else if (i==2) {
			r->re2=new RE2(qr->match_pattern, *r->opt2);
		}
	} else {
		r->opt1=new pcrecpp::RE_Options();
		r->opt1->set_caseless(true);
		if (i==1) {
			r->re1=new pcrecpp::RE(qr->match_digest, *r->opt1);
		} else if (i==2) {
			r->re1=new pcrecpp::RE(qr->match_pattern, *r->opt1);
		}
	}
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
	if (qr->error_msg)
		free(qr->error_msg);
	if (qr->regex_engine1) {
		re2_t *r=(re2_t *)qr->regex_engine1;
		if (r->opt1) { delete r->opt1; r->opt1=NULL; }
		if (r->re1) { delete r->re1; r->re1=NULL; }
		if (r->opt2) { delete r->opt2; r->opt2=NULL; }
		if (r->re2) { delete r->re2; r->re2=NULL; }
		free(qr->regex_engine1);
	}
	if (qr->regex_engine2) {
		re2_t *r=(re2_t *)qr->regex_engine2;
		if (r->opt1) { delete r->opt1; r->opt1=NULL; }
		if (r->re1) { delete r->re1; r->re1=NULL; }
		if (r->opt2) { delete r->opt2; r->opt2=NULL; }
		if (r->re2) { delete r->re2; r->re2=NULL; }
		free(qr->regex_engine2);
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

// per thread variables
__thread unsigned int _thr_SQP_version;
__thread std::vector<QP_rule_t *> * _thr_SQP_rules;
//__thread unsigned int _thr_commands_counters[MYSQL_COM_QUERY___NONE];
__thread Command_Counter * _thr_commands_counters[MYSQL_COM_QUERY___NONE];

Query_Processor::Query_Processor() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Query Processor with version=0\n");
	spinlock_rwlock_init(&rwlock);
	spinlock_rwlock_init(&digest_rwlock);
	version=0;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) commands_counters[i]=new Command_Counter(i);

	commands_counters_desc[MYSQL_COM_QUERY_ALTER_TABLE]=(char *)"ALTER_TABLE";
	commands_counters_desc[MYSQL_COM_QUERY_ALTER_VIEW]=(char *)"ALTER_VIEW";
  commands_counters_desc[MYSQL_COM_QUERY_ANALYZE_TABLE]=(char *)"ANALYZE_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_BEGIN]=(char *)"BEGIN";
  commands_counters_desc[MYSQL_COM_QUERY_CALL]=(char *)"CALL";
  commands_counters_desc[MYSQL_COM_QUERY_CHANGE_MASTER]=(char *)"CHANGE_MASTER";
  commands_counters_desc[MYSQL_COM_QUERY_COMMIT]=(char *)"COMMIT";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_DATABASE]=(char *)"CREATE_DATABASE";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_INDEX]=(char *)"CREATE_INDEX";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TABLE]=(char *)"CREATE_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TEMPORARY]=(char *)"CREATE_TEMPORARY";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_TRIGGER]=(char *)"CREATE_TRIGGER";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_USER]=(char *)"CREATE_USER";
  commands_counters_desc[MYSQL_COM_QUERY_CREATE_VIEW]=(char *)"CREATE_VIEW";
  commands_counters_desc[MYSQL_COM_QUERY_DEALLOCATE]=(char *)"DEALLOCATE";
  commands_counters_desc[MYSQL_COM_QUERY_DELETE]=(char *)"DELETE";
  commands_counters_desc[MYSQL_COM_QUERY_DESCRIBE]=(char *)"DESCRIBE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_DATABASE]=(char *)"DROP_DATABASE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_INDEX]=(char *)"DROP_INDEX";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_TABLE]=(char *)"DROP_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_TRIGGER]=(char *)"DROP_TRIGGER";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_USER]=(char *)"DROP_USER";
  commands_counters_desc[MYSQL_COM_QUERY_DROP_VIEW]=(char *)"DROP_VIEW";
  commands_counters_desc[MYSQL_COM_QUERY_EXECUTE]=(char *)"EXECUTE";
  commands_counters_desc[MYSQL_COM_QUERY_EXPLAIN]=(char *)"EXPLAIN";
  commands_counters_desc[MYSQL_COM_QUERY_FLUSH]=(char *)"FLUSH";
  commands_counters_desc[MYSQL_COM_QUERY_GRANT]=(char *)"GRANT";
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
  commands_counters_desc[MYSQL_COM_QUERY_SHOW]=(char *)"SHOW";
  commands_counters_desc[MYSQL_COM_QUERY_START_TRANSACTION]=(char *)"START_TRANSACTION";
  commands_counters_desc[MYSQL_COM_QUERY_TRUNCATE_TABLE]=(char *)"TRUNCATE_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_UNLOCK_TABLES]=(char *)"UNLOCK_TABLES";
  commands_counters_desc[MYSQL_COM_QUERY_UPDATE]=(char *)"UPDATE";
  commands_counters_desc[MYSQL_COM_QUERY_USE]=(char *)"USE";
  commands_counters_desc[MYSQL_COM_QUERY_UNKNOWN]=(char *)"UNKNOWN";
};

Query_Processor::~Query_Processor() {
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete commands_counters[i];
	__reset_rules(&rules);
};

// This function is called by each thread when it starts. It create a Query Processor Table for each thread
void Query_Processor::init_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Per-Thread Query Processor Table with version=0\n");
	_thr_SQP_version=0;
	_thr_SQP_rules=new std::vector<QP_rule_t *>;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) _thr_commands_counters[i] = new Command_Counter(i);
};


void Query_Processor::end_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Destroying Per-Thread Query Processor Table with version=%d\n", _thr_SQP_version);
	__reset_rules(_thr_SQP_rules);
	delete _thr_SQP_rules;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete _thr_commands_counters[i];
};

void Query_Processor::print_version() {
	fprintf(stderr,"Standard Query Processor rev. %s -- %s -- %s\n", QUERY_PROCESSOR_VERSION, __FILE__, __TIMESTAMP__);
};

void Query_Processor::wrlock() {
	spin_wrlock(&rwlock);
};

void Query_Processor::wrunlock() {
	spin_wrunlock(&rwlock);
};



QP_rule_t * Query_Processor::new_query_rule(int rule_id, bool active, char *username, char *schemaname, int flagIN, char *client_addr, char *proxy_addr, int proxy_port, char *digest, char *match_digest, char *match_pattern, bool negate_match_pattern, int flagOUT, char *replace_pattern, int destination_hostgroup, int cache_ttl, int reconnect, int timeout, int retries, int delay, int mirror_flagOUT, int mirror_hostgroup, char *error_msg, int log, bool apply, char *comment) {
	QP_rule_t * newQR=(QP_rule_t *)malloc(sizeof(QP_rule_t));
	newQR->rule_id=rule_id;
	newQR->active=active;
	newQR->username=(username ? strdup(username) : NULL);
	newQR->schemaname=(schemaname ? strdup(schemaname) : NULL);
	newQR->flagIN=flagIN;
	newQR->match_digest=(match_digest ? strdup(match_digest) : NULL);
	newQR->match_pattern=(match_pattern ? strdup(match_pattern) : NULL);
	newQR->negate_match_pattern=negate_match_pattern;
	newQR->flagOUT=flagOUT;
	newQR->replace_pattern=(replace_pattern ? strdup(replace_pattern) : NULL);
	newQR->destination_hostgroup=destination_hostgroup;
	newQR->cache_ttl=cache_ttl;
	newQR->reconnect=reconnect;
	newQR->timeout=timeout;
	newQR->retries=retries;
	newQR->delay=delay;
	newQR->mirror_flagOUT=mirror_flagOUT;
	newQR->mirror_hostgroup=mirror_hostgroup;
	newQR->error_msg=(error_msg ? strdup(error_msg) : NULL);
	newQR->apply=apply;
	newQR->comment=(comment ? strdup(comment) : NULL); // see issue #643
	newQR->regex_engine1=NULL;
	newQR->regex_engine2=NULL;
	newQR->hits=0;

	newQR->client_addr=(client_addr ? strdup(client_addr) : NULL);
	newQR->proxy_addr=(proxy_addr ? strdup(proxy_addr) : NULL);
	newQR->proxy_port=proxy_port;
	newQR->log=log;
	newQR->digest=0;
	if (digest) {
		unsigned long long num=strtoull(digest,NULL,0);
		if (num!=ULLONG_MAX && num!=0) {
			newQR->digest=num;
		} else {
			proxy_error("Incorrect digest for rule_id %d : %s\n" , rule_id, digest);
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_digest=\"%s\", %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : "") , newQR->match_digest, (newQR->negate_match_pattern ? "(!)" : "") , newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
	return newQR;
};


void Query_Processor::delete_query_rule(QP_rule_t *qr) {
	__delete_query_rule(qr);
};

void Query_Processor::reset_all(bool lock) {
	if (lock) spin_wrlock(&rwlock);
	__reset_rules(&rules);
	if (lock) spin_wrunlock(&rwlock);
};

bool Query_Processor::insert(QP_rule_t *qr, bool lock) {
	bool ret=true;
	if (lock) spin_wrlock(&rwlock);
	rules.push_back(qr);
	if (lock) spin_wrunlock(&rwlock);
	return ret;
};


void Query_Processor::sort(bool lock) {
	if (lock) spin_wrlock(&rwlock);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Sorting rules\n");
	std::sort (rules.begin(), rules.end(), rules_sort_comp_function);
	if (lock) spin_wrunlock(&rwlock);
};

// when commit is called, the version number is increased and the this will trigger the mysql threads to get a new Query Processor Table
// The operation is asynchronous
void Query_Processor::commit() {
	spin_wrlock(&rwlock);
	__sync_add_and_fetch(&version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Increasing version number to %d - all threads will notice this and refresh their rules\n", version);
	spin_wrunlock(&rwlock);
};


SQLite3_result * Query_Processor::get_stats_commands_counters() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping commands counters\n");
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
	}
	return result;
}
SQLite3_result * Query_Processor::get_stats_query_rules() {
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

SQLite3_result * Query_Processor::get_current_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(27);
	spin_rdlock(&rwlock);
	QP_rule_t *qr1;
	result->add_column_definition(SQLITE_TEXT,"rule_id");
	result->add_column_definition(SQLITE_TEXT,"active");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"flagIN");
	result->add_column_definition(SQLITE_TEXT,"client_addr");
	result->add_column_definition(SQLITE_TEXT,"proxy_addr");
	result->add_column_definition(SQLITE_TEXT,"proxy_port");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"match_digest");
	result->add_column_definition(SQLITE_TEXT,"match_pattern");
	result->add_column_definition(SQLITE_TEXT,"negate_match_pattern");
	result->add_column_definition(SQLITE_TEXT,"flagOUT");
	result->add_column_definition(SQLITE_TEXT,"replace_pattern");
	result->add_column_definition(SQLITE_TEXT,"destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"cache_ttl");
	result->add_column_definition(SQLITE_TEXT,"reconnect");
	result->add_column_definition(SQLITE_TEXT,"timeout");
	result->add_column_definition(SQLITE_TEXT,"retries");
	result->add_column_definition(SQLITE_TEXT,"delay");
	result->add_column_definition(SQLITE_TEXT,"mirror_flagOUT");
	result->add_column_definition(SQLITE_TEXT,"mirror_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"error_msg");
	result->add_column_definition(SQLITE_TEXT,"log");
	result->add_column_definition(SQLITE_TEXT,"apply");
	result->add_column_definition(SQLITE_TEXT,"comment"); // issue #643
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

SQLite3_result * Query_Processor::get_query_digests() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query digest\n");
	SQLite3_result *result=new SQLite3_result(11);
	spin_rdlock(&digest_rwlock);
	result->add_column_definition(SQLITE_TEXT,"hid");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"usernname");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"digest_text");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");
	result->add_column_definition(SQLITE_TEXT,"sum_time");
	result->add_column_definition(SQLITE_TEXT,"min_time");
	result->add_column_definition(SQLITE_TEXT,"max_time");
	//for (btree::btree_map<uint64_t, void *>::iterator it=digest_bt_map.begin(); it!=digest_bt_map.end(); ++it) {
	for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
		QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
		char **pta=qds->get_row();
		result->add_row(pta);
		qds->free_row(pta);
	}
	spin_rdunlock(&digest_rwlock);
	return result;
}

SQLite3_result * Query_Processor::get_query_digests_reset() {
	SQLite3_result *result=new SQLite3_result(11);
	spin_wrlock(&digest_rwlock);
	result->add_column_definition(SQLITE_TEXT,"hid");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"usernname");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"digest_text");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");
	result->add_column_definition(SQLITE_TEXT,"sum_time");
	result->add_column_definition(SQLITE_TEXT,"min_time");
	result->add_column_definition(SQLITE_TEXT,"max_time");
	//for (btree::btree_map<uint64_t, void *>::iterator it=digest_bt_map.begin(); it!=digest_bt_map.end(); ++it) {
	for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
		QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
		char **pta=qds->get_row();
		result->add_row(pta);
		qds->free_row(pta);
		delete qds;
	}
	//digest_bt_map.erase(digest_bt_map.begin(),digest_bt_map.end());
	digest_umap.erase(digest_umap.begin(),digest_umap.end());
	spin_wrunlock(&digest_rwlock);
	return result;
}



Query_Processor_Output * Query_Processor::process_mysql_query(MySQL_Session *sess, void *ptr, unsigned int size, Query_Info *qi) {
	// to avoid unnecssary deallocation/allocation, we initialize qpo witout new allocation
	//Query_Processor_Output *ret=NULL;
	//ret=new Query_Processor_Output();
	Query_Processor_Output *ret=sess->qpo;
	ret->init();
	SQP_par_t *qp=NULL;
	if (qi) {
		qp=(SQP_par_t *)&qi->QueryParserArgs;
	}
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
				char buf[20];
				if (qr1->digest) { // not 0
					//uint32_t d32[2];
					//memcpy(&d32,&qr1->digest,sizeof(qr1->digest));
					//sprintf(buf,"0x%X%X", d32[0], d32[1]);
					sprintf(buf,"0x%016llX", (long long unsigned int)qr1->digest);
				}
				qr2=new_query_rule(qr1->rule_id, qr1->active, qr1->username, qr1->schemaname, qr1->flagIN,
					qr1->client_addr, qr1->proxy_addr, qr1->proxy_port,
					( qr1->digest ? buf : NULL ) ,
					qr1->match_digest, qr1->match_pattern, qr1->negate_match_pattern,
					qr1->flagOUT, qr1->replace_pattern, qr1->destination_hostgroup,
					qr1->cache_ttl, qr1->reconnect, qr1->timeout, qr1->retries, qr1->delay, qr1->mirror_flagOUT, qr1->mirror_hostgroup,
					qr1->error_msg, qr1->log, qr1->apply,
					qr1->comment);
				qr2->parent=qr1;	// pointer to parent to speed up parent update (hits)
				if (qr2->match_digest) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_digest: \n", qr2->rule_id, qr2->match_digest);
					qr2->regex_engine1=(void *)compile_query_rule(qr2,1);
				}
				if (qr2->match_pattern) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_pattern: \n", qr2->rule_id, qr2->match_pattern);
					qr2->regex_engine2=(void *)compile_query_rule(qr2,2);
				}
				_thr_SQP_rules->push_back(qr2);
			}
		}
		spin_rdunlock(&rwlock); // unlock should be after the copy
	}
	QP_rule_t *qr;
	re2_t *re2p;
	int flagIN=0;
	int reiterate=mysql_thread___query_processor_iterations;
	if (sess->mirror==true) {
		// we are into a mirror session
		// we immediately set a destination_hostgroup
		ret->destination_hostgroup=sess->mirror_hostgroup;
		if (sess->mirror_flagOUT != -1) {
			// the original session has set a mirror flagOUT
			flagIN=sess->mirror_flagOUT;
		} else {
			// the original session did NOT set any mirror flagOUT
			// so we exit here
			// the only thing set so far is destination_hostgroup
			goto __exit_process_mysql_query;
		}
	}
__internal_loop:
	for (std::vector<QP_rule_t *>::iterator it=_thr_SQP_rules->begin(); it!=_thr_SQP_rules->end(); ++it) {
		qr=*it;
		if (qr->flagIN != flagIN) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 6, "query rule %d has no matching flagIN\n", qr->rule_id);
			continue;
		}
		if (qr->username && strlen(qr->username)) {
			if (strcmp(qr->username,sess->client_myds->myconn->userinfo->username)!=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching username\n", qr->rule_id);
				continue;
			}
		}
		if (qr->schemaname && strlen(qr->schemaname)) {
			if (strcmp(qr->schemaname,sess->client_myds->myconn->userinfo->schemaname)!=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching schemaname\n", qr->rule_id);
				continue;
			}
		}

		// match on client address
		if (qr->client_addr && strlen(qr->client_addr)) {
			if (sess->client_myds->addr.addr) {
				if (strcmp(qr->client_addr,sess->client_myds->addr.addr)!=0) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching client_addr\n", qr->rule_id);
					continue;
				}
			}
		}

		// match on proxy_addr & proxy_port
		if (qr->proxy_addr && strlen(qr->proxy_addr)) {
			if (sess->client_myds->proxy_addr.addr) {
				if (strcmp(qr->proxy_addr,sess->client_myds->proxy_addr.addr)!=0) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching proxy_addr\n", qr->rule_id);
					continue;
				}
				if (qr->proxy_port>=0) {
					if (qr->proxy_port!=sess->client_myds->proxy_addr.port) {
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching proxy_port\n", qr->rule_id);
						continue;
					}
				}
			}
		}

		// match on digest
		if (qp && qp->digest) {
			if (qr->digest) {
				if (qr->digest != qp->digest) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching digest\n", qr->rule_id);
					continue;
				}
			}
		}

		// match on query digest
		if (qp && qp->digest_text ) { // we call this only if we have a query digest
			re2p=(re2_t *)qr->regex_engine1;
			if (qr->match_digest) {
				bool rc;
				// we always match on original query
				if (re2p->re2) {
					rc=RE2::PartialMatch(qp->digest_text,*re2p->re2);
				} else {
					rc=re2p->re1->PartialMatch(qp->digest_text);
				}
				if ((rc==true && qr->negate_match_pattern==true) || ( rc==false && qr->negate_match_pattern==false )) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching pattern\n", qr->rule_id);
					continue;
				}
			}
		}
		// match on query
		re2p=(re2_t *)qr->regex_engine2;
		if (qr->match_pattern) {
			bool rc;
			if (ret && ret->new_query) {
				// if we already rewrote the query, process the new query
				//std::string *s=ret->new_query;
				if (re2p->re2) {
					rc=RE2::PartialMatch(ret->new_query->c_str(),*re2p->re2);
				} else {
					rc=re2p->re1->PartialMatch(ret->new_query->c_str());
				}
			} else {
				// we never rewrote the query
				if (re2p->re2) {
					rc=RE2::PartialMatch(query,*re2p->re2);
				} else {
					rc=re2p->re1->PartialMatch(query);
				}
			}
			if ((rc==true && qr->negate_match_pattern==true) || ( rc==false && qr->negate_match_pattern==false )) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching pattern\n", qr->rule_id);
				continue;
			}
		}

		// if we arrived here, we have a match
		qr->hits++; // this is done without atomic function because it updates only the local variables
		bool set_flagOUT=false;
		if (qr->flagOUT >= 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has changed flagOUT\n", qr->rule_id);
			flagIN=qr->flagOUT;
			set_flagOUT=true;
			//sess->query_info.flagOUT=flagIN;
    }
    if (qr->reconnect >= 0) {
			// Note: negative reconnect means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set reconnect: %d. Query will%s be rexecuted if connection is lost\n", qr->rule_id, qr->reconnect, (qr->reconnect == 0 ? " NOT" : "" ));
      ret->reconnect=qr->reconnect;
    }
    if (qr->timeout >= 0) {
			// Note: negative timeout means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set timeout: %d. Query will%s be interrupted if exceeding %dms\n", qr->rule_id, qr->timeout, (qr->timeout == 0 ? " NOT" : "" ) , qr->timeout);
      ret->timeout=qr->timeout;
    }
    if (qr->retries >= 0) {
			// Note: negative retries means this rule doesn't change
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set retries: %d. Query will%s be re-executed %d times in case of failure\n", qr->rule_id, qr->retries);
      ret->retries=qr->retries;
    }
    if (qr->delay >= 0) {
			// Note: negative delay means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set delay: %d. Session will%s be paused for %dms\n", qr->rule_id, qr->delay, (qr->delay == 0 ? " NOT" : "" ) , qr->delay);
      ret->delay=qr->delay;
    }
    if (qr->mirror_flagOUT >= 0) {
			// Note: negative mirror_flagOUT means this rule doesn't change the mirror flagOUT
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set mirror flagOUT: %d\n", qr->rule_id, qr->mirror_flagOUT);
      ret->mirror_flagOUT=qr->mirror_flagOUT;
    }
    if (qr->mirror_hostgroup >= 0) {
			// Note: negative mirror_hostgroup means this rule doesn't change the mirror
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set mirror hostgroup: %d. A new session will be created\n", qr->rule_id, qr->mirror_hostgroup);
      ret->mirror_hostgroup=qr->mirror_hostgroup;
    }
    if (qr->error_msg) {
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set error_msg: %s\n", qr->rule_id, qr->error_msg);
			//proxy_warning("User \"%s\" has issued query that has been filtered: %s \n " , sess->client_myds->myconn->userinfo->username, query);
      ret->error_msg=strdup(qr->error_msg);
    }
    if (qr->cache_ttl >= 0) {
			// Note: negative TTL means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set cache_ttl: %d. Query will%s hit the cache\n", qr->rule_id, qr->cache_ttl, (qr->cache_ttl == 0 ? " NOT" : "" ));
      ret->cache_ttl=qr->cache_ttl;
    }
    if (qr->destination_hostgroup >= 0) {
			// Note: negative hostgroup means this rule doesn't change 
      proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set destination hostgroup: %d\n", qr->rule_id, qr->destination_hostgroup);
      ret->destination_hostgroup=qr->destination_hostgroup;
    }

		if (qr->replace_pattern) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d on match_pattern \"%s\" has a replace_pattern \"%s\" to apply\n", qr->rule_id, qr->match_pattern, qr->replace_pattern);
			if (ret->new_query==NULL) ret->new_query=new std::string(query);
			re2_t *re2p=(re2_t *)qr->regex_engine2;
			if (re2p->re2) {
				//RE2::Replace(ret->new_query,qr->match_pattern,qr->replace_pattern);
				re2p->re2->Replace(ret->new_query,qr->match_pattern,qr->replace_pattern);
			} else {
				//re2p->re1->Replace(ret->new_query,qr->replace_pattern);
				re2p->re1->Replace(qr->replace_pattern,ret->new_query);
			}
		}

		if (qr->apply==true) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d is the last one to apply: exit!\n", qr->rule_id);
			goto __exit_process_mysql_query;
		}
		if (set_flagOUT==true) {
			if (reiterate) {
				reiterate--;
				goto __internal_loop;
			}
		}
	}
	
__exit_process_mysql_query:
	// FIXME : there is too much data being copied around
	l_free(len+1,query);
	if (sess->mirror==false) { // we process comments only on original queries, not on mirrors
		if (qp && qp->first_comment) {
			// we have a comment to parse
			query_parser_first_comment(ret, qp->first_comment);
		}
	}
	return ret;
};

// this function is called by mysql_session to free the result generated by process_mysql_query()
void Query_Processor::delete_QP_out(Query_Processor_Output *o) {
	//l_free(sizeof(QP_out_t),o);
	if (o) {
		//delete o; // do not deallocate, but "destroy" it
		o->destroy();
	}
};

void Query_Processor::update_query_processor_stats() {
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
			if (_thr_commands_counters[i]->counters[j]) {
				__sync_fetch_and_add(&commands_counters[i]->counters[j],_thr_commands_counters[i]->counters[j]);
				_thr_commands_counters[i]->counters[j]=0;
			}
		}
		if (_thr_commands_counters[i]->total_time)
			__sync_fetch_and_add(&commands_counters[i]->total_time,_thr_commands_counters[i]->total_time);
		_thr_commands_counters[i]->total_time=0;
	}
};


void Query_Processor::query_parser_init(SQP_par_t *qp, char *query, int query_length, int flags) {
	// trying to get rid of libinjection
	// instead of initializing qp->sf , we copy query info later in this function
//	if (mysql_thread___commands_stats)
//		libinjection_sqli_init(&qp->sf, query, query_length, FLAG_SQL_MYSQL);
	qp->digest_text=NULL;
	qp->first_comment=NULL;
	qp->query_prefix=NULL;
	//qp->first_comment=(char *)l_alloc(FIRST_COMMENT_MAX_LENGTH);
	//qp->first_comment[0]=0; // initialize it to 0 . Useful to determine if there is any string or not
	if (mysql_thread___query_digests) {
		qp->digest_text=mysql_query_digest_and_first_comment(query, query_length, &qp->first_comment);
		qp->digest=SpookyHash::Hash64(qp->digest_text,strlen(qp->digest_text),0);
#ifdef DEBUG
		if (qp->first_comment && strlen(qp->first_comment)) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Comment in query = %s \n", qp->first_comment);
		}
#endif /* DEBUG */
	} else {
		// if mysql_thread___query_digests==false but we still want command statistics, we copy the prefix of the query
		if (mysql_thread___commands_stats) {
			qp->query_prefix=strndup(query,32);
		}
	}
};

enum MYSQL_COM_QUERY_command Query_Processor::query_parser_command_type(SQP_par_t *qp) {
	enum MYSQL_COM_QUERY_command ret=__query_parser_command_type(qp);
	return ret;
}

unsigned long long Query_Processor::query_parser_update_counters(MySQL_Session *sess, enum MYSQL_COM_QUERY_command c, SQP_par_t *qp, unsigned long long t) {
	if (c>=MYSQL_COM_QUERY___NONE) return 0;
	unsigned long long ret=_thr_commands_counters[c]->add_time(t);


	if (sess->CurrentQuery.stmt_info==NULL && qp->digest_text) {
		// this code is executed only if digest_text is not NULL , that means mysql_thread___query_digests was true when the query started
		uint64_t hash2;
		SpookyHash myhash;
		myhash.Init(19,3);
		assert(sess);
		assert(sess->client_myds);
		assert(sess->client_myds->myconn);
		assert(sess->client_myds->myconn->userinfo);
		MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;
		assert(ui->username);
		assert(ui->schemaname);
		myhash.Update(ui->username,strlen(ui->username));
		myhash.Update(&qp->digest,sizeof(qp->digest));
		myhash.Update(ui->schemaname,strlen(ui->schemaname));
		myhash.Update(&sess->current_hostgroup,sizeof(sess->default_hostgroup));
		myhash.Final(&qp->digest_total,&hash2);
		update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, NULL);
	}
	if (sess->CurrentQuery.stmt_info && sess->CurrentQuery.stmt_info->digest_text) {
		uint64_t hash2;
		SpookyHash myhash;
		myhash.Init(19,3);
		assert(sess);
		assert(sess->client_myds);
		assert(sess->client_myds->myconn);
		assert(sess->client_myds->myconn->userinfo);
		MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;
		assert(ui->username);
		assert(ui->schemaname);
		MySQL_STMT_Global_info *stmt_info=sess->CurrentQuery.stmt_info;
		myhash.Update(ui->username,strlen(ui->username));
		myhash.Update(&stmt_info->digest,sizeof(qp->digest));
		myhash.Update(ui->schemaname,strlen(ui->schemaname));
		myhash.Update(&sess->current_hostgroup,sizeof(sess->default_hostgroup));
		myhash.Final(&qp->digest_total,&hash2);
		//delete myhash;
		update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, stmt_info);
	}
	return ret;
}

void Query_Processor::update_query_digest(SQP_par_t *qp, int hid, MySQL_Connection_userinfo *ui, unsigned long long t, unsigned long long n, MySQL_STMT_Global_info *_stmt_info) {
	spin_wrlock(&digest_rwlock);

	QP_query_digest_stats *qds;	

	std::unordered_map<uint64_t, void *>::iterator it;
	it=digest_umap.find(qp->digest_total);
	if (it != digest_umap.end()) {
		// found
		qds=(QP_query_digest_stats *)it->second;
		qds->add_time(t,n);
	} else {
		if (_stmt_info==NULL) {
			qds=new QP_query_digest_stats(ui->username, ui->schemaname, qp->digest, qp->digest_text, hid);
		} else {
			qds=new QP_query_digest_stats(ui->username, ui->schemaname, _stmt_info->digest, _stmt_info->digest_text, hid);
		}
		qds->add_time(t,n);
		digest_umap.insert(std::make_pair(qp->digest_total,(void *)qds));
	}

	spin_wrunlock(&digest_rwlock);
}

char * Query_Processor::get_digest_text(SQP_par_t *qp) {
	if (qp==NULL) return NULL;
	//SQP_par_t *qp=(SQP_par_t *)p;
	return qp->digest_text;
}

uint64_t Query_Processor::get_digest(SQP_par_t *qp) {
	if (qp==NULL) return 0;
	//SQP_par_t *qp=(SQP_par_t *)args;
	return qp->digest;
}

enum MYSQL_COM_QUERY_command Query_Processor::__query_parser_command_type(SQP_par_t *qp) {
	//SQP_par_t *qp=(SQP_par_t *)args;
	char *text=NULL; // this new variable is a pointer to either qp->digest_text , or to the query
	if (qp->digest_text) {
		text=qp->digest_text;
	} else {
		text=qp->query_prefix;
	}


	enum MYSQL_COM_QUERY_command ret=MYSQL_COM_QUERY_UNKNOWN;
	char c1;

  tokenizer_t tok = tokenizer( text, " ", TOKENIZER_NO_EMPTIES );
  char* token=NULL;
	token=(char *)tokenize(&tok);
	if (token==NULL) {
		goto __exit__query_parser_command_type;
	}

	//c1=toupper(token[0]);
	c1=token[0];
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%s Prefix:%c\n", token, c1);
	switch (c1) {
		case 'a':
		case 'A':
			if (!mystrcasecmp("ALTER",token)) { // ALTER [ONLINE | OFFLINE] [IGNORE] TABLE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!mystrcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_ALTER_TABLE;
					break;
				} else {
					if (!mystrcasecmp("OFFLINE",token) || !mystrcasecmp("ONLINE",token)) {
						token=(char *)tokenize(&tok);
						if (token==NULL) break;
						if (!mystrcasecmp("TABLE",token)) {
							ret=MYSQL_COM_QUERY_ALTER_TABLE;
							break;
						} else {
							if (!mystrcasecmp("IGNORE",token)) {
								if (token==NULL) break;
								token=(char *)tokenize(&tok);
								if (!mystrcasecmp("TABLE",token))
									ret=MYSQL_COM_QUERY_ALTER_TABLE;
									break;
							}
						}
					} else {
						if (!mystrcasecmp("IGNORE",token)) {
							if (token==NULL) break;
							token=(char *)tokenize(&tok);
							if (!mystrcasecmp("TABLE",token))
								ret=MYSQL_COM_QUERY_ALTER_TABLE;
								break;
						}
					}
				}
				if (!mystrcasecmp("VIEW",token)) {
					ret=MYSQL_COM_QUERY_ALTER_VIEW;
					break;
				}
				break;
			}
			if (!mystrcasecmp("ANALYZE",token)) { // ANALYZE [NO_WRITE_TO_BINLOG | LOCAL] TABLE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_ANALYZE_TABLE;
				} else {
					if (!strcasecmp("NO_WRITE_TO_BINLOG",token) || !strcasecmp("LOCAL",token)) {
						token=(char *)tokenize(&tok);
						if (token==NULL) break;
						if (!strcasecmp("TABLE",token)) {
							ret=MYSQL_COM_QUERY_ANALYZE_TABLE;
						}
					}
				}
				break;
			}
			break;
		case 'b':
		case 'B':
			if (!strcasecmp("BEGIN",token)) { // BEGIN
				ret=MYSQL_COM_QUERY_BEGIN;
			}
			break;
		case 'c':
		case 'C':
			if (!strcasecmp("CALL",token)) { // CALL
				ret=MYSQL_COM_QUERY_CALL;
				break;
			}
			if (!strcasecmp("CHANGE",token)) { // CHANGE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("MASTER",token)) {
					ret=MYSQL_COM_QUERY_CHANGE_MASTER;
					break;
				}
				break;
			}
			if (!strcasecmp("COMMIT",token)) { // COMMIT
				ret=MYSQL_COM_QUERY_COMMIT;
				break;
			}
			if (!strcasecmp("CREATE",token)) { // CREATE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("DATABASE",token)) {
					ret=MYSQL_COM_QUERY_CREATE_DATABASE;
					break;
				}
				if (!strcasecmp("INDEX",token)) {
					ret=MYSQL_COM_QUERY_CREATE_INDEX;
					break;
				}
				if (!strcasecmp("SCHEMA",token)) {
					ret=MYSQL_COM_QUERY_CREATE_DATABASE;
					break;
				}
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_CREATE_TABLE;
					break;
				}
				if (!strcasecmp("TEMPORARY",token)) {
					ret=MYSQL_COM_QUERY_CREATE_TEMPORARY;
					break;
				}
				if (!strcasecmp("TRIGGER",token)) {
					ret=MYSQL_COM_QUERY_CREATE_TRIGGER;
					break;
				}
				if (!strcasecmp("USER",token)) {
					ret=MYSQL_COM_QUERY_CREATE_USER;
					break;
				}
				if (!strcasecmp("VIEW",token)) {
					ret=MYSQL_COM_QUERY_CREATE_VIEW;
					break;
				}
				break;
			}
			break;
		case 'd':
		case 'D':
			if (!strcasecmp("DEALLOCATE",token)) { // DEALLOCATE PREPARE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("PREPARE",token)) {
					ret=MYSQL_COM_QUERY_DEALLOCATE;
					break;
				}
			}
			if (!strcasecmp("DELETE",token)) { // DELETE
				ret=MYSQL_COM_QUERY_DELETE;
				break;
			}
			if (!strcasecmp("DESCRIBE",token)) { // DESCRIBE
				ret=MYSQL_COM_QUERY_DESCRIBE;
				break;
			}
			if (!strcasecmp("DROP",token)) { // DROP
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_DROP_TABLE;
					break;
				}
				if (!strcasecmp("TRIGGER",token)) {
					ret=MYSQL_COM_QUERY_DROP_TRIGGER;
					break;
				}
				if (!strcasecmp("USER",token)) {
					ret=MYSQL_COM_QUERY_DROP_USER;
					break;
				}
				if (!strcasecmp("VIEW",token)) {
					ret=MYSQL_COM_QUERY_DROP_VIEW;
					break;
				}
			}
			break;
		case 'e':
		case 'E':
			if (!strcasecmp("EXECUTE",token)) { // EXECUTE
				ret=MYSQL_COM_QUERY_EXECUTE;
			}
			break;
		case 'f':
		case 'F':
			if (!strcasecmp("FLUSH",token)) { // FLUSH
				ret=MYSQL_COM_QUERY_FLUSH;
				break;
			}
			break;
		case 'g':
		case 'G':
			if (!strcasecmp("GRANT",token)) { // GRANT
				ret=MYSQL_COM_QUERY_GRANT;
				break;
			}
			break;
		case 'i':
		case 'I':
			if (!strcasecmp("INSERT",token)) { // INSERT
				ret=MYSQL_COM_QUERY_INSERT;
				break;
			}
			break;
		case 'k':
		case 'K':
			if (!strcasecmp("KILL",token)) { // KILL
				ret=MYSQL_COM_QUERY_KILL;
				break;
			}
			break;
		case 'l':
		case 'L':
			if (!strcasecmp("LOCK",token)) { // LOCK
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_LOCK_TABLE;
					break;
				}
			}
			if (!strcasecmp("LOAD",token)) { // LOAD
				ret=MYSQL_COM_QUERY_LOAD;
				break;
			}
			break;
		case 'o':
		case 'O':
			if (!strcasecmp("OPTIMIZE",token)) { // OPTIMIZE
				ret=MYSQL_COM_QUERY_OPTIMIZE;
				break;
			}
			break;
		case 'p':
		case 'P':
			if (!strcasecmp("PREPARE",token)) { // PREPARE
				ret=MYSQL_COM_QUERY_PREPARE;
				break;
			}
			if (!strcasecmp("PURGE",token)) { // PURGE
				ret=MYSQL_COM_QUERY_PURGE;
				break;
			}
			break;
		case 'r':
		case 'R':
			if (!strcasecmp("RENAME",token)) { // RENAME
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_RENAME_TABLE;
					break;
				}
			}
			if (!strcasecmp("REPLACE",token)) { // REPLACE
				ret=MYSQL_COM_QUERY_REPLACE;
				break;
			}
			if (!strcasecmp("RESET",token)) { // RESET
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("MASTER",token)) {
					ret=MYSQL_COM_QUERY_RESET_MASTER;
					break;
				}
				if (!strcasecmp("SLAVE",token)) {
					ret=MYSQL_COM_QUERY_RESET_SLAVE;
					break;
				}
				break;
			}
			if (!strcasecmp("REVOKE",token)) { // REVOKE
				ret=MYSQL_COM_QUERY_REVOKE;
				break;
			}
			if (!strcasecmp("ROLLBACK",token)) { // ROLLBACK
				ret=MYSQL_COM_QUERY_ROLLBACK;
				break;
			}
			break;
		case 's':
		case 'S':
			if (!mystrcasecmp("SAVEPOINT",token)) { // SAVEPOINT
				ret=MYSQL_COM_QUERY_SAVEPOINT;
				break;
			}
			if (!mystrcasecmp("SELECT",token)) { // SELECT
				ret=MYSQL_COM_QUERY_SELECT;
				break;
				// FIXME: SELECT FOR UPDATE is not implemented
			}
			if (!mystrcasecmp("SET",token)) { // SET
				ret=MYSQL_COM_QUERY_SET;
				break;
			}
			if (!mystrcasecmp("SHOW",token)) { // SHOW
				ret=MYSQL_COM_QUERY_SHOW;
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					token=(char *)tokenize(&tok);
					if (token==NULL) break;
					if (!strcasecmp("STATUS",token)) {
						ret=MYSQL_COM_QUERY_SHOW_TABLE_STATUS;
					}
				}
				break;
			}
			if (!mystrcasecmp("START",token)) { // START
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("TRANSACTION",token)) {
					ret=MYSQL_COM_QUERY_START_TRANSACTION;
				}
				break;
			}
			break;
		case 't':
		case 'T':
			if (!strcasecmp("TRUNCATE",token)) { // TRUNCATE
				if (token==NULL) break;
				if (!strcasecmp("TABLE",token)) {
					ret=MYSQL_COM_QUERY_TRUNCATE_TABLE;
					break;
				}
			}
			break;
		case 'u':
		case 'U':
			if (!strcasecmp("UNLOCK",token)) { // UNLOCK
				ret=MYSQL_COM_QUERY_UNLOCK_TABLES;
				break;
			}
			if (!strcasecmp("UPDATE",token)) { // UPDATE
				ret=MYSQL_COM_QUERY_UPDATE;
				break;
			}
			break;
		default:
			break;
	}

__exit__query_parser_command_type:
  free_tokenizer( &tok );
	if (qp->query_prefix) {
		free(qp->query_prefix);
		qp->query_prefix=NULL;
	}
	return ret;
}

bool Query_Processor::query_parser_first_comment(Query_Processor_Output *qpo, char *fc) {
	bool ret=false;
	tokenizer_t tok = tokenizer( fc, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for ( token = tokenize( &tok ) ; token ;  token = tokenize( &tok ) ) {
		char *key=NULL;
		char *value=NULL;
    c_split_2(token, "=", &key, &value);
		remove_spaces(key);
		remove_spaces(value);
		if (strlen(key)) {
			char c=value[0];
			if (!strcasecmp(key,"cache_ttl")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->cache_ttl=t;
				}
			}
			if (!strcasecmp(key,"query_delay")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->delay=t;
				}
			}
			if (!strcasecmp(key,"query_retries")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->retries=t;
				}
			}
			if (!strcasecmp(key,"query_timeout")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->timeout=t;
				}
			}
			if (!strcasecmp(key,"hostgroup")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->destination_hostgroup=t;
				}
			}
			if (!strcasecmp(key,"mirror")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					qpo->mirror_hostgroup=t;
				}
			}
		}
		free(key);
		free(value);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Variables in comment %s , key=%s , value=%s\n", token, key, value);
	}
	free_tokenizer( &tok );
	return ret;
}


void Query_Processor::query_parser_free(SQP_par_t *qp) {
	if (qp->digest_text) {
		free(qp->digest_text);
		qp->digest_text=NULL;
	}
	if (qp->first_comment) {
		free(qp->first_comment);
		qp->first_comment=NULL;
	}
};
