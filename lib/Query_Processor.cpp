#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "query_processor.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "pcrecpp.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_PROCESSOR_VERSION "2.0.6.0805" DEB

#define QP_RE_MOD_CASELESS 1
#define QP_RE_MOD_GLOBAL 2


#include <thread>
#include <future>
extern MySQL_Threads_Handler *GloMTH;

static int int_cmp(const void *a, const void *b) {
	const unsigned long long *ia = (const unsigned long long *)a;
	const unsigned long long *ib = (const unsigned long long *)b;
	if (*ia < *ib) return -1;
	if (*ia > *ib) return 1;
	return 0;
}

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
	~QP_rule_text() {
		for(int i=0; i<num_fields; i++) {
			free_null(pta[i]);
		}
		free(pta);
	}
};

/* reverse:  reverse string s in place */
void reverse(char s[]) {
	int i, j;
	char c;
	int l = strlen(s);
	for (i = 0, j = l-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

/* itoa:  convert n to characters in s */
void my_itoa(char s[], unsigned long long n)
{
	int i;
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     s[i] = '\0';
     reverse(s);
}

QP_query_digest_stats::QP_query_digest_stats(char *u, char *s, uint64_t d, char *dt, int h, char *ca) {
	digest=d;
	digest_text=NULL;
	if (dt) {
		digest_text=strndup(dt, mysql_thread___query_digests_max_digest_length);
	}
	if (strlen(u) < sizeof(username_buf)) {
		strcpy(username_buf,u);
		username = username_buf;
	} else {
		username=strdup(u);
	}
	if (strlen(s) < sizeof(schemaname_buf)) {
		strcpy(schemaname_buf,s);
		schemaname = schemaname_buf;
	} else {
		schemaname=strdup(s);
	}
	if (strlen(ca) < sizeof(client_address_buf)) {
		strcpy(client_address_buf,ca);
		client_address = client_address_buf;
	} else {
		client_address=strdup(ca);
	}
	count_star=0;
	first_seen=0;
	last_seen=0;
	sum_time=0;
	min_time=0;
	max_time=0;
	rows_affected=0;
	rows_sent=0;
	hid=h;
}
void QP_query_digest_stats::add_time(unsigned long long t, unsigned long long n, unsigned long long ra, unsigned long long rs) {
	count_star++;
	sum_time+=t;
	rows_affected+=ra;
	rows_sent+=rs;
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
QP_query_digest_stats::~QP_query_digest_stats() {
	if (digest_text) {
		free(digest_text);
		digest_text=NULL;
	}
	if (username) {
		if (username == username_buf) {
		} else {
			free(username);
		}
		username=NULL;
	}
	if (schemaname) {
		if (schemaname == schemaname_buf) {
		} else {
			free(schemaname);
		}
		schemaname=NULL;
	}
	if (client_address) {
		if (client_address == client_address_buf) {
		} else {
			free(client_address);
		}
		client_address=NULL;
	}
}
char **QP_query_digest_stats::get_row(umap_query_digest_text *digest_text_umap, query_digest_stats_pointers_t *qdsp) {
	char **pta=qdsp->pta;

	assert(schemaname);
	pta[0]=schemaname;
	assert(username);
	pta[1]=username;
	assert(client_address);
	pta[2]=client_address;

	assert(qdsp != NULL);
	assert(qdsp->digest);
	sprintf(qdsp->digest,"0x%016llX", (long long unsigned int)digest);
	pta[3]=qdsp->digest;

	if (digest_text) {
		pta[4]=digest_text;
	} else {
		std::unordered_map<uint64_t, char *>::iterator it;
		it=digest_text_umap->find(digest);
		if (it != digest_text_umap->end()) {
			pta[4] = it->second;
		} else {
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
		}
	}

	//sprintf(qdsp->count_star,"%u",count_star);
	my_itoa(qdsp->count_star, count_star);
	pta[5]=qdsp->count_star;

	time_t __now;
	time(&__now);
	unsigned long long curtime=monotonic_time();
	time_t seen_time;
	seen_time= __now - curtime/1000000 + first_seen/1000000;
	//sprintf(qdsp->first_seen,"%ld", seen_time);
	my_itoa(qdsp->first_seen, seen_time);
	pta[6]=qdsp->first_seen;

	seen_time= __now - curtime/1000000 + last_seen/1000000;
	//sprintf(qdsp->last_seen,"%ld", seen_time);
	my_itoa(qdsp->last_seen, seen_time);
	pta[7]=qdsp->last_seen;
	//sprintf(qdsp->sum_time,"%llu",sum_time);
	my_itoa(qdsp->sum_time,sum_time);
	pta[8]=qdsp->sum_time;
	//sprintf(qdsp->min_time,"%llu",min_time);
	my_itoa(qdsp->min_time,min_time);
	pta[9]=qdsp->min_time;
	//sprintf(qdsp->max_time,"%llu",max_time);
	my_itoa(qdsp->max_time,max_time);
	pta[10]=qdsp->max_time;
	// we are reverting this back to the use of sprintf instead of my_itoa
	// because with my_itoa we are losing the sign
	// see issue #2285
	sprintf(qdsp->hid,"%d",hid);
	//my_itoa(qdsp->hid,hid);
	pta[11]=qdsp->hid;
	//sprintf(qdsp->rows_affected,"%llu",rows_affected);
	my_itoa(qdsp->rows_affected,rows_affected);
	pta[12]=qdsp->rows_affected;
	//sprintf(qdsp->rows_sent,"%llu",rows_sent);
	my_itoa(qdsp->rows_sent,rows_sent);
	pta[13]=qdsp->rows_sent;
	return pta;
}

struct __RE2_objects_t {
	pcrecpp::RE_Options *opt1;
	pcrecpp::RE *re1;
	re2::RE2::Options *opt2;
	RE2 *re2;
};

typedef struct __RE2_objects_t re2_t;

static bool rules_sort_comp_function (QP_rule_t * a, QP_rule_t * b) { return (a->rule_id < b->rule_id); }


static unsigned long long mem_used_rule(QP_rule_t *qr) {
	unsigned long long s = sizeof(QP_rule_t);
	if (qr->username)
		s+=strlen(qr->username);
	if (qr->schemaname)
		s+=strlen(qr->schemaname);
	if (qr->client_addr)
		s+=strlen(qr->client_addr);
	if (qr->proxy_addr)
		s+=strlen(qr->proxy_addr);
	if (qr->match_digest)
		s+=strlen(qr->match_digest)*10; // not sure how much is used for regex
	if (qr->match_pattern)
		s+=strlen(qr->match_pattern)*10; // not sure how much is used for regex
	if (qr->replace_pattern)
		s+=strlen(qr->replace_pattern)*10; // not sure how much is used for regex
	if (qr->error_msg)
		s+=strlen(qr->error_msg);
	if (qr->OK_msg)
		s+=strlen(qr->OK_msg);
	if (qr->comment)
		s+=strlen(qr->comment);
	if (qr->match_digest || qr->match_pattern || qr->replace_pattern) {
		s+= sizeof(__RE2_objects_t *)+sizeof(__RE2_objects_t);
		s+= sizeof(pcrecpp::RE_Options *) + sizeof(pcrecpp::RE_Options);
		s+= sizeof(pcrecpp::RE *) + sizeof(pcrecpp::RE);
		s+= sizeof(re2::RE2::Options *) + sizeof(re2::RE2::Options);
		s+= sizeof(RE2 *) + sizeof(RE2);
	}
	return s;
}

static re2_t * compile_query_rule(QP_rule_t *qr, int i) {
	re2_t *r=(re2_t *)malloc(sizeof(re2_t));
	r->opt1=NULL;
	r->re1=NULL;
	r->opt2=NULL;
	r->re2=NULL;
	if (mysql_thread___query_processor_regex==2) {
		r->opt2=new re2::RE2::Options(RE2::Quiet);
		if ((qr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) {
			r->opt2->set_case_sensitive(false);
		}
		if (i==1) {
			r->re2=new RE2(qr->match_digest, *r->opt2);
		} else if (i==2) {
			r->re2=new RE2(qr->match_pattern, *r->opt2);
		}
	} else {
		r->opt1=new pcrecpp::RE_Options();
		if ((qr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) {
			r->opt1->set_caseless(true);
		}
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
	if (qr->match_digest)
		free(qr->match_digest);
	if (qr->match_pattern)
		free(qr->match_pattern);
	if (qr->replace_pattern)
		free(qr->replace_pattern);
	if (qr->error_msg)
		free(qr->error_msg);
	if (qr->OK_msg)
		free(qr->OK_msg);
	if (qr->attributes)
		free(qr->attributes);
	if (qr->comment)
		free(qr->comment);
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
__thread khash_t(khStrInt) * _thr_SQP_rules_fast_routing;
__thread char * _thr___rules_fast_routing___keys_values;
__thread Command_Counter * _thr_commands_counters[MYSQL_COM_QUERY___NONE];

Query_Processor::Query_Processor() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Query Processor with version=0\n");

	// firewall
	pthread_mutex_init(&global_mysql_firewall_whitelist_mutex, NULL);
	global_mysql_firewall_whitelist_users_runtime = NULL;
	global_mysql_firewall_whitelist_rules_runtime = NULL;
	global_mysql_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	global_mysql_firewall_whitelist_users_map___size = 0;
	global_mysql_firewall_whitelist_users_result___size = 0;
	global_mysql_firewall_whitelist_rules_map___size = 0;
	global_mysql_firewall_whitelist_rules_result___size = 0;

	pthread_rwlock_init(&rwlock, NULL);
	pthread_rwlock_init(&digest_rwlock, NULL);
	version=0;
	rules_mem_used=0;
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
  commands_counters_desc[MYSQL_COM_QUERY_RELEASE_SAVEPOINT]=(char *)"RELEASE_SAVEPOINT";
  commands_counters_desc[MYSQL_COM_QUERY_RENAME_TABLE]=(char *)"RENAME_TABLE";
  commands_counters_desc[MYSQL_COM_QUERY_RESET_MASTER]=(char *)"RESET_MASTER";
  commands_counters_desc[MYSQL_COM_QUERY_RESET_SLAVE]=(char *)"RESET_SLAVE";
  commands_counters_desc[MYSQL_COM_QUERY_REPLACE]=(char *)"REPLACE";
  commands_counters_desc[MYSQL_COM_QUERY_REVOKE]=(char *)"REVOKE";
  commands_counters_desc[MYSQL_COM_QUERY_ROLLBACK]=(char *)"ROLLBACK";
  commands_counters_desc[MYSQL_COM_QUERY_ROLLBACK_SAVEPOINT]=(char *)"ROLLBACK_SAVEPOINT";
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

	{
		static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		rand_del[0] = '-';
		rand_del[1] = '-';
		rand_del[2] = '-';
		for (int i = 3; i < 11; i++) {
			rand_del[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}
		rand_del[11] = '-';
		rand_del[12] = '-';
		rand_del[13] = '-';
		rand_del[14] = 0;
	}
	query_rules_resultset = NULL;
	fast_routing_resultset = NULL;
	rules_fast_routing = kh_init(khStrInt); // create a hashtable
	rules_fast_routing___keys_values = NULL;
	rules_fast_routing___keys_values___size = 0;
	new_req_conns_count = 0;
};

Query_Processor::~Query_Processor() {
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete commands_counters[i];
	__reset_rules(&rules);
	kh_destroy(khStrInt, rules_fast_routing);
	if (rules_fast_routing___keys_values) {
		free(rules_fast_routing___keys_values);
		rules_fast_routing___keys_values = NULL;
		rules_fast_routing___keys_values___size = 0;
	}
	for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
		QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
		delete qds;
	}
	for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap.begin(); it!=digest_text_umap.end(); ++it) {
		free(it->second);
	}
	digest_umap.erase(digest_umap.begin(),digest_umap.end());
	digest_text_umap.erase(digest_text_umap.begin(),digest_text_umap.end());
	if (query_rules_resultset) {
		delete query_rules_resultset;
		query_rules_resultset = NULL;
	}
	if (fast_routing_resultset) {
		delete fast_routing_resultset;
		fast_routing_resultset = NULL;
	}
	if (global_mysql_firewall_whitelist_users_runtime) {
		delete global_mysql_firewall_whitelist_users_runtime;
		global_mysql_firewall_whitelist_users_runtime = NULL;
	}
	if (global_mysql_firewall_whitelist_rules_runtime) {
		delete global_mysql_firewall_whitelist_rules_runtime;
		global_mysql_firewall_whitelist_rules_runtime = NULL;
	}
	if (global_mysql_firewall_whitelist_sqli_fingerprints_runtime) {
		delete global_mysql_firewall_whitelist_sqli_fingerprints_runtime;
		global_mysql_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	}
};

// This function is called by each thread when it starts. It create a Query Processor Table for each thread
void Query_Processor::init_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Per-Thread Query Processor Table with version=0\n");
	_thr_SQP_version=0;
	_thr_SQP_rules=new std::vector<QP_rule_t *>;
	_thr_SQP_rules_fast_routing = kh_init(khStrInt); // create a hashtable
	_thr___rules_fast_routing___keys_values = NULL;
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) _thr_commands_counters[i] = new Command_Counter(i);
};


void Query_Processor::end_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Destroying Per-Thread Query Processor Table with version=%d\n", _thr_SQP_version);
	__reset_rules(_thr_SQP_rules);
	delete _thr_SQP_rules;
	kh_destroy(khStrInt, _thr_SQP_rules_fast_routing);
	if (_thr___rules_fast_routing___keys_values) {
		free(_thr___rules_fast_routing___keys_values);
		_thr___rules_fast_routing___keys_values = NULL;
	}
	for (int i=0; i<MYSQL_COM_QUERY___NONE; i++) delete _thr_commands_counters[i];
};

void Query_Processor::print_version() {
	fprintf(stderr,"Standard Query Processor rev. %s -- %s -- %s\n", QUERY_PROCESSOR_VERSION, __FILE__, __TIMESTAMP__);
};

void Query_Processor::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
};

void Query_Processor::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
};

unsigned long long Query_Processor::get_rules_mem_used() {
	unsigned long long s = 0;
	wrlock();
	s = rules_mem_used;
	wrunlock();
	return s;
}

unsigned long long Query_Processor::get_new_req_conns_count() {
	return __sync_fetch_and_add(&new_req_conns_count, 0);
}

QP_rule_t * Query_Processor::new_query_rule(int rule_id, bool active, char *username, char *schemaname, int flagIN, char *client_addr, char *proxy_addr, int proxy_port, char *digest, char *match_digest, char *match_pattern, bool negate_match_pattern, char *re_modifiers, int flagOUT, char *replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result, int cache_timeout , int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_flagOUT, int mirror_hostgroup, char *error_msg, char *OK_msg, int sticky_conn, int multiplex, int gtid_from_hostgroup, int log, bool apply, char *attributes, char *comment) {
	QP_rule_t * newQR=(QP_rule_t *)malloc(sizeof(QP_rule_t));
	newQR->rule_id=rule_id;
	newQR->active=active;
	newQR->username=(username ? strdup(username) : NULL);
	newQR->schemaname=(schemaname ? strdup(schemaname) : NULL);
	newQR->flagIN=flagIN;
	newQR->match_digest=(match_digest ? strdup(match_digest) : NULL);
	newQR->match_pattern=(match_pattern ? strdup(match_pattern) : NULL);
	newQR->negate_match_pattern=negate_match_pattern;
	newQR->re_modifiers=0;
	{
		tokenizer_t tok;
		tokenizer( &tok, re_modifiers, ",", TOKENIZER_NO_EMPTIES );
		const char* token;
		for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
			if (strncasecmp(token,(char *)"CASELESS",strlen((char *)"CASELESS"))==0) {
				newQR->re_modifiers|=QP_RE_MOD_CASELESS;
			}
			if (strncasecmp(token,(char *)"GLOBAL",strlen((char *)"GLOBAL"))==0) {
				newQR->re_modifiers|=QP_RE_MOD_GLOBAL;
			}
		}
		free_tokenizer( &tok );
	}
	newQR->flagOUT=flagOUT;
	newQR->replace_pattern=(replace_pattern ? strdup(replace_pattern) : NULL);
	newQR->destination_hostgroup=destination_hostgroup;
	newQR->cache_ttl=cache_ttl;
	newQR->cache_empty_result=cache_empty_result;
	newQR->cache_timeout=cache_timeout;
	newQR->reconnect=reconnect;
	newQR->timeout=timeout;
	newQR->retries=retries;
	newQR->delay=delay;
	newQR->next_query_flagIN=next_query_flagIN;
	newQR->mirror_flagOUT=mirror_flagOUT;
	newQR->mirror_hostgroup=mirror_hostgroup;
	newQR->error_msg=(error_msg ? strdup(error_msg) : NULL);
	newQR->OK_msg=(OK_msg ? strdup(OK_msg) : NULL);
	newQR->sticky_conn=sticky_conn;
	newQR->multiplex=multiplex;
	newQR->gtid_from_hostgroup = gtid_from_hostgroup;
	newQR->apply=apply;
	newQR->attributes=(attributes ? strdup(attributes) : NULL);
	newQR->comment=(comment ? strdup(comment) : NULL); // see issue #643
	newQR->regex_engine1=NULL;
	newQR->regex_engine2=NULL;
	newQR->hits=0;

	newQR->client_addr_wildcard_position = -1; // not existing by default
	newQR->client_addr=(client_addr ? strdup(client_addr) : NULL);
	if (newQR->client_addr) {
		char *pct = strchr(newQR->client_addr,'%');
		if (pct) { // there is a wildcard . We assume Admin did already all the input validation
			if (pct == newQR->client_addr) {
				// client_addr == '%'
				// % is at the end of the string, but also at the beginning
				// becoming a catch all
				newQR->client_addr_wildcard_position = 0;
			} else {
				// this math is valid also if (pct == newQR->client_addr)
				// but we separate it to clarify that client_addr_wildcard_position is a match all
				newQR->client_addr_wildcard_position = strlen(newQR->client_addr) - strlen(pct);
			}
		}
	}
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
	if (lock)
		pthread_rwlock_wrlock(&rwlock);
	__reset_rules(&rules);
	if (rules_fast_routing) {
		kh_destroy(khStrInt, rules_fast_routing);
		rules_fast_routing = NULL;
		rules_fast_routing = kh_init(khStrInt); // create a hashtable
	}
	free(rules_fast_routing___keys_values);
	rules_fast_routing___keys_values = NULL;
	rules_fast_routing___keys_values___size = 0;
	if (lock)
		pthread_rwlock_unlock(&rwlock);
	rules_mem_used=0;
};

bool Query_Processor::insert(QP_rule_t *qr, bool lock) {
	bool ret=true;
	if (lock)
		pthread_rwlock_wrlock(&rwlock);
	rules.push_back(qr);
	rules_mem_used += mem_used_rule(qr);
	if (lock)
		pthread_rwlock_unlock(&rwlock);
	return ret;
};

void Query_Processor::sort(bool lock) {
	if (lock)
		pthread_rwlock_wrlock(&rwlock);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Sorting rules\n");
	std::sort (rules.begin(), rules.end(), rules_sort_comp_function);
	if (lock)
		pthread_rwlock_unlock(&rwlock);
};

// when commit is called, the version number is increased and the this will trigger the mysql threads to get a new Query Processor Table
// The operation is asynchronous
void Query_Processor::commit() {
	__sync_add_and_fetch(&version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Increasing version number to %d - all threads will notice this and refresh their rules\n", version);
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
	for (int i=0 ; i < MYSQL_COM_QUERY__UNINITIALIZED ; i++) {
		char **pta=commands_counters[i]->get_row();
		result->add_row(pta);
		commands_counters[i]->free_row(pta);
	}
	return result;
}
SQLite3_result * Query_Processor::get_stats_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping query rules statistics, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(2);
	pthread_rwlock_rdlock(&rwlock);
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
	pthread_rwlock_unlock(&rwlock);
	return result;
}

SQLite3_result * Query_Processor::get_current_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(35);
	pthread_rwlock_rdlock(&rwlock);
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
	result->add_column_definition(SQLITE_TEXT,"re_modifiers");
	result->add_column_definition(SQLITE_TEXT,"flagOUT");
	result->add_column_definition(SQLITE_TEXT,"replace_pattern");
	result->add_column_definition(SQLITE_TEXT,"destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"cache_ttl");
	result->add_column_definition(SQLITE_TEXT,"cache_empty_result");
	result->add_column_definition(SQLITE_TEXT,"cache_timeout");
	result->add_column_definition(SQLITE_TEXT,"reconnect");
	result->add_column_definition(SQLITE_TEXT,"timeout");
	result->add_column_definition(SQLITE_TEXT,"retries");
	result->add_column_definition(SQLITE_TEXT,"delay");
	result->add_column_definition(SQLITE_TEXT,"next_query_flagIN");
	result->add_column_definition(SQLITE_TEXT,"mirror_flagOUT");
	result->add_column_definition(SQLITE_TEXT,"mirror_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"error_msg");
	result->add_column_definition(SQLITE_TEXT,"OK_msg");
	result->add_column_definition(SQLITE_TEXT,"sticky_conn");
	result->add_column_definition(SQLITE_TEXT,"multiplex");
	result->add_column_definition(SQLITE_TEXT,"gtid_from_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"log");
	result->add_column_definition(SQLITE_TEXT,"apply");
	result->add_column_definition(SQLITE_TEXT,"attributes");
	result->add_column_definition(SQLITE_TEXT,"comment"); // issue #643
	result->add_column_definition(SQLITE_TEXT,"hits");
	for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
		qr1=*it;
		QP_rule_text *qt=new QP_rule_text(qr1);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
		result->add_row(qt->pta);
		delete qt;
	}
	pthread_rwlock_unlock(&rwlock);
	return result;
}

int Query_Processor::get_current_query_rules_fast_routing_count() {
	int result = 0;
	pthread_rwlock_rdlock(&rwlock);
	result = fast_routing_resultset->rows_count;
	pthread_rwlock_unlock(&rwlock);
	return result;
}

// we return the resultset fast_routing_resultset
// the caller of this function must lock Query Processor
SQLite3_result * Query_Processor::get_current_query_rules_fast_routing_inner() {
	return fast_routing_resultset;
}
// we return the resultset query_rules_resultset
// the caller of this function must lock Query Processor
SQLite3_result * Query_Processor::get_current_query_rules_inner() {
	return query_rules_resultset;
}

SQLite3_result * Query_Processor::get_current_query_rules_fast_routing() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules fast_routing, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(5);
	pthread_rwlock_rdlock(&rwlock);
	//QP_rule_t *qr1;
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"flagIN");
	result->add_column_definition(SQLITE_TEXT,"destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT,"comment");
/*
	for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
		qr1=*it;
		QP_rule_text *qt=new QP_rule_text(qr1);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
		result->add_row(qt->pta);
		delete qt;
	}
*/
	for (std::vector<SQLite3_row *>::iterator it = fast_routing_resultset->rows.begin() ; it != fast_routing_resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		result->add_row(r);
	}
	pthread_rwlock_unlock(&rwlock);
	return result;
}

struct get_query_digests_parallel_args {
	unsigned long long ret;
	pthread_t thr;
	umap_query_digest *gu;
	umap_query_digest_text *gtu;
	int m;
	SQLite3_result *result;
	QP_query_digest_stats **array_qds;
	bool free_me;
	bool defer_free;
};

/*
	All operations are performed without taking an explicit lock because
	the calling function already took the lock
*/
//unsigned long long iget_query_digests_total_size_parallel(umap_query_digest *gu, umap_query_digest_text *gtu, int *m_, unsigned long long *r2) {
void * get_query_digests_total_size_parallel(void *_arg) {
	get_query_digests_parallel_args *arg = (get_query_digests_parallel_args *)_arg;
	unsigned long long i = 0;
	unsigned long long m = arg->m;
	unsigned long long ret = 0;
	for (std::unordered_map<uint64_t, void *>::iterator it=arg->gu->begin(); it!=arg->gu->end(); ++it) {
		if ((i%DIGEST_STATS_FAST_THREADS)==m) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			if (qds->username)
				if (qds->username != qds->username_buf)
					ret += strlen(qds->username) + 1;
			if (qds->schemaname)
				if (qds->schemaname != qds->schemaname_buf)
					ret += strlen(qds->schemaname) + 1;
			if (qds->client_address)
				if (qds->client_address != qds->client_address_buf)
					ret += strlen(qds->client_address) + 1;
			if (qds->digest_text)
				ret += strlen(qds->digest_text) + 1;
		}
		i++;
	}
	i = 0;
	for (std::unordered_map<uint64_t, char *>::iterator it=arg->gtu->begin(); it!=arg->gtu->end(); ++it) {
		if ((i%DIGEST_STATS_FAST_THREADS)==m) {
			if (it->second) {
				ret += strlen(it->second) + 1;
			}
		}
		i++;
	}
	arg->ret = ret;
	return NULL;
}

void * get_query_digests_parallel(void *_arg) {
	get_query_digests_parallel_args *arg = (get_query_digests_parallel_args *)_arg;
	unsigned long long i = 0;
	unsigned long long m = arg->m;
	unsigned long long ret = 0;
	if (arg->free_me) {
		if (arg->defer_free) {
			size_t map_size = arg->gu->size();
			arg->array_qds = (QP_query_digest_stats **)malloc(sizeof(QP_query_digest_stats *)*map_size);
		}
	}
	for (std::unordered_map<uint64_t, void *>::iterator it=arg->gu->begin(); it!=arg->gu->end(); ++it) {
		if ((i%DIGEST_STATS_FAST_THREADS)==m) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			query_digest_stats_pointers_t *a = (query_digest_stats_pointers_t *)malloc(sizeof(query_digest_stats_pointers_t));
			char **pta=qds->get_row(arg->gtu, a);
			arg->result->add_row(pta);
			free(a);
			if (arg->free_me) {
				if (arg->defer_free) {
					arg->array_qds[ret] = qds;
					ret++;
				} else {
					delete qds;
				}
			}
		}
		i++;
	}
	if (arg->free_me) {
		if (arg->defer_free) {
			arg->ret = ret;
		}
	}
/* benchmarks say this part if faster if single-threaded
	if (arg->free_me) {
		i = 0;
		for (std::unordered_map<uint64_t, char *>::iterator it=arg->gtu->begin(); it!=arg->gtu->end(); ++it) {
			if ((i%DIGEST_STATS_FAST_THREADS)==m) {
				free(it->second);
			}
		}
	}
*/
	return NULL;
}

void * purge_query_digests_parallel(void *_arg) {
	get_query_digests_parallel_args *arg = (get_query_digests_parallel_args *)_arg;
	unsigned long long i = 0;
	unsigned long long r = 0;
	unsigned long long m = arg->m;
	for (std::unordered_map<uint64_t, void *>::iterator it=arg->gu->begin(); it!=arg->gu->end(); ++it) {
		if ((i%DIGEST_STATS_FAST_THREADS)==m) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			delete qds;
			r++;
		}
		i++;
	}
	arg->ret = r;
	i = 0;
	for (std::unordered_map<uint64_t, char *>::iterator it=arg->gtu->begin(); it!=arg->gtu->end(); ++it) {
		if ((i%DIGEST_STATS_FAST_THREADS)==m) {
			free(it->second);
		}
	}
	return NULL;
}

unsigned long long Query_Processor::purge_query_digests(bool async_purge, bool parallel, char **msg) {
	unsigned long long ret = 0;
	if (async_purge) {
		ret = purge_query_digests_async(msg);
	} else {
		ret = purge_query_digests_sync(parallel);
	}
	return ret;
}

unsigned long long Query_Processor::purge_query_digests_async(char **msg) {
	unsigned long long ret = 0;
	pthread_rwlock_wrlock(&digest_rwlock);
	unsigned long long curtime1=monotonic_time();
	size_t map1_size = digest_umap.size();
	size_t map2_size = digest_text_umap.size();
	ret = map1_size + map2_size;
	unsigned long long i = 0;
	QP_query_digest_stats **array1 = (QP_query_digest_stats **)malloc(sizeof(QP_query_digest_stats *)*map1_size);
	char **array2 = (char **)malloc(sizeof(char *)*map2_size);

	i=0;
	for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
		array1[i]=(QP_query_digest_stats *)it->second;
		i++;
		//delete qds;
	}
	i=0;
	for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap.begin(); it!=digest_text_umap.end(); ++it) {
		array2[i] = it->second;
		//free(it->second);
		i++;
	}
	digest_umap.erase(digest_umap.begin(),digest_umap.end());
	digest_text_umap.erase(digest_text_umap.begin(),digest_text_umap.end());
	pthread_rwlock_unlock(&digest_rwlock);
	unsigned long long curtime2=monotonic_time();
	curtime1 = curtime1/1000;
	curtime2 = curtime2/1000;
	if (map1_size >= DIGEST_STATS_FAST_MINSIZE) {
		proxy_info("Purging stats_mysql_query_digest: locked for %llums to remove %lu entries\n", curtime2-curtime1, map1_size);
	}
	char buf[128];
	sprintf(buf, "Query digest map locked for %llums", curtime2-curtime1);
	*msg = strdup(buf);
	for (i=0; i<map1_size; i++) {
		QP_query_digest_stats *qds = array1[i];
		delete qds;
	}
	for (i=0; i<map2_size; i++) {
		char *p = array2[i];
		free(p);
	}
	free(array1);
	free(array2);
	return ret;
}

unsigned long long Query_Processor::purge_query_digests_sync(bool parallel) {
	unsigned long long ret = 0;
	pthread_rwlock_wrlock(&digest_rwlock);
	size_t map_size = digest_umap.size();
	if (parallel && map_size >= DIGEST_STATS_FAST_MINSIZE) { // parallel purge
		int n=DIGEST_STATS_FAST_THREADS;
		get_query_digests_parallel_args args[n];
		for (int i=0; i<n; i++) {
			args[i].m=i;
			args[i].ret=0;
			args[i].gu = &digest_umap;
			args[i].gtu = &digest_text_umap;
		}
		for (int i=0; i<n; i++) {
			if ( pthread_create(&args[i].thr, NULL, &purge_query_digests_parallel, &args[i]) != 0 ) {
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
		for (int i=0; i<n; i++) {
			pthread_join(args[i].thr, NULL);
			ret += args[i].ret;
		}
	} else {
		for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			delete qds;
			ret++;
		}
		for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap.begin(); it!=digest_text_umap.end(); ++it) {
			free(it->second);
		}
	}
	digest_umap.erase(digest_umap.begin(),digest_umap.end());
	digest_text_umap.erase(digest_text_umap.begin(),digest_text_umap.end());
	pthread_rwlock_unlock(&digest_rwlock);
	return ret;
}

unsigned long long Query_Processor::get_query_digests_total_size() {
	unsigned long long ret=0;
	pthread_rwlock_rdlock(&digest_rwlock);
	size_t map_size = digest_umap.size();
	ret += sizeof(QP_query_digest_stats)*map_size;
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) { // parallel search
/*
		int n = GloMTH->num_threads;
		std::future<unsigned long long> results[n];
*/
		int n=DIGEST_STATS_FAST_THREADS;
		//unsigned long long result2[n];
		//int k[n];
		get_query_digests_parallel_args args[n];
		for (int i=0; i<n; i++) {
			args[i].m=i;
			args[i].ret=0;
			args[i].gu = &digest_umap;
			args[i].gtu = &digest_text_umap;
		}
		for (int i=0; i<n; i++) {
			if ( pthread_create(&args[i].thr, NULL, &get_query_digests_total_size_parallel, &args[i]) != 0 ) {
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
		for (int i=0; i<n; i++) {
			pthread_join(args[i].thr, NULL);
			ret += args[i].ret;
		}
/*
		// failed attempt to use async . Will try later
		auto results0 = std::async(std::launch::async, get_query_digests_total_size_parallel, &digest_umap, &digest_text_umap, &k[0], &result2[0]);
		auto results1 = std::async(std::launch::async, get_query_digests_total_size_parallel, &digest_umap, &digest_text_umap, &k[1], &result2[1]);
		auto results2 = std::async(std::launch::async, get_query_digests_total_size_parallel, &digest_umap, &digest_text_umap, &k[2], &result2[2]);
		auto results3 = std::async(std::launch::async, get_query_digests_total_size_parallel, &digest_umap, &digest_text_umap, &k[3], &result2[3]);
		ret += results0.get();
		ret += results1.get();
		ret += results2.get();
		ret += results3.get();
*/
	}
#if !defined(__FreeBSD__) && !defined(__APPLE__)
	ret += ((sizeof(uint64_t) + sizeof(void *) + sizeof(std::_Rb_tree_node_base)) * digest_umap.size() );
	ret += ((sizeof(uint64_t) + sizeof(void *) + sizeof(std::_Rb_tree_node_base)) * digest_text_umap.size() );
#else
	ret += ((sizeof(uint64_t) + sizeof(void *) + 32) * digest_umap.size() );
	ret += ((sizeof(uint64_t) + sizeof(void *) + 32) * digest_text_umap.size() );
#endif

	pthread_rwlock_unlock(&digest_rwlock);
	return ret;
}

SQLite3_result * Query_Processor::get_query_digests() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query digest\n");
	SQLite3_result *result = NULL;
	pthread_rwlock_rdlock(&digest_rwlock);
	unsigned long long curtime1;
	unsigned long long curtime2;
	size_t map_size = digest_umap.size();
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		result = new SQLite3_result(14, true);
		curtime1 = monotonic_time();
	} else {
		result = new SQLite3_result(14);
	}
	result->add_column_definition(SQLITE_TEXT,"hid");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"client_address");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"digest_text");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");
	result->add_column_definition(SQLITE_TEXT,"sum_time");
	result->add_column_definition(SQLITE_TEXT,"min_time");
	result->add_column_definition(SQLITE_TEXT,"max_time");
	result->add_column_definition(SQLITE_TEXT,"rows_affected");
	result->add_column_definition(SQLITE_TEXT,"rows_sent");
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		int n=DIGEST_STATS_FAST_THREADS;
		get_query_digests_parallel_args args[n];
		for (int i=0; i<n; i++) {
			args[i].m=i;
			//args[i].ret=0;
			args[i].gu = &digest_umap;
			args[i].gtu = &digest_text_umap;
			args[i].result = result;
			args[i].free_me = false;
		}
		for (int i=0; i<n; i++) {
			if ( pthread_create(&args[i].thr, NULL, &get_query_digests_parallel, &args[i]) != 0 ) {
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
		for (int i=0; i<n; i++) {
			pthread_join(args[i].thr, NULL);
		}
	} else {
		for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			query_digest_stats_pointers_t *a = (query_digest_stats_pointers_t *)malloc(sizeof(query_digest_stats_pointers_t));
			char **pta=qds->get_row(&digest_text_umap, a);
			result->add_row(pta);
			free(a);
		}
	}
	pthread_rwlock_unlock(&digest_rwlock);
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		curtime2=monotonic_time();
		curtime1 = curtime1/1000;
		curtime2 = curtime2/1000;
		proxy_info("Running query on stats_mysql_query_digest: locked for %llums to retrieve %lu entries\n", curtime2-curtime1, map_size);
	}
	return result;
}


void Query_Processor::get_query_digests_reset(umap_query_digest *uqd, umap_query_digest_text *uqdt) {
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(*uqd);
	digest_text_umap.swap(*uqdt);
	pthread_rwlock_unlock(&digest_rwlock);
}

SQLite3_result * Query_Processor::get_query_digests_reset() {
	SQLite3_result *result = NULL;
	pthread_rwlock_wrlock(&digest_rwlock);
	unsigned long long curtime1;
	unsigned long long curtime2;
	bool free_me = true;
	bool defer_free = true;
	int n=DIGEST_STATS_FAST_THREADS;
	get_query_digests_parallel_args args[n];
	size_t map_size = digest_umap.size();
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		curtime1=monotonic_time();
		result = new SQLite3_result(14, true);
	} else {
		result = new SQLite3_result(14);
	}
	result->add_column_definition(SQLITE_TEXT,"hid");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"client_address");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"digest_text");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");
	result->add_column_definition(SQLITE_TEXT,"sum_time");
	result->add_column_definition(SQLITE_TEXT,"min_time");
	result->add_column_definition(SQLITE_TEXT,"max_time");
	result->add_column_definition(SQLITE_TEXT,"rows_affected");
	result->add_column_definition(SQLITE_TEXT,"rows_sent");
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		for (int i=0; i<n; i++) {
			args[i].m=i;
			//args[i].ret=0;
			args[i].gu = &digest_umap;
			args[i].gtu = &digest_text_umap;
			args[i].result = result;
			args[i].free_me = free_me;
			args[i].defer_free = defer_free;
		}
		for (int i=0; i<n; i++) {
			if ( pthread_create(&args[i].thr, NULL, &get_query_digests_parallel, &args[i]) != 0 ) {
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
		for (int i=0; i<n; i++) {
			pthread_join(args[i].thr, NULL);
		}
		if (free_me == false) {
			for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
				QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
				delete qds;
			}
		}
	} else {
		for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
			QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
			query_digest_stats_pointers_t *a = (query_digest_stats_pointers_t *)malloc(sizeof(query_digest_stats_pointers_t));
			char **pta=qds->get_row(&digest_text_umap, a);
			result->add_row(pta);
			//qds->free_row(pta);
			free(a);
			delete qds;
		}
	}
	digest_umap.erase(digest_umap.begin(),digest_umap.end());
	// this part is always single-threaded
	for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap.begin(); it!=digest_text_umap.end(); ++it) {
		free(it->second);
	}
	digest_text_umap.erase(digest_text_umap.begin(),digest_text_umap.end());
	pthread_rwlock_unlock(&digest_rwlock);
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		curtime2=monotonic_time();
		curtime1 = curtime1/1000;
		curtime2 = curtime2/1000;
		proxy_info("Running query on stats_mysql_query_digest_reset: locked for %llums to retrieve %lu entries\n", curtime2-curtime1, map_size);
		if (free_me) {
			if (defer_free) {
				for (int i=0; i<n; i++) {
					for (unsigned long long r = 0; r < args[i].ret; r++) {
						QP_query_digest_stats *qds = args[i].array_qds[r];
						delete qds;
					}
					free(args[i].array_qds);
				}
			}
		}
	}
	return result;
}


Query_Processor_Output * Query_Processor::process_mysql_query(MySQL_Session *sess, void *ptr, unsigned int size, Query_Info *qi) {
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	// to avoid unnecssary deallocation/allocation, we initialize qpo witout new allocation
	Query_Processor_Output *ret=sess->qpo;
	ret->init();


	SQP_par_t stmt_exec_qp;
	SQP_par_t *qp=NULL;
	if (qi) {
		// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
		if (ptr) {
			qp=(SQP_par_t *)&qi->QueryParserArgs;
		} else {
			qp=&stmt_exec_qp;
			qp->digest = qi->stmt_info->digest;
			qp->digest_text = qi->stmt_info->digest_text;
			qp->first_comment = qi->stmt_info->first_comment;
		}
	}
#define stackbuffer_size 128
	char stackbuffer[stackbuffer_size];
	unsigned int len=0;
	char *query=NULL;
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	if (ptr) {
		len = size-sizeof(mysql_hdr)-1;
		if (len < stackbuffer_size) {
			query=stackbuffer;
		} else {
			query=(char *)l_alloc(len+1);
		}
		memcpy(query,(char *)ptr+sizeof(mysql_hdr)+1,len);
		query[len]=0;
	} else {
		query = qi->stmt_info->query;
		len = qi->stmt_info->query_length;
	}
	if (__sync_add_and_fetch(&version,0) > _thr_SQP_version) {
		// update local rules;
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Detected a changed in version. Global:%d , local:%d . Refreshing...\n", version, _thr_SQP_version);
		pthread_rwlock_rdlock(&rwlock);
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
					sprintf(buf,"0x%016llX", (long long unsigned int)qr1->digest);
				}
				std::string re_mod;
				re_mod="";
				if ((qr1->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
				if ((qr1->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
					if (re_mod.length()) {
						re_mod = re_mod + ",";
					}
					re_mod = re_mod + "GLOBAL";
				}
				qr2=new_query_rule(qr1->rule_id, qr1->active, qr1->username, qr1->schemaname, qr1->flagIN,
					qr1->client_addr, qr1->proxy_addr, qr1->proxy_port,
					( qr1->digest ? buf : NULL ) ,
					qr1->match_digest, qr1->match_pattern, qr1->negate_match_pattern, (char *)re_mod.c_str(),
					qr1->flagOUT, qr1->replace_pattern, qr1->destination_hostgroup,
					qr1->cache_ttl, qr1->cache_empty_result, qr1->cache_timeout,
					qr1->reconnect, qr1->timeout, qr1->retries, qr1->delay,
					qr1->next_query_flagIN, qr1->mirror_flagOUT, qr1->mirror_hostgroup,
					qr1->error_msg, qr1->OK_msg, qr1->sticky_conn, qr1->multiplex,
					qr1->gtid_from_hostgroup,
					qr1->log, qr1->apply,
					qr1->attributes,
					qr1->comment);
				qr2->parent=qr1;	// pointer to parent to speed up parent update (hits)
				if (qr2->match_digest) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_digest: %s\n", qr2->rule_id, qr2->match_digest);
					qr2->regex_engine1=(void *)compile_query_rule(qr2,1);
				}
				if (qr2->match_pattern) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_pattern: %s\n", qr2->rule_id, qr2->match_pattern);
					qr2->regex_engine2=(void *)compile_query_rule(qr2,2);
				}
				_thr_SQP_rules->push_back(qr2);
			}
		}
		kh_destroy(khStrInt, _thr_SQP_rules_fast_routing);
		_thr_SQP_rules_fast_routing = kh_init(khStrInt); // create a hashtable
		if (_thr___rules_fast_routing___keys_values) {
			free(_thr___rules_fast_routing___keys_values);
			_thr___rules_fast_routing___keys_values = NULL;
		}
		if (rules_fast_routing___keys_values___size) {
			_thr___rules_fast_routing___keys_values = (char *)malloc(rules_fast_routing___keys_values___size);
			memcpy(_thr___rules_fast_routing___keys_values, rules_fast_routing___keys_values, rules_fast_routing___keys_values___size);
			char *ptr = _thr___rules_fast_routing___keys_values;
			while (ptr < _thr___rules_fast_routing___keys_values + rules_fast_routing___keys_values___size) {
				char *ptr2 = ptr+strlen(ptr)+1;
				int destination_hostgroup = atoi(ptr2);
				int ret;
				khiter_t k = kh_put(khStrInt, _thr_SQP_rules_fast_routing, ptr, &ret); // add the key
				kh_value(_thr_SQP_rules_fast_routing, k) = destination_hostgroup; // set the value of the key
				ptr = ptr2+strlen(ptr2)+1;
			}
		}
		//for (std::unordered_map<std::string, int>::iterator it = rules_fast_routing.begin(); it != rules_fast_routing.end(); ++it) {
		//	_thr_SQP_rules_fast_routing->insert(
		//}
		pthread_rwlock_unlock(&rwlock);
	}
	QP_rule_t *qr = NULL;
	re2_t *re2p;
	int flagIN=0;
	ret->next_query_flagIN=-1; // reset
	if (sess->next_query_flagIN >= 0) {
		flagIN=sess->next_query_flagIN;
	}
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
				if (qr->client_addr_wildcard_position == -1) { // no wildcard , old algorithm
					if (strcmp(qr->client_addr,sess->client_myds->addr.addr)!=0) {
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching client_addr\n", qr->rule_id);
						continue;
					}
				} else if (qr->client_addr_wildcard_position==0) {
					// catch all!
					// therefore we have a match
				} else { // client_addr_wildcard_position > 0
					if (strncmp(qr->client_addr,sess->client_myds->addr.addr,qr->client_addr_wildcard_position)!=0) {
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching client_addr\n", qr->rule_id);
						continue;
					}
				}
			}
		}

		// match on proxy_addr
		if (qr->proxy_addr && strlen(qr->proxy_addr)) {
			if (sess->client_myds->proxy_addr.addr) {
				if (strcmp(qr->proxy_addr,sess->client_myds->proxy_addr.addr)!=0) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching proxy_addr\n", qr->rule_id);
					continue;
				}
			}
		}

		// match on proxy_port
		if (qr->proxy_port>=0) {
			if (qr->proxy_port!=sess->client_myds->proxy_addr.port) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has no matching proxy_port\n", qr->rule_id);
				continue;
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
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set retries: %d. Query will be re-executed %d times in case of failure\n", qr->rule_id, qr->retries, qr->retries);
			ret->retries=qr->retries;
		}
		if (qr->delay >= 0) {
			// Note: negative delay means this rule doesn't change
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set delay: %d. Session will%s be paused for %dms\n", qr->rule_id, qr->delay, (qr->delay == 0 ? " NOT" : "" ) , qr->delay);
			ret->delay=qr->delay;
		}
		if (qr->next_query_flagIN >= 0) {
			// Note: Negative next_query_flagIN means this rule doesn't change the next query flagIN
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set next query flagIN: %d\n", qr->rule_id, qr->next_query_flagIN);
			ret->next_query_flagIN=qr->next_query_flagIN;
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
		if (qr->OK_msg) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set error_msg: %s\n", qr->rule_id, qr->OK_msg);
			//proxy_warning("User \"%s\" has issued query that has been filtered: %s \n " , sess->client_myds->myconn->userinfo->username, query);
			ret->OK_msg=strdup(qr->OK_msg);
		}
		if (qr->cache_ttl >= 0) {
			// Note: negative TTL means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set cache_ttl: %d. Query will%s hit the cache\n", qr->rule_id, qr->cache_ttl, (qr->cache_ttl == 0 ? " NOT" : "" ));
			ret->cache_ttl=qr->cache_ttl;
		}
		if (qr->cache_empty_result >= 0) {
			// Note: negative value means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set cache_empty_result: %d. Query with empty result will%s hit the cache\n", qr->rule_id, qr->cache_empty_result, (qr->cache_empty_result == 0 ? " NOT" : "" ));
			ret->cache_empty_result=qr->cache_empty_result;
		}
		if (qr->cache_timeout >= 0) {
			// Note: negative value means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set cache_timeout: %dms. Query will wait up resulset to be avaiable in query cache before running on backend\n", qr->rule_id, qr->cache_timeout);
			ret->cache_timeout=qr->cache_timeout;
		}
		if (qr->sticky_conn >= 0) {
			// Note: negative sticky_conn means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set sticky_conn: %d. Connection will%s stick\n", qr->rule_id, qr->sticky_conn, (qr->sticky_conn == 0 ? " NOT" : "" ));
			ret->sticky_conn=qr->sticky_conn;
		}
		if (qr->multiplex >= 0) {
			// Note: negative multiplex means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set multiplex: %d. Connection will%s multiplex\n", qr->rule_id, qr->multiplex, (qr->multiplex == 0 ? " NOT" : "" ));
			ret->multiplex=qr->multiplex;
		}
		if (qr->gtid_from_hostgroup >= 0) {
			// Note: negative gtid_from_hostgroup means this rule doesn't change the gtid_from_hostgroup
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set gtid from hostgroup: %d. A new session will be created\n", qr->rule_id, qr->gtid_from_hostgroup);
			ret->gtid_from_hostgroup = qr->gtid_from_hostgroup;
		}
		if (qr->log >= 0) {
			// Note: negative log means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set log: %d. Query will%s logged\n", qr->rule_id, qr->log, (qr->log == 0 ? " NOT" : "" ));
			ret->log=qr->log;
		}
		if (qr->destination_hostgroup >= 0) {
			// Note: negative hostgroup means this rule doesn't change
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has set destination hostgroup: %d\n", qr->rule_id, qr->destination_hostgroup);
			ret->destination_hostgroup=qr->destination_hostgroup;
		}
		if (ptr) { // we aren't processing a STMT_EXECUTE
			if (qr->replace_pattern) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d on match_pattern \"%s\" has a replace_pattern \"%s\" to apply\n", qr->rule_id, qr->match_pattern, qr->replace_pattern);
				if (ret->new_query==NULL) ret->new_query=new std::string(query);
				re2_t *re2p=(re2_t *)qr->regex_engine2;
				if (re2p->re2) {
					//RE2::Replace(ret->new_query,qr->match_pattern,qr->replace_pattern);
					if ((qr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
						re2p->re2->GlobalReplace(ret->new_query,qr->match_pattern,qr->replace_pattern);
					} else {
						re2p->re2->Replace(ret->new_query,qr->match_pattern,qr->replace_pattern);
					}
				} else {
					//re2p->re1->Replace(ret->new_query,qr->replace_pattern);
					if ((qr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
						re2p->re1->GlobalReplace(qr->replace_pattern,ret->new_query);
					} else {
						re2p->re1->Replace(qr->replace_pattern,ret->new_query);
					}
				}
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
	if (qr == NULL || qr->apply == false) {
		// now it is time to check mysql_query_rules_fast_routing
		// it is only check if "apply" is not true
		if (_thr___rules_fast_routing___keys_values) {
			char keybuf[256];
			char * keybuf_ptr = keybuf;
			const char * u = sess->client_myds->myconn->userinfo->username;
			const char * s = sess->client_myds->myconn->userinfo->schemaname;
			size_t keylen = strlen(u)+strlen(rand_del)+strlen(s)+30; // 30 is a big number
			if (keylen > 250) {
				keybuf_ptr = (char *)malloc(keylen);
			}
			sprintf(keybuf_ptr,"%s%s%s---%d", u, rand_del, s, flagIN);
			khiter_t k = kh_get(khStrInt, _thr_SQP_rules_fast_routing, keybuf_ptr);
			if (k == kh_end(_thr_SQP_rules_fast_routing)) {
				sprintf(keybuf_ptr,"%s%s---%d", rand_del, s, flagIN);
				khiter_t k2 = kh_get(khStrInt, _thr_SQP_rules_fast_routing, keybuf_ptr);
				if (k2 == kh_end(_thr_SQP_rules_fast_routing)) {
				} else {
					ret->destination_hostgroup = kh_val(_thr_SQP_rules_fast_routing,k2);
				}
			} else {
				ret->destination_hostgroup = kh_val(_thr_SQP_rules_fast_routing,k);
			}
			if (keylen > 250) {
				free(keybuf_ptr);
			}
		}
	}
	// FIXME : there is too much data being copied around
	if (len < stackbuffer_size) {
		// query is in the stack
	} else {
		if (ptr) {
			l_free(len+1,query);
		}
	}
	if (sess->mirror==false) { // we process comments only on original queries, not on mirrors
		if (qp && qp->first_comment) {
			// we have a comment to parse
			query_parser_first_comment(ret, qp->first_comment);
		}
	}
	if (mysql_thread___firewall_whitelist_enabled) {
		char *username = NULL;
		char *client_address = NULL;
		bool check_run = true;
		if (sess->client_myds) {
			check_run = false;
			if (sess->client_myds->myconn && sess->client_myds->myconn->userinfo && sess->client_myds->myconn->userinfo->username) {
				if (sess->client_myds->addr.addr) {
					check_run = true;
					username = sess->client_myds->myconn->userinfo->username;
					client_address = sess->client_myds->addr.addr;
					pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
					// FIXME
					// for now this function search for either username@ip or username@''
					int wus_status = find_firewall_whitelist_user(username, client_address);
					if (wus_status == WUS_NOT_FOUND) {
						client_address = (char *)"";
						wus_status = find_firewall_whitelist_user(username, client_address);
					}
					if (wus_status == WUS_NOT_FOUND) {
						wus_status = WUS_PROTECTING; // by default, everything should be blocked!
					}
					ret->firewall_whitelist_mode = wus_status;
					if (wus_status == WUS_DETECTING || wus_status == WUS_PROTECTING) {
						bool allowed_query = false;
						char * schemaname = sess->client_myds->myconn->userinfo->schemaname;
						if (qp && qp->digest) {
							allowed_query = find_firewall_whitelist_rule(username, client_address, schemaname, flagIN, qp->digest);
						}
						if (allowed_query == false) {
							if (wus_status == WUS_PROTECTING) {
								if (ret->error_msg == NULL) {
									// change error message only if not already set
									ret->error_msg = strdup(mysql_thread___firewall_whitelist_errormsg);
								}
							}
						}
						if (allowed_query == true) {
							ret->firewall_whitelist_mode = WUS_OFF;
						}
					}
					pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
					if (ret->firewall_whitelist_mode == WUS_DETECTING || ret->firewall_whitelist_mode == WUS_PROTECTING) {
						char buf[32];
						if (qp && qp->digest) {
							sprintf(buf,"0x%016llX", (long long unsigned int)qp->digest);
						} else {
							sprintf(buf,"unknown");
						}
						char *action = (char *)"blocked";
						if (ret->firewall_whitelist_mode == WUS_DETECTING) {
							action = (char *)"detected unknown";
						}
						proxy_warning("Firewall %s query with digest %s from user %s@%s\n", action, buf, username, sess->client_myds->addr.addr);
					}
				}
			}
		}
		if (check_run == false) {
			// LCOV_EXCL_START
			proxy_error("Firewall problem: unknown user\n");
			assert(0);
			// LCOV_EXCL_STOP
		}
	} else {
		ret->firewall_whitelist_mode = WUS_NOT_FOUND;
	}
	return ret;
};

int Query_Processor::find_firewall_whitelist_user(char *username, char *client) {
	int ret = WUS_NOT_FOUND;
	string s = username;
	s += rand_del;
	s += client;
	std::unordered_map<std::string, int>:: iterator it2;
	it2 = global_mysql_firewall_whitelist_users.find(s);
	if (it2 != global_mysql_firewall_whitelist_users.end()) {
		ret = it2->second;
		return ret;
	}
	s = username;
	return ret;
}

bool Query_Processor::find_firewall_whitelist_rule(char *username, char *client_address, char *schemaname, int flagIN, uint64_t digest) {
	bool ret = false;
	string s = username;
	s += rand_del;
	s += client_address;
	s += rand_del;
	s += schemaname;
	s += rand_del;
	s += to_string(flagIN);
	std::unordered_map<std::string, void *>:: iterator it;
	it = global_mysql_firewall_whitelist_rules.find(s);
	if (it != global_mysql_firewall_whitelist_rules.end()) {
		PtrArray *myptrarray = (PtrArray *)it->second;
		void * found = bsearch(&digest, myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
		if (found) {
			ret = true;
		}
	}
	return ret;
}

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
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 8, "Updating query rules statistics\n");
	pthread_rwlock_rdlock(&rwlock);
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
	pthread_rwlock_unlock(&rwlock);
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
	qp->digest_text=NULL;
	qp->first_comment=NULL;
	qp->query_prefix=NULL;
	if (mysql_thread___query_digests) {
		qp->digest_text=mysql_query_digest_and_first_comment_2(query, query_length, &qp->first_comment, ((query_length < QUERY_DIGEST_BUF) ? qp->buf : NULL));
		// the hash is computed only up to query_digests_max_digest_length bytes
		int digest_text_length=strnlen(qp->digest_text, mysql_thread___query_digests_max_digest_length);
		qp->digest=SpookyHash::Hash64(qp->digest_text, digest_text_length, 0);
#ifdef DEBUG
		if (qp->first_comment && strlen(qp->first_comment)) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Comment in query = %s \n", qp->first_comment);
		}
#endif /* DEBUG */
	} else {
		if (mysql_thread___commands_stats) {
			size_t sl=32;
			if ((unsigned int)query_length < sl) {
				sl=query_length;
			}
			qp->query_prefix=strndup(query,sl);
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

	char *ca = (char *)"";
	if (mysql_thread___query_digests_track_hostname) {
		if (sess->client_myds) {
			if (sess->client_myds->addr.addr) {
				ca = sess->client_myds->addr.addr;
			}
		}
	}

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
		myhash.Update(ca,strlen(ca));
		myhash.Final(&qp->digest_total,&hash2);
		update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, NULL, sess);
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
		myhash.Update(ca,strlen(ca));
		myhash.Final(&qp->digest_total,&hash2);
		//delete myhash;
		update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, stmt_info, sess);
	}
	return ret;
}

void Query_Processor::update_query_digest(SQP_par_t *qp, int hid, MySQL_Connection_userinfo *ui, unsigned long long t, unsigned long long n, MySQL_STMT_Global_info *_stmt_info, MySQL_Session *sess) {
	pthread_rwlock_wrlock(&digest_rwlock);
	QP_query_digest_stats *qds;

	unsigned long long rows_affected = 0;
	unsigned long long rows_sent = 0;

	if (sess) {
		rows_affected = sess->CurrentQuery.affected_rows;
		rows_sent = sess->CurrentQuery.rows_sent;
	}

	std::unordered_map<uint64_t, void *>::iterator it;
	it=digest_umap.find(qp->digest_total);
	if (it != digest_umap.end()) {
		// found
		qds=(QP_query_digest_stats *)it->second;
		qds->add_time(t,n, rows_affected,rows_sent);
	} else {
		char *dt = NULL;
		if (mysql_thread___query_digests_normalize_digest_text==false) {
			if (_stmt_info==NULL) {
				dt = qp->digest_text;
			} else {
				dt = _stmt_info->digest_text;
			}
		}
		char *ca = (char *)"";
		if (mysql_thread___query_digests_track_hostname) {
			if (sess->client_myds) {
				if (sess->client_myds->addr.addr) {
					ca = sess->client_myds->addr.addr;
				}
			}
		}
		if (_stmt_info==NULL) {
			qds=new QP_query_digest_stats(ui->username, ui->schemaname, qp->digest, dt, hid, ca);
		} else {
			qds=new QP_query_digest_stats(ui->username, ui->schemaname, _stmt_info->digest, dt, hid, ca);
		}
		qds->add_time(t,n, rows_affected,rows_sent);
		digest_umap.insert(std::make_pair(qp->digest_total,(void *)qds));
		if (mysql_thread___query_digests_normalize_digest_text==true) {
			uint64_t dig = 0;
			if (_stmt_info==NULL) {
				dig = qp->digest;
			} else {
				dig = _stmt_info->digest;
			}
			std::unordered_map<uint64_t, char *>::iterator it2;
			it2=digest_text_umap.find(dig);
			if (it2 != digest_text_umap.end()) {
				// found
			} else {
				if (_stmt_info==NULL) {
					dt = strdup(qp->digest_text);
				} else {
					dt = strdup(_stmt_info->digest_text);
				}
				digest_text_umap.insert(std::make_pair(dig,dt));
			}
		}
	}

	pthread_rwlock_unlock(&digest_rwlock);
}

char * Query_Processor::get_digest_text(SQP_par_t *qp) {
	if (qp==NULL) return NULL;
	return qp->digest_text;
}

uint64_t Query_Processor::get_digest(SQP_par_t *qp) {
	if (qp==NULL) return 0;
	return qp->digest;
}

enum MYSQL_COM_QUERY_command Query_Processor::__query_parser_command_type(SQP_par_t *qp) {
	char *text=NULL; // this new variable is a pointer to either qp->digest_text , or to the query
	if (qp->digest_text) {
		text=qp->digest_text;
	} else {
		text=qp->query_prefix;
	}

	enum MYSQL_COM_QUERY_command ret=MYSQL_COM_QUERY_UNKNOWN;
	char c1;

	tokenizer_t tok;
	tokenizer( &tok, text, " ", TOKENIZER_NO_EMPTIES );
	char* token=NULL;
__get_token:
	token=(char *)tokenize(&tok);
	if (token==NULL) {
		goto __exit__query_parser_command_type;
	}
__remove_paranthesis:
	if (token[0] == '(') {
		if (strlen(token) > 1) {
			token++;
			goto __remove_paranthesis;
		} else {
			goto __get_token;
		}
	}
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
								if (!mystrcasecmp("TABLE",token)) {
									ret=MYSQL_COM_QUERY_ALTER_TABLE;
									break;
								}
							}
						}
					} else {
						if (!mystrcasecmp("IGNORE",token)) {
							if (token==NULL) break;
							token=(char *)tokenize(&tok);
							if (!mystrcasecmp("TABLE",token)) {
								ret=MYSQL_COM_QUERY_ALTER_TABLE;
								break;
							}
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
			if (!strcasecmp("RELEASE",token)) { // RELEASE
				token=(char *)tokenize(&tok);
				if (token==NULL) break;
				if (!strcasecmp("SAVEPOINT",token)) {
					ret=MYSQL_COM_QUERY_RELEASE_SAVEPOINT;
					break;
				}
			}
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
				token=(char *)tokenize(&tok);
				if (token==NULL) {
					ret=MYSQL_COM_QUERY_ROLLBACK;
					break;
				} else {
					if (!strcasecmp("TO",token)) {
						token=(char *)tokenize(&tok);
						if (token==NULL) break;
						if (!strcasecmp("SAVEPOINT",token)) {
							ret=MYSQL_COM_QUERY_ROLLBACK_SAVEPOINT;
							break;
						}
					}
				}
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
	tokenizer_t tok;
	tokenizer( &tok, fc, ";", TOKENIZER_NO_EMPTIES );
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
			if (!strcasecmp(key,"max_lag_ms")) {
				if (c >= '0' && c <= '9') { // it is a digit
					int t=atoi(value);
					if (t >= 0 && t <= 600000) {
						qpo->max_lag_ms = t;
					}
				}
			}
			if (!strcasecmp(key,"min_epoch_ms")) {
				if (c >= '0' && c <= '9') { // it is a digit
					unsigned long long now_us = realtime_time();
					unsigned long long now_ms = now_us/1000;
					long long now_ms_s = (long long)now_ms;
					long long t=atoll(value);
					long long diff = now_ms_s - t;
					if (diff >= 0 && diff <= 600000) {
						qpo->max_lag_ms = diff;
					}
				}
			}
			if (!strcasecmp(key,"min_gtid")) {
				size_t l = strlen(value);
				if (is_valid_gtid(value, l)) {
					char *buf=(char*)malloc(l+1);
					strncpy(buf, value, l);
					buf[l+1] = '\0';
					qpo->min_gtid = buf;
				} else {
					proxy_warning("Invalid gtid value=%s\n", value);
				}
			}
			if (!strcasecmp(key, "create_new_connection")) {
				int32_t val = atoi(value);
				if (val == 1) {
					qpo->create_new_conn = true;
				}
			}
		}

		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Variables in comment %s , key=%s , value=%s\n", token, key, value);
		free(key);
		free(value);
	}
	free_tokenizer( &tok );
	return ret;
}

bool Query_Processor::is_valid_gtid(char *gtid, size_t gtid_len) {
	if (gtid_len < 3) {
		return false;
	}
	char *sep_pos = index(gtid, ':');
	if (sep_pos == NULL) {
		return false;
	}
	size_t uuid_len = sep_pos - gtid;
	if (uuid_len < 1) {
		return false;
	}
	if (gtid_len < uuid_len + 2) {
		return false;
	}
	return true;
}

void Query_Processor::query_parser_free(SQP_par_t *qp) {
	if (qp->digest_text) {
		if (qp->digest_text != qp->buf) {
			free(qp->digest_text);
		}
		qp->digest_text=NULL;
	}
	if (qp->first_comment) {
		free(qp->first_comment);
		qp->first_comment=NULL;
	}
};

bool Query_Processor::whitelisted_sqli_fingerprint(char *_s) {
	bool ret = false;
	string s = _s;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	for (std::vector<std::string>::iterator it = global_mysql_firewall_whitelist_sqli_fingerprints.begin() ; ret == false && it != global_mysql_firewall_whitelist_sqli_fingerprints.end(); ++it) {
		if (s == *it) {
			ret = true;
		}
	}
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

void Query_Processor::load_mysql_firewall_sqli_fingerprints(SQLite3_result *resultset) {
	global_mysql_firewall_whitelist_sqli_fingerprints.erase(global_mysql_firewall_whitelist_sqli_fingerprints.begin(), global_mysql_firewall_whitelist_sqli_fingerprints.end());
	// perform the inserts
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int active = atoi(r->fields[0]);
		if (active == 0) {
			continue;
		}
		char * fingerprint = r->fields[1];
		string s = fingerprint;
		global_mysql_firewall_whitelist_sqli_fingerprints.push_back(s);
	}
}

void Query_Processor::load_mysql_firewall_users(SQLite3_result *resultset) {
	unsigned long long tot_size = 0;
	std::unordered_map<std::string, int>::iterator it;
	for (it = global_mysql_firewall_whitelist_users.begin() ; it != global_mysql_firewall_whitelist_users.end(); ++it) {
		it->second = WUS_NOT_FOUND;
	}
	// perform the inserts/updates
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int active = atoi(r->fields[0]);
		if (active == 0) {
			continue;
		}
		char * username = r->fields[1];
		char * client_address = r->fields[2];
		char * mode = r->fields[3];
		string s = username;
		s += rand_del;
		s += client_address;
		std::unordered_map<std::string, int>:: iterator it2;
		it2 = global_mysql_firewall_whitelist_users.find(s);
		if (it2 != global_mysql_firewall_whitelist_users.end()) {
			if (strcmp(mode,(char *)"DETECTING")==0) {
				it2->second = WUS_DETECTING;
			} else if (strcmp(mode,(char *)"PROTECTING")==0) {
				it2->second = WUS_PROTECTING;
			} else if (strcmp(mode,(char *)"OFF")==0) {
				it2->second = WUS_OFF;
			}
		} else {
			//whitelist_user_setting *wus = (whitelist_user_setting *)malloc(sizeof(whitelist_user_setting));
			int m = WUS_OFF;
			if (strcmp(mode,(char *)"DETECTING")==0) {
				m = WUS_DETECTING;
			} else if (strcmp(mode,(char *)"PROTECTING")==0) {
				m = WUS_PROTECTING;
			}
			//wus->myptrarray = new PtrArray();
			global_mysql_firewall_whitelist_users[s] = m;
		}
	}
	// cleanup
	it = global_mysql_firewall_whitelist_users.begin();
	while (it != global_mysql_firewall_whitelist_users.end()) {
		int m = it->second;
		if (m != WUS_NOT_FOUND) {
			tot_size += it->first.capacity();
			tot_size += sizeof(m);
			it++;
		} else {
			// remove the entry
			it = global_mysql_firewall_whitelist_users.erase(it);
		}
	}
	global_mysql_firewall_whitelist_users_map___size = tot_size;
}

void Query_Processor::load_mysql_firewall_rules(SQLite3_result *resultset) {
	unsigned long long tot_size = 0;
	global_mysql_firewall_whitelist_rules_map___size = 0;
	//size_t rand_del_size = strlen(rand_del);
	int num_rows = resultset->rows_count;
	std::unordered_map<std::string, void *>::iterator it;
	if (num_rows == 0) {
		// we must clean it completely
		for (it = global_mysql_firewall_whitelist_rules.begin() ; it != global_mysql_firewall_whitelist_rules.end(); ++it) {
			PtrArray * myptrarray = (PtrArray *)it->second;
			delete myptrarray;
		}
		global_mysql_firewall_whitelist_rules.clear();
		return;
	}
	// remove all the pointer array
	for (it = global_mysql_firewall_whitelist_rules.begin() ; it != global_mysql_firewall_whitelist_rules.end(); ++it) {
		PtrArray * myptrarray = (PtrArray *)it->second;
		myptrarray->reset();
	}
	// perform the inserts
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int active = atoi(r->fields[0]);
		if (active == 0) {
			continue;
		}
		char * username = r->fields[1];
		char * client_address = r->fields[2];
		char * schemaname = r->fields[3];
		char * flagIN = r->fields[4];
		char * digest_hex = r->fields[5];
		unsigned long long digest_num = strtoull(digest_hex,NULL,0);
		string s = username;
		s += rand_del;
		s += client_address;
		s += rand_del;
		s += schemaname;
		s += rand_del;
		s += flagIN;
		std::unordered_map<std::string, void *>:: iterator it2;
		it2 = global_mysql_firewall_whitelist_rules.find(s);
		if (it2 != global_mysql_firewall_whitelist_rules.end()) {
			PtrArray * myptrarray = (PtrArray *)it2->second;
			myptrarray->add((void *)digest_num);
		} else {
			PtrArray * myptrarray = new PtrArray();
			myptrarray->add((void *)digest_num);
			global_mysql_firewall_whitelist_rules[s] = (void *)myptrarray;
		}
	}
	// perform ordering and cleanup
	it = global_mysql_firewall_whitelist_rules.begin();
	while (it != global_mysql_firewall_whitelist_rules.end()) {
		PtrArray * myptrarray = (PtrArray *)it->second;
		if (myptrarray->len) {
			// there are digests, sort them
			qsort(myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
			tot_size += it->first.capacity();
			unsigned long long a = (myptrarray->size * sizeof(void *));
			tot_size += a;
			it++;
		} else {
			// remove the entry
			delete myptrarray;
			it = global_mysql_firewall_whitelist_rules.erase(it);
		}
	}
	unsigned long long nsize = global_mysql_firewall_whitelist_rules.size();
	unsigned long long oh = sizeof(std::string) + sizeof(PtrArray) + sizeof(PtrArray *);
	nsize *= oh;
	tot_size += nsize;
	global_mysql_firewall_whitelist_rules_map___size = tot_size;
}

void Query_Processor::save_query_rules(SQLite3_result *resultset) {
	delete query_rules_resultset;
	query_rules_resultset = resultset; // save it
}

void Query_Processor::load_fast_routing(SQLite3_result *resultset) {
	unsigned long long tot_size = 0;
	size_t rand_del_size = strlen(rand_del);
	int num_rows = resultset->rows_count;
	if (num_rows) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			size_t row_length = strlen(r->fields[0]) + strlen(r->fields[1]) + strlen(r->fields[2]) + strlen(r->fields[3]);
			row_length += 2; // 2 = 2x NULL bytes
			row_length += 3; // "---"
			row_length += rand_del_size;
			tot_size += row_length;
		}
		int nt = GloMTH->num_threads;
		rules_fast_routing___keys_values = (char *)malloc(tot_size);
		rules_fast_routing___keys_values___size = tot_size;
		rules_mem_used += rules_fast_routing___keys_values___size; // global
		rules_mem_used += rules_fast_routing___keys_values___size * nt; // per-thread
		char *ptr = rules_fast_routing___keys_values;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			sprintf(ptr,"%s%s%s---%s",r->fields[0],rand_del,r->fields[1],r->fields[2]);
			int destination_hostgroup = atoi(r->fields[3]);
			int ret;
			khiter_t k = kh_put(khStrInt, rules_fast_routing, ptr, &ret); // add the key
			kh_value(rules_fast_routing, k) = destination_hostgroup; // set the value of the key
			int l = strlen((const char *)ptr);
			ptr += l;
			ptr++; // NULL 1
			l = strlen(r->fields[3]);
			memcpy(ptr,r->fields[3],l+1);
			ptr += l;
			ptr++; // NULL 2
			rules_mem_used += ((sizeof(int) + sizeof(char *) + 4 )); // not sure about memory overhead
			rules_mem_used += ((sizeof(int) + sizeof(char *) + 4 ) * nt); // per-thread . not sure about memory overhead
		}
	}
	delete fast_routing_resultset;
	fast_routing_resultset = resultset; // save it
	rules_mem_used += fast_routing_resultset->get_size();
};

// this testing function doesn't care if the user exists or not
// the arguments are coming from this query:
// SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()
int Query_Processor::testing___find_HG_in_mysql_query_rules_fast_routing(char *username, char *schemaname, int flagIN) {
	int ret = -1;
	pthread_rwlock_rdlock(&rwlock);
	if (rules_fast_routing) {
		char keybuf[256];
		char * keybuf_ptr = keybuf;
		size_t keylen = strlen(username)+strlen(rand_del)+strlen(schemaname)+30; // 30 is a big number
		if (keylen > 250) {
			keybuf_ptr = (char *)malloc(keylen);
		}
		sprintf(keybuf_ptr,"%s%s%s---%d", username, rand_del, schemaname, flagIN);
		khiter_t k = kh_get(khStrInt, rules_fast_routing, keybuf_ptr);
		if (k == kh_end(rules_fast_routing)) {
		} else {
			ret = kh_val(rules_fast_routing,k);
		}
		if (keylen > 250) {
			free(keybuf_ptr);
		}
	}
	pthread_rwlock_unlock(&rwlock);
	return ret;
}

// this testing function implement the dual search: with and without username
// if the length of username is 0 , it will search for random username (that shouldn't exist!)
int Query_Processor::testing___find_HG_in_mysql_query_rules_fast_routing_dual(char *username, char *schemaname, int flagIN) {
	int ret = -1;
	const char * random_user = (char *)"my_ReaLLy_Rand_User_123456";
	char * u = NULL;
	if (strlen(username)) {
		u = username;
	} else {
		u = (char *)random_user;
	}
	pthread_rwlock_rdlock(&rwlock);
	if (rules_fast_routing) {
		char keybuf[256];
		char * keybuf_ptr = keybuf;
		size_t keylen = strlen(u)+strlen(rand_del)+strlen(schemaname)+30; // 30 is a big number
		if (keylen > 250) {
			keybuf_ptr = (char *)malloc(keylen);
		}
		sprintf(keybuf_ptr,"%s%s%s---%d", username, rand_del, schemaname, flagIN);
		khiter_t k = kh_get(khStrInt, rules_fast_routing, keybuf_ptr);
		if (k == kh_end(rules_fast_routing)) {
		} else {
			ret = kh_val(rules_fast_routing,k);
		}
		if (ret == -1) { // we didn't find it
			if (strlen(username)==0) { // we need to search for empty username
				sprintf(keybuf_ptr,"%s%s---%d", rand_del, schemaname, flagIN); // no username here
				khiter_t k = kh_get(khStrInt, rules_fast_routing, keybuf_ptr);
				if (k == kh_end(rules_fast_routing)) {
				} else {
					ret = kh_val(rules_fast_routing,k);
				}
			}
		}
		if (keylen > 250) {
			free(keybuf_ptr);
		}
	}
	pthread_rwlock_unlock(&rwlock);
	return ret;
}

void Query_Processor::get_current_mysql_firewall_whitelist(SQLite3_result **u, SQLite3_result **r, SQLite3_result **sf) {
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	if (global_mysql_firewall_whitelist_rules_runtime) {
		*r = new SQLite3_result(global_mysql_firewall_whitelist_rules_runtime);
	}
	if (global_mysql_firewall_whitelist_users_runtime) {
		*u = new SQLite3_result(global_mysql_firewall_whitelist_users_runtime);
	}
	if (global_mysql_firewall_whitelist_sqli_fingerprints_runtime) {
		*sf = new SQLite3_result(global_mysql_firewall_whitelist_sqli_fingerprints_runtime);
	}
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
}

void Query_Processor::load_mysql_firewall(SQLite3_result *u, SQLite3_result *r, SQLite3_result *sf) {
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	if (global_mysql_firewall_whitelist_rules_runtime) {
		delete global_mysql_firewall_whitelist_rules_runtime;
		global_mysql_firewall_whitelist_rules_runtime = NULL;
	}
	global_mysql_firewall_whitelist_rules_runtime = r;
	global_mysql_firewall_whitelist_rules_result___size = r->get_size();
	if (global_mysql_firewall_whitelist_users_runtime) {
		delete global_mysql_firewall_whitelist_users_runtime;
		global_mysql_firewall_whitelist_users_runtime = NULL;
	}
	global_mysql_firewall_whitelist_users_runtime = u;
	if (global_mysql_firewall_whitelist_sqli_fingerprints_runtime) {
		delete global_mysql_firewall_whitelist_sqli_fingerprints_runtime;
		global_mysql_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	}
	global_mysql_firewall_whitelist_sqli_fingerprints_runtime = sf;
	load_mysql_firewall_users(global_mysql_firewall_whitelist_users_runtime);
	load_mysql_firewall_rules(global_mysql_firewall_whitelist_rules_runtime);
	load_mysql_firewall_sqli_fingerprints(global_mysql_firewall_whitelist_sqli_fingerprints_runtime);
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return;
}

unsigned long long Query_Processor::get_mysql_firewall_memory_users_table() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	ret = global_mysql_firewall_whitelist_users_map___size;
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

unsigned long long Query_Processor::get_mysql_firewall_memory_users_config() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	ret = global_mysql_firewall_whitelist_users_result___size;
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

unsigned long long Query_Processor::get_mysql_firewall_memory_rules_table() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	ret = global_mysql_firewall_whitelist_rules_map___size;
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

unsigned long long Query_Processor::get_mysql_firewall_memory_rules_config() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	ret = global_mysql_firewall_whitelist_rules_result___size;
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

SQLite3_result * Query_Processor::get_mysql_firewall_whitelist_rules() {
	SQLite3_result *ret = NULL;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	if (global_mysql_firewall_whitelist_rules_runtime) {
		ret = new SQLite3_result(global_mysql_firewall_whitelist_rules_runtime);
	}
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}

SQLite3_result * Query_Processor::get_mysql_firewall_whitelist_users() {
	SQLite3_result *ret = NULL;
	pthread_mutex_lock(&global_mysql_firewall_whitelist_mutex);
	if (global_mysql_firewall_whitelist_users_runtime) {
		ret = new SQLite3_result(global_mysql_firewall_whitelist_users_runtime);
	}
	pthread_mutex_unlock(&global_mysql_firewall_whitelist_mutex);
	return ret;
}
