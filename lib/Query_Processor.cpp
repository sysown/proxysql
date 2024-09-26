#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include <thread>
#include <future>
#include "re2/re2.h"
#include "re2/regexp.h"
#include "pcrecpp.h"
#include "proxysql.h"
#include "cpp.h"

#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "QP_rule_text.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_PROCESSOR_VERSION "3.0.0.0004" DEB

#define GET_THREAD_VARIABLE(VARIABLE_NAME) \
({((std::is_same_v<QP_DERIVED,MySQL_Query_Processor>) ? mysql_thread___##VARIABLE_NAME : pgsql_thread___##VARIABLE_NAME) ;})

extern MySQL_Threads_Handler *GloMTH;
extern PgSQL_Threads_Handler* GloPTH;
extern ProxySQL_Admin *GloAdmin;

// per thread variables
__thread unsigned int _thr_SQP_version;
__thread std::vector<QP_rule_t*>* _thr_SQP_rules;
__thread khash_t(khStrInt)* _thr_SQP_rules_fast_routing;
__thread char* _thr___rules_fast_routing___keys_values;

struct __RE2_objects_t {
	pcrecpp::RE_Options* opt1;
	pcrecpp::RE* re1;
	re2::RE2::Options* opt2;
	RE2* re2;
};

typedef struct __RE2_objects_t re2_t;

static int int_cmp(const void *a, const void *b) {
	const unsigned long long *ia = (const unsigned long long *)a;
	const unsigned long long *ib = (const unsigned long long *)b;
	if (*ia < *ib) return -1;
	if (*ia > *ib) return 1;
	return 0;
}

static bool rules_sort_comp_function (QP_rule_t * a, QP_rule_t * b) { 
	return (a->rule_id < b->rule_id); 
}

static unsigned long long mem_used_rule(QP_rule_t *qr) {
	unsigned long long s = 0;
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

static re2_t * compile_query_rule(QP_rule_t *qr, int i, int query_processor_regex) {
	re2_t *r=(re2_t *)malloc(sizeof(re2_t));
	r->opt1=NULL;
	r->re1=NULL;
	r->opt2=NULL;
	r->re2=NULL;
	if (query_processor_regex==2) {
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
	if (qr->flagOUT_ids != NULL) {
		qr->flagOUT_ids->clear();
		delete qr->flagOUT_ids;
		qr->flagOUT_ids = NULL;
	}
	if (qr->flagOUT_weights != NULL) {
		qr->flagOUT_weights->clear();
		delete qr->flagOUT_weights;
		qr->flagOUT_weights = NULL;
	}
	free(qr);
};

// delete all the query rules in a Query Processor Table
// Note that this function is called by:
//  - GloQPro with &rules (generic table). In Query_Processor destrutor.
//  - Each mysql thread with _thr_SQP_rules (per thread table). During destruction or rules recreation.
//  - ProxySQL_Admin at 'load_mysql_variables_to_runtime', during global rules recreation. For this case, the
//    function is used outside the 'Query_Processor' due to flow present in 'load_mysql_variables_to_runtime'
//    of freeing the previous resources associated to the 'query_rules' and 'query_rules_fast_routing' out of
//    the 'Query_Processor' general locking ('wrlock').
void __reset_rules(std::vector<QP_rule_t *> * qrs) {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Resetting rules in Query Processor Table %p\n", qrs);
	if (qrs==NULL) return;
	QP_rule_t *qr;
	for (std::vector<QP_rule_t *>::iterator it=qrs->begin(); it!=qrs->end(); ++it) {
		qr=*it;
		__delete_query_rule(qr);
	}
	qrs->clear();
}

template <typename QP_DERIVED>
Query_Processor<QP_DERIVED>::Query_Processor(int _query_rules_fast_routing_algorithm) {
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
	pthread_mutex_init(&global_firewall_whitelist_mutex, NULL);
	global_firewall_whitelist_users_runtime = NULL;
	global_firewall_whitelist_rules_runtime = NULL;
	global_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	global_firewall_whitelist_users_map___size = 0;
	global_firewall_whitelist_users_result___size = 0;
	global_firewall_whitelist_rules_map___size = 0;
	global_firewall_whitelist_rules_result___size = 0;

	pthread_rwlock_init(&rwlock, NULL);
	pthread_rwlock_init(&digest_rwlock, NULL);
	version=0;
	rules_mem_used=0;
	
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
	// 'rules_fast_routing' structures created on demand
	rules_fast_routing = nullptr;
	rules_fast_routing___keys_values = NULL;
	rules_fast_routing___keys_values___size = 0;
	new_req_conns_count = 0;
}

template <typename QP_DERIVED>
Query_Processor<QP_DERIVED>::~Query_Processor() {
	__reset_rules(&rules);
	if (rules_fast_routing) {
		kh_destroy(khStrInt, rules_fast_routing);
	}
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
	digest_umap.clear();
	digest_text_umap.clear();
	if (query_rules_resultset) {
		delete query_rules_resultset;
		query_rules_resultset = NULL;
	}
	if (fast_routing_resultset) {
		delete fast_routing_resultset;
		fast_routing_resultset = NULL;
	}
	if (global_firewall_whitelist_users_runtime) {
		delete global_firewall_whitelist_users_runtime;
		global_firewall_whitelist_users_runtime = NULL;
	}
	if (global_firewall_whitelist_rules_runtime) {
		delete global_firewall_whitelist_rules_runtime;
		global_firewall_whitelist_rules_runtime = NULL;
	}
	if (global_firewall_whitelist_sqli_fingerprints_runtime) {
		delete global_firewall_whitelist_sqli_fingerprints_runtime;
		global_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	}
}

// This function is called by each thread when it starts. It create a Query Processor Table for each thread
template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::init_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Initializing Per-Thread Query Processor Table with version=0\n");
	_thr_SQP_version=0;
	_thr_SQP_rules=new std::vector<QP_rule_t *>;
	// per-thread 'rules_fast_routing' structures are created on demand
	_thr_SQP_rules_fast_routing = nullptr;
	_thr___rules_fast_routing___keys_values = NULL;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::end_thread() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Destroying Per-Thread Query Processor Table with version=%d\n", _thr_SQP_version);
	__reset_rules(_thr_SQP_rules);
	delete _thr_SQP_rules;
	if (_thr_SQP_rules_fast_routing) {
		kh_destroy(khStrInt, _thr_SQP_rules_fast_routing);
	}
	if (_thr___rules_fast_routing___keys_values) {
		free(_thr___rules_fast_routing___keys_values);
		_thr___rules_fast_routing___keys_values = NULL;
	}
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::print_version() {
	fprintf(stderr,"Standard Query Processor rev. %s -- %s -- %s\n", QUERY_PROCESSOR_VERSION, __FILE__, __TIMESTAMP__);
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::rdlock() {
	pthread_rwlock_rdlock(&rwlock);
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_rules_mem_used() {
	unsigned long long s = 0;
	wrlock();
	s = rules_mem_used;
	wrunlock();
	return s;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_new_req_conns_count() {
	return __sync_fetch_and_add(&new_req_conns_count, 0);
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::delete_query_rule(QP_rule_t *qr) {
	__delete_query_rule(qr);
}

template <typename QP_DERIVED>
rules_mem_sts_t Query_Processor<QP_DERIVED>::reset_all(bool lock) {
	if (lock)
		wrlock();

	rules_mem_sts_t hashmaps_data {};
	this->rules.swap(hashmaps_data.query_rules);

	if (rules_fast_routing) {
		hashmaps_data.rules_fast_routing = rules_fast_routing;
		rules_fast_routing = nullptr;
	}

	if (rules_fast_routing___keys_values) {
		hashmaps_data.rules_fast_routing___keys_values = rules_fast_routing___keys_values;
		rules_fast_routing___keys_values = NULL;
		rules_fast_routing___keys_values___size = 0;
	}

	if (lock)
		wrunlock();
	rules_mem_used=0;

	return hashmaps_data;
}

template <typename QP_DERIVED>
bool Query_Processor<QP_DERIVED>::insert(QP_rule_t *qr, bool lock) {
	bool ret=true;
	if (lock)
		wrlock();
	rules.push_back(qr);
	rules_mem_used += sizeof(TypeQueryRule);
	rules_mem_used += mem_used_rule(qr);
	if (lock)
		wrunlock();
	return ret;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::sort(bool lock) {
	if (lock)
		wrlock();
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Sorting rules\n");
	std::sort (rules.begin(), rules.end(), rules_sort_comp_function);
	if (lock)
		wrunlock();
}

// when commit is called, the version number is increased and the this will trigger the mysql threads to get a new Query Processor Table
// The operation is asynchronous
template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::commit() {
	__sync_add_and_fetch(&version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Increasing version number to %d - all threads will notice this and refresh their rules\n", version);
}

template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_stats_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping query rules statistics, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(2);
	rdlock();
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
	wrunlock();
	return result;
}

template <typename QP_DERIVED>
int Query_Processor<QP_DERIVED>::get_current_query_rules_fast_routing_count() {
	int result = 0;
	rdlock();
	result = fast_routing_resultset->rows_count;
	wrunlock();
	return result;
}

// we return the resultset fast_routing_resultset
// the caller of this function must lock Query Processor
template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_current_query_rules_fast_routing_inner() {
	return fast_routing_resultset;
}
// we return the resultset query_rules_resultset
// the caller of this function must lock Query Processor
template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_current_query_rules_inner() {
	return query_rules_resultset;
}

template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_current_query_rules_fast_routing() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules fast_routing, using Global version %d\n", version);
	SQLite3_result *result=new SQLite3_result(5);
	rdlock();
	//QP_rule_t *qr1;
	result->add_column_definition(SQLITE_TEXT,"username");
	if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "schemaname");
	} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "database");
	}
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
	wrunlock();
	return result;
}

template <typename QP_DERIVED>
int Query_Processor<QP_DERIVED>::search_rules_fast_routing_dest_hg(
	khash_t(khStrInt)** __rules_fast_routing, const char* u, const char* s, int flagIN, bool lock
) {
	int dest_hg = -1;
	const size_t u_len = strlen(u);
	size_t keylen = u_len+strlen(rand_del)+strlen(s)+30; // 30 is a big number

	char keybuf[256];
	char * keybuf_ptr = keybuf;

	if (keylen >= sizeof(keybuf)) {
		keybuf_ptr = (char *)malloc(keylen);
	}
	sprintf(keybuf_ptr,"%s%s%s---%d", u, rand_del, s, flagIN);

	if (lock) {
		rdlock();
	}
	khash_t(khStrInt)* _rules_fast_routing = *__rules_fast_routing;
	khiter_t k = kh_get(khStrInt, _rules_fast_routing, keybuf_ptr);
	if (k == kh_end(_rules_fast_routing)) {
		khiter_t k2 = kh_get(khStrInt, _rules_fast_routing, keybuf_ptr + u_len);
		if (k2 == kh_end(_rules_fast_routing)) {
		} else {
			dest_hg = kh_val(_rules_fast_routing,k2);
		}
	} else {
		dest_hg = kh_val(_rules_fast_routing,k);
	}
	if (lock) {
		wrunlock();
	}

	if (keylen >= sizeof(keybuf)) {
		free(keybuf_ptr);
	}

	return dest_hg;
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
	set_thread_name("GetQueryDigeTot");
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
	set_thread_name("GetQueryDigests");
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
	set_thread_name("PurgeQueryDgest");
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

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::purge_query_digests(bool async_purge, bool parallel, char **msg) {
	unsigned long long ret = 0;
	if (async_purge) {
		ret = purge_query_digests_async(msg);
	} else {
		ret = purge_query_digests_sync(parallel);
	}
	return ret;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::purge_query_digests_async(char **msg) {
	unsigned long long ret = 0;
	umap_query_digest digest_umap_aux;
	umap_query_digest_text digest_text_umap_aux;
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(digest_umap_aux);
	digest_text_umap.swap(digest_text_umap_aux);
	pthread_rwlock_unlock(&digest_rwlock);
	unsigned long long curtime1=monotonic_time();
	size_t map1_size = digest_umap_aux.size();
	size_t map2_size = digest_text_umap_aux.size();
	ret = map1_size + map2_size;


	for (
		std::unordered_map<uint64_t, void *>::iterator it = digest_umap_aux.begin();
		it != digest_umap_aux.end();
		++it
	) {
		QP_query_digest_stats *qds = (QP_query_digest_stats *)it->second;
		delete qds;
	}
	digest_umap_aux.clear();
	for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap_aux.begin(); it!=digest_text_umap_aux.end(); ++it) {
		free(it->second);
	}
	digest_text_umap_aux.clear();


	if (map1_size >= DIGEST_STATS_FAST_MINSIZE) {
		unsigned long long curtime2=monotonic_time();
		curtime1 = curtime1/1000;
		curtime2 = curtime2/1000;
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			proxy_info("TRUNCATE stats_mysql_query_digest: (not locked) %llums to remove %lu entries\n", curtime2 - curtime1, map1_size);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			proxy_info("TRUNCATE stats_pgsql_query_digest: (not locked) %llums to remove %lu entries\n", curtime2 - curtime1, map1_size);
		}
	}
	return ret;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::purge_query_digests_sync(bool parallel) {
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

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_query_digests_total_size() {
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

template <typename QP_DERIVED>
std::pair<SQLite3_result *, int> Query_Processor<QP_DERIVED>::get_query_digests_v2(const bool use_resultset) {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query digest\n");
	SQLite3_result *result = NULL;
	// Create two auxiliary maps and swap its content with the main maps. This
	// way, this function can read query digests stored until now while other
	// threads write in the other map. We need to lock while swapping.
	umap_query_digest digest_umap_aux, digest_umap_aux_2;
	umap_query_digest_text digest_text_umap_aux, digest_text_umap_aux_2;
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(digest_umap_aux);
	digest_text_umap.swap(digest_text_umap_aux);
	pthread_rwlock_unlock(&digest_rwlock);
	int num_rows = 0;
	unsigned long long curtime1;
	unsigned long long curtime2;
	size_t map_size = digest_umap_aux.size();
	curtime1 = monotonic_time(); // curtime1 must always be initialized
	if (use_resultset) {
		if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
			result = new SQLite3_result(14, true);
		} else {
			result = new SQLite3_result(14);
		}
		result->add_column_definition(SQLITE_TEXT,"hid");
		if constexpr (std::is_same_v<QP_DERIVED,MySQL_Query_Processor>){
			result->add_column_definition(SQLITE_TEXT, "schemaname");
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			result->add_column_definition(SQLITE_TEXT, "database");
		}
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
				args[i].gu = &digest_umap_aux;
				args[i].gtu = &digest_text_umap_aux;
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
			for (
				std::unordered_map<uint64_t, void *>::iterator it = digest_umap_aux.begin();
				it != digest_umap_aux.end();
				++it
			) {
				QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
				query_digest_stats_pointers_t *a = (query_digest_stats_pointers_t *)malloc(sizeof(query_digest_stats_pointers_t));
				char **pta=qds->get_row(&digest_text_umap_aux, a);
				result->add_row(pta);
				free(a);
			}
		}
	} else {
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			num_rows = GloAdmin->stats___save_mysql_query_digest_to_sqlite(
				false, false, NULL, &digest_umap_aux, &digest_text_umap_aux
			);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			num_rows = GloAdmin->stats___save_pgsql_query_digest_to_sqlite(
				false, false, NULL, &digest_umap_aux, &digest_text_umap_aux
			);
		}
	}
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		curtime2=monotonic_time();
		curtime1 = curtime1/1000;
		curtime2 = curtime2/1000;
		
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			proxy_info("Running query on stats_mysql_query_digest: (not locked) %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			proxy_info("Running query on stats_pgsql_query_digest: (not locked) %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		}
	}

	// Once we finish creating the resultset or writing to SQLite, we use a
	// second group of auxiliary maps to swap it with the first group of
	// auxiliary maps.  This way, we can merge the main maps and the first
	// auxiliary maps without locking the mutex during the process. This is
	// useful because writing to SQLite can take a lot of time, so the first
	// group of auxiliary maps could grow large.
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(digest_umap_aux_2);
	digest_text_umap.swap(digest_text_umap_aux_2);
	pthread_rwlock_unlock(&digest_rwlock);

	// Once we do the swap, we merge the content of the first auxiliary maps
	// in the main maps and clear the content of the auxiliary maps.
	for (const auto& element : digest_umap_aux_2) {
		uint64_t digest = element.first;
		QP_query_digest_stats *qds = (QP_query_digest_stats *)element.second;
		std::unordered_map<uint64_t, void *>::iterator it = digest_umap_aux.find(digest);
		if (it != digest_umap_aux.end()) {
			// found
			QP_query_digest_stats *qds_equal = (QP_query_digest_stats *)it->second;
			qds_equal->add_time(
				qds->min_time, qds->last_seen, qds->rows_affected, qds->rows_sent, qds->count_star
			);
			delete qds;
		} else {
			digest_umap_aux.insert(element);
		}
	}
	digest_text_umap_aux.insert(digest_text_umap_aux_2.begin(), digest_text_umap_aux_2.end());
	digest_umap_aux_2.clear();
	digest_text_umap_aux_2.clear();

	// Once we finish merging the main maps and the first auxiliary maps, we
	// lock and swap the main maps with the second auxiliary maps. Then, we
	// merge the content of the auxiliary maps in the main maps and clear the
	// content of the auxiliary maps.
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap_aux.swap(digest_umap);
	for (const auto& element : digest_umap_aux) {
		uint64_t digest = element.first;
		QP_query_digest_stats *qds = (QP_query_digest_stats *)element.second;
		std::unordered_map<uint64_t, void *>::iterator it = digest_umap.find(digest);
		if (it != digest_umap.end()) {
			// found
			QP_query_digest_stats *qds_equal = (QP_query_digest_stats *)it->second;
			qds_equal->add_time(
				qds->min_time, qds->last_seen, qds->rows_affected, qds->rows_sent, qds->count_star
			);
			delete qds;
		} else {
			digest_umap.insert(element);
		}
	}
	digest_text_umap.insert(digest_text_umap_aux.begin(), digest_text_umap_aux.end());
	pthread_rwlock_unlock(&digest_rwlock);
	digest_umap_aux.clear();
	digest_text_umap_aux.clear();

	std::pair<SQLite3_result *, int> res{result, num_rows};
	return res;
}

template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_query_digests() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query digest\n");
	SQLite3_result *result = NULL;
	pthread_rwlock_rdlock(&digest_rwlock);
	unsigned long long curtime1;
	unsigned long long curtime2;
	size_t map_size = digest_umap.size();
	curtime1 = monotonic_time(); // curtime1 must always be initialized
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		result = new SQLite3_result(14, true);
	} else {
		result = new SQLite3_result(14);
	}
	result->add_column_definition(SQLITE_TEXT,"hid");
	if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "schemaname");
	} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "database");
	}
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
		
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			proxy_info("Running query on stats_mysql_query_digest: locked for %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			proxy_info("Running query on stats_pgsql_query_digest: locked for %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		}
	}
	return result;
}

template <typename QP_DERIVED>
std::pair<SQLite3_result *, int> Query_Processor<QP_DERIVED>::get_query_digests_reset_v2(
	const bool copy, const bool use_resultset
) {
	SQLite3_result *result = NULL;
	umap_query_digest digest_umap_aux;
	umap_query_digest_text digest_text_umap_aux;
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(digest_umap_aux);
	digest_text_umap.swap(digest_text_umap_aux);
	pthread_rwlock_unlock(&digest_rwlock);
	int num_rows = 0;
	unsigned long long curtime1;
	unsigned long long curtime2;
	size_t map_size = digest_umap_aux.size(); // we need to use the new map
	bool free_me = false;
	bool defer_free = false;
	int n=DIGEST_STATS_FAST_THREADS;
	get_query_digests_parallel_args args[n];
	curtime1 = monotonic_time(); // curtime1 must always be initialized
	if (use_resultset) {
		free_me = true;
		defer_free = true;
		if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
			result = new SQLite3_result(14, true);
		} else {
			result = new SQLite3_result(14);
		}
		result->add_column_definition(SQLITE_TEXT,"hid");
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			result->add_column_definition(SQLITE_TEXT, "schemaname");
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			result->add_column_definition(SQLITE_TEXT, "database");
		}
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
				args[i].gu = &digest_umap_aux;
				args[i].gtu = &digest_text_umap_aux;
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
				for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap_aux.begin(); it!=digest_umap_aux.end(); ++it) {
					QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
					delete qds;
				}
			}
		} else {
			for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap_aux.begin(); it!=digest_umap_aux.end(); ++it) {
				QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
				query_digest_stats_pointers_t *a = (query_digest_stats_pointers_t *)malloc(sizeof(query_digest_stats_pointers_t));
				char **pta=qds->get_row(&digest_text_umap_aux, a);
				result->add_row(pta);
				free(a);
				delete qds;
			}
		}
	} else {
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			num_rows = GloAdmin->stats___save_mysql_query_digest_to_sqlite(
				true, copy, result, &digest_umap_aux, &digest_text_umap_aux
			);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			num_rows = GloAdmin->stats___save_pgsql_query_digest_to_sqlite(
				true, copy, result, &digest_umap_aux, &digest_text_umap_aux
			);
		}
		for (
			std::unordered_map<uint64_t, void *>::iterator it = digest_umap_aux.begin();
			it != digest_umap_aux.end();
			++it
		) {
			QP_query_digest_stats *qds = (QP_query_digest_stats *)it->second;
			delete qds;
		}
	}
	digest_umap_aux.clear();
	// this part is always single-threaded
	for (std::unordered_map<uint64_t, char *>::iterator it=digest_text_umap_aux.begin(); it!=digest_text_umap_aux.end(); ++it) {
		free(it->second);
	}
	digest_text_umap_aux.clear();
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		curtime2=monotonic_time();
		curtime1 = curtime1/1000;
		curtime2 = curtime2/1000;
		
		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			proxy_info("Running query on stats_mysql_query_digest: (not locked) %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			proxy_info("Running query on stats_pgsql_query_digest: (not locked) %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		}

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

	std::pair<SQLite3_result *, int> res{result, num_rows};
	return res;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::get_query_digests_reset(umap_query_digest *uqd, umap_query_digest_text *uqdt) {
	pthread_rwlock_wrlock(&digest_rwlock);
	digest_umap.swap(*uqd);
	digest_text_umap.swap(*uqdt);
	pthread_rwlock_unlock(&digest_rwlock);
}

template <typename QP_DERIVED>
SQLite3_result * Query_Processor<QP_DERIVED>::get_query_digests_reset() {
	SQLite3_result *result = NULL;
	pthread_rwlock_wrlock(&digest_rwlock);
	unsigned long long curtime1;
	unsigned long long curtime2;
	bool free_me = true;
	bool defer_free = true;
	int n=DIGEST_STATS_FAST_THREADS;
	get_query_digests_parallel_args args[n];
	size_t map_size = digest_umap.size();
	curtime1 = monotonic_time(); // curtime1 must always be initialized
	if (map_size >= DIGEST_STATS_FAST_MINSIZE) {
		result = new SQLite3_result(14, true);
	} else {
		result = new SQLite3_result(14);
	}
	result->add_column_definition(SQLITE_TEXT,"hid");
	if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "schemaname");
	} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
		result->add_column_definition(SQLITE_TEXT, "database");
	}
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

		if constexpr (std::is_same_v<QP_DERIVED, MySQL_Query_Processor>) {
			proxy_info("Running query on stats_mysql_query_digest_reset: locked for %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		} else if constexpr (std::is_same_v<QP_DERIVED, PgSQL_Query_Processor>) {
			proxy_info("Running query on stats_pgsql_query_digest_reset: locked for %llums to retrieve %lu entries\n", curtime2 - curtime1, map_size);
		}

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
template <typename QP_DERIVED>
Query_Processor_Output* Query_Processor<QP_DERIVED>::process_query(TypeSession* sess, bool stmt_exec, const char *query,
	unsigned int len, Query_Processor_Output* ret, SQP_par_t* qp) {
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	// to avoid unnecssary deallocation/allocation, we initialize qpo witout new allocation

	if (__sync_add_and_fetch(&version,0) > _thr_SQP_version) {
		// update local rules;
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Detected a changed in version. Global:%d , local:%d . Refreshing...\n", version, _thr_SQP_version);
		rdlock();
		_thr_SQP_version=__sync_add_and_fetch(&version,0);
		__reset_rules(_thr_SQP_rules);
		QP_rule_t *qr1;
		QP_rule_t *qr2;
		for (std::vector<QP_rule_t *>::iterator it=rules.begin(); it!=rules.end(); ++it) {
			qr1=*it;
			if (qr1->active) {
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Copying Query Rule id: %d\n", qr1->rule_id);
				qr2=(static_cast<QP_DERIVED*>(this))->new_query_rule(static_cast<const TypeQueryRule*>(qr1));
				qr2->parent=qr1;	// pointer to parent to speed up parent update (hits)
				if (qr2->match_digest) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_digest: %s\n", qr2->rule_id, qr2->match_digest);
					qr2->regex_engine1=(void *)compile_query_rule(qr2,1, GET_THREAD_VARIABLE(query_processor_regex));
				}
				if (qr2->match_pattern) {
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Compiling regex for rule_id: %d, match_pattern: %s\n", qr2->rule_id, qr2->match_pattern);
					qr2->regex_engine2=(void *)compile_query_rule(qr2,2, GET_THREAD_VARIABLE(query_processor_regex));
				}
				_thr_SQP_rules->push_back(qr2);
			}
		}
		if (this->query_rules_fast_routing_algorithm == 1) {
			if (_thr_SQP_rules_fast_routing) {
				kh_destroy(khStrInt, _thr_SQP_rules_fast_routing);
				_thr_SQP_rules_fast_routing = nullptr;
			}
			if (_thr___rules_fast_routing___keys_values) {
				free(_thr___rules_fast_routing___keys_values);
				_thr___rules_fast_routing___keys_values = NULL;
			}
			if (rules_fast_routing___keys_values___size) {
				_thr_SQP_rules_fast_routing = kh_init(khStrInt); // create a hashtable
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
		} else {
			if (_thr_SQP_rules_fast_routing) {
				kh_destroy(khStrInt, _thr_SQP_rules_fast_routing);
				_thr_SQP_rules_fast_routing = nullptr;
			}
			if (_thr___rules_fast_routing___keys_values) {
				free(_thr___rules_fast_routing___keys_values);
				_thr___rules_fast_routing___keys_values = nullptr;
			}
		}
		//for (std::unordered_map<std::string, int>::iterator it = rules_fast_routing.begin(); it != rules_fast_routing.end(); ++it) {
		//	_thr_SQP_rules_fast_routing->insert(
		//}
		wrunlock();
	}
	QP_rule_t *qr = NULL;
	re2_t *re2p;
	int flagIN=0;
	ret->next_query_flagIN=-1; // reset
	if (sess->next_query_flagIN >= 0) {
		flagIN=sess->next_query_flagIN;
	}
	int reiterate=GET_THREAD_VARIABLE(query_processor_iterations);
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
		if (qr->flagOUT_weights_total > 0) {
			int rnd = random() % qr->flagOUT_weights_total;
			for (unsigned int i=0; i< qr->flagOUT_weights->size(); i++) {
				int w = qr->flagOUT_weights->at(i);
				if (rnd < w) {
					flagIN= qr->flagOUT_ids->at(i);
					proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "query rule %d has changed flagOUT based on weight\n", qr->rule_id);
					set_flagOUT=true;
					break;
				} else {
					rnd -= w;
				}
			}
		}
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
		if constexpr (has_process_query_extended<QP_DERIVED>::value) {
			(static_cast<QP_DERIVED*>(this))->process_query_extended(static_cast<TypeQPOutput*>(ret), static_cast<TypeQueryRule*>(qr));
		}
		if (stmt_exec == false) { // we aren't processing a STMT_EXECUTE
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
		const char * u = sess->client_myds->myconn->userinfo->username;
		const char * s = sess->client_myds->myconn->userinfo->schemaname;

		int dst_hg = -1;

		if (_thr_SQP_rules_fast_routing != nullptr) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 7, "Searching thread-local 'rules_fast_routing' hashmap with: user='%s', schema='%s', and flagIN='%d'\n", u, s, flagIN);
			dst_hg = search_rules_fast_routing_dest_hg(&_thr_SQP_rules_fast_routing, u, s, flagIN, false);
		} else if (rules_fast_routing != nullptr) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 7, "Searching global 'rules_fast_routing' hashmap with: user='%s', schema='%s', and flagIN='%d'\n", u, s, flagIN);
			// NOTE: A pointer to the member 'this->rules_fast_routing' is required, since the value of the
			// member could have changed before the function acquires the internal lock. See function doc.
			dst_hg = search_rules_fast_routing_dest_hg(&this->rules_fast_routing, u, s, flagIN, true);
		}

		if (dst_hg != -1) {
			ret->destination_hostgroup = dst_hg;
		}
	}
	
	if (sess->mirror==false) { // we process comments only on original queries, not on mirrors
		if (qp && qp->first_comment) {
			// we have a comment to parse
			query_parser_first_comment(ret, qp->first_comment);
		}
	}
	if (GET_THREAD_VARIABLE(firewall_whitelist_enabled)) {
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
					pthread_mutex_lock(&global_firewall_whitelist_mutex);
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
									ret->error_msg = strdup(GET_THREAD_VARIABLE(firewall_whitelist_errormsg));
								}
							}
						}
						if (allowed_query == true) {
							ret->firewall_whitelist_mode = WUS_OFF;
						}
					}
					pthread_mutex_unlock(&global_firewall_whitelist_mutex);
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

template <typename QP_DERIVED>
int Query_Processor<QP_DERIVED>::find_firewall_whitelist_user(char *username, char *client) {
	int ret = WUS_NOT_FOUND;
	string s = username;
	s += rand_del;
	s += client;
	std::unordered_map<std::string, int>:: iterator it2;
	it2 = global_firewall_whitelist_users.find(s);
	if (it2 != global_firewall_whitelist_users.end()) {
		ret = it2->second;
		return ret;
	}
	s = username;
	return ret;
}

template <typename QP_DERIVED>
bool Query_Processor<QP_DERIVED>::find_firewall_whitelist_rule(char *username, char *client_address, char *schemaname, int flagIN, uint64_t digest) {
	bool ret = false;
	string s = username;
	s += rand_del;
	s += client_address;
	s += rand_del;
	s += schemaname;
	s += rand_del;
	s += to_string(flagIN);
	std::unordered_map<std::string, void *>:: iterator it;
	it = global_firewall_whitelist_rules.find(s);
	if (it != global_firewall_whitelist_rules.end()) {
		PtrArray *myptrarray = (PtrArray *)it->second;
		void * found = bsearch(&digest, myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
		if (found) {
			ret = true;
		}
	}
	return ret;
}

// this function is called by mysql_session to free the result generated by process_mysql_query()
template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::delete_QP_out(Query_Processor_Output *o) {
	//l_free(sizeof(QP_out_t),o);
	if (o) {
		//delete o; // do not deallocate, but "destroy" it
		o->destroy();
	}
};

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::update_query_processor_stats() {
	// Note:
	// this function is called by each thread to update global query statistics
	//
	// As an extra safety, it checks that the version didn't change
	// Yet, if version changed doesn't perfomr any rules update
	//
	// It acquires a read lock to ensure that the rules table doesn't change
	// Yet, because it has to update vales, it uses atomic operations
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 8, "Updating query rules statistics\n");
	rdlock();
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
	wrunlock();
	
};

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::query_parser_init(SQP_par_t *qp, const char *query, int query_length, int flags) {
	// trying to get rid of libinjection
	// instead of initializing qp->sf , we copy query info later in this function
	qp->digest_text=NULL;
	qp->first_comment=NULL;
	qp->query_prefix=NULL;
	if (GET_THREAD_VARIABLE(query_digests)) {
		options opts;
		opts.lowercase = GET_THREAD_VARIABLE(query_digests_lowercase);
		opts.replace_null = GET_THREAD_VARIABLE(query_digests_replace_null);
		opts.replace_number = GET_THREAD_VARIABLE(query_digests_no_digits);
		opts.grouping_limit = GET_THREAD_VARIABLE(query_digests_grouping_limit);
		opts.groups_grouping_limit = GET_THREAD_VARIABLE(query_digests_groups_grouping_limit);
		opts.keep_comment = GET_THREAD_VARIABLE(query_digests_keep_comment);
		opts.max_query_length = GET_THREAD_VARIABLE(query_digests_max_query_length);

		qp->digest_text=query_digest_and_first_comment_2(query, query_length, &qp->first_comment, 
			((query_length < QUERY_DIGEST_BUF) ? qp->buf : NULL), &opts);
		// the hash is computed only up to query_digests_max_digest_length bytes
		const int digest_text_length=strnlen(qp->digest_text, GET_THREAD_VARIABLE(query_digests_max_digest_length));
		qp->digest=SpookyHash::Hash64(qp->digest_text, digest_text_length, 0);
#ifdef DEBUG
		if (qp->first_comment && strlen(qp->first_comment)) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Comment in query = %s \n", qp->first_comment);
		}
#endif /* DEBUG */
	} else {
		if (GET_THREAD_VARIABLE(commands_stats)) {
			size_t sl=32;
			if ((unsigned int)query_length < sl) {
				sl=query_length;
			}
			qp->query_prefix=strndup(query,sl);
		}
	}
};


template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::query_parser_update_counters(TypeSession* sess, uint64_t digest_total, uint64_t digest, 
	char* digest_text, unsigned long long t) {

	if (digest_text) {
		char* ca = (char*)"";
		if (GET_THREAD_VARIABLE(query_digests_track_hostname)) {
			if (sess->client_myds) {
				if (sess->client_myds->addr.addr) {
					ca = sess->client_myds->addr.addr;
				}
			}
		}
		// this code is executed only if digest_text is not NULL , that means mysql_thread___query_digests was true when the query started
		uint64_t hash2;
		SpookyHash myhash;
		myhash.Init(19,3);
		assert(sess);
		assert(sess->client_myds);
		assert(sess->client_myds->myconn);
		assert(sess->client_myds->myconn->userinfo);
		auto *ui=sess->client_myds->myconn->userinfo;
		assert(ui->username);
		assert(ui->schemaname);
		myhash.Update(ui->username,strlen(ui->username));
		myhash.Update(&digest,sizeof(digest));
		myhash.Update(ui->schemaname,strlen(ui->schemaname));
		myhash.Update(&sess->current_hostgroup,sizeof(sess->current_hostgroup));
		myhash.Update(ca,strlen(ca));
		myhash.Final(&digest_total,&hash2);
		update_query_digest(digest_total, digest, digest_text, sess->current_hostgroup, ui, t, sess->thread->curtime, ca, 
			sess->CurrentQuery.affected_rows, sess->CurrentQuery.rows_sent);
	}
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::update_query_digest(uint64_t digest_total, uint64_t digest, char* digest_text, int hid, 
	TypeConnInfo* ui, unsigned long long t, unsigned long long n, const char* client_addr, unsigned long long rows_affected,
	unsigned long long rows_sent) {
	pthread_rwlock_wrlock(&digest_rwlock);
	QP_query_digest_stats *qds;

	std::unordered_map<uint64_t, void *>::iterator it;
	it=digest_umap.find(digest_total);
	if (it != digest_umap.end()) {
		// found
		qds=(QP_query_digest_stats *)it->second;
		qds->add_time(t,n,rows_affected,rows_sent);
	} else {
		char *dt = NULL;
		if (GET_THREAD_VARIABLE(query_digests_normalize_digest_text)==false) {
			dt = digest_text;
		}
		qds=new QP_query_digest_stats(ui->username, ui->schemaname, digest, dt, hid, client_addr, GET_THREAD_VARIABLE(query_digests_max_digest_length));
		qds->add_time(t,n, rows_affected,rows_sent);
		digest_umap.insert(std::make_pair(digest_total,(void *)qds));
		if (GET_THREAD_VARIABLE(query_digests_normalize_digest_text)==true) {
			const uint64_t dig = digest;
			std::unordered_map<uint64_t, char *>::iterator it2;
			it2=digest_text_umap.find(dig);
			if (it2 != digest_text_umap.end()) {
				// found
			} else {
				dt = strdup(digest_text);
				digest_text_umap.insert(std::make_pair(dig,dt));
			}
		}
	}

	pthread_rwlock_unlock(&digest_rwlock);
}

template <typename QP_DERIVED>
char * Query_Processor<QP_DERIVED>::get_digest_text(SQP_par_t *qp) {
	if (qp==NULL) return NULL;
	return qp->digest_text;
}

template <typename QP_DERIVED>
uint64_t Query_Processor<QP_DERIVED>::get_digest(SQP_par_t *qp) {
	if (qp==NULL) return 0;
	return qp->digest;
}

template <typename QP_DERIVED>
bool Query_Processor<QP_DERIVED>::query_parser_first_comment(Query_Processor_Output *qpo, char *fc) {
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
			if (!strcasecmp(key, "create_new_connection")) {
				int32_t val = atoi(value);
				if (val == 1) {
					qpo->create_new_conn = true;
				}
			}
			if constexpr (has_query_parser_first_comment_extended<QP_DERIVED>::value) {
				(static_cast<QP_DERIVED*>(this))->query_parser_first_comment_extended(key, value, static_cast<TypeQPOutput*>(qpo));
			}
		}

		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Variables in comment %s , key=%s , value=%s\n", token, key, value);
		free(key);
		free(value);
	}
	free_tokenizer( &tok );
	return ret;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::query_parser_free(SQP_par_t *qp) {
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

template <typename QP_DERIVED>
bool Query_Processor<QP_DERIVED>::whitelisted_sqli_fingerprint(char *_s) {
	bool ret = false;
	string s = _s;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	for (std::vector<std::string>::iterator it = global_firewall_whitelist_sqli_fingerprints.begin() ; ret == false && it != global_firewall_whitelist_sqli_fingerprints.end(); ++it) {
		if (s == *it) {
			ret = true;
		}
	}
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::load_firewall_sqli_fingerprints(SQLite3_result *resultset) {
	global_firewall_whitelist_sqli_fingerprints.erase(global_firewall_whitelist_sqli_fingerprints.begin(), global_firewall_whitelist_sqli_fingerprints.end());
	// perform the inserts
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int active = atoi(r->fields[0]);
		if (active == 0) {
			continue;
		}
		char * fingerprint = r->fields[1];
		string s = fingerprint;
		global_firewall_whitelist_sqli_fingerprints.push_back(s);
	}
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::load_firewall_users(SQLite3_result *resultset) {
	unsigned long long tot_size = 0;
	std::unordered_map<std::string, int>::iterator it;
	for (it = global_firewall_whitelist_users.begin() ; it != global_firewall_whitelist_users.end(); ++it) {
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
		it2 = global_firewall_whitelist_users.find(s);
		if (it2 != global_firewall_whitelist_users.end()) {
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
			global_firewall_whitelist_users[s] = m;
		}
	}
	// cleanup
	it = global_firewall_whitelist_users.begin();
	while (it != global_firewall_whitelist_users.end()) {
		int m = it->second;
		if (m != WUS_NOT_FOUND) {
			tot_size += it->first.capacity();
			tot_size += sizeof(m);
			it++;
		} else {
			// remove the entry
			it = global_firewall_whitelist_users.erase(it);
		}
	}
	global_firewall_whitelist_users_map___size = tot_size;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::load_firewall_rules(SQLite3_result *resultset) {
	unsigned long long tot_size = 0;
	global_firewall_whitelist_rules_map___size = 0;
	//size_t rand_del_size = strlen(rand_del);
	int num_rows = resultset->rows_count;
	std::unordered_map<std::string, void *>::iterator it;
	if (num_rows == 0) {
		// we must clean it completely
		for (it = global_firewall_whitelist_rules.begin() ; it != global_firewall_whitelist_rules.end(); ++it) {
			PtrArray * myptrarray = (PtrArray *)it->second;
			delete myptrarray;
		}
		global_firewall_whitelist_rules.clear();
		return;
	}
	// remove all the pointer array
	for (it = global_firewall_whitelist_rules.begin() ; it != global_firewall_whitelist_rules.end(); ++it) {
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
		it2 = global_firewall_whitelist_rules.find(s);
		if (it2 != global_firewall_whitelist_rules.end()) {
			PtrArray * myptrarray = (PtrArray *)it2->second;
			myptrarray->add((void *)digest_num);
		} else {
			PtrArray * myptrarray = new PtrArray();
			myptrarray->add((void *)digest_num);
			global_firewall_whitelist_rules[s] = (void *)myptrarray;
		}
	}
	// perform ordering and cleanup
	it = global_firewall_whitelist_rules.begin();
	while (it != global_firewall_whitelist_rules.end()) {
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
			it = global_firewall_whitelist_rules.erase(it);
		}
	}
	unsigned long long nsize = global_firewall_whitelist_rules.size();
	unsigned long long oh = sizeof(std::string) + sizeof(PtrArray) + sizeof(PtrArray *);
	nsize *= oh;
	tot_size += nsize;
	global_firewall_whitelist_rules_map___size = tot_size;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::save_query_rules(SQLite3_result *resultset) {
	delete query_rules_resultset;
	query_rules_resultset = resultset; // save it
}

template <typename QP_DERIVED>
fast_routing_hashmap_t Query_Processor<QP_DERIVED>::create_fast_routing_hashmap(SQLite3_result* resultset) {
	khash_t(khStrInt)* fast_routing = nullptr;
	char* keys_values = nullptr;
	unsigned long long keys_values_size = 0;

	size_t rand_del_size = strlen(rand_del);
	int num_rows = resultset->rows_count;
	if (num_rows) {
		unsigned long long tot_size = 0;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			size_t row_length = strlen(r->fields[0]) + strlen(r->fields[1]) + strlen(r->fields[2]) + strlen(r->fields[3]);
			row_length += 2; // 2 = 2x NULL bytes
			row_length += 3; // "---"
			row_length += rand_del_size;
			tot_size += row_length;
		}
		keys_values = (char *)malloc(tot_size);
		keys_values_size = tot_size;
		char *ptr = keys_values;
		fast_routing = kh_init(khStrInt);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			sprintf(ptr,"%s%s%s---%s",r->fields[0],rand_del,r->fields[1],r->fields[2]);
			int destination_hostgroup = atoi(r->fields[3]);
			int ret;
			khiter_t k = kh_put(khStrInt, fast_routing, ptr, &ret); // add the key
			kh_value(fast_routing, k) = destination_hostgroup; // set the value of the key
			int l = strlen((const char *)ptr);
			ptr += l;
			ptr++; // NULL 1
			l = strlen(r->fields[3]);
			memcpy(ptr,r->fields[3],l+1);
			ptr += l;
			ptr++; // NULL 2
		}
	}

	return { resultset, resultset->get_size(), fast_routing, keys_values, keys_values_size };
}

template <typename QP_DERIVED>
SQLite3_result* Query_Processor<QP_DERIVED>::load_fast_routing(const fast_routing_hashmap_t& fast_routing_hashmap) {
	khash_t(khStrInt)* _rules_fast_routing = fast_routing_hashmap.rules_fast_routing;
	SQLite3_result* _rules_resultset = fast_routing_hashmap.rules_resultset;

	if (_rules_fast_routing && _rules_resultset) {
		unsigned int nt = 0;
		if constexpr (std::is_same_v<QP_DERIVED,MySQL_Query_Processor>) {
			nt = GloMTH->num_threads;
		} else if constexpr (std::is_same_v<QP_DERIVED,PgSQL_Query_Processor>) {
			nt = GloPTH->num_threads;
		}
		// Replace map structures, assumed to be previously reset
		this->rules_fast_routing___keys_values = fast_routing_hashmap.rules_fast_routing___keys_values;
		this->rules_fast_routing___keys_values___size = fast_routing_hashmap.rules_fast_routing___keys_values___size;
		this->rules_fast_routing = _rules_fast_routing;
		// Update global memory stats
		rules_mem_used += rules_fast_routing___keys_values___size; // global
		if (this->query_rules_fast_routing_algorithm == 1) {
			rules_mem_used += rules_fast_routing___keys_values___size * nt; // per-thread
		}
		khint_t map_size = kh_size(_rules_fast_routing);
		rules_mem_used += map_size * ((sizeof(int) + sizeof(char *) + 4 )); // not sure about memory overhead
		if (this->query_rules_fast_routing_algorithm == 1) {
			rules_mem_used += map_size * ((sizeof(int) + sizeof(char *) + 4 )) * nt; // not sure about memory overhead
		}
	}

	// Backup current resultset for later freeing
	SQLite3_result* prev_fast_routing_resultset = this->fast_routing_resultset;
	// Save new resultset
	fast_routing_resultset = _rules_resultset;
	// Use resultset pre-computed size
	rules_mem_used += fast_routing_hashmap.rules_resultset_size;

	return prev_fast_routing_resultset;
};

// this testing function doesn't care if the user exists or not
// the arguments are coming from this query:
// SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()
template <typename QP_DERIVED>
int Query_Processor<QP_DERIVED>::testing___find_HG_in_mysql_query_rules_fast_routing(char *username, char *schemaname, int flagIN) {
	int ret = -1;
	rdlock();
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
	wrunlock();
	return ret;
}

// this testing function implement the dual search: with and without username
// if the length of username is 0 , it will search for random username (that shouldn't exist!)
template <typename QP_DERIVED>
int Query_Processor<QP_DERIVED>::testing___find_HG_in_mysql_query_rules_fast_routing_dual(
	khash_t(khStrInt)* _rules_fast_routing, char* username, char* schemaname, int flagIN, bool lock
) {
	int ret = -1;
	khash_t(khStrInt)* rules_fast_routing = _rules_fast_routing ? _rules_fast_routing : this->rules_fast_routing;

	if (rules_fast_routing) {
		ret = search_rules_fast_routing_dest_hg(&rules_fast_routing, username, schemaname, flagIN, lock);
	}

	return ret;
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::get_current_firewall_whitelist(SQLite3_result **u, SQLite3_result **r, SQLite3_result **sf) {
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	if (global_firewall_whitelist_rules_runtime) {
		*r = new SQLite3_result(global_firewall_whitelist_rules_runtime);
	}
	if (global_firewall_whitelist_users_runtime) {
		*u = new SQLite3_result(global_firewall_whitelist_users_runtime);
	}
	if (global_firewall_whitelist_sqli_fingerprints_runtime) {
		*sf = new SQLite3_result(global_firewall_whitelist_sqli_fingerprints_runtime);
	}
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
}

template <typename QP_DERIVED>
void Query_Processor<QP_DERIVED>::load_firewall(SQLite3_result *u, SQLite3_result *r, SQLite3_result *sf) {
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	if (global_firewall_whitelist_rules_runtime) {
		delete global_firewall_whitelist_rules_runtime;
		global_firewall_whitelist_rules_runtime = NULL;
	}
	global_firewall_whitelist_rules_runtime = r;
	global_firewall_whitelist_rules_result___size = r->get_size();
	if (global_firewall_whitelist_users_runtime) {
		delete global_firewall_whitelist_users_runtime;
		global_firewall_whitelist_users_runtime = NULL;
	}
	global_firewall_whitelist_users_runtime = u;
	if (global_firewall_whitelist_sqli_fingerprints_runtime) {
		delete global_firewall_whitelist_sqli_fingerprints_runtime;
		global_firewall_whitelist_sqli_fingerprints_runtime = NULL;
	}
	global_firewall_whitelist_sqli_fingerprints_runtime = sf;
	load_firewall_users(global_firewall_whitelist_users_runtime);
	load_firewall_rules(global_firewall_whitelist_rules_runtime);
	load_firewall_sqli_fingerprints(global_firewall_whitelist_sqli_fingerprints_runtime);
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_firewall_memory_users_table() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	ret = global_firewall_whitelist_users_map___size;
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_firewall_memory_users_config() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	ret = global_firewall_whitelist_users_result___size;
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_firewall_memory_rules_table() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	ret = global_firewall_whitelist_rules_map___size;
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
unsigned long long Query_Processor<QP_DERIVED>::get_firewall_memory_rules_config() {
	unsigned long long ret = 0;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	ret = global_firewall_whitelist_rules_result___size;
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
SQLite3_result* Query_Processor<QP_DERIVED>::get_firewall_whitelist_rules() {
	SQLite3_result *ret = NULL;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	if (global_firewall_whitelist_rules_runtime) {
		ret = new SQLite3_result(global_firewall_whitelist_rules_runtime);
	}
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}

template <typename QP_DERIVED>
SQLite3_result* Query_Processor<QP_DERIVED>::get_firewall_whitelist_users() {
	SQLite3_result *ret = NULL;
	pthread_mutex_lock(&global_firewall_whitelist_mutex);
	if (global_firewall_whitelist_users_runtime) {
		ret = new SQLite3_result(global_firewall_whitelist_users_runtime);
	}
	pthread_mutex_unlock(&global_firewall_whitelist_mutex);
	return ret;
}


void Query_Processor_Output::get_info_json(json& j) {
	j["create_new_connection"] = create_new_conn;
	j["reconnect"] = reconnect;
	j["sticky_conn"] = sticky_conn;
	j["cache_timeout"] = cache_timeout;
	j["cache_ttl"] = cache_ttl;
	j["delay"] = delay;
	j["destination_hostgroup"] = destination_hostgroup;
	j["firewall_whitelist_mode"] = firewall_whitelist_mode;
	j["multiplex"] = multiplex;
	j["timeout"] = timeout;
	j["retries"] = retries;
	j["max_lag_ms"] = max_lag_ms;
}
template
class Query_Processor<MySQL_Query_Processor>;

template
class Query_Processor<PgSQL_Query_Processor>;
