#ifndef __CLASS_QUERY_PROCESSOR_H
#define __CLASS_QUERY_PROCESSOR_H
#include <type_traits>
#include <set>
#include "proxysql.h"
#include "cpp.h"

// Optimization introduced in 2.0.6
// to avoid a lot of unnecessary copy
#define DIGEST_STATS_FAST_MINSIZE   100000
#define DIGEST_STATS_FAST_THREADS   4

//#include "../deps/json/json.hpp"

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

#include "khash.h"
KHASH_MAP_INIT_STR(khStrInt, int)

#include "proxysql_typedefs.h"

#define WUS_NOT_FOUND   0	// couldn't find any filter
#define WUS_OFF         1	// allow the query
#define WUS_DETECTING   2	// allow the query but log it
#define WUS_PROTECTING  3	// block the query

// Utilizing SFINAE (Substitution Failure Is Not An Error) to check if a class contains a specific method
#define DEFINE_HAS_METHOD_STRUCT(METHODNAME) 	\
					template <typename T> \
					class has_##METHODNAME \
					{ \
					private: \
						typedef char YesType[1]; \
						typedef char NoType[2]; \
						template <typename C> static YesType& test(decltype(&C::METHODNAME)); \
						template <typename C> static NoType& test(...); \
					public: \
						enum { value = sizeof(test<T>(0)) == sizeof(YesType) }; \
					};

typedef struct _query_digest_stats_pointers_t {
	char *pta[14];
	char digest[24];
	char count_star[24];
	char first_seen[24];
	char last_seen[24];
	char sum_time[24];
	char min_time[24];
	char max_time[24];
	char hid[24];
	char rows_affected[24];
	char rows_sent[24];
} query_digest_stats_pointers_t;

class QP_query_digest_stats {
	public:
	uint64_t digest;
	char *digest_text;
	char *username;
	char *schemaname;
	char *client_address;
	char username_buf[24];
	char schemaname_buf[24];
	char client_address_buf[24];
	time_t first_seen;
	time_t last_seen;
	unsigned int count_star;
	unsigned long long sum_time;
	unsigned long long min_time;
	unsigned long long max_time;
	unsigned long long rows_affected;
	unsigned long long rows_sent;
	int hid;
	QP_query_digest_stats(const char* _user, const char* _schema, uint64_t _digest, const char* _digest_text,
		int _hid, const char* _client_addr, int query_digests_max_digest_length);
	void add_time(
		unsigned long long t, unsigned long long n, unsigned long long ra, unsigned long long rs,
		unsigned long long cnt = 1
	);
	~QP_query_digest_stats();
	char *get_digest_text(const umap_query_digest_text *digest_text_umap);
	char **get_row(umap_query_digest_text *digest_text_umap, query_digest_stats_pointers_t *qdsp);
};

typedef struct _Query_Processor_rule_t {
	int rule_id;
	bool active;
	char *username;
	char *schemaname;
	int flagIN;
	char *client_addr;
	int client_addr_wildcard_position;
	char *proxy_addr;
	int proxy_port;
	uint64_t digest;
	char *match_digest;
	char *match_pattern;
	bool negate_match_pattern;
	int re_modifiers; // note: this is passed as char*, but converted to bitsfield
	int flagOUT;
	char *replace_pattern;
	int destination_hostgroup;
	int cache_ttl;
	int cache_empty_result;
	int cache_timeout;
	int reconnect;
	int timeout;
	int retries;
	int delay;
	int next_query_flagIN;
	int mirror_hostgroup;
	int mirror_flagOUT;
	char *error_msg;
	char *OK_msg;
	int sticky_conn;
	int multiplex;
	int log;
	bool apply;
	char* attributes;
	char *comment; // #643
	void *regex_engine1;
	void *regex_engine2;
	uint64_t hits;
	struct _Query_Processor_rule_t *parent; // pointer to parent, to speed up parent update
	std::vector<int>* flagOUT_ids;
	std::vector<int>* flagOUT_weights;
	int flagOUT_weights_total;
} QP_rule_t;

class Query_Processor_Output {
	public:
	void *ptr;
	unsigned int size;
	int destination_hostgroup;
	int mirror_hostgroup;
	int mirror_flagOUT;
	int next_query_flagIN;
	int cache_ttl;
	int cache_empty_result;
	int cache_timeout;
	int reconnect;
	int timeout;
	int retries;
	int delay;
	char *error_msg;
	char *OK_msg;
	int sticky_conn;
	int multiplex;
	long long max_lag_ms;
	int log;
	int firewall_whitelist_mode;
	char *attributes;
	char *comment; // #643
	
	bool create_new_conn;
	std::string *new_query;
	void * operator new(size_t size) {
		return l_alloc(size);
	}
	void operator delete(void *ptr) {
		l_free(sizeof(Query_Processor_Output),ptr);
	}
	Query_Processor_Output() {
		//init();
	}
	~Query_Processor_Output() {
		//destroy();
	}
	void init() {
		ptr=NULL;
		size=0;
		destination_hostgroup=-1;
		mirror_hostgroup=-1;
		mirror_flagOUT=-1;
		next_query_flagIN=-1;
		cache_ttl=-1;
		cache_empty_result=1;
		cache_timeout=-1;
		reconnect=-1;
		timeout=-1;
		retries=-1;
		delay=-1;
		sticky_conn=-1;
		multiplex=-1;
		max_lag_ms=-1;
		log=-1;
		new_query=NULL;
		error_msg=NULL;
		OK_msg=NULL;
		attributes=NULL;
		comment=NULL; // #643
		firewall_whitelist_mode = WUS_NOT_FOUND;
		create_new_conn=0;
	}
	void destroy() {
		if (error_msg) {
			free(error_msg);
			error_msg=NULL;
		}
		if (OK_msg) {
			free(OK_msg);
			OK_msg=NULL;
		}
		if (attributes) {
			free(attributes);
		}
		if (comment) { // #643
			free(comment);
		}
	}
	void get_info_json(nlohmann::json& j);
};

/**
 * @brief Frees the supplied query rules and cleans the vector.
 */
void __reset_rules(std::vector<QP_rule_t*>* qrs);

/**
 * @brief Helper type for performing the 'mysql_rules_fast_routing' hashmaps creation.
 * @details Holds all the info 'Query_Processor' requires about the hashmap.
 */
struct fast_routing_hashmap_t {
	SQLite3_result* rules_resultset;
	unsigned long long rules_resultset_size;
	khash_t(khStrInt)* rules_fast_routing;
	char* rules_fast_routing___keys_values;
	unsigned long long rules_fast_routing___keys_values___size;
};

/**
 * @brief Helper type for backing up 'query_rules' memory structures.
 * @details Used when reinitializing the query rules.
 */
struct rules_mem_sts_t {
	std::vector<QP_rule_t*> query_rules;
	char* rules_fast_routing___keys_values;
	khash_t(khStrInt)* rules_fast_routing;
};

class MySQL_Query_Processor;
class PgSQL_Query_Processor;
class MySQL_Connection_userinfo;
class PgSQL_Connection_userinfo;
class MySQL_Session;
class PgSQL_Session; 
class MySQL_Query_Processor_Output;
class PgSQL_Query_Processor_Output;
struct _MySQL_Query_processor_Rule_t;
struct PgSQL_Query_Processor_Rule_t;
typedef struct _MySQL_Query_processor_Rule_t MySQL_Query_Processor_Rule_t;

/**
 * @brief Query Processor class.
 * @details This class is responsible for managing the query rules and processing the incoming queries.
 */
template <typename QP_DERIVED>
class Query_Processor {
	static_assert(std::is_same_v<QP_DERIVED,MySQL_Query_Processor> || std::is_same_v<QP_DERIVED,PgSQL_Query_Processor>,
		"Invalid QP_DERIVED Query Processor type");
	using TypeSession   = typename std::conditional<std::is_same_v<QP_DERIVED,MySQL_Query_Processor>,MySQL_Session,PgSQL_Session>::type;
	using TypeConnInfo  = typename std::conditional<std::is_same_v<QP_DERIVED,MySQL_Query_Processor>,MySQL_Connection_userinfo,PgSQL_Connection_userinfo>::type;
	using TypeQPOutput  = typename std::conditional<std::is_same_v<QP_DERIVED,MySQL_Query_Processor>,MySQL_Query_Processor_Output,PgSQL_Query_Processor_Output>::type;
	using TypeQueryRule = typename std::conditional<std::is_same_v<QP_DERIVED,MySQL_Query_Processor>,MySQL_Query_Processor_Rule_t,PgSQL_Query_Processor_Rule_t>::type;
public:
	Query_Processor(int _query_rules_fast_routing_algorithm);
	~Query_Processor();

	void print_version();
	rules_mem_sts_t reset_all(bool lock = true);
	void delete_QP_out(Query_Processor_Output* o);
	void query_parser_init(SQP_par_t* qp, const char* query, int query_length, int flags);
	void query_parser_free(SQP_par_t* qp);
	char* get_digest_text(SQP_par_t* qp);
	uint64_t get_digest(SQP_par_t* qp);
	void update_query_digest(uint64_t digest_total, uint64_t digest, char* digest_text, int hid, 
		TypeConnInfo* ui, unsigned long long t, unsigned long long n, const char* client_addr, 
		unsigned long long rows_affected, unsigned long long rows_sent);
	std::pair<SQLite3_result*,int> get_query_digests_v2(const bool use_resultset = true);
	std::pair<SQLite3_result*,int> get_query_digests_reset_v2(const bool copy, const bool use_resultset = true);
	void get_query_digests_reset(umap_query_digest* uqd, umap_query_digest_text* uqdt);
	unsigned long long purge_query_digests(bool async_purge, bool parallel, char** msg);

	void save_query_rules(SQLite3_result* resultset);

	void wrlock(); // explicit write lock, to be used in multi-insert
	void rdlock(); // explicit read lock
	void wrunlock(); // explicit unlock
	void commit(); // this applies all the changes in memory

	unsigned long long get_query_digests_total_size();
	unsigned long long get_rules_mem_used();
	unsigned long long get_new_req_conns_count();

	SQLite3_result* get_current_query_rules_inner();
	SQLite3_result* get_stats_query_rules();
	SQLite3_result* get_query_digests();
	SQLite3_result* get_query_digests_reset();
	
	
	/**
	 * @brief Creates a hashmap for 'rules_fast_routing' from the provided resultset.
	 * @param resultset A resulset from which to create a hashmap.
	 * @return A hashmap encapsulated into the 'fast_routing_hashmap_t' type.
	 */
	fast_routing_hashmap_t create_fast_routing_hashmap(SQLite3_result* resultset);

	/**
	 * @brief Swaps the current 'rules_fast_routing' hashmap, updating all the required related info.
	 * @details This function assumes caller has taken write access over ''
	 * @param fast_routing_hashmap New hashmap and info replacing current.
	 * @return Old 'fast_routing_resultset' that has been replaced. Required to be freed by caller.
	 */
	SQLite3_result* load_fast_routing(const fast_routing_hashmap_t& fast_routing_hashmap);

	SQLite3_result* get_current_query_rules_fast_routing();
	SQLite3_result* get_current_query_rules_fast_routing_inner();
	int get_current_query_rules_fast_routing_count();

	bool insert(QP_rule_t* qr, bool lock = true); // insert a new rule. Uses a generic void pointer to a structure that may vary depending from the Query Processor
	void delete_query_rule(QP_rule_t* qr);	// destructor
	void sort(bool lock = true);
	
	int testing___find_HG_in_mysql_query_rules_fast_routing(char* username, char* schemaname, int flagIN);
	int testing___find_HG_in_mysql_query_rules_fast_routing_dual(khash_t(khStrInt)* _rules_fast_routing, char* username, char* schemaname, int flagIN, bool lock);

	// firewall
	void load_firewall(SQLite3_result* u, SQLite3_result* r, SQLite3_result* sf);
	void load_firewall_users(SQLite3_result*);
	void load_firewall_rules(SQLite3_result*);
	void load_firewall_sqli_fingerprints(SQLite3_result*);

	unsigned long long get_firewall_memory_users_table();
	unsigned long long get_firewall_memory_users_config();
	unsigned long long get_firewall_memory_rules_table();
	unsigned long long get_firewall_memory_rules_config();
	void get_current_firewall_whitelist(SQLite3_result** u, SQLite3_result** r, SQLite3_result** sf);
	int find_firewall_whitelist_user(char* username, char* client);
	bool find_firewall_whitelist_rule(char* username, char* client_address, char* schemaname, int flagIN, uint64_t digest);

	SQLite3_result* get_firewall_whitelist_users();
	SQLite3_result* get_firewall_whitelist_rules();
	bool whitelisted_sqli_fingerprint(char*);

	uint32_t query_rules_fast_routing_algorithm = 1;

protected:
	volatile unsigned int version;
	std::vector<QP_rule_t*> rules;

	Query_Processor_Output* process_query(TypeSession* sess, bool stmt_exec, const char* query, unsigned int len,
		Query_Processor_Output*, SQP_par_t* qp);
	void init_thread();
	void end_thread();
	void update_query_processor_stats();
	void query_parser_update_counters(TypeSession* sess, uint64_t digest_total, uint64_t digest, char* digest_text, unsigned long long t);
	bool query_parser_first_comment(Query_Processor_Output* qpo, char* fc);

private:
	char rand_del[16];
	umap_query_digest digest_umap;
	umap_query_digest_text digest_text_umap;
	pthread_rwlock_t digest_rwlock;
	pthread_rwlock_t rwlock;
	khash_t(khStrInt)* rules_fast_routing;
	char* rules_fast_routing___keys_values;
	unsigned long long rules_fast_routing___keys_values___size;
	unsigned long long rules_fast_routing___number;
	
	// firewall
	pthread_mutex_t global_firewall_whitelist_mutex;
	std::unordered_map<std::string, int> global_firewall_whitelist_users;
	std::unordered_map<std::string, void*> global_firewall_whitelist_rules;
	std::vector<std::string> global_firewall_whitelist_sqli_fingerprints;
	SQLite3_result* global_firewall_whitelist_users_runtime;
	SQLite3_result* global_firewall_whitelist_rules_runtime;
	SQLite3_result* global_firewall_whitelist_sqli_fingerprints_runtime;

	unsigned long long global_firewall_whitelist_users_map___size;
	unsigned long long global_firewall_whitelist_users_result___size;
	unsigned long long global_firewall_whitelist_rules_map___size;
	unsigned long long global_firewall_whitelist_rules_result___size;

	unsigned long long rules_mem_used;
	unsigned long long new_req_conns_count;
	
	SQLite3_result* query_rules_resultset; // here we save a copy of resultset for query rules
	// fast routing
	SQLite3_result* fast_routing_resultset; // here we save a copy of resultset for query rules fast routing

	DEFINE_HAS_METHOD_STRUCT(query_parser_first_comment_extended);
	DEFINE_HAS_METHOD_STRUCT(process_query_extended);

	unsigned long long purge_query_digests_async(char** msg);
	unsigned long long purge_query_digests_sync(bool parallel);

	/**
	 * @brief Searches for a matching rule in the supplied map, returning the destination hostgroup.
	 * @details This functions takes a pointer to the hashmap pointer. This is because it performs a
	 *  conditional internal locking of member 'rwlock'. Since the original pointer value could be modified
	 *  after the function call, we must perform the resource acquisition (dereference) after we have
	 *  acquired the internal locking.
	 * @param khStrInt The map to be used for performing the search. See @details.
	 * @param u Username, used for the search as part of the map key.
	 * @param s Schemaname, used for the search as part of the map key.
	 * @param flagIN FlagIn, used for the search as part of the map key.
	 * @param lock Whether or not the member lock 'rwlock' should be taken for the search.
	 * @return If a matching rule is found, the target destination hostgroup, -1 otherwise.
	 */
	int search_rules_fast_routing_dest_hg(
		khash_t(khStrInt)** __rules_fast_routing, const char* u, const char* s, int flagIN, bool lock
	);
	
	friend Web_Interface_plugin;
};

#endif /* __CLASS_QUERY_PROCESSOR_H */
