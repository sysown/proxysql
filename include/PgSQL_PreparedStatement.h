#ifndef CLASS_PGSQL_PREPARED_STATEMENT_H
#define CLASS_PGSQL_PREPARED_STATEMENT_H

#include "proxysql.h"
#include "cpp.h"

// class PgSQL_STMT_Global_info represents information about a PgSQL Prepared Statement
// it is an internal representation of prepared statement
// it include all metadata associated with it
class PgSQL_STMT_Global_info {
public:
	uint64_t digest;
	PGSQL_QUERY_command PgQueryCmd;
	char* digest_text;
	uint64_t hash;
	char *username;
	char *dbname;
	char *query;
	unsigned int query_length;
	int ref_count_client;
	int ref_count_server;
	uint64_t statement_id;
	char* first_comment;
	uint64_t total_mem_usage;
	PgSQL_Describe_Prepared_Info* stmt_metadata;
	bool is_select_NOT_for_update;

	Parse_Param_Types parse_param_types;// array of parameter types, used for prepared statements

	PgSQL_STMT_Global_info(uint64_t id, char* u, char* d, char* q, unsigned int ql, char* fc, Parse_Param_Types&& ppt, uint64_t _h);
	~PgSQL_STMT_Global_info();

	void update_stmt_metadata(PgSQL_Describe_Prepared_Info** new_stmt_metadata);
	void calculate_mem_usage();
	void unlock() { pthread_rwlock_unlock(&rwlock_); }
	void wrlock() { pthread_rwlock_wrlock(&rwlock_); }
	void rdlock() { pthread_rwlock_rdlock(&rwlock_); }

private:
	pthread_rwlock_t rwlock_;
	void compute_hash();
};

class PgSQL_STMTs_local_v14 {
public:
	// this map associate client_stmt_id to global_stmt_id : this is used only for client connections
	std::map<std::string, uint64_t> stmt_name_to_global_ids;
	// this multimap associate global_stmt_id to client_stmt_id : this is used only for client connections
	std::multimap<uint64_t, std::string> global_id_to_stmt_names;

	// this map associate backend_stmt_id to global_stmt_id : this is used only for backend connections
	std::map<uint32_t, uint64_t> backend_stmt_to_global_ids;
	// this map associate global_stmt_id to backend_stmt_id : this is used only for backend connections
	std::map<uint64_t, uint32_t> global_stmt_to_backend_ids;

	PgSQL_Session *sess;
	PgSQL_STMTs_local_v14(bool _ic) : sess(NULL), is_client_(_ic) { }
	~PgSQL_STMTs_local_v14();

	inline
	void set_is_client(PgSQL_Session *_s) {
		sess=_s;
		is_client_ = true;
	}
	
	inline
	bool is_client() { return is_client_; }
	inline
	unsigned int get_num_backend_stmts() { return backend_stmt_to_global_ids.size(); }

	void backend_insert(uint64_t global_stmt_id, uint32_t backend_stmt_id);
	void client_insert(uint64_t global_stmt_id, const std::string& client_stmt_name);
	uint64_t compute_hash(const char *user, const char *database, const char *query, unsigned int query_length, 
		const Parse_Param_Types& param_types);
	uint32_t generate_new_backend_stmt_id();
	uint64_t find_global_id_from_stmt_name(const std::string& client_stmt_name);
	uint32_t find_backend_stmt_id_from_global_id(uint64_t global_id);
	bool client_close(const std::string& stmt_name);
	void client_close_all();

private:
	bool is_client_;
	std::stack<uint32_t> free_backend_ids;
	uint32_t local_max_stmt_id = 0;
};


class PgSQL_STMT_Manager_v14 { 
public:
	PgSQL_STMT_Manager_v14();
	~PgSQL_STMT_Manager_v14();
	PgSQL_STMT_Global_info* find_prepared_statement_by_hash(uint64_t hash, bool lock=true);
	PgSQL_STMT_Global_info* find_prepared_statement_by_stmt_id(uint64_t id, bool lock=true);
	inline void rdlock() { pthread_rwlock_rdlock(&rwlock_); }
	inline void wrlock() { pthread_rwlock_wrlock(&rwlock_); }
	inline void unlock() { pthread_rwlock_unlock(&rwlock_); }
	void ref_count_client(uint64_t _stmt, int _v, bool lock=true) noexcept;
	void ref_count_server(uint64_t _stmt, int _v, bool lock=true) noexcept;
	PgSQL_STMT_Global_info* add_prepared_statement(char *user, char *database, char *query, unsigned int query_len, 
		char *fc, Parse_Param_Types&& ppt, bool lock=true);
	void get_metrics(uint64_t *c_unique, uint64_t *c_total, uint64_t *stmt_max_stmt_id, uint64_t *cached,
		uint64_t *s_unique, uint64_t *s_total);
	SQLite3_result* get_prepared_statements_global_infos();
	void get_memory_usage(uint64_t& prep_stmt_metadata_mem_usage, uint64_t& prep_stmt_backend_mem_usage);

private:
	uint64_t next_statement_id;
	uint64_t num_stmt_with_ref_client_count_zero;
	uint64_t num_stmt_with_ref_server_count_zero;
	pthread_rwlock_t rwlock_;
	std::map<uint64_t, PgSQL_STMT_Global_info*> map_stmt_id_to_info;	// map using statement id
	std::map<uint64_t, PgSQL_STMT_Global_info*> map_stmt_hash_to_info;	// map using hashes
	std::stack<uint64_t> free_stmt_ids;
	struct {
		uint64_t c_unique;
		uint64_t c_total;
		uint64_t stmt_max_stmt_id;
		uint64_t cached;
		uint64_t s_unique;
		uint64_t s_total;
	} statuses;
	time_t last_purge_time;
};

#endif /* CLASS_PGSQL_PREPARED_STATEMENT_H */
