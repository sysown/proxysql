#ifndef CLASS_PGSQL_PREPARED_STATEMENT_H
#define CLASS_PGSQL_PREPARED_STATEMENT_H

#include "proxysql.h"
#include "cpp.h"

static constexpr uint16_t PGSQL_MAX_THREADS = 255;

// class PgSQL_STMT_Global_info represents information about a PgSQL Prepared Statement
// it is an internal representation of prepared statement
// it include all metadata associated with it
class PgSQL_STMT_Global_info {
public:
	char* query;
	char* digest_text;
	char* first_comment;
	unsigned int query_length;
	uint64_t statement_id;
	mutable std::atomic<uint32_t> ref_count_client;
	mutable std::atomic<uint32_t> ref_count_server;
	Parse_Param_Types parse_param_types;// array of parameter types, used for prepared statements
	char* username;
	char* dbname;
	uint64_t digest;
	uint64_t hash;
	uint64_t total_mem_usage;
	PGSQL_QUERY_command PgQueryCmd;
	
	PgSQL_STMT_Global_info(uint64_t id, const char* _user, const char* _database, const char* _query, unsigned int _query_len,
		Parse_Param_Types&& _ppt, const char* _first_comment, uint64_t _h);
	~PgSQL_STMT_Global_info();
	void calculate_mem_usage();

private:
	void compute_hash();
};

// class PgSQL_STMT_Local represents prepared statements local to a session/connection
class PgSQL_STMT_Local {
public:
	explicit PgSQL_STMT_Local(bool _ic) : sess(nullptr), local_max_stmt_id(0), is_client_(_ic) { }
	~PgSQL_STMT_Local();

	inline void set_is_client(PgSQL_Session *_s) { sess=_s; is_client_ = true; }
	inline bool is_client() const { return is_client_; }
	inline unsigned int get_num_backend_stmts() const { return backend_stmt_to_global_info.size(); }
	
	/**
	 * Map client statement name to a global prepared statement.
	 *
	 *  - If client statement (local_stmt_info_ptr) already references a different global stmt: decrement old refcount,
	 *    increment new, and replace pointer.
	 *  - If client statement (local_stmt_info_ptr) references the same stmt: no-op.
	 *  - Otherwise: insert into stmt_name_to_global_info and increment client refcount.
	 *
	 * Parameters:
	 *  stmt_info            Global prepared statement (shared_ptr, must be valid).
	 *  client_stmt_name     Statement name from client scope.
	 *  local_stmt_info_ptr  Optional existing local pointer to update instead of map insert.
	 */
	void client_insert(std::shared_ptr<const PgSQL_STMT_Global_info>& stmt_info, const std::string& client_stmt_name, 
		std::shared_ptr<const PgSQL_STMT_Global_info>* local_stmt_info_ptr);

	/**
	 * @brief Find statement info by client statement name in stmt_name_to_global_info.
	 *
	 * Performs a map lookup using the provided client statement name and returns the
	 * associated PgSQL_STMT_Global_info pointer, or nullptr if not present.
	 */
	const PgSQL_STMT_Global_info* find_stmt_info_from_stmt_name(const std::string& client_stmt_name) const;

	/**
	 * Close a client-side prepared statement mapping by its name.
	 *
	 *  - If the name exists: decrement the global statement's client refcount,
	 *    remove the mapping, return true.
	 *  - If not found: do nothing, return false.
	 * 
	 * @param client_stmt_name Client statement identifier.
	 * @return true if a mapping was removed, false otherwise.
	 */
	bool client_close(const std::string& client_stmt_name);

	/**
	 * Close all client-side prepared statement mappings.
	 *
	 * Decrements the client refcount for each associated global statement
	 * and clears the stmt_name_to_global_info map.
	 */
	void client_close_all();

	/**
	 * Generate a new backend statement ID.
	 * 
	 * @return A backend statement id.
	 */
	uint32_t generate_new_backend_stmt_id();

	/**
	 * @brief Register a backend prepared statement mapping.
	 *
	 * Adds bidirectional associations:
	 *  - backend_stmt_id -> global statement info
	 *  - global statement_id -> backend_stmt_id
	 */
	void backend_insert(std::shared_ptr<const PgSQL_STMT_Global_info>& stmt_info, uint32_t backend_stmt_id);

	/**
	 * @brief Find backend statement ID from global statement ID.
	 *
	 * Looks up the backend statement ID associated with the given global statement ID.
	 * 
	 * @param global_id The global statement ID to look up.
	 * @return The associated backend statement ID, or 0 if not found.
	 */
	uint32_t find_backend_stmt_id_from_global_id(uint64_t global_id) const;

	/**
	 * @brief Compute a unique hash for a prepared statement.
	 *
	 * Combines user, database, query, and parameter types into a hash value.
	 * 
	 * @param user The username.
	 * @param database The database name.
	 * @param query The SQL query string.
	 * @param query_length The length of the query string.
	 * @param param_types The parameter types for the prepared statement.
	 * @return A computed hash value representing the prepared statement.
	 */
	static uint64_t compute_hash(const char* user, const char* database, const char* query, 
		unsigned int query_length, const Parse_Param_Types& param_types);

private:
	// this map associate client_stmt_id to global_stmt_info : this is used only for client connections
	std::map<std::string, std::shared_ptr<const PgSQL_STMT_Global_info>> stmt_name_to_global_info;

	// this map associate backend_stmt_id to global_stmt_info : this is used only for backend connections
	std::map<uint32_t, std::shared_ptr<const PgSQL_STMT_Global_info>> backend_stmt_to_global_info;

	// this map associate global_stmt_id to backend_stmt_id : this is used only for backend connections
	std::map<uint64_t, uint32_t> global_stmt_to_backend_ids;

	PgSQL_Session* sess = nullptr;

	// stack of free backend statement ids
	std::stack<uint32_t> free_backend_ids;

	// maximum assigned statement id in this session
	uint32_t local_max_stmt_id = 0;

	// is client session ?
	bool is_client_;

	friend class PgSQL_Session;
};

// class PgSQL_STMT_Manager manages global prepared statements across all sessions
class PgSQL_STMT_Manager { 
public:
	PgSQL_STMT_Manager();
	~PgSQL_STMT_Manager();

	/**
	 * @brief Lookup a prepared statement by its 64-bit hash.
	 * 
	 * @param hash Unique hash computed from user, db, query, and parameter types.
	 * @param lock If true acquires/release internal read lock; set false only if caller already holds it.
	 * @return Shared pointer to global statement info or nullptr if not found.
	 */
	std::shared_ptr<const PgSQL_STMT_Global_info> find_prepared_statement_by_hash(uint64_t hash, bool lock=true);

	/**
	 * @brief Retrieve existing or create a new global prepared statement.
	 *
	 * Computes a hash from user, database, query and parameter types. If an entry with that hash
	 * exists it is returned. Otherwise a new PgSQL_STMT_Global_info is allocated, assigned a
	 * statement_id (preferring reused IDs from free_stmt_ids), optional digest metadata copied,
	 * inserted into map_stmt_hash_to_info, and zero-refcount tracking counters updated.
	 * Always increments the server refcount for the returned statement.
	 *
	 * Concurrency: Acquires/release write lock when lock == true.
	 *
	 * @param user          Client username (null-terminated).
	 * @param database      Database/schema name.
	 * @param query         SQL text.
	 * @param query_len     Length of query.
	 * @param ppt           Vector of parameter type OIDs (moved if new entry is created).
	 * @param first_comment First comment prefix (optional, may be null).
	 * @param digest_text   Normalized digest text (optional, may be null).
	 * @param digest        64-bit digest value (used only if digest_text provided).
	 * @param PgQueryCmd    Parsed command classification.
	 * @param lock          If true, method manages locking internally.
	 * @return shared_ptr to the global prepared statement (never nullptr).
	 */
	std::shared_ptr<const PgSQL_STMT_Global_info> add_prepared_statement(const char* user, const char* database, const char* query, 
		unsigned int query_len, Parse_Param_Types&& ppt, const char* first_comment, const char* digest_text, uint64_t digest, 
		PGSQL_QUERY_command PgQueryCmd, bool lock = true);

	/**
	 * @brief Adjust client refcount for a prepared statement and update per-thread stats.
	 * 
	 * - Applies delta _v (positive or negative) atomically.
	 * - Maintains zero-refcount tracking counters on transitions to/from zero.
	 * - Triggers opportunistic purge heuristic after modification.
	 * 
	 * Thread-safety: uses atomic operations; no external lock required.
	 * 
	 * @param stmt_info Non-null pointer to global PS metadata.
	 * @param _v Delta to apply (typically +1 or -1).
	 */
	void ref_count_client(const PgSQL_STMT_Global_info* stmt_info, int _v) noexcept;

	/**
	 * @brief Adjust server refcount for a prepared statement and update per-thread stats.
	 * 
	 * - Applies delta _v (positive or negative) atomically.
	 * - Maintains zero-refcount tracking counters on transitions to/from zero.
	 * 
	 * Thread-safety: uses atomic operations; no external lock required.
	 * 
	 * @param stmt_info Non-null pointer to global PS metadata.
	 * @param _v Delta to apply (typically +1 or -1).
	 */
	void ref_count_server(const PgSQL_STMT_Global_info* stmt_info, int _v) noexcept;

	/**
	 * @brief Retrieve global prepared statement metrics.
	 *
	 * Outputs:
	 *  - c_unique: Number of unique prepared statements with client refcount > 0.
	 *  - c_total: Total number of client references across all prepared statements.
	 *  - stmt_max_stmt_id: Maximum assigned statement ID.
	 *  - cached: Total number of unique prepared statements in the global cache.
	 *  - s_unique: Number of unique prepared statements with server refcount > 0.
	 *  - s_total: Total number of server references across all prepared statements.
	 */
	void get_metrics(uint64_t *c_unique, uint64_t *c_total, uint64_t *stmt_max_stmt_id, uint64_t *cached,
		uint64_t *s_unique, uint64_t *s_total);

	/**
	 * @brief Retrieve memory usage statistics for prepared statements.
	 *
	 * Outputs:
	 *  - prep_stmt_metadata_mem_usage: Total memory used for prepared statement metadata.
	 *  - prep_stmt_backend_mem_usage: Total memory used for backend prepared statement allocations.
	 */
	void get_memory_usage(uint64_t& prep_stmt_metadata_mem_usage, uint64_t& prep_stmt_backend_mem_usage);

	/**
	 * @brief Build and return a snapshot of all global prepared statements.
	 *
	 * @return SQLite3_result* containing one row per prepared statement (must be freed by caller).
	 */
	SQLite3_result* get_prepared_statements_global_infos();

private:
	struct Statistics {
		struct Totals {
			uint64_t c_total;
			uint64_t s_total;
		} total;
		uint64_t c_unique;
		uint64_t s_unique;
		uint64_t cached;
	};

	// map from statement hash to global prepared statement info
	std::map<uint64_t, std::shared_ptr<const PgSQL_STMT_Global_info>> map_stmt_hash_to_info;	// map using hashes

	// next statement ID to assign if no free IDs are available
	uint64_t next_statement_id;

	// counters to track number of statements with zero refcounts
	std::atomic<uint64_t> num_stmt_with_ref_client_count_zero;

	// counters to track number of statements with zero refcounts
	std::atomic<uint64_t> num_stmt_with_ref_server_count_zero;

	// read-write lock to protect map_stmt_hash_to_info and free_stmt_ids
	pthread_rwlock_t rwlock_;

	// stack of freed statement IDs for reuses
	std::stack<uint64_t> free_stmt_ids;

	// last time we purged unused statements
	time_t last_purge_time;

	// to make lock free status counting per thread, we use thread local storage
	inline static thread_local int thd_idx = -1;
	std::atomic<int> next_status_idx{};

	// FIXME: should be equal to number of worker threads configured in ProxySQL
	std::array<Statistics::Totals, PGSQL_MAX_THREADS> stats_total{};

	// get per thread statistics totals
	inline
	Statistics::Totals& get_current_thread_statistics_totals() noexcept {
		if (thd_idx == -1) {
			thd_idx = next_status_idx.fetch_add(1, std::memory_order_relaxed);
		}
		return stats_total[thd_idx];
	}

	// read-write lock wrappers
	inline void rdlock() noexcept { pthread_rwlock_rdlock(&rwlock_); }
	inline void wrlock() noexcept { pthread_rwlock_wrlock(&rwlock_); }
	inline void unlock() noexcept { pthread_rwlock_unlock(&rwlock_); }

	/**
	 * @brief Opportunistically purge unused prepared statements from the global cache.
	 *
	 * Concurrency:
	 *  - Fast lock-free pre-check avoids unnecessary write lock.
	 */
	void ref_count_client___purge_stmts_if_needed() noexcept;
};

#endif /* CLASS_PGSQL_PREPARED_STATEMENT_H */
