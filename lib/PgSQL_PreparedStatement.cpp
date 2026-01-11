#include "proxysql.h"
#include "cpp.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Protocol.h"

extern PgSQL_STMT_Manager *GloPgStmt;

const int PS_GLOBAL_STATUS_FIELD_NUM = 8;

static uint64_t stmt_compute_hash(const char *user,
	const char *database, const char *query, unsigned int query_length, const Parse_Param_Types& param_types) {
	// two random seperators
	static const char DELIM1[] = "-ZiODNjvcNHTFaARXoqqSPDqQe-";
	static const char DELIM2[] = "-aSfpWDoswfuRsJXqZKfcelzCL-";
	static const char DELIM3[] = "-rQkhRVXdvgVYsmiqZCMikjKmP-";

	// NOSONAR: strlen is safe here 
	size_t user_length = strlen(user); // NOSONAR
	// NOSONAR: strlen is safe here 
	size_t database_length = strlen(database); // NOSONAR
	size_t delim1_length = sizeof(DELIM1) - 1;
	size_t delim2_length = sizeof(DELIM2) - 1;
	size_t delim3_length = sizeof(DELIM3) - 1;

	size_t l = 0;
	l += user_length;
	l += database_length;
	l += delim1_length;
	l += delim2_length;
	l += query_length;
	if (!param_types.empty()) {
		l += delim3_length; // add length for the third delimiter
		l += sizeof(uint16_t); // add length for number of parameter types
		l += (param_types.size() * sizeof(uint32_t)); // add length for parameter types
	}

	std::vector<char> storage(l);
	char* buf = storage.data();
	l = 0;
	memcpy(buf + l, user, user_length);		l += user_length;		// write user
	memcpy(buf + l, DELIM1, delim1_length); l += delim1_length; // write delimiter1
	memcpy(buf + l, database, database_length); l += database_length; // write database
	memcpy(buf + l, DELIM2, delim2_length); l += delim2_length; // write delimiter2
	memcpy(buf + l, query, query_length);	l += query_length; 	// write query
	if (!param_types.empty()) {
		uint16_t size = param_types.size();
		memcpy(buf + l, DELIM3, delim3_length); l += delim3_length; // write delimiter3
		memcpy(buf + l, &size, sizeof(uint16_t)); l += sizeof(uint16_t); // write number of parameter types
		memcpy(buf + l, param_types.data(), size * sizeof(uint32_t)); l += (size * sizeof(uint32_t)); // write each parameter type
	}
	uint64_t hash = SpookyHash::Hash64(buf, l, 0);
	return hash;
}

void PgSQL_STMT_Global_info::compute_hash() {
	hash = stmt_compute_hash(username, dbname, query,
		query_length, parse_param_types);
}

PgSQL_STMT_Global_info::PgSQL_STMT_Global_info(uint64_t id, const char *_user, const char *_database, const char *_query,
                                               unsigned int _query_len, Parse_Param_Types&& _ppt,
											   const char *_first_comment, uint64_t _h) {
	total_mem_usage = 0;
	statement_id = id;
	ref_count_client = 0;
	ref_count_server = 0;
	digest_text = nullptr;
	username = strdup(_user);
	dbname = strdup(_database);
	query_length = _query_len;
	query = (char *)malloc(query_length + 1);
	memcpy(query, _query, query_length);
	query[query_length] = '\0';  // add NULL byte
	first_comment = _first_comment ? strdup(_first_comment) : nullptr;
	parse_param_types = std::move(_ppt);
	PgQueryCmd = PGSQL_QUERY__UNINITIALIZED;
	
	if (_h) {
		hash = _h;
	} else {
		compute_hash();
	}
	calculate_mem_usage();
}

PgSQL_STMT_Global_info::~PgSQL_STMT_Global_info() {
	free(username);
	free(dbname);
	free(query);
	if (first_comment)
		free(first_comment);
	if (digest_text)
		free(digest_text);
	parse_param_types.clear(); // clear the parameter types vector
}

void PgSQL_STMT_Global_info::calculate_mem_usage() {
	total_mem_usage = sizeof(PgSQL_STMT_Global_info) + 	query_length + 1;

	// NOSONAR: strlen is safe here 
	if (username) total_mem_usage += strlen(username) + 1; // NOSONAR
	if (dbname) total_mem_usage += strlen(dbname) + 1; // NOSONAR
	if (first_comment) total_mem_usage += strlen(first_comment) + 1; // NOSONAR
	if (digest_text) total_mem_usage += strlen(digest_text) + 1; // NOSONAR
}

PgSQL_STMT_Local::~PgSQL_STMT_Local() {
	// Note: we do not free the prepared statements because we assume that
	// if we call this destructor the connection is being destroyed anyway
	if (is_client_) {
		for (auto it = stmt_name_to_global_info.begin(); it != stmt_name_to_global_info.end(); ++it) {
			auto* stmt_info = it->second.get();
			GloPgStmt->ref_count_client(stmt_info, -1);
		}
		stmt_name_to_global_info.clear();
	}
	else {
		for (auto it = backend_stmt_to_global_info.begin(); it != backend_stmt_to_global_info.end(); ++it) {
			auto* stmt_info = it->second.get();
			GloPgStmt->ref_count_server(stmt_info, -1);
		}
		backend_stmt_to_global_info.clear();
	}
}

void PgSQL_STMT_Local::client_insert(std::shared_ptr<const PgSQL_STMT_Global_info>& stmt_info,
	const std::string& client_stmt_name, std::shared_ptr<const PgSQL_STMT_Global_info>* local_stmt_info_ptr) {
	assert(stmt_info);

	if (local_stmt_info_ptr && (*local_stmt_info_ptr)) {
		auto& local_stmt_info = *local_stmt_info_ptr;
		if (local_stmt_info->statement_id == stmt_info->statement_id)
			return; // no change

		// Adjust refcounts: decrement old, increment new
		GloPgStmt->ref_count_client(local_stmt_info.get(), -1);
		local_stmt_info.reset();
		
		GloPgStmt->ref_count_client(stmt_info.get(), 1);
		// Update existing entry to new global stmt info one
		local_stmt_info = stmt_info;
		return;
	}

	// New statement name - just insert
	stmt_name_to_global_info.emplace(client_stmt_name, stmt_info);
	GloPgStmt->ref_count_client(stmt_info.get(), 1);
}

const PgSQL_STMT_Global_info* PgSQL_STMT_Local::find_stmt_info_from_stmt_name(const std::string& client_stmt_name) const {
	const PgSQL_STMT_Global_info* ret = nullptr;
	if (auto s = stmt_name_to_global_info.find(client_stmt_name); s != stmt_name_to_global_info.end()) {
		ret = s->second.get();
	}
	return ret;
}

bool PgSQL_STMT_Local::client_close(const std::string& client_stmt_name) {
	if (auto s = stmt_name_to_global_info.find(client_stmt_name); s != stmt_name_to_global_info.end()) {  // found
		const PgSQL_STMT_Global_info* stmt_info = s->second.get();
		GloPgStmt->ref_count_client(stmt_info, -1);
		stmt_name_to_global_info.erase(s);
		return true;
	}
	return false;  // we don't really remove the prepared statement
}

void PgSQL_STMT_Local::client_close_all() {
	for (auto& [_, global_stmt_info] : stmt_name_to_global_info) {
		GloPgStmt->ref_count_client(global_stmt_info.get(), -1);
	}
	stmt_name_to_global_info.clear();
}

uint32_t PgSQL_STMT_Local::generate_new_backend_stmt_id() {
	assert(is_client_ == false);
	if (free_backend_ids.empty() == false) {
		uint32_t backend_stmt_id = free_backend_ids.top();
		free_backend_ids.pop();
		return backend_stmt_id;
	}
	local_max_stmt_id++;
	return local_max_stmt_id;
}

void PgSQL_STMT_Local::backend_insert(std::shared_ptr<const PgSQL_STMT_Global_info>& stmt_info, uint32_t backend_stmt_id) {
	backend_stmt_to_global_info.emplace(backend_stmt_id, stmt_info);
	global_stmt_to_backend_ids.emplace(stmt_info->statement_id, backend_stmt_id);
}

uint32_t PgSQL_STMT_Local::find_backend_stmt_id_from_global_id(uint64_t global_id) const {
	if (auto s = global_stmt_to_backend_ids.find(global_id); s != global_stmt_to_backend_ids.end()) {
		return s->second;
	}
	return 0;  // not found
}

uint64_t PgSQL_STMT_Local::compute_hash(const char *user,
	const char *database, const char *query, unsigned int query_length, const Parse_Param_Types& param_types) {
	uint64_t hash = stmt_compute_hash(user, database, query, query_length, param_types);
	return hash;
}

PgSQL_STMT_Manager::PgSQL_STMT_Manager() {
	last_purge_time = time(NULL);
	pthread_rwlock_init(&rwlock_, NULL);
	next_statement_id = 1;  // we initialize this as 1 because we 0 is not allowed
	num_stmt_with_ref_client_count_zero = 0;
	num_stmt_with_ref_server_count_zero = 0;
	next_status_idx = 0;
}

PgSQL_STMT_Manager::~PgSQL_STMT_Manager() {
	wrlock();
	map_stmt_hash_to_info.clear();
	unlock();
}

void PgSQL_STMT_Manager::ref_count_client___purge_stmts_if_needed() noexcept {

	/* Heuristic trigger(checked twice : before and after acquiring write lock) :
	 * 1. At least 1 second since last_purge_time.
	 * 2. map_stmt_hash_to_info.size() > pgsql_thread___max_stmts_cache.
	 * 3. >= 10% of entries have client refcount == 0.
	 * 4. >= 10% of entries have server refcount == 0.
	 */

	time_t ct = time(NULL);
	if (ct <= last_purge_time + 1)
		return; // too soon, skip

	// --- Light pre-check without lock ---
	size_t map_size = map_stmt_hash_to_info.size();
	uint64_t num_client_zero = num_stmt_with_ref_client_count_zero.load(std::memory_order_relaxed);
	uint64_t num_server_zero = num_stmt_with_ref_server_count_zero.load(std::memory_order_relaxed);

	if (map_size <= (unsigned)pgsql_thread___max_stmts_cache ||
		num_client_zero <= map_size / 10 ||
		num_server_zero <= map_size / 10) {
		// Heuristic says no purge needed
		return;
	}

	// --- Now we know we might purge, take write lock ---
	wrlock();

	// Double-check under exclusive lock (authoritative)
	ct = time(NULL);
	if (ct <= last_purge_time + 1) {
		unlock();
		return;
	}

	map_size = map_stmt_hash_to_info.size();
	num_client_zero = num_stmt_with_ref_client_count_zero.load(std::memory_order_relaxed);
	num_server_zero = num_stmt_with_ref_server_count_zero.load(std::memory_order_relaxed);

	if (map_size <= (unsigned)pgsql_thread___max_stmts_cache ||
		num_client_zero <= map_size / 10 ||
		num_server_zero <= map_size / 10) {
		last_purge_time = ct;
		unlock();
		return;
	}

	// --- Actual purge happens here under wrlock() ---
	last_purge_time = ct;

	//auto& stat_totals = get_current_thread_statistics_totals();

	// Determine how many entries we are allowed to remove
	size_t remaining_removals = std::min(map_size, static_cast<size_t>(num_client_zero));

	/* Purge logic :
	 * - Iterate statements while remaining_removals > 0.
	 * - Candidate removal only when shared_ptr use_count() == 1 (only the map holds it).
	 * - Return its statement_id to free_stmt_ids stack.
	 * - Decrement zero-refcount counters.
	 */
	for (auto it = map_stmt_hash_to_info.begin(); it != map_stmt_hash_to_info.end() && remaining_removals > 0; ) {

		auto& global_stmt_info = it->second;

		// use_count() == 1 indicates that only map_stmt_hash_to_info holds a reference,
		// meaning there are no other references (from client or server) to this prepared statement.
		// So we can safely remove this entry.
		if (global_stmt_info.use_count() == 1) {

			// ref_count_client and ref_count_server should both be 0 in this case
			assert(global_stmt_info->ref_count_client.load(std::memory_order_relaxed) == 0);
			assert(global_stmt_info->ref_count_server.load(std::memory_order_relaxed) == 0);

			// Atomic counters
			num_stmt_with_ref_client_count_zero.fetch_sub(1, std::memory_order_relaxed);
			num_stmt_with_ref_server_count_zero.fetch_sub(1, std::memory_order_relaxed);

			// Free ID
			free_stmt_ids.push(global_stmt_info->statement_id);

			// Update totals
			//stat_totals.s_total -= global_stmt_info->ref_count_server.load(std::memory_order_relaxed);

			// Safe erase from map while iterating
			it = map_stmt_hash_to_info.erase(it);
			remaining_removals--;
		} else {
			++it;
		}
	}

	unlock();
}

std::shared_ptr<const PgSQL_STMT_Global_info> PgSQL_STMT_Manager::find_prepared_statement_by_hash(uint64_t hash, bool lock) {
	std::shared_ptr<const PgSQL_STMT_Global_info> ret = nullptr;  // assume we do not find it

	if (lock) {
		rdlock();
	}

	if (auto s = map_stmt_hash_to_info.find(hash); s != map_stmt_hash_to_info.end()) {
		ret = s->second;
	}

	if (lock) {
		unlock();
	}
	return ret;
}

std::shared_ptr<const PgSQL_STMT_Global_info> PgSQL_STMT_Manager::add_prepared_statement(const char* user, const char* database, const char* query,
	unsigned int query_len, Parse_Param_Types&& ppt, const char* first_comment, const char* digest_text, uint64_t digest, 
	PGSQL_QUERY_command PgQueryCmd, bool lock) {
	std::shared_ptr<const PgSQL_STMT_Global_info> ret = nullptr;

	uint64_t hash = stmt_compute_hash(user, database, query, query_len, ppt);  // this identifies the prepared statement

	if (lock) {
		wrlock();
	}
	// try to find the statement
	if (auto f = map_stmt_hash_to_info.find(hash); f != map_stmt_hash_to_info.end()) {
		// found it!
		ret = f->second;
	} else {
		uint64_t next_id = 0;
		if (!free_stmt_ids.empty()) {
			next_id = free_stmt_ids.top();
			free_stmt_ids.pop();
		} else {
			next_id = next_statement_id;
			next_statement_id++;
		}

		auto stmt_info = std::make_shared<PgSQL_STMT_Global_info>(next_id, user, database, query, query_len, std::move(ppt), first_comment, hash);

		if (digest_text) {
			stmt_info->digest_text = strdup(digest_text);
			stmt_info->digest = digest;	// copy digest
			stmt_info->PgQueryCmd = PgQueryCmd; // copy PgComQueryCmd
			stmt_info->calculate_mem_usage();
		}

		ret = std::move(stmt_info);
		
		//map_stmt_hash_to_info[ret->hash] = ret;
		map_stmt_hash_to_info.emplace(ret->hash, ret);

		num_stmt_with_ref_client_count_zero.fetch_add(1, std::memory_order_relaxed);
		num_stmt_with_ref_server_count_zero.fetch_add(1, std::memory_order_relaxed);
	}

	// Server refcount increment logic
	ref_count_server(ret.get(), 1);

	if (lock) {
		unlock();
	}
	return ret;
}

void PgSQL_STMT_Manager::ref_count_client(const PgSQL_STMT_Global_info* stmt_info, int _v) noexcept {
	assert(stmt_info);

	auto& stat_totals = get_current_thread_statistics_totals();

	stat_totals.c_total += _v;

	if (_v == 1) {
		// increment: relaxed is fine for performance
		int prev = stmt_info->ref_count_client.fetch_add(1, std::memory_order_relaxed);
		// if prev was 0 -> we transitioned 0 -> 1: one fewer zero-count entry
		if (prev == 0) {
			num_stmt_with_ref_client_count_zero.fetch_sub(1, std::memory_order_relaxed);
		}
	}
	else if (_v == -1) {
		// decrement: use acq_rel to synchronize-with potential deleter
		int prev = stmt_info->ref_count_client.fetch_sub(1, std::memory_order_acq_rel);
		// prev is the value before subtraction
		if (prev == 1) {
			// we just transitioned to zero
			num_stmt_with_ref_client_count_zero.fetch_add(1, std::memory_order_relaxed);
		}
	}
	else {
		// support other increments/decrements (if needed)
		int prev = stmt_info->ref_count_client.fetch_add(_v,
			(_v > 0) ? std::memory_order_relaxed : std::memory_order_acq_rel);
		if (_v > 0 && prev == 0) num_stmt_with_ref_client_count_zero.fetch_sub(1, std::memory_order_relaxed);
		if (_v < 0 && prev + _v == 0) num_stmt_with_ref_client_count_zero.fetch_add(1, std::memory_order_relaxed);
	}

	ref_count_client___purge_stmts_if_needed();
}

void PgSQL_STMT_Manager::ref_count_server(const PgSQL_STMT_Global_info* stmt_info, int _v) noexcept {
	assert(stmt_info);

	auto& stat_totals = get_current_thread_statistics_totals();

	stat_totals.s_total += _v;

	if (_v == 1) {
		int prev = stmt_info->ref_count_server.fetch_add(1, std::memory_order_relaxed);
		if (prev == 0) {
			num_stmt_with_ref_server_count_zero.fetch_sub(1, std::memory_order_relaxed);
		}
	}
	else if (_v == -1) {
		int prev = stmt_info->ref_count_server.fetch_sub(1, std::memory_order_acq_rel);
		if (prev == 1) {
			num_stmt_with_ref_server_count_zero.fetch_add(1, std::memory_order_relaxed);
		}
	}
	else {
		int prev = stmt_info->ref_count_server.fetch_add(_v,
			(_v > 0) ? std::memory_order_relaxed : std::memory_order_acq_rel);
		if (_v > 0 && prev == 0) num_stmt_with_ref_server_count_zero.fetch_sub(1, std::memory_order_relaxed);
		if (_v < 0 && prev + _v == 0) num_stmt_with_ref_server_count_zero.fetch_add(1, std::memory_order_relaxed);
	}
}

void PgSQL_STMT_Manager::get_metrics(uint64_t* c_unique, uint64_t* c_total, uint64_t* stmt_max_stmt_id, uint64_t* cached,
	uint64_t* s_unique, uint64_t* s_total) {

#ifdef DEBUG
	uint64_t c_u = 0;
	uint64_t c_t = 0;
	//uint64_t m = 0;
	uint64_t c = 0;
	uint64_t s_u = 0;
	uint64_t s_t = 0;
#endif
	Statistics stats{};

	for (int i = 0; i < next_status_idx.load(std::memory_order_relaxed); ++i) {
		stats.total.c_total += stats_total[i].c_total;
		stats.total.s_total += stats_total[i].s_total;
	}

	stats.cached = map_stmt_hash_to_info.size();
	stats.c_unique = stats.cached - num_stmt_with_ref_client_count_zero.load(std::memory_order_relaxed);
	stats.s_unique = stats.cached - num_stmt_with_ref_server_count_zero.load(std::memory_order_relaxed);
#ifdef DEBUG
	rdlock();
	for (const auto& [_, value] : map_stmt_hash_to_info) {
		const PgSQL_STMT_Global_info* a = value.get();
		c++;
		if (a->ref_count_client.load(std::memory_order_relaxed)) {
			c_u++;
			c_t += a->ref_count_client.load(std::memory_order_relaxed);
		}
		if (a->ref_count_server.load(std::memory_order_relaxed)) {
			s_u++;
			s_t += a->ref_count_server.load(std::memory_order_relaxed);
		}
		//if (it->first > m) {
		//	m = it->first;
		//}
	}
	unlock();
	
	//assert(c_u == stats.c_unique);
	//assert(c_t == stats.total.c_total);
	//assert(c == stats.cached);
	//assert(s_t == stats.total.s_total);
	//assert(s_u == stats.s_unique);
	
	if (c_u != stats.c_unique) {
		proxy_warning("PgSQL_STMT_Manager::get_metrics mismatch: c_u=%llu stats.c_unique=%llu",
			(unsigned long long)c_u, (unsigned long long)stats.c_unique);
	}
	if (c_t != stats.total.c_total) {
		proxy_warning("PgSQL_STMT_Manager::get_metrics mismatch: c_t=%llu stats.total.c_total=%llu",
			(unsigned long long)c_t, (unsigned long long)stats.total.c_total);
	}
	if (c != stats.cached) {
		proxy_warning("PgSQL_STMT_Manager::get_metrics mismatch: cached(counted)=%llu stats.cached=%llu",
			(unsigned long long)c, (unsigned long long)stats.cached);
	}
	if (s_t != stats.total.s_total) {
		proxy_warning("PgSQL_STMT_Manager::get_metrics mismatch: s_t=%llu stats.total.s_total=%llu",
			(unsigned long long)s_t, (unsigned long long)stats.total.s_total);
	}
	if (s_u != stats.s_unique) {
		proxy_warning("PgSQL_STMT_Manager::get_metrics mismatch: s_u=%llu stats.s_unique=%llu",
			(unsigned long long)s_u, (unsigned long long)stats.s_unique);
	}
	
	//*stmt_max_stmt_id = m;
#endif
	* stmt_max_stmt_id = next_statement_id; // this is max stmt_id, no matter if in used or not
	*c_unique = stats.c_unique;
	*c_total = stats.total.c_total;
	*cached = stats.cached;
	*s_total = stats.total.s_total;
	*s_unique = stats.s_unique;
}

void PgSQL_STMT_Manager::get_memory_usage(uint64_t& prep_stmt_metadata_mem_usage, uint64_t& prep_stmt_backend_mem_usage) {
	prep_stmt_backend_mem_usage = 0;
	prep_stmt_metadata_mem_usage = sizeof(PgSQL_STMT_Manager);
	rdlock();
	prep_stmt_metadata_mem_usage += map_stmt_hash_to_info.size() * (sizeof(uint64_t) + sizeof(PgSQL_STMT_Global_info*));
	prep_stmt_metadata_mem_usage += free_stmt_ids.size() * (sizeof(uint64_t));
	for (const auto& [_, value] : map_stmt_hash_to_info) {
		const PgSQL_STMT_Global_info* stmt_global_info = value.get();
		prep_stmt_metadata_mem_usage += stmt_global_info->total_mem_usage;
		prep_stmt_metadata_mem_usage += stmt_global_info->ref_count_server * ((sizeof(uint64_t) * 2) + sizeof(std::shared_ptr<PgSQL_STMT_Global_info>));
		prep_stmt_metadata_mem_usage += stmt_global_info->ref_count_client * (sizeof(std::string) + 16 + sizeof(std::shared_ptr<PgSQL_STMT_Global_info>));

		// backend
		prep_stmt_backend_mem_usage += stmt_global_info->ref_count_server; // FIXME: add backend memory usage
	}
	unlock();
}

class PgSQL_PS_global_stats {
public:
	uint64_t statement_id;
	char* username;
	char* dbname;
	uint64_t digest;
	unsigned long long ref_count_client;
	unsigned long long ref_count_server;
	char* query;
	int num_param_types;
	PgSQL_PS_global_stats(uint64_t stmt_id, const char* d, const char* u, uint64_t dig, const char* q,
		unsigned long long ref_c, unsigned long long ref_s, int params) {
		statement_id = stmt_id;
		digest = dig;
		query = strndup(q, pgsql_thread___query_digests_max_digest_length);
		username = strdup(u);
		dbname = strdup(d);
		ref_count_client = ref_c;
		ref_count_server = ref_s;
		num_param_types = params;
	}
	~PgSQL_PS_global_stats() {
		if (query)
			free(query);
		if (username)
			free(username);
		if (dbname)
			free(dbname);
	}
	char** get_row() {
		char buf[128];
		char** pta = (char**)malloc(sizeof(char*) * PS_GLOBAL_STATUS_FIELD_NUM);
		snprintf(buf, sizeof(buf), "%lu", statement_id);
		pta[0] = strdup(buf);
		assert(dbname);
		pta[1] = strdup(dbname);
		assert(username);
		pta[2] = strdup(username);
		snprintf(buf, sizeof(buf), "0x%016llX", (long long unsigned int)digest);
		pta[3] = strdup(buf);
		assert(query);
		pta[4] = strdup(query);
		snprintf(buf, sizeof(buf), "%llu", ref_count_client);
		pta[5] = strdup(buf);
		snprintf(buf, sizeof(buf), "%llu", ref_count_server);
		pta[6] = strdup(buf);
		snprintf(buf, sizeof(buf), "%d", num_param_types);
		pta[7] = strdup(buf);

		return pta;
	}
	void free_row(char** pta) {
		int i;
		for (i = 0; i < PS_GLOBAL_STATUS_FIELD_NUM; i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};

SQLite3_result* PgSQL_STMT_Manager::get_prepared_statements_global_infos() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current prepared statements global info\n");
	auto result = std::make_unique<SQLite3_result>(PS_GLOBAL_STATUS_FIELD_NUM);
	result->add_column_definition(SQLITE_TEXT, "stmt_id");
	result->add_column_definition(SQLITE_TEXT, "database");
	result->add_column_definition(SQLITE_TEXT, "username");
	result->add_column_definition(SQLITE_TEXT, "digest");
	result->add_column_definition(SQLITE_TEXT, "query");
	result->add_column_definition(SQLITE_TEXT, "ref_count_client");
	result->add_column_definition(SQLITE_TEXT, "ref_count_server");
	result->add_column_definition(SQLITE_TEXT, "num_param_types");

	rdlock();
	for (auto it = map_stmt_hash_to_info.begin(); it != map_stmt_hash_to_info.end(); ++it) {
		const PgSQL_STMT_Global_info* stmt_global_info = it->second.get();

		auto pgs = std::make_unique<PgSQL_PS_global_stats>(stmt_global_info->statement_id,
			stmt_global_info->dbname, stmt_global_info->username, stmt_global_info->hash, stmt_global_info->query,
			stmt_global_info->ref_count_client.load(std::memory_order_relaxed), stmt_global_info->ref_count_server.load(std::memory_order_relaxed),
			stmt_global_info->parse_param_types.size());
		char** pta = pgs->get_row();
		result->add_row(pta);
		pgs->free_row(pta);
	}
	unlock();
	return result.release();
}
