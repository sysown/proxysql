#include "proxysql.h"
#include "cpp.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Protocol.h"

extern PgSQL_STMT_Manager_v14 *GloPgStmt;

const int PS_GLOBAL_STATUS_FIELD_NUM = 9;

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

PgSQL_STMT_Global_info::PgSQL_STMT_Global_info(uint64_t id,
                                               char *u, char *d, char *q,
                                               unsigned int ql,
                                               char *fc,
											   Parse_Param_Types&& ppt,
                                               uint64_t _h) {
	pthread_rwlock_init(&rwlock_, NULL);
	total_mem_usage = 0;
	statement_id = id;
	ref_count_client = 0;
	ref_count_server = 0;
	digest_text = nullptr;
	stmt_metadata = nullptr;
	username = strdup(u);
	dbname = strdup(d);
	query = (char *)malloc(ql + 1);
	memcpy(query, q, ql);
	query[ql] = '\0';  // add NULL byte
	query_length = ql;
	first_comment = fc ? strdup(fc) : nullptr;
	parse_param_types = std::move(ppt);
	PgQueryCmd = PGSQL_QUERY__UNINITIALIZED;
	
	if (_h) {
		hash = _h;
	} else {
		compute_hash();
	}

	is_select_NOT_for_update = false;
	{  // see bug #899 . Most of the code is borrowed from
	   // Query_Info::is_select_NOT_for_update()
		if (ql >= 7) {
			if (strncasecmp(q, (char *)"SELECT ", 7) == 0) {  // is a SELECT
				if (ql >= 17) {
					char *p = q;
					p += ql - 11;
					if (strncasecmp(p, " FOR UPDATE", 11) == 0) {  // is a SELECT FOR UPDATE
						__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
						goto __exit_PgSQL_STMT_Global_info___search_select;
					}
					p = q;
					p += ql-10;
					if (strncasecmp(p, " FOR SHARE", 10) == 0) {  // is a SELECT FOR SHARE
						__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
						goto __exit_PgSQL_STMT_Global_info___search_select;
					}
					if (ql >= 25) {
						p = q;
						p += ql-19;
						if (strncasecmp(p, " LOCK IN SHARE MODE", 19) == 0) {  // is a SELECT LOCK IN SHARE MODE
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_PgSQL_STMT_Global_info___search_select;
						}
						p = q;
						p += ql-7;
						if (strncasecmp(p," NOWAIT",7)==0) {
							// let simplify. If NOWAIT is used, we assume FOR UPDATE|SHARE is used
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_PgSQL_STMT_Global_info___search_select;

						}
						p = q;
						p += ql-12;
						if (strncasecmp(p," SKIP LOCKED",12)==0) {
							// let simplify. If SKIP LOCKED is used, we assume FOR UPDATE|SHARE is used
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_PgSQL_STMT_Global_info___search_select;
						}
						p=q;
						char buf[129];
						if (ql>=128) { // for long query, just check the last 128 bytes
							p+=ql-128;
							memcpy(buf,p,128);
							buf[128]=0;
						} else {
							memcpy(buf,p,ql);
							buf[ql]=0;
						}
						if (strcasestr(buf," FOR ")) {
							if (strcasestr(buf," FOR UPDATE ")) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_PgSQL_STMT_Global_info___search_select;
							}
							if (strcasestr(buf," FOR SHARE ")) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_PgSQL_STMT_Global_info___search_select;
							}
						}
					}
				}
				is_select_NOT_for_update = true;
			}
		}
	}
__exit_PgSQL_STMT_Global_info___search_select:
	calculate_mem_usage();
}

void PgSQL_STMT_Global_info::calculate_mem_usage() {
	total_mem_usage = sizeof(PgSQL_STMT_Global_info) +
		query_length + 1;

	// NOSONAR: strlen is safe here 
	if (username) total_mem_usage += strlen(username) + 1; // NOSONAR
	if (dbname) total_mem_usage += strlen(dbname) + 1; // NOSONAR
	if (first_comment) total_mem_usage += strlen(first_comment) + 1; // NOSONAR
	if (digest_text) total_mem_usage += strlen(digest_text) + 1; // NOSONAR

	if (stmt_metadata) {
		total_mem_usage += sizeof(PgSQL_Describe_Prepared_Info);
		total_mem_usage += stmt_metadata->parameter_types_count * sizeof(uint32_t) ;
		total_mem_usage += stmt_metadata->columns_count * sizeof(ColumnMetadata);
		for (uint16_t i = 0; i < stmt_metadata->columns_count; i++) {
			if (stmt_metadata->columns[i].name)
				// NOSONAR: strlen is safe here
				total_mem_usage += strlen(stmt_metadata->columns[i].name) + 1; // NOSONAR
		}
	}
}

void PgSQL_STMT_Global_info::update_stmt_metadata(PgSQL_Describe_Prepared_Info** new_stmt_metadata) {

	bool need_refresh = false;
	pthread_rwlock_wrlock(&rwlock_);

	if (stmt_metadata == nullptr) {
		stmt_metadata = *new_stmt_metadata;
		*new_stmt_metadata = nullptr;
		pthread_rwlock_unlock(&rwlock_);
		return;
	}

	if (stmt_metadata->parameter_types_count != (*new_stmt_metadata)->parameter_types_count) {
		need_refresh = true;
	} else {
		for (size_t i = 0; i < (*new_stmt_metadata)->parameter_types_count; i++) {
			if (stmt_metadata->parameter_types[i] != (*new_stmt_metadata)->parameter_types[i]) {
				need_refresh = true;
				break;
			}
		}
	}

	if (need_refresh == false) {
		if (stmt_metadata->columns_count != (*new_stmt_metadata)->columns_count) {
			need_refresh = true;
		} else {
			for (size_t i = 0; i < (*new_stmt_metadata)->columns_count; ++i) {
				const auto& current_col = stmt_metadata->columns[i];
				const auto& update_col = (*new_stmt_metadata)->columns[i];
				if (strcmp(current_col.name, update_col.name) || // NOSONAR: strcmp is safe here
					current_col.table_oid != update_col.table_oid ||
					current_col.column_index != update_col.column_index ||
					current_col.type_oid != update_col.type_oid ||
					current_col.length != update_col.length ||
					current_col.type_modifier != update_col.type_modifier ||
					current_col.format != update_col.format) {
					need_refresh = true;
					break;
				}
			}
		}
	}

	if (need_refresh) {
		delete stmt_metadata;
		stmt_metadata = *new_stmt_metadata;
		*new_stmt_metadata = nullptr;
		calculate_mem_usage();
	}
	pthread_rwlock_unlock(&rwlock_);
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
	if (stmt_metadata)
		delete stmt_metadata;
	pthread_rwlock_destroy(&rwlock_);
}

void PgSQL_STMTs_local_v14::backend_insert(uint64_t global_stmt_id, uint32_t backend_stmt_id) {
	global_stmt_to_backend_ids.insert(std::make_pair(global_stmt_id, backend_stmt_id));
	backend_stmt_to_global_ids.insert(std::make_pair(backend_stmt_id,global_stmt_id));
}

void PgSQL_STMTs_local_v14::client_insert(uint64_t global_stmt_id, const std::string& client_stmt_name) {
	// validate that client_stmt_name is not empty and global_stmt_id is a valid id
	[[maybe_unused]] auto [it, inserted] = stmt_name_to_global_ids.try_emplace(client_stmt_name, global_stmt_id);
	assert(inserted && "client_stmt_name already exists in stmt_name_to_global_ids"); // Should not happen, as we expect unique client_stmt_name
#ifdef DEBUG
	auto range = global_id_to_stmt_names.equal_range(global_stmt_id);
	for (auto it = range.first; it != range.second; ++it) {
		assert(it->second != client_stmt_name && "client_stmt_name is already mapped to global_stmt_id in global_id_to_stmt_names"); // Should not happen, as we expect unique client_stmt_name per global_stmt_id
	}
#endif
	global_id_to_stmt_names.emplace(global_stmt_id, client_stmt_name);
	GloPgStmt->ref_count_client(global_stmt_id, 1, false); // do not lock!
}

uint64_t PgSQL_STMTs_local_v14::compute_hash(const char *user,
	const char *database, const char *query, unsigned int query_length, const Parse_Param_Types& param_types) {
	uint64_t hash = stmt_compute_hash(user, database, query, query_length, param_types);
	return hash;
}

PgSQL_STMT_Manager_v14::PgSQL_STMT_Manager_v14() {
	last_purge_time = time(NULL);
	pthread_rwlock_init(&rwlock_, NULL);
	next_statement_id = 1;  // we initialize this as 1 because we 0 is not allowed
	num_stmt_with_ref_client_count_zero = 0;
	num_stmt_with_ref_server_count_zero = 0;
	statuses.c_unique = 0;
	statuses.c_total = 0;
	statuses.stmt_max_stmt_id = 0;
	statuses.cached = 0;
	statuses.s_unique = 0;
	statuses.s_total = 0;
}

PgSQL_STMT_Manager_v14::~PgSQL_STMT_Manager_v14() {
	for (auto it = map_stmt_id_to_info.begin(); it != map_stmt_id_to_info.end(); ++it) {
		PgSQL_STMT_Global_info * a = it->second;
		delete a;
	}
}

void PgSQL_STMT_Manager_v14::ref_count_client(uint64_t _stmt_id ,int _v, bool lock) noexcept {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	
	if (auto s = map_stmt_id_to_info.find(_stmt_id); s != map_stmt_id_to_info.end()) {
		statuses.c_total += _v;
		PgSQL_STMT_Global_info *stmt_info = s->second;
		if (stmt_info->ref_count_client == 0 && _v == 1) {
			__sync_sub_and_fetch(&num_stmt_with_ref_client_count_zero,1);
		} else {
			if (stmt_info->ref_count_client == 1 && _v == -1) {
				__sync_add_and_fetch(&num_stmt_with_ref_client_count_zero,1);
			}
		}
		stmt_info->ref_count_client += _v;
		time_t ct = time(NULL);
		uint64_t num_client_count_zero = __sync_add_and_fetch(&num_stmt_with_ref_client_count_zero, 0);
		uint64_t num_server_count_zero = __sync_add_and_fetch(&num_stmt_with_ref_server_count_zero, 0);

		size_t map_size = map_stmt_id_to_info.size();
		if (
			(ct > last_purge_time+1) &&
			(map_size > (unsigned)pgsql_thread___max_stmts_cache) &&
			(num_client_count_zero > map_size/10) &&
			(num_server_count_zero > map_size/10)
		) { // purge only if there is at least 10% gain
			last_purge_time = ct;
			int max_purge = map_size ;
			std::vector<uint64_t> torem;
			torem.reserve(max_purge);

			for (auto it = map_stmt_id_to_info.begin(); it != map_stmt_id_to_info.end(); ++it) {
				if (torem.size() >= std::min(static_cast<size_t>(max_purge),
					static_cast<size_t>(num_client_count_zero))) {
					break;
				}
				PgSQL_STMT_Global_info *a = it->second;
				if ((__sync_add_and_fetch(&a->ref_count_client, 0) == 0) &&
					(a->ref_count_server == 0) ) // this to avoid that IDs are incorrectly reused
				{
					uint64_t hash = a->hash;
					map_stmt_hash_to_info.erase(hash);
					__sync_sub_and_fetch(&num_stmt_with_ref_client_count_zero,1);
					torem.emplace_back(it->first);
				}
			}
			while (!torem.empty()) {
				uint64_t id = torem.back();
				torem.pop_back();
				auto s3 = map_stmt_id_to_info.find(id);
				PgSQL_STMT_Global_info *a = s3->second;
				if (a->ref_count_server == 0) {
					__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
					free_stmt_ids.push(id);
				}
				map_stmt_id_to_info.erase(s3);
				statuses.s_total -= a->ref_count_server;
				delete a;
			}
		}
	}
	if (lock)
		pthread_rwlock_unlock(&rwlock_);
}

void PgSQL_STMT_Manager_v14::ref_count_server(uint64_t _stmt_id ,int _v, bool lock) noexcept {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	std::map<uint64_t, PgSQL_STMT_Global_info *>::iterator s;
	s = map_stmt_id_to_info.find(_stmt_id);
	if (s != map_stmt_id_to_info.end()) {
		statuses.s_total += _v;
		PgSQL_STMT_Global_info *stmt_info = s->second;
		if (stmt_info->ref_count_server == 0 && _v == 1) {
			__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
		} else {
			if (stmt_info->ref_count_server == 1 && _v == -1) {
				__sync_add_and_fetch(&num_stmt_with_ref_server_count_zero,1);
			}
		}
		stmt_info->ref_count_server += _v;
	}
	if (lock)
		pthread_rwlock_unlock(&rwlock_);
}

PgSQL_STMTs_local_v14::~PgSQL_STMTs_local_v14() {
	// Note: we do not free the prepared statements because we assume that
	// if we call this destructor the connection is being destroyed anyway

	if (is_client_) {
		for (auto it = stmt_name_to_global_ids.begin();
			it != stmt_name_to_global_ids.end(); ++it) {
			uint64_t global_stmt_id = it->second;
			GloPgStmt->ref_count_client(global_stmt_id, -1);
		}
	} else {
		for (auto it = backend_stmt_to_global_ids.begin();
			it != backend_stmt_to_global_ids.end(); ++it) {
			uint64_t global_stmt_id = it->second;
			GloPgStmt->ref_count_server(global_stmt_id, -1);
		}
	}
}


PgSQL_STMT_Global_info *PgSQL_STMT_Manager_v14::find_prepared_statement_by_hash(uint64_t hash, bool lock) {
	PgSQL_STMT_Global_info *ret = nullptr;  // assume we do not find it
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

PgSQL_STMT_Global_info* PgSQL_STMT_Manager_v14::find_prepared_statement_by_stmt_id(
    uint64_t id, bool lock) {
	PgSQL_STMT_Global_info*ret = nullptr;  // assume we do not find it
	if (lock) {
		rdlock();
	}

	if (auto s = map_stmt_id_to_info.find(id); s != map_stmt_id_to_info.end()) {
		ret = s->second;
	}

	if (lock) {
		unlock();
	}
	return ret;
}

uint32_t PgSQL_STMTs_local_v14::generate_new_backend_stmt_id() {
	assert(is_client_ == false);
	if (free_backend_ids.empty() == false) {
		uint32_t backend_stmt_id = free_backend_ids.top();
		free_backend_ids.pop();
		return backend_stmt_id;
	}
	local_max_stmt_id++;
	return local_max_stmt_id;
}

uint64_t PgSQL_STMTs_local_v14::find_global_id_from_stmt_name(const std::string& client_stmt_name) {
	uint64_t ret=0;
	if (auto s = stmt_name_to_global_ids.find(client_stmt_name); s != stmt_name_to_global_ids.end()) {
		ret = s->second;
	}
	return ret;
}

uint32_t PgSQL_STMTs_local_v14::find_backend_stmt_id_from_global_id(uint64_t global_id) {
	if (auto s = global_stmt_to_backend_ids.find(global_id); s != global_stmt_to_backend_ids.end()) {
		return s->second;
	}
	return 0;  // not found
}

bool PgSQL_STMTs_local_v14::client_close(const std::string& stmt_name) {
	if (auto s = stmt_name_to_global_ids.find(stmt_name); s != stmt_name_to_global_ids.end()) {  // found
		uint64_t global_stmt_id = s->second;
		stmt_name_to_global_ids.erase(s);
		GloPgStmt->ref_count_client(global_stmt_id, -1);
		std::pair<std::multimap<uint64_t,std::string>::iterator, std::multimap<uint64_t,std::string>::iterator> ret;
		ret = global_id_to_stmt_names.equal_range(global_stmt_id);
		for (std::multimap<uint64_t, std::string>::iterator it=ret.first; it!=ret.second; ++it) {
			if (it->second == stmt_name) {
				global_id_to_stmt_names.erase(it);
				break;
			}
		}
		return true;
	}
	return false;  // we don't really remove the prepared statement
}

void PgSQL_STMTs_local_v14::client_close_all() {
	for (auto [_, global_stmt_id] : stmt_name_to_global_ids) {
		GloPgStmt->ref_count_client(global_stmt_id, -1);
	}
	stmt_name_to_global_ids.clear();
	global_id_to_stmt_names.clear();
}

PgSQL_STMT_Global_info* PgSQL_STMT_Manager_v14::add_prepared_statement(
    char *u, char *d, char *q, unsigned int ql,
    char *fc, Parse_Param_Types&& ppt, bool lock) {
	PgSQL_STMT_Global_info *ret = nullptr;
	uint64_t hash = stmt_compute_hash(
		u, d, q, ql, ppt);  // this identifies the prepared statement
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

		auto stmt_info = std::make_unique<PgSQL_STMT_Global_info>(next_id, u, d, q, ql, fc, std::move(ppt), hash);
		// insert it in both maps
		map_stmt_id_to_info.insert(std::make_pair(stmt_info->statement_id, stmt_info.get()));
		map_stmt_hash_to_info.insert(std::make_pair(stmt_info->hash, stmt_info.get()));
		ret = stmt_info.release();
		__sync_add_and_fetch(&num_stmt_with_ref_client_count_zero,1);
		__sync_add_and_fetch(&num_stmt_with_ref_server_count_zero,1);
	}
	if (ret->ref_count_server == 0) {
		__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
	}
	ret->ref_count_server++;
	statuses.s_total++;
	if (lock) {
		pthread_rwlock_unlock(&rwlock_);
	}
	return ret;
}


void PgSQL_STMT_Manager_v14::get_memory_usage(uint64_t& prep_stmt_metadata_mem_usage, uint64_t& prep_stmt_backend_mem_usage) {
	prep_stmt_backend_mem_usage = 0;
	prep_stmt_metadata_mem_usage = sizeof(PgSQL_STMT_Manager_v14);
	rdlock();	
	prep_stmt_metadata_mem_usage += map_stmt_id_to_info.size() * (sizeof(uint64_t) + sizeof(PgSQL_STMT_Global_info*));
	prep_stmt_metadata_mem_usage += map_stmt_hash_to_info.size() * (sizeof(uint64_t) + sizeof(PgSQL_STMT_Global_info*));
	prep_stmt_metadata_mem_usage += free_stmt_ids.size() * (sizeof(uint64_t));
	for (const auto&[key, value] : map_stmt_id_to_info) {
		const PgSQL_STMT_Global_info* stmt_global_info = value;
		prep_stmt_metadata_mem_usage += stmt_global_info->total_mem_usage;
		prep_stmt_metadata_mem_usage += stmt_global_info->ref_count_server * 16; // ~16 bytes of memory utilized by global_stmt_id and stmt_id mappings
		prep_stmt_metadata_mem_usage += stmt_global_info->ref_count_client * 40; // ~40 bytes of memory utilized by client_stmt_name and global_stmt_id mappings;

		// backend
		prep_stmt_backend_mem_usage += stmt_global_info->ref_count_server; // FIXME: add backend memory usage
	}
	unlock();
}

void PgSQL_STMT_Manager_v14::get_metrics(uint64_t *c_unique, uint64_t *c_total,
                             uint64_t *stmt_max_stmt_id, uint64_t *cached,
                             uint64_t *s_unique, uint64_t *s_total) {
#ifdef DEBUG
	uint64_t c_u = 0;
	uint64_t c_t = 0;
	uint64_t m = 0;
	uint64_t c = 0;
	uint64_t s_u = 0;
	uint64_t s_t = 0;
#endif
	wrlock();
	statuses.cached = map_stmt_id_to_info.size();
	statuses.c_unique = statuses.cached - num_stmt_with_ref_client_count_zero;
	statuses.s_unique = statuses.cached - num_stmt_with_ref_server_count_zero;
#ifdef DEBUG
	for (std::map<uint64_t, PgSQL_STMT_Global_info *>::iterator it = map_stmt_id_to_info.begin();
	     it != map_stmt_id_to_info.end(); ++it) {
		const PgSQL_STMT_Global_info *a = it->second;
		c++;
		if (a->ref_count_client) {
			c_u++;
			c_t += a->ref_count_client;
		}
		if (a->ref_count_server) {
			s_u++;
			s_t += a->ref_count_server;
		}
		if (it->first > m) {
			m = it->first;
		}
	}
	assert (c_u == statuses.c_unique);
	assert (c_t == statuses.c_total);
	assert (c == statuses.cached);
	assert (s_t == statuses.s_total);
	assert (s_u == statuses.s_unique);
	*stmt_max_stmt_id = m;
#endif
	*stmt_max_stmt_id = next_statement_id; // this is max stmt_id, no matter if in used or not
	*c_unique = statuses.c_unique;
	*c_total = statuses.c_total;
	*cached = statuses.cached;
	*s_total = statuses.s_total;
	*s_unique = statuses.s_unique;
	pthread_rwlock_unlock(&rwlock_);
}


class PgSQL_PS_global_stats {
	public:
	uint64_t statement_id;
	char *username;
	char *dbname;
	uint64_t digest;
	unsigned long long ref_count_client;
	unsigned long long ref_count_server;
	char *query;
	int num_columns;
	int num_params;
	PgSQL_PS_global_stats(uint64_t stmt_id, const char *d, const char *u, uint64_t dig, const char *q,
		unsigned long long ref_c, unsigned long long ref_s, int columns, int params) {
		statement_id = stmt_id;
		digest = dig;
		query = strndup(q, pgsql_thread___query_digests_max_digest_length);
		username = strdup(u);
		dbname = strdup(d);
		ref_count_client = ref_c;
		ref_count_server = ref_s;
		num_columns = columns;
		num_params = params;
	}
	~PgSQL_PS_global_stats() {
		if (query) 
			free(query);
		if (username)
			free(username);
		if (dbname)
			free(dbname);
	}
	char **get_row() {
		char buf[128];
		char **pta=(char **)malloc(sizeof(char *)*PS_GLOBAL_STATUS_FIELD_NUM);
		snprintf(buf,sizeof(buf),"%lu",statement_id);
		pta[0]=strdup(buf);
		assert(dbname);
		pta[1]=strdup(dbname);
		assert(username);
		pta[2]=strdup(username);
		snprintf(buf,sizeof(buf),"0x%016llX", (long long unsigned int)digest);
		pta[3]=strdup(buf);
		assert(query);
		pta[4]=strdup(query);
		snprintf(buf,sizeof(buf),"%llu",ref_count_client);
		pta[5]=strdup(buf);
		snprintf(buf,sizeof(buf),"%llu",ref_count_server);
		pta[6]=strdup(buf);
		snprintf(buf,sizeof(buf),"%d",num_columns);
		pta[7]=strdup(buf);
		snprintf(buf,sizeof(buf),"%d",num_params);
		pta[8]=strdup(buf);

		return pta;
	}
	void free_row(char **pta) {
		int i;
		for (i=0;i<PS_GLOBAL_STATUS_FIELD_NUM;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};


SQLite3_result* PgSQL_STMT_Manager_v14::get_prepared_statements_global_infos() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current prepared statements global info\n");
	auto result = std::make_unique<SQLite3_result>(PS_GLOBAL_STATUS_FIELD_NUM);
	rdlock();
	result->add_column_definition(SQLITE_TEXT,"stmt_id");
	result->add_column_definition(SQLITE_TEXT,"database");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"query");
	result->add_column_definition(SQLITE_TEXT,"ref_count_client");
	result->add_column_definition(SQLITE_TEXT,"ref_count_server");
	result->add_column_definition(SQLITE_TEXT,"num_columns");
	result->add_column_definition(SQLITE_TEXT,"num_params");
	for (auto it = map_stmt_id_to_info.begin(); it != map_stmt_id_to_info.end(); ++it) {
		int columns_count = -1;
		int parameter_types_count = -1;
		PgSQL_STMT_Global_info *a = it->second;

		a->rdlock();
		if (const PgSQL_Describe_Prepared_Info* stmt_metadata = a->stmt_metadata; stmt_metadata != nullptr) {
			columns_count = stmt_metadata->columns_count;
			parameter_types_count = stmt_metadata->parameter_types_count;
		}
		a->unlock();

		auto pgs = std::make_unique<PgSQL_PS_global_stats>(a->statement_id,
			a->dbname, a->username, a->hash, a->query,
			a->ref_count_client, a->ref_count_server,
			columns_count,
			parameter_types_count);
		char **pta = pgs->get_row();
		result->add_row(pta);
		pgs->free_row(pta);
	}
	unlock();
	return result.release();
}
