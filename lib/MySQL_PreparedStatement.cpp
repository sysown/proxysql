#include "proxysql.h"
#include "cpp.h"

#include "SpookyV2.h"

#ifndef PROXYSQL_STMT_V14
extern MySQL_STMT_Manager *GloMyStmt;
static uint32_t add_prepared_statement_calls = 0;
static uint32_t find_prepared_statement_by_hash_calls = 0;
#else
extern MySQL_STMT_Manager_v14 *GloMyStmt;
#endif


static uint64_t stmt_compute_hash(unsigned int hostgroup, char *user,
                                  char *schema, char *query,
                                  unsigned int query_length) {
	int l = 0;
	l += sizeof(hostgroup);
	l += strlen(user);
	l += strlen(schema);
// two random seperators
#define _COMPUTE_HASH_DEL1_ "-ujhtgf76y576574fhYTRDFwdt-"
#define _COMPUTE_HASH_DEL2_ "-8k7jrhtrgJHRgrefgreRFewg6-"
	l += strlen(_COMPUTE_HASH_DEL1_);
	l += strlen(_COMPUTE_HASH_DEL2_);
	l += query_length;
	char *buf = (char *)malloc(l);
	l = 0;
	// write hostgroup
	memcpy(buf, &hostgroup, sizeof(hostgroup));
	l += sizeof(hostgroup);

	// write user
	strcpy(buf + l, user);
	l += strlen(user);

	// write delimiter1
	strcpy(buf + l, _COMPUTE_HASH_DEL1_);
	l += strlen(_COMPUTE_HASH_DEL1_);

	// write schema
	strcpy(buf + l, schema);
	l += strlen(schema);

	// write delimiter2
	strcpy(buf + l, _COMPUTE_HASH_DEL2_);
	l += strlen(_COMPUTE_HASH_DEL2_);

	// write query
	memcpy(buf + l, query, query_length);
	l += query_length;

	uint64_t hash = SpookyHash::Hash64(buf, l, 0);
	free(buf);
	return hash;
}

void MySQL_STMT_Global_info::compute_hash() {
	hash = stmt_compute_hash(hostgroup_id, username, schemaname, query,
	                         query_length);
}

StmtLongDataHandler::StmtLongDataHandler() { long_datas = new PtrArray(); }

StmtLongDataHandler::~StmtLongDataHandler() {
	while (long_datas->len) {
		stmt_long_data_t *sld =
		    (stmt_long_data_t *)long_datas->remove_index_fast(0);
		free(sld->data);
		free(sld);
	}
	delete long_datas;
}

bool StmtLongDataHandler::add(uint32_t _stmt_id, uint16_t _param_id,
                              void *_data, unsigned long _size) {
	stmt_long_data_t *sld = NULL;
	unsigned int i;
	for (i = 0; i < long_datas->len; i++) {
		sld = (stmt_long_data_t *)long_datas->index(i);
		if (sld->stmt_id == _stmt_id && sld->param_id == _param_id) {
			// we found it!
			unsigned long _new_size = sld->size + _size;
			sld->data = realloc(sld->data, _new_size);
			memcpy((unsigned char *)sld->data + sld->size, _data, _size);
			sld->size = _new_size;
			return true;
		}
	}
	// if we reached here, we didn't find it
	sld = (stmt_long_data_t *)malloc(sizeof(stmt_long_data_t));
	sld->stmt_id = _stmt_id;
	sld->param_id = _param_id;
	sld->size = _size;
	sld->data = malloc(_size);
	memcpy(sld->data, _data, _size);
	long_datas->add(sld);
	return false;  // a new entry was created
}

unsigned int StmtLongDataHandler::reset(uint32_t _stmt_id) {
	unsigned int cnt = 0;
	int i;
	stmt_long_data_t *sld = NULL;
	for (i = 0; i < (int)long_datas->len;
	     i++) {  // we treat it as an int, so we can go to -1
		sld = (stmt_long_data_t *)long_datas->index(i);
		if (sld->stmt_id == _stmt_id) {
			sld = (stmt_long_data_t *)long_datas->remove_index_fast(i);
			free(sld->data);
			free(sld);
			i--;
			cnt++;
		}
	}
	return cnt;
}

void *StmtLongDataHandler::get(uint32_t _stmt_id, uint16_t _param_id,
                               unsigned long **_size) {
	stmt_long_data_t *sld = NULL;
	unsigned int i;
	for (i = 0; i < long_datas->len; i++) {
		sld = (stmt_long_data_t *)long_datas->index(i);
		if (sld->stmt_id == _stmt_id && sld->param_id == _param_id) {
			// we found it!
			*_size = &sld->size;
			return sld->data;
		}
	}
	return NULL;
}

#ifndef PROXYSQL_STMT_V14
MySQL_STMT_Global_info::MySQL_STMT_Global_info(uint32_t id, unsigned int h,
#else
MySQL_STMT_Global_info::MySQL_STMT_Global_info(uint64_t id, unsigned int h,
#endif
                                               char *u, char *s, char *q,
                                               unsigned int ql,
                                               MYSQL_STMT *stmt, uint64_t _h) {
	statement_id = id;
	hostgroup_id = h;
	ref_count_client = 0;
	ref_count_server = 0;
	digest_text = NULL;
	username = strdup(u);
	schemaname = strdup(s);
	query = (char *)malloc(ql + 1);
	memcpy(query, q, ql);
	query[ql] = '\0';  // add NULL byte
	query_length = ql;
	num_params = stmt->param_count;
	num_columns = stmt->field_count;
	warning_count = stmt->upsert_status.warning_count;
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
				is_select_NOT_for_update = true;
				if (ql >= 17) {
					char *p = (char *)q;
					p += ql - 11;
					if (strncasecmp(p, " FOR UPDATE", 11) ==
					    0) {  // is a SELECT FOR UPDATE
						is_select_NOT_for_update = false;
					}
				}
			}
		}
	}

	// set default properties:
	properties.cache_ttl = -1;
	properties.timeout = -1;
	properties.delay = -1;

	fields = NULL;
	if (num_columns) {
		fields = (MYSQL_FIELD **)malloc(num_columns * sizeof(MYSQL_FIELD *));
		uint16_t i;
		for (i = 0; i < num_columns; i++) {
			fields[i] = (MYSQL_FIELD *)malloc(sizeof(MYSQL_FIELD));
			MYSQL_FIELD *fs = &(stmt->fields[i]);
			MYSQL_FIELD *fd = fields[i];
			// first copy all fields
			memcpy(fd, fs, sizeof(MYSQL_FIELD));
			// then duplicate strings
			fd->name = (fs->name ? strdup(fs->name) : NULL);
			fd->org_name = (fs->org_name ? strdup(fs->org_name) : NULL);
			fd->table = (fs->table ? strdup(fs->table) : NULL);
			fd->org_table = (fs->org_table ? strdup(fs->org_table) : NULL);
			fd->db = (fs->db ? strdup(fs->db) : NULL);
			fd->catalog = (fs->catalog ? strdup(fs->catalog) : NULL);
			fd->def = (fs->def ? strdup(fs->def) : NULL);
		}
	}

	params = NULL;
	if (num_params == 2) {
		PROXY_TRACE();
	}
	if (num_params) {
		params = (MYSQL_BIND **)malloc(num_params * sizeof(MYSQL_BIND *));
		uint16_t i;
		for (i = 0; i < num_params; i++) {
			params[i] = (MYSQL_BIND *)malloc(sizeof(MYSQL_BIND));
			// MYSQL_BIND *ps=&(stmt->params[i]);
			// MYSQL_BIND *pd=params[i];
			// copy all params
			// memcpy(pd,ps,sizeof(MYSQL_BIND));
			memset(params[i], 0, sizeof(MYSQL_BIND));
		}
	}
}

MySQL_STMT_Global_info::~MySQL_STMT_Global_info() {
	free(username);
	free(schemaname);
	free(query);
	if (num_columns) {
		uint16_t i;
		for (i = 0; i < num_columns; i++) {
			MYSQL_FIELD *f = fields[i];
			if (f->name) {
				free(f->name);
				f->name = NULL;
			}
			if (f->org_name) {
				free(f->org_name);
				f->org_name = NULL;
			}
			if (f->table) {
				free(f->table);
				f->table = NULL;
			}
			if (f->org_table) {
				free(f->org_table);
				f->org_table = NULL;
			}
			if (f->db) {
				free(f->db);
				f->db = NULL;
			}
			if (f->catalog) {
				free(f->catalog);
				f->catalog = NULL;
			}
			if (f->def) {
				free(f->def);
				f->def = NULL;
			}
			free(fields[i]);
		}
		free(fields);
		fields = NULL;
	}

	if (num_params) {
		uint16_t i;
		for (i = 0; i < num_params; i++) {
			free(params[i]);
		}
		free(params);
		params = NULL;
	}
	if (digest_text) {
		free(digest_text);
		digest_text = NULL;
	}
}
#ifndef PROXYSQL_STMT_V14
uint64_t MySQL_STMTs_local::compute_hash(unsigned int hostgroup, char *user,
                                         char *schema, char *query,
                                         unsigned int query_length) {
	uint64_t hash;
	hash = stmt_compute_hash(hostgroup, user, schema, query, query_length);
	return hash;
}

MySQL_STMTs_local::~MySQL_STMTs_local() {
	// Note: we do not free the prepared statements because we assume that
	// if we call this destructor the connection is being destroyed anyway
	for (std::map<uint32_t, MYSQL_STMT *>::iterator it = m.begin();
	     it != m.end(); ++it) {
		uint32_t stmt_id = it->first;
		MYSQL_STMT *stmt = it->second;
		if (stmt) {  // is a server
			if (stmt->mysql) {
				stmt->mysql->stmts =
				    list_delete(stmt->mysql->stmts, &stmt->list);
			}
			// we do a hack here: we pretend there is no server associate
			// the connection will be dropped anyway immediately after
			stmt->mysql = NULL;
			mysql_stmt_close(stmt);
			GloMyStmt->ref_count(stmt_id, -1, true, false);
		} else {  // is a client
			GloMyStmt->ref_count(stmt_id, -1, true, true);
		}
	}
	m.erase(m.begin(), m.end());
}

uint32_t MySQL_STMTs_local::generate_new_stmt_id(uint32_t global_statement_id) {
	uint32_t new_id;
	new_id = GloMyStmt->generate_new_stmt_id();
	client_stmt_to_global_id.insert(std::make_pair(global_statement_id, new_id));
	return new_id;
}


uint32_t MySQL_STMTs_local::find_original_id(uint32_t client_stmt_id) {
	auto s = client_stmt_to_global_id.find(client_stmt_id);
	if (s != client_stmt_to_global_id.end()) {
		uint32_t ret=s->second;
		return ret;
	}
	return 0;
}

bool MySQL_STMTs_local::erase(uint32_t global_statement_id) {
	auto s = m.find(global_statement_id);
	if (s != m.end()) {  // found
		if (is_client) {
			// we are removing it from a client, not backend
			GloMyStmt->ref_count(global_statement_id, -1, true, true);
			m.erase(s);
			return true;
		}
		// the following seems deprecated for now. Asserting
		assert(0);
		if (num_entries > 1000) {
			MYSQL_STMT *stmt = s->second;
			mysql_stmt_close(stmt);
			m.erase(s);
			num_entries--;
			return true;  // we truly removed the prepared statement
		}
	}
	return false;  // we don't really remove the prepared statement
}

void MySQL_STMTs_local::insert(uint32_t global_statement_id, MYSQL_STMT *stmt) {
	std::pair<std::map<uint32_t, MYSQL_STMT *>::iterator, bool> ret;
	ret = m.insert(std::make_pair(global_statement_id, stmt));
	if (ret.second == true) {
		num_entries++;
	}
	if (stmt == NULL) {  // only for clients
		GloMyStmt->ref_count(global_statement_id, 1, true, true);
	}
}

MySQL_STMT_Manager::MySQL_STMT_Manager() {
	spinlock_rwlock_init(&rwlock);
	next_statement_id =
		33;	// we initialize this as 33, leaving the first 32 reserved for special prepared statements (future use)
}

MySQL_STMT_Manager::~MySQL_STMT_Manager() {
	for (std::map<uint32_t, MySQL_STMT_Global_info *>::iterator it = m.begin();
	     it != m.end(); ++it) {
		MySQL_STMT_Global_info *a = it->second;
		delete a;
	}
	m.erase(m.begin(), m.end());
	// we do not loop in h because all the MySQL_STMT_Global_info() were already
	// deleted
	h.erase(h.begin(), h.end());
}

void MySQL_STMT_Manager::active_prepared_statements(uint32_t *unique,
                                                    uint32_t *total) {
	uint32_t u = 0;
	uint32_t t = 0;
	spin_wrlock(&rwlock);
	// fprintf(stderr,"%u , %u , %u , %u\n",
	// find_prepared_statement_by_hash_calls, add_prepared_statement_calls,
	// m.size(), total_prepared_statements());
	for (std::map<uint32_t, MySQL_STMT_Global_info *>::iterator it = m.begin();
	     it != m.end(); ++it) {
		MySQL_STMT_Global_info *a = it->second;
		if (a->ref_count_client) {
			u++;
			t += a->ref_count_client;
#ifdef DEBUG
			fprintf(stderr, "stmt %d , client_ref_count %d\n", a->statement_id,
			        a->ref_count_client);
#endif
		}
	}
	spin_wrunlock(&rwlock);
	*unique = u;
	*total = t;
}

int MySQL_STMT_Manager::ref_count(uint32_t statement_id, int cnt, bool lock,
                                  bool is_client) {
	int ret = -1;
	if (lock) {
		spin_wrlock(&rwlock);
	}
	auto s = m.find(statement_id);
	if (s != m.end()) {
		MySQL_STMT_Global_info *a = s->second;
		if (is_client) {
			ret = __sync_add_and_fetch(&a->ref_count_client, cnt);
			//__sync_fetch_and_add(&a->ref_count_client,cnt);
			// ret=a->ref_count_client;
			if (m.size() > (unsigned)mysql_thread___max_stmts_cache) {
				int max_purge = m.size() / 20;  // purge up to 5%
				int i = -1;
				uint32_t *torem =
				    (uint32_t *)malloc(max_purge * sizeof(uint32_t));
				for (std::map<uint32_t, MySQL_STMT_Global_info *>::iterator it =
				         m.begin();
				     it != m.end(); ++it) {
					if (i == (max_purge - 1)) continue;
					MySQL_STMT_Global_info *a = it->second;
					if (__sync_add_and_fetch(&a->ref_count_client, 0) == 0) {
						uint64_t hash = a->hash;
						auto s2 = h.find(hash);
						if (s2 != h.end()) {
							h.erase(s2);
						}
						// m.erase(it);
						// delete a;
						i++;
						torem[i] = it->first;
					}
				}
				while (i >= 0) {
					uint32_t id = torem[i];
					auto s3 = m.find(id);
					MySQL_STMT_Global_info *a = s3->second;
					if (a->ref_count_server == 0) {
						free_stmt_ids.push(id);
					}
					m.erase(s3);
					delete a;
					i--;
				}
				free(torem);
			}
		} else {
			__sync_fetch_and_add(&a->ref_count_server, cnt);
			ret = a->ref_count_server;
		}
	}
	if (lock) {
		spin_wrunlock(&rwlock);
	}
	return ret;
}

MySQL_STMT_Global_info *MySQL_STMT_Manager::add_prepared_statement(
    bool *is_new, unsigned int _h, char *u, char *s, char *q, unsigned int ql,
    MYSQL_STMT *stmt, bool lock) {
	return add_prepared_statement(is_new, _h, u, s, q, ql, stmt, -1, -1, -1,
	                              lock);
}

MySQL_STMT_Global_info *MySQL_STMT_Manager::add_prepared_statement(
    bool *is_new, unsigned int _h, char *u, char *s, char *q, unsigned int ql,
    MYSQL_STMT *stmt, int _cache_ttl, int _timeout, int _delay, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;
	uint64_t hash = stmt_compute_hash(
	    _h, u, s, q, ql);  // this identifies the prepared statement
	if (lock) {
		spin_wrlock(&rwlock);
	}
	// try to find the statement
	auto f = h.find(hash);
	if (f != h.end()) {
		// found it!
		// MySQL_STMT_Global_info *a=f->second;
		// ret=a->statement_id;
		ret = f->second;
		*is_new = false;
	} else {
		// we need to create a new one
		bool free_id_avail = false;
		free_id_avail = free_stmt_ids.size();
		uint32_t next_id = 0;
		if (free_id_avail) {
			next_id = free_stmt_ids.top();
			free_stmt_ids.pop();
		} else {
			// next_id = next_statement_id;
			// next_statement_id++;
			__sync_fetch_and_add(&next_statement_id, 1);
		}
		MySQL_STMT_Global_info *a =
		    new MySQL_STMT_Global_info(next_id, _h, u, s, q, ql, stmt, hash);
		a->properties.cache_ttl = _cache_ttl;
		a->properties.timeout = _timeout;
		a->properties.delay = _delay;
		// insert it in both maps
		m.insert(std::make_pair(a->statement_id, a));
		h.insert(std::make_pair(a->hash, a));
		// ret=a->statement_id;
		ret = a;
		// next_statement_id++;	// increment it
		//__sync_fetch_and_add(&ret->ref_count_client,1); // increase reference
		//count
		__sync_fetch_and_add(&ret->ref_count_client,
		                     1);  // increase reference count
		*is_new = true;
	}
	__sync_fetch_and_add(&add_prepared_statement_calls, 1);
	__sync_fetch_and_add(&ret->ref_count_server,
	                     1);  // increase reference count
	if (lock) {
		spin_wrunlock(&rwlock);
	}
	return ret;
}

MySQL_STMT_Global_info *MySQL_STMT_Manager::find_prepared_statement_by_stmt_id(
    uint32_t id, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;  // assume we do not find it
	if (lock) {
		spin_wrlock(&rwlock);
	}

	auto s = m.find(id);
	if (s != m.end()) {
		ret = s->second;
		//__sync_fetch_and_add(&ret->ref_count,1); // increase reference count
	}

	if (lock) {
		spin_wrunlock(&rwlock);
	}
	return ret;
}

MySQL_STMT_Global_info *MySQL_STMT_Manager::find_prepared_statement_by_hash(
    uint64_t hash, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;  // assume we do not find it
	if (lock) {
		spin_wrlock(&rwlock);
	}

	auto s = h.find(hash);
	if (s != h.end()) {
		ret = s->second;
		//__sync_fetch_and_add(&ret->ref_count_client,1); // increase reference
		//count
		__sync_fetch_and_add(&find_prepared_statement_by_hash_calls, 1);
		__sync_fetch_and_add(&ret->ref_count_client, 1);
	}

	if (lock) {
		spin_wrunlock(&rwlock);
	}
	return ret;
}



#else // PROXYSQL_STMT_V14
extern MySQL_STMT_Manager_v14 *GloMyStmt;

void MySQL_STMTs_local_v14::backend_insert(uint64_t global_statement_id, MYSQL_STMT *stmt) {
	std::pair<std::map<uint64_t, MYSQL_STMT *>::iterator, bool> ret;
	ret = global_stmt_to_backend_stmt.insert(std::make_pair(global_statement_id, stmt));
	global_stmt_to_backend_ids.insert(std::make_pair(global_statement_id,stmt->stmt_id));
	backend_stmt_to_global_ids.insert(std::make_pair(stmt->stmt_id,global_statement_id));
	// note: backend_insert() is always called after add_prepared_statement()
	// for this reason, we will the ref count increase in add_prepared_statement()
	// GloMyStmt->ref_count_client(global_statement_id, 1);
}

uint64_t MySQL_STMTs_local_v14::compute_hash(unsigned int hostgroup, char *user,
                                         char *schema, char *query,
                                         unsigned int query_length) {
	uint64_t hash;
	hash = stmt_compute_hash(hostgroup, user, schema, query, query_length);
	return hash;
}

MySQL_STMT_Manager_v14::MySQL_STMT_Manager_v14() {
	pthread_rwlock_init(&rwlock_, NULL);
	next_statement_id =
	    1;  // we initialize this as 1 because we 0 is not allowed
}

MySQL_STMT_Manager_v14::~MySQL_STMT_Manager_v14() {
}

void MySQL_STMT_Manager_v14::ref_count_client(uint64_t _stmt_id ,int _v, bool lock) {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	auto s = map_stmt_id_to_info.find(_stmt_id);
	if (s != map_stmt_id_to_info.end()) {
		MySQL_STMT_Global_info *stmt_info = s->second;
		stmt_info->ref_count_client += _v;
	}
	if (lock)
		pthread_rwlock_unlock(&rwlock_);
}

void MySQL_STMT_Manager_v14::ref_count_server(uint64_t _stmt_id ,int _v, bool lock) {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	auto s = map_stmt_id_to_info.find(_stmt_id);
	if (s != map_stmt_id_to_info.end()) {
		MySQL_STMT_Global_info *stmt_info = s->second;
		stmt_info->ref_count_server += _v;
	}
	if (lock)
		pthread_rwlock_unlock(&rwlock_);
}

MySQL_STMTs_local_v14::~MySQL_STMTs_local_v14() {
	// Note: we do not free the prepared statements because we assume that
	// if we call this destructor the connection is being destroyed anyway

	if (is_client_) {
		for (std::map<uint32_t, uint64_t>::iterator it = client_stmt_to_global_ids.begin();
			it != client_stmt_to_global_ids.end(); ++it) {
			uint64_t global_stmt_id = it->second;
			GloMyStmt->ref_count_client(global_stmt_id, -1);
		}
	} else {
		for (std::map<uint64_t, MYSQL_STMT *>::iterator it = global_stmt_to_backend_stmt.begin();
			it != global_stmt_to_backend_stmt.end(); ++it) {
			uint64_t global_stmt_id = it->first;
			MYSQL_STMT *stmt = it->second;
			if (stmt->mysql) {
				stmt->mysql->stmts =
				    list_delete(stmt->mysql->stmts, &stmt->list);
			}
			stmt->mysql = NULL;
			mysql_stmt_close(stmt);
			GloMyStmt->ref_count_server(global_stmt_id, -1);
		}
	}
/*
	for (std::map<uint32_t, MYSQL_STMT *>::iterator it = m.begin();
	     it != m.end(); ++it) {
		uint32_t stmt_id = it->first;
		MYSQL_STMT *stmt = it->second;
		if (stmt) {  // is a server
			if (stmt->mysql) {
				stmt->mysql->stmts =
				    list_delete(stmt->mysql->stmts, &stmt->list);
			}
			// we do a hack here: we pretend there is no server associate
			// the connection will be dropped anyway immediately after
			stmt->mysql = NULL;
			mysql_stmt_close(stmt);
			GloMyStmt->ref_count(stmt_id, -1, true, false);
		} else {  // is a client
			GloMyStmt->ref_count(stmt_id, -1, true, true);
		}
	}
	m.erase(m.begin(), m.end());
*/
}


MySQL_STMT_Global_info *MySQL_STMT_Manager_v14::find_prepared_statement_by_hash(
    uint64_t hash, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;  // assume we do not find it
	if (lock) {
		pthread_rwlock_wrlock(&rwlock_);
	}

	auto s = map_stmt_hash_to_info.find(hash);
	if (s != map_stmt_hash_to_info.end()) {
		ret = s->second;
		//__sync_fetch_and_add(&ret->ref_count_client,1); // increase reference
		//count
//		__sync_fetch_and_add(&find_prepared_statement_by_hash_calls, 1);
//		__sync_fetch_and_add(&ret->ref_count_client, 1);
	}

	if (lock) {
		pthread_rwlock_unlock(&rwlock_);
	}
	return ret;
}

MySQL_STMT_Global_info *MySQL_STMT_Manager_v14::find_prepared_statement_by_stmt_id(
    uint64_t id, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;  // assume we do not find it
	if (lock) {
		pthread_rwlock_wrlock(&rwlock_);
	}

	auto s = map_stmt_id_to_info.find(id);
	if (s != map_stmt_id_to_info.end()) {
		ret = s->second;
	}

	if (lock) {
		pthread_rwlock_unlock(&rwlock_);
	}
	return ret;
}

uint32_t MySQL_STMTs_local_v14::generate_new_client_stmt_id(uint64_t global_statement_id) {
	uint32_t ret=0;
	if (free_client_ids.size()) {
		ret=free_client_ids.top();
		free_client_ids.pop();
	} else {
		local_max_stmt_id+=1;
		ret=local_max_stmt_id;
	}
	assert(ret);
	client_stmt_to_global_ids.insert(std::make_pair(ret,global_statement_id));
	global_stmt_to_client_ids.insert(std::make_pair(global_statement_id,ret));
	GloMyStmt->ref_count_client(global_statement_id, 1, false); // do not lock!
	return ret;
}

uint64_t MySQL_STMTs_local_v14::find_global_stmt_id_from_client(uint32_t client_stmt_id) {
	uint64_t ret=0;
	auto s = client_stmt_to_global_ids.find(client_stmt_id);
	if (s != client_stmt_to_global_ids.end()) {
		ret = s->second;
	}
	return ret;
}

bool MySQL_STMTs_local_v14::client_close(uint32_t client_statement_id) {
	auto s = client_stmt_to_global_ids.find(client_statement_id);
	if (s != client_stmt_to_global_ids.end()) {  // found
		uint64_t global_stmt_id = s->second;
		client_stmt_to_global_ids.erase(s);
		GloMyStmt->ref_count_client(global_stmt_id, -1);
		auto s2 = global_stmt_to_client_ids.find(global_stmt_id);
		std::pair<std::multimap<uint64_t,uint32_t>::iterator, std::multimap<uint64_t,uint32_t>::iterator> ret;
		ret = global_stmt_to_client_ids.equal_range(global_stmt_id);
		for (std::multimap<uint64_t,uint32_t>::iterator it=ret.first; it!=ret.second; ++it) {
			if (it->second==client_statement_id) {
				free_client_ids.push(client_statement_id);
				global_stmt_to_client_ids.erase(it);
				break;
			}
		}
		return true;
	}
	return false;  // we don't really remove the prepared statement
}

MySQL_STMT_Global_info *MySQL_STMT_Manager_v14::add_prepared_statement(
    unsigned int _h, char *u, char *s, char *q, unsigned int ql,
    MYSQL_STMT *stmt, int _cache_ttl, int _timeout, int _delay, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;
	uint64_t hash = stmt_compute_hash(
	    _h, u, s, q, ql);  // this identifies the prepared statement
	if (lock) {
		pthread_rwlock_wrlock(&rwlock_);
	}
	// try to find the statement
	auto f = map_stmt_hash_to_info.find(hash);
	if (f != map_stmt_hash_to_info.end()) {
		// found it!
		// MySQL_STMT_Global_info *a=f->second;
		// ret=a->statement_id;
		ret = f->second;
		//*is_new = false;
	} else {
		// FIXME: add a stack here too!!!
		// we need to create a new one
/*
		bool free_id_avail = false;
		free_id_avail = free_stmt_ids.size();

		uint32_t next_id = 0;
		if (free_id_avail) {
			next_id = free_stmt_ids.top();
			free_stmt_ids.pop();
		} else {
			// next_id = next_statement_id;
			// next_statement_id++;
			__sync_fetch_and_add(&next_statement_id, 1);
		}
*/
		next_statement_id++;
		MySQL_STMT_Global_info *a =
		    new MySQL_STMT_Global_info(next_statement_id, _h, u, s, q, ql, stmt, hash);
		a->properties.cache_ttl = _cache_ttl;
		a->properties.timeout = _timeout;
		a->properties.delay = _delay;
		// insert it in both maps
		map_stmt_id_to_info.insert(std::make_pair(a->statement_id, a));
		map_stmt_hash_to_info.insert(std::make_pair(a->hash, a));
		// ret=a->statement_id;
		ret = a;
		// next_statement_id++;	// increment it
		//__sync_fetch_and_add(&ret->ref_count_client,1); // increase reference
		//count
//		__sync_fetch_and_add(&ret->ref_count_client,
//		                     1);  // increase reference count
//		*is_new = true;
	}
	ret->ref_count_server++;
//	__sync_fetch_and_add(&add_prepared_statement_calls, 1);
//	__sync_fetch_and_add(&ret->ref_count_server,
//	                     1);  // increase reference count
	if (lock) {
		pthread_rwlock_unlock(&rwlock_);
	}
	return ret;
}

void MySQL_STMT_Manager_v14::get_metrics(uint64_t *c_unique, uint64_t *c_total,
                             uint64_t *stmt_max_stmt_id, uint64_t *cached,
                             uint64_t *s_unique, uint64_t *s_total) {
	uint64_t c_u = 0;
	uint64_t c_t = 0;
	uint64_t m = 0;
	uint64_t c = 0;
	uint64_t s_u = 0;
	uint64_t s_t = 0;
	pthread_rwlock_wrlock(&rwlock_);
	for (std::map<uint64_t, MySQL_STMT_Global_info *>::iterator it = map_stmt_id_to_info.begin();
	     it != map_stmt_id_to_info.end(); ++it) {
		MySQL_STMT_Global_info *a = it->second;
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
	pthread_rwlock_unlock(&rwlock_);
	*c_unique = c_u;
	*c_total = c_t;
	*stmt_max_stmt_id = m;
	*cached = c;
	*s_unique = s_u;
	*s_total = s_t;
}

#endif // PROXYSQL_STMT_V14
