#include "proxysql.h"
#include "cpp.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "MySQL_PreparedStatement.h"
#include "MySQL_Protocol.h"

//extern MySQL_STMT_Manager *GloMyStmt;
//static uint32_t add_prepared_statement_calls = 0;
//static uint32_t find_prepared_statement_by_hash_calls = 0;
//#else
extern MySQL_STMT_Manager_v14 *GloMyStmt;
//#endif

static uint64_t stmt_compute_hash(char *user,
                                  char *schema, char *query,
                                  unsigned int query_length) {
	int l = 0;
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
	hash = stmt_compute_hash(username, schemaname, query,
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
	sld->is_null = 0; // because the client is sending data, the field cannot be NULL
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
                               unsigned long **_size, my_bool **_is_null) {
	stmt_long_data_t *sld = NULL;
	unsigned int i;
	for (i = 0; i < long_datas->len; i++) {
		sld = (stmt_long_data_t *)long_datas->index(i);
		if (sld->stmt_id == _stmt_id && sld->param_id == _param_id) {
			// we found it!
			*_size = &sld->size;
			*_is_null = &sld->is_null;
			return sld->data;
		}
	}
	return NULL;
}

MySQL_STMT_Global_info::MySQL_STMT_Global_info(uint64_t id,
                                               char *u, char *s, char *q,
                                               unsigned int ql,
                                               char *fc,
                                               MYSQL_STMT *stmt, uint64_t _h) {
	pthread_rwlock_init(&rwlock_, NULL);
	statement_id = id;
	ref_count_client = 0;
	ref_count_server = 0;
	digest_text = NULL;
	username = strdup(u);
	schemaname = strdup(s);
	query = (char *)malloc(ql + 1);
	memcpy(query, q, ql);
	query[ql] = '\0';  // add NULL byte
	query_length = ql;
	if (fc) {
		first_comment = strdup(fc);
	} else {
		first_comment = NULL;
	}
	MyComQueryCmd = MYSQL_COM_QUERY__UNINITIALIZED;
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
				if (ql >= 17) {
					char *p = q;
					p += ql - 11;
					if (strncasecmp(p, " FOR UPDATE", 11) == 0) {  // is a SELECT FOR UPDATE
						__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
						goto __exit_MySQL_STMT_Global_info___search_select;
					}
					p = q;
					p += ql-10;
					if (strncasecmp(p, " FOR SHARE", 10) == 0) {  // is a SELECT FOR SHARE
						__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
						goto __exit_MySQL_STMT_Global_info___search_select;
					}
					if (ql >= 25) {
						p = q;
						p += ql-19;
						if (strncasecmp(p, " LOCK IN SHARE MODE", 19) == 0) {  // is a SELECT LOCK IN SHARE MODE
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_MySQL_STMT_Global_info___search_select;
						}
						p = q;
						p += ql-7;
						if (strncasecmp(p," NOWAIT",7)==0) {
							// let simplify. If NOWAIT is used, we assume FOR UPDATE|SHARE is used
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_MySQL_STMT_Global_info___search_select;
/*
							if (strcasestr(q," FOR UPDATE ")) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
							if (strcasestr(q," FOR SHARE ")) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
*/
						}
						p = q;
						p += ql-12;
						if (strncasecmp(p," SKIP LOCKED",12)==0) {
							// let simplify. If SKIP LOCKED is used, we assume FOR UPDATE|SHARE is used
							__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
							goto __exit_MySQL_STMT_Global_info___search_select;
/*
							if (strcasestr(q," FOR UPDATE ")==NULL) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
							if (strcasestr(q," FOR SHARE ")==NULL) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
*/
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
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
							if (strcasestr(buf," FOR SHARE ")) {
								__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
								goto __exit_MySQL_STMT_Global_info___search_select;
							}
						}
					}
				}
				is_select_NOT_for_update = true;
			}
		}
	}
__exit_MySQL_STMT_Global_info___search_select:

	// set default properties:
//	properties.cache_ttl = -1;
//	properties.timeout = -1;
//	properties.delay = -1;

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

void MySQL_STMT_Global_info::update_metadata(MYSQL_STMT *stmt) {
	int i;
	bool need_refresh = false;
	pthread_rwlock_wrlock(&rwlock_);
	if (
		(num_params != stmt->param_count)
		||
		(num_columns != stmt->field_count)
	) {
		need_refresh = true;
	}
	for (i = 0; i < num_columns; i++) {
		if (need_refresh == false) { // don't bother to check if need_refresh == true
			bool ok = true;
			MYSQL_FIELD *fs = &(stmt->fields[i]);
			MYSQL_FIELD *fd = fields[i];
			if (ok) {
				ok = false;
				if (fd->name == NULL && fs->name == NULL) {
					ok = true;
				} else {
					if (fd->name && fs->name && strcmp(fd->name,fs->name)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->org_name == NULL && fs->org_name == NULL) {
					ok = true;
				} else {
					if (fd->org_name && fs->org_name && strcmp(fd->org_name,fs->org_name)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->table == NULL && fs->table == NULL) {
					ok = true;
				} else {
					if (fd->table && fs->table && strcmp(fd->table,fs->table)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->org_table == NULL && fs->org_table == NULL) {
					ok = true;
				} else {
					if (fd->org_table && fs->org_table && strcmp(fd->org_table,fs->org_table)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->db == NULL && fs->db == NULL) {
					ok = true;
				} else {
					if (fd->db && fs->db && strcmp(fd->db,fs->db)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->catalog == NULL && fs->catalog == NULL) {
					ok = true;
				} else {
					if (fd->catalog && fs->catalog && strcmp(fd->catalog,fs->catalog)==0) {
						ok = true;
					}
				}
			}
			if (ok) {
				ok = false;
				if (fd->def == NULL && fs->def == NULL) {
					ok = true;
				} else {
					if (fd->def && fs->def && strcmp(fd->def,fs->def)==0) {
						ok = true;
					}
				}
			}
			if (ok == false) {
				need_refresh = true;
			}
		}
	}
	if (need_refresh) {
		proxy_warning("Updating metadata for stmt %lu , user %s, query %s\n", statement_id, username, query);
// from here is copied from destructor
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
// till here is copied from destructor

// from here is copied from constructor
		num_params = stmt->param_count;
		num_columns = stmt->field_count;
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
// till here is copied from constructor
	}
	pthread_rwlock_unlock(&rwlock_);
}

MySQL_STMT_Global_info::~MySQL_STMT_Global_info() {
	free(username);
	free(schemaname);
	free(query);
	if (first_comment) {
		free(first_comment);
	}
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

uint64_t MySQL_STMTs_local_v14::compute_hash(char *user,
                                         char *schema, char *query,
                                         unsigned int query_length) {
	uint64_t hash;
	hash = stmt_compute_hash(user, schema, query, query_length);
	return hash;
}

MySQL_STMT_Manager_v14::MySQL_STMT_Manager_v14() {
	last_purge_time = time(NULL);
	pthread_rwlock_init(&rwlock_, NULL);
	map_stmt_id_to_info= std::map<uint64_t, MySQL_STMT_Global_info *>();       // map using statement id
	map_stmt_hash_to_info = std::map<uint64_t, MySQL_STMT_Global_info *>();     // map using hashes
	free_stmt_ids = std::stack<uint64_t> ();

	next_statement_id =
	    1;  // we initialize this as 1 because we 0 is not allowed
	num_stmt_with_ref_client_count_zero = 0;
	num_stmt_with_ref_server_count_zero = 0;
	statuses.c_unique = 0;
	statuses.c_total = 0;
	statuses.stmt_max_stmt_id = 0;
	statuses.cached = 0;
	statuses.s_unique = 0;
	statuses.s_total = 0;
}

MySQL_STMT_Manager_v14::~MySQL_STMT_Manager_v14() {
}

void MySQL_STMT_Manager_v14::ref_count_client(uint64_t _stmt_id ,int _v, bool lock) {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	auto s = map_stmt_id_to_info.find(_stmt_id);
	if (s != map_stmt_id_to_info.end()) {
		statuses.c_total += _v;
		MySQL_STMT_Global_info *stmt_info = s->second;
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
				(map_size > (unsigned)mysql_thread___max_stmts_cache ) &&
				(num_client_count_zero > map_size/10) &&
				(num_server_count_zero > map_size/10)
			) { // purge only if there is at least 10% gain
				last_purge_time = ct;
				int max_purge = map_size ;
				int i = -1;
				uint64_t *torem =
				    (uint64_t *)malloc(max_purge * sizeof(uint64_t));
				for (std::map<uint64_t, MySQL_STMT_Global_info *>::iterator it =
				         map_stmt_id_to_info.begin();
					it != map_stmt_id_to_info.end(); ++it) {
					if ( (i == (max_purge - 1)) || (i == ((int)num_client_count_zero - 1)) ) {
						break; // nothing left to clean up
					}
					MySQL_STMT_Global_info *a = it->second;
					if ((__sync_add_and_fetch(&a->ref_count_client, 0) == 0) &&
						(a->ref_count_server == 0) ) // this to avoid that IDs are incorrectly reused
					{
						uint64_t hash = a->hash;
						auto s2 = map_stmt_hash_to_info.find(hash);
						if (s2 != map_stmt_hash_to_info.end()) {
							map_stmt_hash_to_info.erase(s2);
						}
						__sync_sub_and_fetch(&num_stmt_with_ref_client_count_zero,1);
						//if (a->ref_count_server == 0) {
							//__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
						//}
						// m.erase(it);
						// delete a;
						i++;
						torem[i] = it->first;
					}
				}
				while (i >= 0) {
					uint64_t id = torem[i];
					auto s3 = map_stmt_id_to_info.find(id);
					MySQL_STMT_Global_info *a = s3->second;
					if (a->ref_count_server == 0) {
						__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
						free_stmt_ids.push(id);
					}
					map_stmt_id_to_info.erase(s3);
					statuses.s_total -= a->ref_count_server;
					delete a;
					i--;
				}
				free(torem);
			}
	}
	if (lock)
		pthread_rwlock_unlock(&rwlock_);
}

void MySQL_STMT_Manager_v14::ref_count_server(uint64_t _stmt_id ,int _v, bool lock) {
	if (lock)
		pthread_rwlock_wrlock(&rwlock_);
	std::map<uint64_t, MySQL_STMT_Global_info *>::iterator s;
	s = map_stmt_id_to_info.find(_stmt_id);
	if (s != map_stmt_id_to_info.end()) {
		statuses.s_total += _v;
		MySQL_STMT_Global_info *stmt_info = s->second;
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
			proxy_mysql_stmt_close(stmt);
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
    uint64_t hash) {
    //uint64_t hash, bool lock) { // removed in 2.3
	MySQL_STMT_Global_info *ret = NULL;  // assume we do not find it
/* removed in 2.3
	if (lock) {
		pthread_rwlock_wrlock(&rwlock_);
	}
*/
	auto s = map_stmt_hash_to_info.find(hash);
	if (s != map_stmt_hash_to_info.end()) {
		ret = s->second;
		//__sync_fetch_and_add(&ret->ref_count_client,1); // increase reference
		//count
//		__sync_fetch_and_add(&find_prepared_statement_by_hash_calls, 1);
//		__sync_fetch_and_add(&ret->ref_count_client, 1);
	}

/* removed in 2.3
	if (lock) {
		pthread_rwlock_unlock(&rwlock_);
	}
*/
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
/*
	//auto s2 = global_stmt_to_client_ids.find(global_statement_id);
	std::pair<std::multimap<uint64_t,uint32_t>::iterator, std::multimap<uint64_t,uint32_t>::iterator> itret;
	itret = global_stmt_to_client_ids.equal_range(global_statement_id);
	for (std::multimap<uint64_t,uint32_t>::iterator it=itret.first; it!=itret.second; ++it) {
		ret = it->second;
		return ret;
	}
*/
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
		//auto s2 = global_stmt_to_client_ids.find(global_stmt_id);
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
    char *u, char *s, char *q, unsigned int ql,
    char *fc, MYSQL_STMT *stmt, bool lock) {
	MySQL_STMT_Global_info *ret = NULL;
	uint64_t hash = stmt_compute_hash(
		u, s, q, ql);  // this identifies the prepared statement
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
		ret->update_metadata(stmt);
		//*is_new = false;
	} else {
		// FIXME: add a stack here too!!!
		// we need to create a new one

		bool free_id_avail = false;
		free_id_avail = free_stmt_ids.size();

		uint64_t next_id = 0;
		if (free_id_avail) {
			next_id = free_stmt_ids.top();
			free_stmt_ids.pop();
		} else {
			next_id = next_statement_id;
			next_statement_id++;
			//__sync_fetch_and_add(&next_statement_id, 1);
		}

		//next_statement_id++;
		MySQL_STMT_Global_info *a =
		    new MySQL_STMT_Global_info(next_id, u, s, q, ql, fc, stmt, hash);
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
		__sync_add_and_fetch(&num_stmt_with_ref_client_count_zero,1);
		__sync_add_and_fetch(&num_stmt_with_ref_server_count_zero,1);
	}
	if (ret->ref_count_server == 0) {
		__sync_sub_and_fetch(&num_stmt_with_ref_server_count_zero,1);
	}
	ret->ref_count_server++;
	statuses.s_total++;
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
#ifdef DEBUG
	uint64_t c_u = 0;
	uint64_t c_t = 0;
	uint64_t m = 0;
	uint64_t c = 0;
	uint64_t s_u = 0;
	uint64_t s_t = 0;
#endif
	pthread_rwlock_wrlock(&rwlock_);
	statuses.cached = map_stmt_id_to_info.size();
	statuses.c_unique = statuses.cached - num_stmt_with_ref_client_count_zero;
	statuses.s_unique = statuses.cached - num_stmt_with_ref_server_count_zero;
#ifdef DEBUG
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


class PS_global_stats {
	public:
	uint64_t statement_id;
	char *username;
	char *schemaname;
	uint64_t digest;
	unsigned long long ref_count_client;
	unsigned long long ref_count_server;
	char *query;
	uint64_t num_columns;
	uint64_t num_params;
	PS_global_stats(uint64_t stmt_id, char *s, char *u, uint64_t d, char *q, unsigned long long ref_c, unsigned long long ref_s, uint64_t columns, uint64_t params) {
		statement_id = stmt_id;
		digest=d;
		query=strndup(q, mysql_thread___query_digests_max_digest_length);
		username=strdup(u);
		schemaname=strdup(s);
		ref_count_client = ref_c;
		ref_count_server = ref_s;
		num_columns = columns;
		num_params = params;
	}
	~PS_global_stats() {
		if (query) {
			free(query);
			query=NULL;
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
		char **pta=(char **)malloc(sizeof(char *)*9);
		sprintf(buf,"%lu",statement_id);
		pta[0]=strdup(buf);
		assert(schemaname);
		pta[1]=strdup(schemaname);
		assert(username);
		pta[2]=strdup(username);

		sprintf(buf,"0x%016llX", (long long unsigned int)digest);
		pta[3]=strdup(buf);

		assert(query);
		pta[4]=strdup(query);
		sprintf(buf,"%llu",ref_count_client);
		pta[5]=strdup(buf);
		sprintf(buf,"%llu",ref_count_server);
		pta[6]=strdup(buf);
		sprintf(buf,"%lu",num_columns);
		pta[7]=strdup(buf);
		sprintf(buf,"%lu",num_params);
		pta[8]=strdup(buf);

		return pta;
	}
	void free_row(char **pta) {
		int i;
		for (i=0;i<7;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};


SQLite3_result * MySQL_STMT_Manager_v14::get_prepared_statements_global_infos() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current prepared statements global info\n");
	SQLite3_result *result=new SQLite3_result(9);
	rdlock();
	result->add_column_definition(SQLITE_TEXT,"stmt_id");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"digest");
	result->add_column_definition(SQLITE_TEXT,"query");
	result->add_column_definition(SQLITE_TEXT,"ref_count_client");
	result->add_column_definition(SQLITE_TEXT,"ref_count_server");
	result->add_column_definition(SQLITE_TEXT,"num_columns");
	result->add_column_definition(SQLITE_TEXT,"num_params");
	for (std::map<uint64_t, MySQL_STMT_Global_info *>::iterator it = map_stmt_id_to_info.begin();
			it != map_stmt_id_to_info.end(); ++it) {
		MySQL_STMT_Global_info *a = it->second;
		PS_global_stats * pgs = new PS_global_stats(a->statement_id,
			a->schemaname, a->username,
			a->hash, a->query,
			a->ref_count_client, a->ref_count_server, a->num_columns, a->num_params);
			char **pta = pgs->get_row();
			result->add_row(pta);
			pgs->free_row(pta);
			delete pgs;
	}
/*
	for (std::unordered_map<uint64_t, void *>::iterator it=digest_umap.begin(); it!=digest_umap.end(); ++it) {
		QP_query_digest_stats *qds=(QP_query_digest_stats *)it->second;
		char **pta=qds->get_row();
		result->add_row(pta);
		qds->free_row(pta);
	}
*/
	unlock();
	return result;
}
