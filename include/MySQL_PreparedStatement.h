#ifndef CLASS_MYSQL_PREPARED_STATEMENT_H
#define CLASS_MYSQL_PREPARED_STATEMENT_H

#include "proxysql.h"
#include "cpp.h"


class MySQL_STMTs_local {
	private:
	std::map<uint32_t, MYSQL_STMT *> m;
	public:
	MySQL_STMTs_local() {
	}
	~MySQL_STMTs_local();
	// we declare it here to be inline
	void insert(uint32_t global_statement_id, MYSQL_STMT *stmt) {
		m.insert(std::make_pair(global_statement_id, stmt));
	}
	// we declare it here to be inline
	MYSQL_STMT * find(uint32_t global_statement_id) {
		auto s=m.find(global_statement_id);
		if (s!=m.end()) {	// found
			return s->second;
		}
		return NULL;	// not found
	}
	uint64_t compute_hash(unsigned int hostgroup, char *user, char *schema, char *query, unsigned int query_length);
};

class MySQL_STMT_Global_info {
	private:
	void compute_hash();
  public:
  uint64_t hash;
  char *username;
  char *schemaname;
  char *query;
  unsigned int query_length;
	unsigned int hostgroup_id;
	int ref_count;
  uint32_t statement_id;
  uint16_t num_columns;
  uint16_t num_params;
  uint16_t warning_count;
	MySQL_STMT_Global_info(uint32_t id, unsigned int h, char *u, char *s, char *q, unsigned int ql, MYSQL_STMT *stmt, uint64_t _h) {
		statement_id=id;
		hostgroup_id=h;
		ref_count=0;
		username=strdup(u);
		schemaname=strdup(s);
		query=strdup(q);
		query_length=ql;
		num_params=stmt->param_count;
		num_columns=stmt->field_count;
		warning_count=stmt->upsert_status.warning_count;
		if (_h) {
			hash=_h;
		} else {
			compute_hash();
		}
	}
	~MySQL_STMT_Global_info() {
		free(username);
		free(schemaname);
		free(query);
	}
};

class MySQL_STMT_Manager {
	private:
	uint32_t next_statement_id;
	rwlock_t rwlock;
	std::map<uint32_t, MySQL_STMT_Global_info *> m;	// map using statement id
	std::map<uint64_t, MySQL_STMT_Global_info *> h;	// map using hashes
	public:
	MySQL_STMT_Manager();
	~MySQL_STMT_Manager();
	int ref_count(uint32_t statement_id, int cnt, bool lock=true);
	uint32_t add_prepared_statement(unsigned int h, char *u, char *s, char *q, unsigned int ql, MYSQL_STMT *stmt, bool lock=true);
	MySQL_STMT_Global_info * find_prepared_statement_by_stmt_id(uint32_t id, bool lock=true);
	MySQL_STMT_Global_info * find_prepared_statement_by_hash(uint64_t hash, bool lock=true);
	uint32_t total_prepared_statements() { return next_statement_id-1; }
};

#endif /* CLASS_MYSQL_PREPARED_STATEMENT_H */
