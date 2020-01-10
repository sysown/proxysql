#ifndef __CLASS_SQLITE3DB_H
#define __CLASS_SQLITE3DB_H
#include "sqlite3.h"
#undef swap
#undef min
#undef max
#include <vector>
#define PROXYSQL_SQLITE3DB_PTHREAD_MUTEX

class SQLite3_row {
	public:
	int cnt;
	int ds;
	int *sizes;
	char **fields;
	char *data;
	SQLite3_row(int c);
	unsigned long long get_size();
	~SQLite3_row();
	void add_fields(sqlite3_stmt *stmt);
	void add_fields(char **_fields);
};

class SQLite3_column {
	public:
	int datatype;
	char *name;
	SQLite3_column(int a, const char *b);
	~SQLite3_column();
};

class SQLite3_result {
	public:
	pthread_mutex_t m;
	bool enabled_mutex;
	int columns;
	int rows_count;
	char *checksum();
	uint64_t raw_checksum();

	std::vector<SQLite3_column *> column_definition;
	std::vector<SQLite3_row *> rows;
	SQLite3_result();
	SQLite3_result(SQLite3_result *);
	unsigned long long get_size();
	void add_column_definition(int a, const char *b);
	int add_row(sqlite3_stmt *stmt);
	int add_row(char **_fields);
	int add_row(SQLite3_row *old_row);
	SQLite3_result(sqlite3_stmt *stmt);
	SQLite3_result(int num_columns, bool en_mutex=false);
	~SQLite3_result();
	void dump_to_stderr();
};

class SQLite3DB {
	private:
	char *url;
	sqlite3 *db;
	pthread_rwlock_t rwlock;
	public:
	char *get_url() const { return url; }
	sqlite3 *get_db() const { return db; }
	int assert_on_error;
	SQLite3DB();
	~SQLite3DB();
	int open(char *, int);

	void rdlock();
	void rdunlock();
	void wrlock();
	void wrunlock();

	bool execute(const char *);
	bool execute_statement(const char *, char **, int *, int *, SQLite3_result **);
	SQLite3_result* execute_statement(const char *, char **_error=NULL, int *_cols=NULL, int *_affected_rows=NULL);
	bool execute_statement_raw(const char *, char **, int *, int *, sqlite3_stmt **);
	int return_one_int(const char *);
	int check_table_structure(char *table_name, char *table_def);
	bool build_table(char *table_name, char *table_def, bool dropit);
	bool check_and_build_table(char *table_name, char *table_def);
	int prepare_v2(const char *, sqlite3_stmt **);
};

#endif /* __CLASS_SQLITE3DB_H */
