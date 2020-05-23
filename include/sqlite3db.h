#ifndef __CLASS_SQLITE3DB_H
#define __CLASS_SQLITE3DB_H
#include "sqlite3.h"
#undef swap
#undef min
#undef max
#include <vector>
#define PROXYSQL_SQLITE3DB_PTHREAD_MUTEX


#ifndef MAIN_PROXY_SQLITE3
extern int (*proxy_sqlite3_bind_double)(sqlite3_stmt*, int, double);
extern int (*proxy_sqlite3_bind_int)(sqlite3_stmt*, int, int);
extern int (*proxy_sqlite3_bind_int64)(sqlite3_stmt*, int, sqlite3_int64);
extern int (*proxy_sqlite3_bind_null)(sqlite3_stmt*, int);
extern int (*proxy_sqlite3_bind_text)(sqlite3_stmt*,int,const char*,int,void(*)(void*));
extern const char *(*proxy_sqlite3_column_name)(sqlite3_stmt*, int N);
extern const unsigned char *(*proxy_sqlite3_column_text)(sqlite3_stmt*, int iCol);
extern int (*proxy_sqlite3_column_bytes)(sqlite3_stmt*, int iCol);
extern int (*proxy_sqlite3_column_type)(sqlite3_stmt*, int iCol);
extern int (*proxy_sqlite3_column_count)(sqlite3_stmt *pStmt);
extern int (*proxy_sqlite3_column_int)(sqlite3_stmt*, int iCol);
extern const char *(*proxy_sqlite3_errmsg)(sqlite3*);
extern int (*proxy_sqlite3_finalize)(sqlite3_stmt *pStmt);
extern int (*proxy_sqlite3_reset)(sqlite3_stmt *pStmt);
extern int (*proxy_sqlite3_clear_bindings)(sqlite3_stmt*);
extern int (*proxy_sqlite3_close_v2)(sqlite3*);
extern int (*proxy_sqlite3_get_autocommit)(sqlite3*);
extern void (*proxy_sqlite3_free)(void*);
extern int (*proxy_sqlite3_status)(int op, int *pCurrent, int *pHighwater, int resetFlag);
extern int (*proxy_sqlite3_changes)(sqlite3*);
extern int (*proxy_sqlite3_step)(sqlite3_stmt*);
extern int (*proxy_sqlite3_config)(int, ...);
extern int (*proxy_sqlite3_shutdown)(void);

extern int (*proxy_sqlite3_prepare_v2)(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);

extern int (*proxy_sqlite3_open_v2)(
  const char *filename,   /* Database filename (UTF-8) */
  sqlite3 **ppDb,         /* OUT: SQLite db handle */
  int flags,              /* Flags */
  const char *zVfs        /* Name of VFS module to use */
);

extern int (*proxy_sqlite3_exec)(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
#else
int (*proxy_sqlite3_bind_double)(sqlite3_stmt*, int, double);
int (*proxy_sqlite3_bind_int)(sqlite3_stmt*, int, int);
int (*proxy_sqlite3_bind_int64)(sqlite3_stmt*, int, sqlite3_int64);
int (*proxy_sqlite3_bind_null)(sqlite3_stmt*, int);
int (*proxy_sqlite3_bind_text)(sqlite3_stmt*,int,const char*,int,void(*)(void*));
const char *(*proxy_sqlite3_column_name)(sqlite3_stmt*, int N);
const unsigned char *(*proxy_sqlite3_column_text)(sqlite3_stmt*, int iCol);
int (*proxy_sqlite3_column_bytes)(sqlite3_stmt*, int iCol);
int (*proxy_sqlite3_column_type)(sqlite3_stmt*, int iCol);
int (*proxy_sqlite3_column_count)(sqlite3_stmt *pStmt);
int (*proxy_sqlite3_column_int)(sqlite3_stmt*, int iCol);
const char *(*proxy_sqlite3_errmsg)(sqlite3*);
int (*proxy_sqlite3_finalize)(sqlite3_stmt *pStmt);
int (*proxy_sqlite3_reset)(sqlite3_stmt *pStmt);
int (*proxy_sqlite3_clear_bindings)(sqlite3_stmt*);
int (*proxy_sqlite3_close_v2)(sqlite3*);
int (*proxy_sqlite3_get_autocommit)(sqlite3*);
void (*proxy_sqlite3_free)(void*);
int (*proxy_sqlite3_status)(int op, int *pCurrent, int *pHighwater, int resetFlag);
int (*proxy_sqlite3_changes)(sqlite3*);
int (*proxy_sqlite3_step)(sqlite3_stmt*);
int (*proxy_sqlite3_config)(int, ...);
int (*proxy_sqlite3_shutdown)(void);

int (*proxy_sqlite3_prepare_v2)(
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);

int (*proxy_sqlite3_open_v2)(
  const char *filename,   /* Database filename (UTF-8) */
  sqlite3 **ppDb,         /* OUT: SQLite db handle */
  int flags,              /* Flags */
  const char *zVfs        /* Name of VFS module to use */
);

int (*proxy_sqlite3_exec)(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
#endif //MAIN_PROXY_SQLITE3

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
	int add_row(sqlite3_stmt *stmt, bool skip=false);
	int add_row(char **_fields);
	int add_row(SQLite3_row *old_row);
	SQLite3_result(sqlite3_stmt *stmt);
	SQLite3_result(sqlite3_stmt *stmt, int *found_rows, unsigned int offset, unsigned int limit);
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
