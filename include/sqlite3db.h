#ifndef __CLASS_SQLITE3DB_H
#define __CLASS_SQLITE3DB_H
#include "proxysql.h"
#include "cpp.h"
#define PROXYSQL_SQLITE3DB_PTHREAD_MUTEX

class SQLite3_row {
	public:
	int cnt;
	int ds;
	int *sizes;
	char **fields;
	char *data;
	SQLite3_row(int c) {
		sizes=(int *)malloc(sizeof(int)*c);
		fields=(char **)malloc(sizeof(char *)*c);
		memset(fields,0,sizeof(char *)*c);
		cnt=c;
		data=NULL;
		ds=0;
	};
	unsigned long long get_size() {
		unsigned long long s = sizeof(SQLite3_row);
		s += cnt * sizeof(int);
		s += cnt * sizeof(char *);
		s += ds;
		return s;
	};
	~SQLite3_row() {
		free(fields);
		free(sizes);
		if (data) {
			free(data);
		}
	};
	void add_fields(sqlite3_stmt *stmt) {
		int i;
		int t;
		int data_size=0;
		int data_ptr=0;
		// compute the length
		for (i=0;i<cnt;i++) {
			t=sqlite3_column_type(stmt,i);
			if (t==SQLITE_NULL) {
				sizes[i]=0;
			} else {
				sizes[i]=sqlite3_column_bytes(stmt,i);
				data_size+=sizes[i];
				data_size++; // leading 0
			}
		}
		if (data_size) {
			data=(char *)malloc(data_size);
		}
		for (i=0;i<cnt;i++) {
			t=sqlite3_column_type(stmt,i);
			const char *c=(char *)sqlite3_column_text(stmt,i);
			if (t==SQLITE_NULL) {
				//sizes[i]=0;
				fields[i]=NULL;
			} else {
				memcpy(data+data_ptr,c,sizes[i]);
				fields[i]=data+data_ptr;
				data_ptr+=sizes[i];
				data[data_ptr]='\0';
				data_ptr++; // leading 0
			}
		}
		ds=data_size;
	};
	void add_fields(char **_fields) {
		int i;
		int data_size=0;
		int data_ptr=0;
		for (i=0;i<cnt;i++) {
			if (_fields[i]) {
				sizes[i]=strlen(_fields[i]);
				data_size+=sizes[i];
				data_size++; // leading 0
			} else {
				sizes[i]=0;
			}
		}
		if (data_size) {
			data=(char *)malloc(data_size);
		}
		for (i=0;i<cnt;i++) {
			if (_fields[i]) {
				memcpy(data+data_ptr,_fields[i],sizes[i]);
				fields[i]=data+data_ptr;
				data_ptr+=sizes[i];
				data[data_ptr]='\0';
				data_ptr++; // leading 0
			} else {
				fields[i]=NULL;
			}
		}
		ds=data_size;
	};
};

class SQLite3_column {
	public:
	int datatype;
	char *name;
	SQLite3_column(int a, const char *b) {
		datatype=a;
		if (b) {
			name=strdup(b);
		} else {
			name=strdup((char *)"");
		}
	};
	~SQLite3_column() {
		free(name);
	};
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
	SQLite3_result() {
		columns=0;
	};
	unsigned long long get_size() {
		unsigned long long s = sizeof(SQLite3_result);
		s += column_definition.size() * sizeof(SQLite3_column *);
		s += rows.size() * sizeof(SQLite3_row *);
		for (std::vector<SQLite3_column *>::iterator it = column_definition.begin() ; it != column_definition.end(); ++it) {
			SQLite3_column *r=*it;
			s+= sizeof(SQLite3_column) + strlen(r->name);
		}
		for (std::vector<SQLite3_row *>::iterator it = rows.begin() ; it != rows.end(); ++it) {
			SQLite3_row *r=*it;
			s += r->get_size();
		}
		return s;
	};
	void add_column_definition(int a, const char *b) {
		SQLite3_column *cf=new SQLite3_column(a,b);
		column_definition.push_back(cf);
		//columns++;
	};
	int add_row(sqlite3_stmt *stmt) {
		int rc=sqlite3_step(stmt);
		if (rc!=SQLITE_ROW) return rc;
		SQLite3_row *row=new SQLite3_row(columns);
		row->add_fields(stmt);
		rows.push_back(row);
		rows_count++;
		return SQLITE_ROW;
	};
	int add_row(char **_fields) {
		SQLite3_row *row=new SQLite3_row(columns);	
		row->add_fields(_fields);
		if (enabled_mutex) {
			pthread_mutex_lock(&m);
		}
		rows.push_back(row);
		rows_count++;
		if (enabled_mutex) {
			pthread_mutex_unlock(&m);
		}
		return SQLITE_ROW;
	};
	int add_row(SQLite3_row *old_row) {
		SQLite3_row *row=new SQLite3_row(columns);
		row->add_fields(old_row->fields);
		rows.push_back(row);
		rows_count++;
		return SQLITE_ROW;
	};
	SQLite3_result(sqlite3_stmt *stmt) {
		rows_count=0;
		columns=sqlite3_column_count(stmt);
		for (int i=0; i<columns; i++) {
			add_column_definition(sqlite3_column_type(stmt,i), sqlite3_column_name(stmt,i));
		}
		while (add_row(stmt)==SQLITE_ROW) {};
	};
	SQLite3_result(int num_columns, bool en_mutex=false) {
		rows_count=0;
		columns=num_columns;
		if (en_mutex) {
			pthread_mutex_init(&m,NULL);
			enabled_mutex = true;
		} else {
			enabled_mutex = false;
		}
	};
	~SQLite3_result() {
		for (std::vector<SQLite3_column *>::iterator it = column_definition.begin() ; it != column_definition.end(); ++it) {
			SQLite3_column *c=*it;
			delete c;
		}
		for (std::vector<SQLite3_row *>::iterator it = rows.begin() ; it != rows.end(); ++it) {
			SQLite3_row *r=*it;
			delete r;
		}
	};
	void dump_to_stderr();
};

class SQLite3DB {
	private:
	char *url;
	sqlite3 *db;
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif
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
	bool execute_statement_raw(const char *, char **, int *, int *, sqlite3_stmt **);
	int return_one_int(const char *);
	int check_table_structure(char *table_name, char *table_def);
	bool build_table(char *table_name, char *table_def, bool dropit);
	bool check_and_build_table(char *table_name, char *table_def);
	int prepare_v2(const char *, sqlite3_stmt **);
};

#endif /* __CLASS_SQLITE3DB_H */
