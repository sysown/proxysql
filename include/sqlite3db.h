#ifndef __CLASS_SQLITE3DB_H
#define __CLASS_SQLITE3DB_H
#include "proxysql.h"
#include "cpp.h"



//struct _sqlite3row_t {
//};

//typedef struct _sqlite3row_t sqlite3row;

class SQLite3_row {
	public:
	int cnt;
	int *sizes;
	char **fields;
	SQLite3_row(int c) {
		sizes=(int *)malloc(sizeof(int)*c);
		fields=(char **)malloc(sizeof(char *)*c);
		memset(fields,0,sizeof(char *)*c);
		cnt=c;
	};
	~SQLite3_row() {
		int i=0;
		for (i=0;i<cnt;i++) {
			if (fields[i]) free(fields[i]);
		}
		free(fields);
		free(sizes);
	};
//	void add_field(const char *str, int i) {
//		fields[i]=strdup(str);
//		//sizes[i]=strlen(fields[i]);
//		sizes[i]=sqlite3_column_bytes(stmt,i);
//	};
	void add_fields(sqlite3_stmt *stmt) {
		int i;
		int t;
		for (i=0;i<cnt;i++) {
			t=sqlite3_column_type(stmt,i);
			const char *c=(char *)sqlite3_column_text(stmt,i);
			if (t==SQLITE_NULL) {
				sizes[i]=0;
				fields[i]=NULL;
			} else {
				sizes[i]=sqlite3_column_bytes(stmt,i);
				fields[i]=strdup(c);
			}
//			} else {
//				fields[i]=NULL;
//			}
			//fields[i]=(sizes[i] ? strdup((char *)sqlite3_column_text(stmt,i)) : NULL);
		}
	};
	void add_fields(char **_fields) {
		int i;
		for (i=0;i<cnt;i++) {
			if (_fields[i]) {
				sizes[i]=strlen(_fields[i]);
				fields[i]=strdup(_fields[i]);
			} else {
				sizes[i]=0;
				fields[i]=NULL;
				//fields[i]=strdup((char *)"");
			}
		}
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
	int columns;
	int rows_count;
	char *checksum();
	int64_t raw_checksum();

	std::vector<SQLite3_column *> column_definition;
	std::vector<SQLite3_row *> rows;
	SQLite3_result() {
		columns=0;
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
	SQLite3_result(int num_columns) {
		rows_count=0;
		columns=num_columns;
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
};

class SQLite3DB {
	private:
	char *url;
	sqlite3 *db;
	rwlock_t rwlock;
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
	int return_one_int(const char *);
	int check_table_structure(char *table_name, char *table_def);
	bool build_table(char *table_name, char *table_def, bool dropit);
	bool check_and_build_table(char *table_name, char *table_def);
};

#endif /* __CLASS_SQLITE3DB_H */
