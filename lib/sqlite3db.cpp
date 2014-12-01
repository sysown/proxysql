#include "proxysql.h"
#include "cpp.h"


SQLite3DB::SQLite3DB() {
	db=NULL;
	url=NULL;
	assert_on_error=0;
}

SQLite3DB::~SQLite3DB() {
	if (db) {
		// close db
		int rc;
		rc=sqlite3_close_v2(db);
		if (rc!=SQLITE_OK) {
	    proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_close_v2(): %s\n", sqlite3_errmsg(db));	
			if (assert_on_error) {
				assert(rc==0);
			}
		}
	}
	if (url) {free(url); url=NULL;}
}

int SQLite3DB::open(char *__url, int flags) {
	// we shouldn't call open if url is not NULL
	assert(url==NULL); // we always assert() here
	assert(db==NULL);
	url=strdup(__url);
	int rc;
	rc=sqlite3_open_v2(url, &db, flags , NULL);
	if(rc){
    proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open_v2(): %s\n", sqlite3_errmsg(db));
		if (assert_on_error) {
			assert(rc==0);
		}
		return -1;		
  }
	return 0;
}

bool SQLite3DB::execute(const char *str) {
	assert(url);
	assert(db);
	char *err=NULL;
	sqlite3_exec(db, str, NULL, 0, &err);
	if(err!=NULL) {
        proxy_error("SQLITE error: %s --- %s\n", err, str);
		if (assert_on_error) {
			assert(err==0);
		}
		return false;		
	}
	return true;
}


bool SQLite3DB::execute_statement(const char *str, char **error, int *cols, int *affected_rows, SQLite3_result **resultset) {
	int rc;
	sqlite3_stmt *statement;
	*error=NULL;
	bool ret=false;
	if(sqlite3_prepare_v2(db, str, -1, &statement, 0) != SQLITE_OK) {
		*error=strdup(sqlite3_errmsg(db));
		goto __exit_execute_statement;
	}
	*cols = sqlite3_column_count(statement);
	if (*cols==0) { // not a SELECT
		*resultset=NULL;
		rc=sqlite3_step(statement);
		if (rc==SQLITE_DONE) {
			*affected_rows=sqlite3_changes(db);
			ret=true;
		} else {
			*error=strdup(sqlite3_errmsg(db));
			goto __exit_execute_statement;
		}
	} else {
		*affected_rows=0;
		*resultset=new SQLite3_result(statement);
		ret=true;
	}
__exit_execute_statement:
	sqlite3_finalize(statement);
	return ret;
}


int SQLite3DB::check_table_structure(char *table_name, char *table_def) {
	const char *q1="SELECT COUNT(*) FROM sqlite_master WHERE type=\"table\" AND name=\"%s\" AND sql=\"%s\"";
	int count=0;
	int l=strlen(q1)+strlen(table_name)+strlen(table_def)+1;
	sqlite3_stmt *statement;
	char *buff=(char *)calloc(1,l);
	sprintf(buff, q1, table_name , table_def);
	if(sqlite3_prepare_v2(db, buff, -1, &statement, 0) != SQLITE_OK) {
	  proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", buff, sqlite3_errmsg(db));
	  sqlite3_finalize(statement);
	  free(buff);
	  assert(0);
	}
	int result=0;
	while ((result=sqlite3_step(statement))==SQLITE_ROW) {
	  count+=sqlite3_column_int(statement,0);
	}
	sqlite3_finalize(statement);
	free(buff);
	return count;
}

bool SQLite3DB::build_table(char *table_name, char *table_def, bool dropit) {
	bool rc;
	if (dropit) {
		const char *q2="DROP TABLE IF EXISTS %s";
		int l=strlen(q2)+strlen(table_name)+1;
		char *buff=(char *)calloc(1,l);
		sprintf(buff,q2,table_name);
		proxy_debug(PROXY_DEBUG_SQLITE, 5, "SQLITE: dropping table: %s\n", buff);
		rc=execute(buff);
		free(buff);
		if (rc==false) return rc;
	}
	proxy_debug(PROXY_DEBUG_SQLITE, 5, "SQLITE: creating table: %s\n", table_def);
	rc=execute(table_def);
	return rc;
}

bool SQLite3DB::check_and_build_table(char *table_name, char *table_def) {
	int rci;
	bool rcb;
	rci=check_table_structure(table_name,table_def);
	if (rci) return true;
	rcb=build_table(table_name,table_def,true);
	return rcb;
}

