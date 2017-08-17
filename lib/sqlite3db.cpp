#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

#define USLEEP_SQLITE_LOCKED 100

SQLite3DB::SQLite3DB() {
	db=NULL;
	url=NULL;
	assert_on_error=0;
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_init(&rwlock, NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
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
	int rc=0;
	do {
	rc=sqlite3_exec(db, str, NULL, 0, &err);
//	fprintf(stderr,"%d : %s\n", rc, str);
		if(err!=NULL) {
			if (rc!=SQLITE_LOCKED) {
				proxy_error("SQLITE error: %s --- %s\n", err, str);
				if (assert_on_error) {
					assert(err==0);
				}
			}
			sqlite3_free(err);
			err=NULL;
		}
		if (rc==SQLITE_LOCKED) { // the execution of sqlite3_exec() failed because locked
			usleep(USLEEP_SQLITE_LOCKED);
		}
	} while (rc==SQLITE_LOCKED);
	if (rc==SQLITE_OK) {
		return true;
	}
	return false;
}


bool SQLite3DB::execute_statement(const char *str, char **error, int *cols, int *affected_rows, SQLite3_result **resultset) {
	int rc;
	sqlite3_stmt *statement=NULL;
	*error=NULL;
	bool ret=false;
	VALGRIND_DISABLE_ERROR_REPORTING;
	if(sqlite3_prepare_v2(db, str, -1, &statement, 0) != SQLITE_OK) {
		*error=strdup(sqlite3_errmsg(db));
		goto __exit_execute_statement;
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	*cols = sqlite3_column_count(statement);
	if (*cols==0) { // not a SELECT
		*resultset=NULL;
		do {
			rc=sqlite3_step(statement);
			if (rc==SQLITE_LOCKED) { // the execution of the prepared statement failed because locked
				usleep(USLEEP_SQLITE_LOCKED);
			}
		} while (rc==SQLITE_LOCKED);
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

bool SQLite3DB::execute_statement_raw(const char *str, char **error, int *cols, int *affected_rows, sqlite3_stmt **statement) {
	int rc;
	//sqlite3_stmt *statement=NULL;
	*error=NULL;
	bool ret=false;
	VALGRIND_DISABLE_ERROR_REPORTING;
	if(sqlite3_prepare_v2(db, str, -1, statement, 0) != SQLITE_OK) {
		*error=strdup(sqlite3_errmsg(db));
		goto __exit_execute_statement;
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	*cols = sqlite3_column_count(*statement);
	if (*cols==0) { // not a SELECT
		//*resultset=NULL;
		do {
			rc=sqlite3_step(*statement);
			if (rc==SQLITE_LOCKED) { // the execution of the prepared statement failed because locked
				usleep(USLEEP_SQLITE_LOCKED);
			}
		} while (rc==SQLITE_LOCKED);
		if (rc==SQLITE_DONE) {
			*affected_rows=sqlite3_changes(db);
			ret=true;
		} else {
			*error=strdup(sqlite3_errmsg(db));
			goto __exit_execute_statement;
		}
	} else {
		*affected_rows=0;
		//*resultset=new SQLite3_result(statement);
		ret=true;
	}
__exit_execute_statement:
	// NOTE: the caller MUST call sqlite3_finalize()
	//sqlite3_finalize(statement);
	return ret;
}

int SQLite3DB::return_one_int(const char *str) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	int ret=0;
	SQLite3_result *resultset=NULL;
	execute_statement(str, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", str, error);
		free(error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			ret=atoi(r->fields[0]);
			break;
		}
	}
	if (resultset) delete resultset;
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

void SQLite3DB::rdlock() {
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
}

void SQLite3DB::rdunlock() {
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
}

void SQLite3DB::wrlock() {
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
}

void SQLite3DB::wrunlock() {
#ifdef PROXYSQL_SQLITE3DB_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
}

uint64_t SQLite3_result::raw_checksum() {
	if (this->rows_count==0) return 0;
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(19,3);

	for (std::vector<SQLite3_row *>::iterator it=rows.begin() ; it!=rows.end(); ++it) {
		SQLite3_row *r=*it;
		for (int i=0; i<columns;i++) {
			if (r->fields[i]) {
				myhash.Update(r->fields[i],r->sizes[i]);
			} else {
				myhash.Update("",0);
			}
		}
	}
	myhash.Final(&hash1, &hash2);
	return hash1;
}


char *SQLite3_result::checksum() {
	uint64_t hash1=raw_checksum();
	char buf[128];
	memset(buf,'0',128);
	uint32_t d32[2];
	memcpy(&d32,&hash1,sizeof(hash1));
	sprintf(buf,"0x%X%X", d32[0], d32[1]);
	return strdup(buf);
}
