#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define USLEEP_SQLITE_LOCKED 100

SQLite3_column::SQLite3_column(int a, const char *b) {
	datatype=a;
	if (b) {
		name=strdup(b);
	} else {
		name=strdup((char *)"");
	}
}

SQLite3_column::~SQLite3_column() {
	free(name);
}


SQLite3_row::SQLite3_row(int c) {
	sizes=(int *)malloc(sizeof(int)*c);
	fields=(char **)malloc(sizeof(char *)*c);
	memset(fields,0,sizeof(char *)*c);
	cnt=c;
	data=NULL;
	ds=0;
}

unsigned long long SQLite3_row::get_size() {
	unsigned long long s = sizeof(SQLite3_row);
	s += cnt * sizeof(int);
	s += cnt * sizeof(char *);
	s += ds;
	return s;
}

SQLite3_row::~SQLite3_row() {
	free(fields);
	free(sizes);
	if (data) {
		free(data);
	}
}

void SQLite3_row::add_fields(sqlite3_stmt *stmt) {
	int i;
	int t;
	int data_size=0;
	int data_ptr=0;
	// compute the length
	for (i=0;i<cnt;i++) {
		t=(*proxy_sqlite3_column_type)(stmt,i);
		if (t==SQLITE_NULL) {
			sizes[i]=0;
		} else {
			sizes[i]=(*proxy_sqlite3_column_bytes)(stmt,i);
			data_size+=sizes[i];
			data_size++; // leading 0
		}
	}
	if (data_size) {
		data=(char *)malloc(data_size);
	}
	for (i=0;i<cnt;i++) {
		t=(*proxy_sqlite3_column_type)(stmt,i);
		const char *c=(char *)(*proxy_sqlite3_column_text)(stmt,i);
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
}

void SQLite3_row::add_fields(char **_fields) {
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
}

SQLite3DB::SQLite3DB() {
	db=NULL;
	url=NULL;
	assert_on_error=0;
	pthread_rwlock_init(&rwlock, NULL);
}

SQLite3DB::~SQLite3DB() {
	if (db) {
		// close db
		int rc;
		rc=(*proxy_sqlite3_close_v2)(db);
		if (rc!=SQLITE_OK) {
	    proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on (*proxy_sqlite3_close_v2)(): %s\n", (*proxy_sqlite3_errmsg)(db));	
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
	rc=(*proxy_sqlite3_open_v2)(url, &db, flags , NULL);
	if (rc) {
    proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on (*proxy_sqlite3_open_v2)(): %s\n", (*proxy_sqlite3_errmsg)(db));
		if (assert_on_error) {
			assert(rc==0);
		}
		proxy_error("SQLITE CRITICAL error: Unable to open %s. Shutting down.\n", url);
		exit(EXIT_SUCCESS);
	}
	return 0;
}

bool SQLite3DB::execute(const char *str) {
	assert(url);
	assert(db);
	char *err=NULL;
	int rc=0;
	do {
	rc=(*proxy_sqlite3_exec)(db, str, NULL, 0, &err);
//	fprintf(stderr,"%d : %s\n", rc, str);
		if(err!=NULL) {
			if (rc!=SQLITE_LOCKED && rc!=SQLITE_BUSY) {
				proxy_error("SQLITE error: %s --- %s\n", err, str);
				if (assert_on_error) {
					assert(err==0);
				}
			}
			(*proxy_sqlite3_free)(err);
			err=NULL;
		}
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) { // the execution of (*proxy_sqlite3_exec)() failed because locked
			usleep(USLEEP_SQLITE_LOCKED);
		}
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);
	if (rc==SQLITE_OK) {
		return true;
	}
	return false;
}

int SQLite3DB::prepare_v2(const char *str, sqlite3_stmt **statement) {
	int rc;
	do {
		rc = (*proxy_sqlite3_prepare_v2)(db, str, -1, statement, 0);
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) { // the execution of the prepared statement failed because locked
			usleep(USLEEP_SQLITE_LOCKED);
		}
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);
	return rc;
}

SQLite3_result* SQLite3DB::execute_statement(const char *str, char **_error, int *_cols, int *_affected_rows) {
	SQLite3_result* resultset;

	char *myerror;
	char **error = (_error == NULL ? &myerror : _error);

	int mycols;
	int *cols = (_cols == NULL ? &mycols : _cols);

	int my_affected_rows;
	int *affected_rows = (_affected_rows == NULL ? &my_affected_rows : _affected_rows);

	if (execute_statement(str, error, cols, affected_rows, &resultset))
		return resultset;

	return NULL;
}

bool SQLite3DB::execute_statement(const char *str, char **error, int *cols, int *affected_rows, SQLite3_result **resultset) {
	int rc;
	sqlite3_stmt *statement=NULL;
	*error=NULL;
	bool ret=false;
	VALGRIND_DISABLE_ERROR_REPORTING;
	do {
		rc = (*proxy_sqlite3_prepare_v2)(db, str, -1, &statement, 0);
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) { // the execution of the prepared statement failed because locked
			if ((*proxy_sqlite3_get_autocommit)(db)==0) {
				*error=strdup((*proxy_sqlite3_errmsg)(db));
				goto __exit_execute_statement;
			}
			usleep(USLEEP_SQLITE_LOCKED);
		}
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);
	if (rc == SQLITE_OK) {
	} else {
		*error=strdup((*proxy_sqlite3_errmsg)(db));
		goto __exit_execute_statement;
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	*cols = (*proxy_sqlite3_column_count)(statement);
	if (*cols==0) { // not a SELECT
		*resultset=NULL;
		do {
			rc=(*proxy_sqlite3_step)(statement);
			if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) { // the execution of the prepared statement failed because locked
				if ((*proxy_sqlite3_get_autocommit)(db)==0) {
					*error=strdup((*proxy_sqlite3_errmsg)(db));
					goto __exit_execute_statement;
				}
				usleep(USLEEP_SQLITE_LOCKED);
			}
		} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);
		if (rc==SQLITE_DONE) {
			*affected_rows=(*proxy_sqlite3_changes)(db);
			ret=true;
		} else {
			*error=strdup((*proxy_sqlite3_errmsg)(db));
			goto __exit_execute_statement;
		}
	} else {
		*affected_rows=0;
		*resultset=new SQLite3_result(statement);
		ret=true;
	}
__exit_execute_statement:
	(*proxy_sqlite3_reset)(statement);
	(*proxy_sqlite3_finalize)(statement);
	return ret;
}

bool SQLite3DB::execute_statement_raw(const char *str, char **error, int *cols, int *affected_rows, sqlite3_stmt **statement) {
	int rc;
	//sqlite3_stmt *statement=NULL;
	*error=NULL;
	bool ret=false;
	VALGRIND_DISABLE_ERROR_REPORTING;
	if((*proxy_sqlite3_prepare_v2)(db, str, -1, statement, 0) != SQLITE_OK) {
		*error=strdup((*proxy_sqlite3_errmsg)(db));
		goto __exit_execute_statement;
	}
	VALGRIND_ENABLE_ERROR_REPORTING;
	*cols = (*proxy_sqlite3_column_count)(*statement);
	if (*cols==0) { // not a SELECT
		//*resultset=NULL;
		do {
			rc=(*proxy_sqlite3_step)(*statement);
			if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) { // the execution of the prepared statement failed because locked
				usleep(USLEEP_SQLITE_LOCKED);
			}
		} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);
		if (rc==SQLITE_DONE) {
			*affected_rows=(*proxy_sqlite3_changes)(db);
			ret=true;
		} else {
			*error=strdup((*proxy_sqlite3_errmsg)(db));
			goto __exit_execute_statement;
		}
	} else {
		*affected_rows=0;
		//*resultset=new SQLite3_result(statement);
		ret=true;
	}
__exit_execute_statement:
	// NOTE: the caller MUST call (*proxy_sqlite3_finalize)()
	//(*proxy_sqlite3_finalize)(statement);
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
	if((*proxy_sqlite3_prepare_v2)(db, buff, -1, &statement, 0) != SQLITE_OK) {
	  proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on (*proxy_sqlite3_prepare_v2)() running query \"%s\" : %s\n", buff, (*proxy_sqlite3_errmsg)(db));
	  (*proxy_sqlite3_finalize)(statement);
	  free(buff);
	  assert(0);
	}
	int result=0;
	while ((result=(*proxy_sqlite3_step)(statement))==SQLITE_ROW) {
	  count+=(*proxy_sqlite3_column_int)(statement,0);
	}
	(*proxy_sqlite3_finalize)(statement);
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
	pthread_rwlock_rdlock(&rwlock);
}

void SQLite3DB::rdunlock() {
	pthread_rwlock_unlock(&rwlock);
}

void SQLite3DB::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void SQLite3DB::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
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

void SQLite3_result::dump_to_stderr() {
	if (columns == 0) return;
	size_t *columns_lengths = (size_t *)malloc(sizeof(size_t)*columns);

	int i = 0;
	for (i = 0; i<columns; i++) {
		columns_lengths[i] = 0;
	}
	i = 0;
	for (std::vector<SQLite3_column *>::iterator it=column_definition.begin() ; it!=column_definition.end(); ++it) {
		SQLite3_column *r=*it;
		size_t len = strlen(r->name);
		if (len > columns_lengths[i]) {
			columns_lengths[i] = len;
			i++;
		}
	}
	for (std::vector<SQLite3_row *>::iterator it=rows.begin() ; it!=rows.end(); ++it) {
		SQLite3_row *r=*it;
		for (int i=0; i<columns;i++) {
			if (r->fields[i]) {
				if ((unsigned int)r->sizes[i] > columns_lengths[i]) {
					columns_lengths[i] = r->sizes[i];
				}
			} else {
				if (columns_lengths[i] < 4) {
					columns_lengths[i] = 4; // NULL
				}
			}
		}
	}
	string s;
	s = "+";
	for (i=0; i<columns; i++) {
		unsigned int j;
		for (j=0; j < columns_lengths[i] + 2; j++) {
			s.append("-");
		}
		s.append("+");
	}
	fprintf(stderr,"%s\n",s.c_str());
	s = "|";
	i = 0;
	for (std::vector<SQLite3_column *>::iterator it=column_definition.begin() ; it!=column_definition.end(); ++it) {
		SQLite3_column *r=*it;
		size_t len = strlen(r->name);
		s.append(" ");
		s.append(r->name);
		unsigned int j;
		for (j=0; j < columns_lengths[i] - len + 1 ; j++) {
			s.append(" ");
		}
		s.append("|");
		i++;
	}
	fprintf(stderr,"%s\n",s.c_str());
	s = "+";
	for (i=0; i<columns; i++) {
		unsigned int j;
		for (j=0; j < columns_lengths[i] + 2 ; j++) {
			s.append("-");
		}
		s.append("+");
	}
	fprintf(stderr,"%s\n",s.c_str());

	for (std::vector<SQLite3_row *>::iterator it=rows.begin() ; it!=rows.end(); ++it) {
		SQLite3_row *r=*it;
		s = "|";
		i = 0;
		for (int i=0; i<columns;i++) {
			s.append(" ");
			int len = 0;
			if (r->fields[i]) {
				len = r->sizes[i];
				s.append(r->fields[i]);
			} else {
				len = 4;
				s.append("NULL");
			}
			unsigned int j;
			for (j=0; j < columns_lengths[i] - len + 1 ; j++) {
				s.append(" ");
			}
			s.append("|");
		}
		fprintf(stderr,"%s\n",s.c_str());
	}

	s = "+";
	for (i=0; i<columns; i++) {
		unsigned int j;
		for (j=0; j < columns_lengths[i] + 2 ; j++) {
			s.append("-");
		}
		s.append("+");
	}
	fprintf(stderr,"%s\n",s.c_str());
	free(columns_lengths);
}

SQLite3_result::SQLite3_result(SQLite3_result *src) {
	enabled_mutex = false; // default
	rows_count=0;
	columns=src->columns;
	if (src->enabled_mutex) {
		pthread_mutex_init(&m,NULL);
		enabled_mutex = true;
	} else {
		enabled_mutex = false;
	}
	for (std::vector<SQLite3_column *>::iterator it = src->column_definition.begin() ; it != src->column_definition.end(); ++it) {
		SQLite3_column *r=*it;
		add_column_definition(SQLITE_TEXT,r->name);
	}
	for (std::vector<SQLite3_row *>::iterator it = src->rows.begin() ; it != src->rows.end(); ++it) {
		SQLite3_row *r=*it;
		add_row(r);
	}
}

unsigned long long SQLite3_result::get_size() {
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
}

void SQLite3_result::add_column_definition(int a, const char *b) {
	SQLite3_column *cf=new SQLite3_column(a,b);
	column_definition.push_back(cf);
}

int SQLite3_result::add_row(sqlite3_stmt *stmt, bool skip) {
	int rc=(*proxy_sqlite3_step)(stmt);
	if (rc!=SQLITE_ROW) return rc;
	if (skip==false) {
		SQLite3_row *row=new SQLite3_row(columns);
		row->add_fields(stmt);
		rows.push_back(row);
		rows_count++;
	}
	return SQLITE_ROW;
}

int SQLite3_result::add_row(char **_fields) {
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
}

/**
 * @brief Adds a new row to the resulset using a NULL terminated variadic list of
 *  'const char*' as argument.
 *
 * NOTE: This function is unsafe, the final 'NULL' element should be supplied,
 * otherwise a segfault is likely to happen.
 *
 * @param _field Initial element of variadic arguments supplied.
 * @param ... Variadic NULL terminated list of 'const char*' holding the rest
 *  of fields to add.
 *
 * @return SQLITE_ROW
 */
int SQLite3_result::add_row(const char* _field, ...) {
	va_list ap;
	va_start(ap, _field);
	vector<const char*> fields {};

	while (_field) {
		fields.push_back(_field);
		_field = va_arg(ap, const char *);
	}

	va_end(ap);

	return this->add_row(const_cast<char**>(&fields[0]));
}

int SQLite3_result::add_row(SQLite3_row *old_row) {
	SQLite3_row *row=new SQLite3_row(columns);
	row->add_fields(old_row->fields);
	rows.push_back(row);
	rows_count++;
	return SQLITE_ROW;
}

SQLite3_result::SQLite3_result(sqlite3_stmt *stmt) {
	enabled_mutex = false; // default
	rows_count=0;
	columns=(*proxy_sqlite3_column_count)(stmt);
	for (int i=0; i<columns; i++) {
		add_column_definition((*proxy_sqlite3_column_type)(stmt,i), (*proxy_sqlite3_column_name)(stmt,i));
	}
	while (add_row(stmt)==SQLITE_ROW) {};
}

SQLite3_result::SQLite3_result(sqlite3_stmt *stmt, int * found_rows, unsigned int offset, unsigned int limit) {
	enabled_mutex = false; // default
	rows_count=0;
	int fr = 0;
	columns=(*proxy_sqlite3_column_count)(stmt);
	for (int i=0; i<columns; i++) {
		add_column_definition((*proxy_sqlite3_column_type)(stmt,i), (*proxy_sqlite3_column_name)(stmt,i));
	}
	int rc = SQLITE_ROW;
	if (offset > 0 || limit > 0) {
		while (offset > 0 && rc==SQLITE_ROW) {
			rc = add_row(stmt, true);
			if (rc == SQLITE_ROW) fr++;
			offset--;
		}
		while (limit > 0 && rc==SQLITE_ROW) {
			rc = add_row(stmt, false);
			if (rc == SQLITE_ROW) fr++;
			limit--;
		}
	} else {
		while (rc == SQLITE_ROW) {
			rc=add_row(stmt, false);
			if (rc == SQLITE_ROW) fr++;
		}
	}
	while (rc == SQLITE_ROW) {
		rc=add_row(stmt, true);
		if (rc == SQLITE_ROW) fr++;
	}
	*found_rows = fr;
}

SQLite3_result::SQLite3_result(int num_columns, bool en_mutex) {
	rows_count=0;
	columns=num_columns;
	if (en_mutex) {
		pthread_mutex_init(&m,NULL);
		enabled_mutex = true;
	} else {
		enabled_mutex = false;
	}
}

SQLite3_result::~SQLite3_result() {
	for (std::vector<SQLite3_column *>::iterator it = column_definition.begin() ; it != column_definition.end(); ++it) {
		SQLite3_column *c=*it;
		delete c;
	}
	for (std::vector<SQLite3_row *>::iterator it = rows.begin() ; it != rows.end(); ++it) {
		SQLite3_row *r=*it;
		delete r;
	}
}

SQLite3_result::SQLite3_result() {
	enabled_mutex = false; // default
	columns=0;
}

void SQLite3DB::LoadPlugin(const char *plugin_name) {
	proxy_sqlite3_config = NULL;
	proxy_sqlite3_bind_double = NULL;
	proxy_sqlite3_bind_int = NULL;
	proxy_sqlite3_bind_int64 = NULL;
	proxy_sqlite3_bind_null = NULL;
	proxy_sqlite3_bind_text = NULL;
	proxy_sqlite3_column_name = NULL;
	proxy_sqlite3_column_text = NULL;
	proxy_sqlite3_column_bytes = NULL;
	proxy_sqlite3_column_type = NULL;
	proxy_sqlite3_column_count = NULL;
	proxy_sqlite3_column_int = NULL;
	proxy_sqlite3_errmsg = NULL;
	proxy_sqlite3_finalize = NULL;
	proxy_sqlite3_reset = NULL;
	proxy_sqlite3_clear_bindings = NULL;
	proxy_sqlite3_close_v2 = NULL;
	proxy_sqlite3_get_autocommit = NULL;
	proxy_sqlite3_free = NULL;
	proxy_sqlite3_status = NULL;
	proxy_sqlite3_changes = NULL;
	proxy_sqlite3_step = NULL;
	proxy_sqlite3_shutdown = NULL;
	proxy_sqlite3_prepare_v2 = NULL;
	proxy_sqlite3_open_v2 = NULL;
	proxy_sqlite3_exec = NULL;
	if (plugin_name) {
		int fd = -1;
		fd = ::open(plugin_name, O_RDONLY);
		char binary_sha1_sqlite3[SHA_DIGEST_LENGTH*2+1];
		if(fd >= 0) {
			struct stat statbuf;
			if(fstat(fd, &statbuf) == 0) {
				unsigned char *fb = (unsigned char *)mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
				if (fb != MAP_FAILED) {
					unsigned char temp[SHA_DIGEST_LENGTH];
					SHA1(fb, statbuf.st_size, temp);
					memset(binary_sha1_sqlite3, 0, SHA_DIGEST_LENGTH*2+1);
					char buf[SHA_DIGEST_LENGTH*2];
					for (int i=0; i < SHA_DIGEST_LENGTH - 1; i++) {
						sprintf((char*)&(buf[i*2]), "%02x", temp[i]);
					}
					memcpy(binary_sha1_sqlite3, buf, SHA_DIGEST_LENGTH*2);
					munmap(fb,statbuf.st_size);
				} else {
					proxy_error("Unable to mmap %s: %s\n", plugin_name, strerror(errno));
				}
			} else {
				proxy_error("Unable to fstat %s: %s\n", plugin_name, strerror(errno));
			}
		} else {
			proxy_error("Unable to open %s: %s\n", plugin_name, strerror(errno));
		}

		close(fd);
		proxy_info("SQLite3 Plugin SHA1 checksum: %s\n", binary_sha1_sqlite3);

		dlerror();
		char * dlsym_error = NULL;
		dlerror();
		dlsym_error=NULL;
		void * handle_sqlite3_plugin = dlopen(plugin_name, RTLD_NOW);
		if (!handle_sqlite3_plugin) {
			cerr << "Cannot load SQLite3 plugin from library: " << dlerror() << '\n';
			exit(EXIT_FAILURE);
		} else {
			dlerror();
			int (*proxy_load_sqlite3)();
			proxy_load_sqlite3 = (int (*)()) dlsym(handle_sqlite3_plugin, "proxy_load_sqlite3"); dlsym_error = dlerror();
			if (dlsym_error!=NULL) { cerr << "Cannot load symbol proxy_load_sqlite3: " << dlsym_error << '\n'; exit(EXIT_FAILURE); }
			(*proxy_load_sqlite3)();
		}
		if (handle_sqlite3_plugin==NULL || dlsym_error) {
			proxy_error("Unable to load SQLite3 plugin from %s\n", plugin_name);
			exit(EXIT_FAILURE);
		}
		proxy_info("Loaded SQLite3 from plugin\n");
	} else {
		proxy_sqlite3_config = sqlite3_config;
		proxy_sqlite3_bind_double = sqlite3_bind_double;
		proxy_sqlite3_bind_int = sqlite3_bind_int;
		proxy_sqlite3_bind_int64 = sqlite3_bind_int64;
		proxy_sqlite3_bind_null = sqlite3_bind_null;
		proxy_sqlite3_bind_text = sqlite3_bind_text;
		proxy_sqlite3_column_name = sqlite3_column_name;
		proxy_sqlite3_column_text = sqlite3_column_text;
		proxy_sqlite3_column_bytes = sqlite3_column_bytes;
		proxy_sqlite3_column_type = sqlite3_column_type;
		proxy_sqlite3_column_count = sqlite3_column_count;
		proxy_sqlite3_column_int = sqlite3_column_int;
		proxy_sqlite3_errmsg = sqlite3_errmsg;
		proxy_sqlite3_finalize = sqlite3_finalize;
		proxy_sqlite3_reset = sqlite3_reset;
		proxy_sqlite3_clear_bindings = sqlite3_clear_bindings;
		proxy_sqlite3_close_v2 = sqlite3_close_v2;
		proxy_sqlite3_get_autocommit = sqlite3_get_autocommit;
		proxy_sqlite3_free = sqlite3_free;
		proxy_sqlite3_status = sqlite3_status;
		proxy_sqlite3_changes = sqlite3_changes;
		proxy_sqlite3_step = sqlite3_step;
		proxy_sqlite3_shutdown = sqlite3_shutdown;
		proxy_sqlite3_prepare_v2 = sqlite3_prepare_v2;
		proxy_sqlite3_open_v2 = sqlite3_open_v2;
		proxy_sqlite3_exec = sqlite3_exec;
		proxy_info("Loaded built-in SQLite3\n");
	}
	assert(proxy_sqlite3_config);
	assert(proxy_sqlite3_bind_double);
	assert(proxy_sqlite3_bind_int);
	assert(proxy_sqlite3_bind_int64);
	assert(proxy_sqlite3_bind_null);
	assert(proxy_sqlite3_bind_text);
	assert(proxy_sqlite3_column_name);
	assert(proxy_sqlite3_column_text);
	assert(proxy_sqlite3_column_bytes);
	assert(proxy_sqlite3_column_type);
	assert(proxy_sqlite3_column_count);
	assert(proxy_sqlite3_column_int);
	assert(proxy_sqlite3_errmsg);
	assert(proxy_sqlite3_finalize);
	assert(proxy_sqlite3_reset);
	assert(proxy_sqlite3_clear_bindings);
	assert(proxy_sqlite3_close_v2);
	assert(proxy_sqlite3_get_autocommit);
	assert(proxy_sqlite3_free);
	assert(proxy_sqlite3_status);
	assert(proxy_sqlite3_changes);
	assert(proxy_sqlite3_step);
	assert(proxy_sqlite3_shutdown);
	assert(proxy_sqlite3_prepare_v2);
	assert(proxy_sqlite3_open_v2);
	assert(proxy_sqlite3_exec);
	{
		/* moved here, so if needed by multiple modules it applies to all of them */
		int i=(*proxy_sqlite3_config)(SQLITE_CONFIG_URI, 1);
		if (i!=SQLITE_OK) {
			fprintf(stderr,"SQLITE: Error on (*proxy_sqlite3_config)(SQLITE_CONFIG_URI,1)\n");
			assert(i==SQLITE_OK);
			exit(EXIT_FAILURE);
		}
	}
}

