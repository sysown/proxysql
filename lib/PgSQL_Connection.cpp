
#include <fcntl.h>
#include <sstream>
#include <atomic>

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON
#include "PgSQL_HostGroups_Manager.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_PreparedStatement.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "MySQL_Variables.h"


#if 0
// some of the code that follows is from mariadb client library memory allocator
typedef int     myf;    // Type of MyFlags in my_funcs
#define MYF(v)      (myf) (v)
#define MY_KEEP_PREALLOC    1
#define MY_ALIGN(A,L)    (((A) + (L) - 1) & ~((L) - 1))
#define ALIGN_SIZE(A)    MY_ALIGN((A),sizeof(double))
static void ma_free_root(MA_MEM_ROOT *root, myf MyFLAGS);
static void *ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size);
#define MAX(a,b) (((a) > (b)) ? (a) : (b))


static void * ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size)
{
  size_t get_size;
  void * point;
  MA_USED_MEM *next= 0;
  MA_USED_MEM **prev;

  Size= ALIGN_SIZE(Size);

  if ((*(prev= &mem_root->free)))
  {
    if ((*prev)->left < Size &&
        mem_root->first_block_usage++ >= 16 &&
        (*prev)->left < 4096)
    {
      next= *prev;
      *prev= next->next;
      next->next= mem_root->used;
      mem_root->used= next;
      mem_root->first_block_usage= 0;
    }
    for (next= *prev; next && next->left < Size; next= next->next)
      prev= &next->next;
  }
  if (! next)
  {                     /* Time to alloc new block */
    get_size= MAX(Size+ALIGN_SIZE(sizeof(MA_USED_MEM)),
              (mem_root->block_size & ~1) * ( (mem_root->block_num >> 2) < 4 ? 4 : (mem_root->block_num >> 2) ) );

    if (!(next = (MA_USED_MEM*) malloc(get_size)))
    {
      if (mem_root->error_handler)
    (*mem_root->error_handler)();
      return((void *) 0);               /* purecov: inspected */
    }
    mem_root->block_num++;
    next->next= *prev;
    next->size= get_size;
    next->left= get_size-ALIGN_SIZE(sizeof(MA_USED_MEM));
    *prev=next;
  }
  point= (void *) ((char*) next+ (next->size-next->left));
  if ((next->left-= Size) < mem_root->min_malloc)
  {                     /* Full block */
    *prev=next->next;               /* Remove block from list */
    next->next=mem_root->used;
    mem_root->used=next;
    mem_root->first_block_usage= 0;
  }
  return(point);
}


static void ma_free_root(MA_MEM_ROOT *root, myf MyFlags)
{ 
  MA_USED_MEM *next,*old;

  if (!root)
    return; /* purecov: inspected */
  if (!(MyFlags & MY_KEEP_PREALLOC))
    root->pre_alloc=0;

  for ( next=root->used; next ;)
  {
    old=next; next= next->next ;
    if (old != root->pre_alloc)
      free(old);
  }
  for (next= root->free ; next ; )
  {
    old=next; next= next->next ;
    if (old != root->pre_alloc)
      free(old);
  }
  root->used=root->free=0;
  if (root->pre_alloc)
  {
    root->free=root->pre_alloc;
    root->free->left=root->pre_alloc->size-ALIGN_SIZE(sizeof(MA_USED_MEM));
    root->free->next=0;
  }
}
#endif // 0

extern char * binary_sha1;

#include "proxysql_find_charset.h"

void PgSQL_Variable::fill_server_internal_session(json &j, int conn_num, int idx) {
	if (idx == SQL_CHARACTER_SET_RESULTS || idx == SQL_CHARACTER_SET_CLIENT || idx == SQL_CHARACTER_SET_DATABASE) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value) {
			ci = proxysql_find_charset_name(mysql_tracked_variables[idx].default_value);
		} else if (strcasecmp("NULL", value) && strcasecmp("binary", value)) {
			ci = proxysql_find_charset_nr(atoi(value));
		}
		if (!ci) {
			if (idx == SQL_CHARACTER_SET_RESULTS && (!strcasecmp("NULL", value) || !strcasecmp("binary", value))) {
				if (!strcasecmp("NULL", value)) {
					j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = "";
				} else {
					j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = value;
				}
			} else {
				// LCOV_EXCL_START
				proxy_error("Cannot find charset [%s] for variables %d\n", value, idx);
				assert(0);
				// LCOV_EXCL_STOP
			}
		} else {
			j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = std::string((ci && ci->csname)?ci->csname:"");
		}
	} else if (idx == SQL_CHARACTER_SET_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value)
			ci = proxysql_find_charset_name(mysql_tracked_variables[idx].default_value);
		else
			ci = proxysql_find_charset_nr(atoi(value));

		j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = std::string((ci && ci->csname)?ci->csname:"");
	} else if (idx == SQL_COLLATION_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value)
			ci = proxysql_find_charset_collate(mysql_tracked_variables[idx].default_value);
		else
			ci = proxysql_find_charset_nr(atoi(value));

		j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = std::string((ci && ci->name)?ci->name:"");
/*
//	NOTE: it seems we treat SQL_LOG_BIN in a special way
//	it doesn't seem necessary
	} else if (idx == SQL_SQL_LOG_BIN) {
		if (!value)
			j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = mysql_tracked_variables[idx].default_value;
		else
			j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = std::string(!strcmp("1",value)?"ON":"OFF");
*/
	} else {
		j["backends"][conn_num]["conn"][mysql_tracked_variables[idx].internal_variable_name] = std::string(value?value:"");
	}
}

void PgSQL_Variable::fill_client_internal_session(json &j, int idx) {
	if (idx == SQL_CHARACTER_SET_RESULTS || idx == SQL_CHARACTER_SET_CLIENT || idx == SQL_CHARACTER_SET_DATABASE) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value) {
			ci = proxysql_find_charset_name(mysql_tracked_variables[idx].default_value);
		} else if (strcasecmp("NULL", value) && strcasecmp("binary", value)) {
			ci = proxysql_find_charset_nr(atoi(value));
		}
		if (!ci) {
			if (idx == SQL_CHARACTER_SET_RESULTS && (!strcasecmp("NULL", value) || !strcasecmp("binary", value))) {
				if (!strcasecmp("NULL", value)) {
					j["conn"][mysql_tracked_variables[idx].internal_variable_name] = "";
				} else {
					j["conn"][mysql_tracked_variables[idx].internal_variable_name] = value;
				}
			} else {
				// LCOV_EXCL_START
				proxy_error("Cannot find charset [%s] for variables %d\n", value, idx);
				assert(0);
				// LCOV_EXCL_STOP
			}
		} else {
			j["conn"][mysql_tracked_variables[idx].internal_variable_name] = (ci && ci->csname)?ci->csname:"";
		}
	} else if (idx == SQL_CHARACTER_SET_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value)
			ci = proxysql_find_charset_collate(mysql_tracked_variables[idx].default_value);
		else
			ci = proxysql_find_charset_nr(atoi(value));
		j["conn"][mysql_tracked_variables[idx].internal_variable_name] = (ci && ci->csname)?ci->csname:"";
	} else if (idx == SQL_COLLATION_CONNECTION) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		if (!value)
			ci = proxysql_find_charset_collate(mysql_tracked_variables[idx].default_value);
		else
			ci = proxysql_find_charset_nr(atoi(value));
		j["conn"][mysql_tracked_variables[idx].internal_variable_name] = (ci && ci->name)?ci->name:"";
/*
//	NOTE: it seems we treat SQL_LOG_BIN in a special way
//	it doesn't seem necessary
	}  else if (idx == SQL_LOG_BIN) {
		if (!value)
			j["conn"][mysql_tracked_variables[idx].internal_variable_name] = mysql_tracked_variables[idx].default_value;
		else
			j["conn"][mysql_tracked_variables[idx].internal_variable_name] = !strcmp("1", value)?"ON":"OFF";
*/
	} else {
		j["conn"][mysql_tracked_variables[idx].internal_variable_name] = value?value:"";
	}
}

static int
mysql_status(short event, short cont) {
	int status= 0;
	if (event & POLLIN)
		status|= MYSQL_WAIT_READ;
	if (event & POLLOUT)
		status|= MYSQL_WAIT_WRITE;
//	if (event==0 && cont==true) {
//		status |= MYSQL_WAIT_TIMEOUT;
//	}
//	FIXME: handle timeout
//	if (event & PROXY_TIMEOUT)
//		status|= MYSQL_WAIT_TIMEOUT;
	return status;
}

/* deprecating session_vars[] because we are introducing a better algorithm
// Defining list of session variables for comparison with query digest to disable multiplexing for "SET <variable_name>" commands
static char * session_vars[]= {
	// For issue #555 , multiplexing is disabled if --safe-updates is used
	//(char *)"SQL_SAFE_UPDATES=?,SQL_SELECT_LIMIT=?,MAX_JOIN_SIZE=?",
	// for issue #1832 , we are splitting the above into 3 variables
//	(char *)"SQL_SAFE_UPDATES",
//	(char *)"SQL_SELECT_LIMIT",
//	(char *)"MAX_JOIN_SIZE",
	(char *)"FOREIGN_KEY_CHECKS",
	(char *)"UNIQUE_CHECKS",
	(char *)"AUTO_INCREMENT_INCREMENT",
	(char *)"AUTO_INCREMENT_OFFSET",
	(char *)"TIMESTAMP",
	(char *)"GROUP_CONCAT_MAX_LEN"
};
*/

PgSQL_Connection_userinfo::PgSQL_Connection_userinfo() {
	username=NULL;
	password=NULL;
	sha1_pass=NULL;
	dbname=NULL;
	fe_username=NULL;
	hash=0;
}

PgSQL_Connection_userinfo::~PgSQL_Connection_userinfo() {
	if (username) free(username);
	if (fe_username) free(fe_username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (dbname) free(dbname);
}

void PgSQL_Connection_Placeholder::compute_unknown_transaction_status() {
	if (pgsql) {
		int _myerrno=mysql_errno(pgsql);
		if (_myerrno == 0) {
			unknown_transaction_status = false; // no error
			return;
		}
		if (_myerrno >= 2000 && _myerrno < 3000) { // client error
			// do not change it
			return;
		}
		if (_myerrno >= 1000 && _myerrno < 2000) { // server error
			unknown_transaction_status = true;
			return;
		}
		if (_myerrno >= 3000 && _myerrno < 4000) { // server error
			unknown_transaction_status = true;
			return;
		}
		// all other cases, server error
	}
}

uint64_t PgSQL_Connection_userinfo::compute_hash() {
	int l=0;
	if (username)
		l+=strlen(username);
	if (password)
		l+=strlen(password);
	if (dbname)
		l+=strlen(dbname);
// two random seperator
#define _COMPUTE_HASH_DEL1_	"-ujhtgf76y576574fhYTRDF345wdt-"
#define _COMPUTE_HASH_DEL2_	"-8k7jrhtrgJHRgrefgreyhtRFewg6-"
	l+=strlen(_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	char *buf=(char *)malloc(l+1);
	l=0;
	if (username) {
		strcpy(buf+l,username);
		l+=strlen(username);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL1_);
	if (password) {
		strcpy(buf+l,password);
		l+=strlen(password);
	}
	if (dbname) {
		strcpy(buf+l, dbname);
		l+=strlen(dbname);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL2_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	hash=SpookyHash::Hash64(buf,l,0);
	free(buf);
	return hash;
}

void PgSQL_Connection_userinfo::set(char *user, char *pass, char *db, char *sh1) {
	if (user) {
		if (username) {
			if (strcmp(user,username)) {
				free(username);
				username=strdup(user);
			}
		} else {
			username=strdup(user);
		}
	}
	if (pass) {
		if (password) {
			if (strcmp(pass,password)) {
				free(password);
				password=strdup(pass);
			}
		} else {
			password=strdup(pass);
		}
	}
	if (db) {
		if (dbname) { 
			if (strcmp(db,dbname)) {
				free(dbname);
				dbname=strdup(db);
			}
		} else {
			dbname=strdup(db);
		}
	}
	if (sh1) {
		if (sha1_pass) {
			free(sha1_pass);
		}
		sha1_pass=strdup(sh1);
	}
	compute_hash();
}

void PgSQL_Connection_userinfo::set(PgSQL_Connection_userinfo *ui) {
	set(ui->username, ui->password, ui->dbname, ui->sha1_pass);
}

bool PgSQL_Connection_userinfo::set_dbname(const char* db) {
	assert(db);
	const int new_db_len = db ? strlen(db) : 0;
	const int old_db_len = dbname ? strlen(dbname) : 0;

	if (old_db_len == 0 ||
		old_db_len != new_db_len ||
		strncmp(db, dbname, new_db_len)) {
		if (dbname) {
			free(dbname);
		}
		dbname = (char*)malloc(new_db_len + 1);
		memcpy(dbname, db, new_db_len);
		dbname[new_db_len] = 0;
		compute_hash();
		return true;
	}
	return false;
}

PgSQL_Connection_Placeholder::PgSQL_Connection_Placeholder() {
	pgsql=NULL;
	async_state_machine=ASYNC_CONNECT_START;
	ret_mysql=NULL;
	send_quit=true;
	myds=NULL;
	inserted_into_pool=0;
	reusable=false;
	parent=NULL;
	userinfo=new PgSQL_Connection_userinfo();
	fd=-1;
	status_flags=0;
	last_time_used=0;

	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		variables[i].value = NULL;
		var_hash[i] = 0;
	}

	options.client_flag = 0;
	options.server_capabilities = 0;
	options.compression_min_length=0;
	options.server_version=NULL;
	options.last_set_autocommit=-1;	// -1 = never set
	options.autocommit=true;
	options.no_backslash_escapes=false;
	options.init_connect=NULL;
	options.init_connect_sent=false;
	options.session_track_gtids = NULL;
	options.session_track_gtids_sent = false;
	options.ldap_user_variable=NULL;
	options.ldap_user_variable_value=NULL;
	options.ldap_user_variable_sent=false;
	options.session_track_gtids_int=0;
	compression_pkt_id=0;
	mysql_result=NULL;
	query.ptr=NULL;
	query.length=0;
	query.stmt=NULL;
	query.stmt_meta=NULL;
	query.stmt_result=NULL;
	largest_query_length=0;
	warning_count=0;
	multiplex_delayed=false;
	MyRS=NULL;
	MyRS_reuse=NULL;
	unknown_transaction_status = false;
	creation_time=0;
	auto_increment_delay_token = 0;
	processing_multi_statement=false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new PgSQL_Connection %p\n", this);
	local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
	bytes_info.bytes_recv = 0;
	bytes_info.bytes_sent = 0;
	statuses.questions = 0;
	statuses.pgconnpoll_get = 0;
	statuses.pgconnpoll_put = 0;
	memset(gtid_uuid,0,sizeof(gtid_uuid));
	memset(&connected_host_details, 0, sizeof(connected_host_details));
};

PgSQL_Connection_Placeholder::~PgSQL_Connection_Placeholder() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying PgSQL_Connection %p\n", this);
	if (options.server_version) free(options.server_version);
	if (options.init_connect) free(options.init_connect);
	if (options.ldap_user_variable) free(options.ldap_user_variable);
	if (options.ldap_user_variable_value) free(options.ldap_user_variable_value);
	if (userinfo) {
		delete userinfo;
		userinfo=NULL;
	}
	if (local_stmts) {
		delete local_stmts;
	}
	if (pgsql) {
		// always decrease the counter
		if (ret_mysql) {
			__sync_fetch_and_sub(&PgHGM->status.server_connections_connected,1);
			if (query.stmt_result) {
				if (query.stmt_result->handle) {
					query.stmt_result->handle->status = MYSQL_STATUS_READY; // avoid calling mthd_my_skip_result()
				}
			}
			if (mysql_result) {
				if (mysql_result->handle) {
					mysql_result->handle->status = MYSQL_STATUS_READY; // avoid calling mthd_my_skip_result()
				}
			}
			async_free_result();
		}
		close_mysql(); // this take care of closing pgsql connection
		pgsql=NULL;
	}
	if (MyRS) {
		delete MyRS;
		MyRS = NULL;
	}
	if (MyRS_reuse) {
		delete MyRS_reuse;
		MyRS_reuse = NULL;
	}
	if (query.stmt) {
		query.stmt=NULL;
	}

	if (options.session_track_gtids) {
		free(options.session_track_gtids);
		options.session_track_gtids=NULL;
	}

	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
			var_hash[i] = 0;
		}
	}

	if (connected_host_details.hostname) {
		free(connected_host_details.hostname);
		connected_host_details.hostname = NULL;
	}
	if (connected_host_details.ip) {
		free(connected_host_details.ip);
		connected_host_details.hostname = NULL;
	}
};

bool PgSQL_Connection_Placeholder::set_autocommit(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting autocommit %d\n", _ac);
	options.autocommit=_ac;
	return _ac;
}

bool PgSQL_Connection_Placeholder::set_no_backslash_escapes(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting no_backslash_escapes %d\n", _ac);
	options.no_backslash_escapes=_ac;
	return _ac;
}

void print_backtrace(void);

unsigned int PgSQL_Connection_Placeholder::set_charset(unsigned int _c, enum pgsql_charset_action action) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting charset %d\n", _c);

	// SQL_CHARACTER_SET should be set befor setting SQL_CHRACTER_ACTION
	std::stringstream ss;
	ss << _c;
	pgsql_variables.client_set_value(myds->sess, SQL_CHARACTER_SET, ss.str());

	// When SQL_CHARACTER_ACTION is set character set variables are set according to
	// SQL_CHRACTER_SET value
	ss.str(std::string());
	ss.clear();
	ss << action;
	pgsql_variables.client_set_value(myds->sess, SQL_CHARACTER_ACTION, ss.str());

	return _c;
}

void PgSQL_Connection_Placeholder::update_warning_count_from_connection() {
	// if a prepared statement was cached while 'mysql_thread_query_digest' was true, and subsequently, 
	// 'mysql_thread_query_digest' is set to false, fetching that statement from the cache may still contain the digest text.
	// To prevent this, we will check the digest text in conjunction with 'mysql_thread_query_digest' to verify whether it 
	// is enabled or disabled.
	if (myds && myds->sess && myds->sess->CurrentQuery.QueryParserArgs.digest_text) { 
		const char* dig_text = myds->sess->CurrentQuery.QueryParserArgs.digest_text;
		const size_t dig_len = strlen(dig_text);
		// SHOW WARNINGS doesn't have any impact warning count,
		// so we are replication same behaviour here
		if (parent->myhgc->handle_warnings_enabled() && 
			(dig_len != 13 || strncasecmp(dig_text, "SHOW WARNINGS", 13) != 0)) {
			warning_count = mysql_warning_count(pgsql);
		}
	}
}

void PgSQL_Connection_Placeholder::update_warning_count_from_statement() {
	// if a prepared statement was cached while 'mysql_thread_query_digest' was true, and subsequently, 
	// 'mysql_thread_query_digest' is set to false, fetching that statement from the cache may still contain the digest text.
	// To prevent this, we will check the digest text in conjunction with 'mysql_thread_query_digest' to verify whether it 
	// is enabled or disabled.
	if (myds && myds->sess && myds->sess->CurrentQuery.stmt_info && myds->sess->CurrentQuery.stmt_info->digest_text &&
		pgsql_thread___query_digests == true) {
		if (parent->myhgc->handle_warnings_enabled()) {
			warning_count = mysql_stmt_warning_count(query.stmt);
		}
	}
}

bool PgSQL_Connection_Placeholder::is_expired(unsigned long long timeout) {
// FIXME: here the check should be a sanity check
// FIXME: for now this is just a temporary (and stupid) check
	return false;
}

void PgSQL_Connection_Placeholder::set_status(bool set, uint32_t status_flag) {
	if (set) {
		this->status_flags |= status_flag;
	} else {
		this->status_flags &= ~status_flag;
	}
}

bool PgSQL_Connection_Placeholder::get_status(uint32_t status_flag) {
	return this->status_flags & status_flag;
}

#if 0
void PgSQL_Connection_Placeholder::set_status_sql_log_bin0(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	}
}

bool PgSQL_Connection_Placeholder::get_status_sql_log_bin0() {
	return status_flags & STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
}
#endif // 0

unsigned int PgSQL_Connection_Placeholder::reorder_dynamic_variables_idx() {
	dynamic_variables_idx.clear();
	// note that we are inserting the index already ordered
	for (auto i = SQL_NAME_LAST_LOW_WM + 1 ; i < SQL_NAME_LAST_HIGH_WM ; i++) {
		if (var_hash[i] != 0) {
			dynamic_variables_idx.push_back(i);
		}
	}
	unsigned int r = dynamic_variables_idx.size();
	return r;
}

unsigned int PgSQL_Connection_Placeholder::number_of_matching_session_variables(const PgSQL_Connection *client_conn, unsigned int& not_matching) {
	unsigned int ret=0;
	for (auto i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (client_conn->var_hash[i] && i != SQL_CHARACTER_ACTION) { // client has a variable set
			if (var_hash[i] == client_conn->var_hash[i]) { // server conection has the variable set to the same value
				ret++;
			} else {
				not_matching++;
			}
		}
	}
	// increse not_matching y the sum of client and server variables
	// when a match is found the counter will be reduced by 2
	not_matching += client_conn->dynamic_variables_idx.size();
	not_matching += dynamic_variables_idx.size();
	std::vector<uint32_t>::const_iterator it_c = client_conn->dynamic_variables_idx.begin(); // client connection iterator
	std::vector<uint32_t>::const_iterator it_s = dynamic_variables_idx.begin();              // server connection iterator
	for ( ; it_c != client_conn->dynamic_variables_idx.end() && it_s != dynamic_variables_idx.end() ; it_c++) {
		while (it_s != dynamic_variables_idx.end() && *it_s < *it_c) {
			it_s++;
		}
		if (it_s != dynamic_variables_idx.end()) {
			if (*it_s == *it_c) {
				if (var_hash[*it_s] == client_conn->var_hash[*it_c]) { // server conection has the variable set to the same value
					// when a match is found the counter is reduced by 2
					not_matching-=2;
					ret++;
				}
			}
		}
	}
	return ret;
}

#if 0
void PgSQL_Connection_Placeholder::initdb_start() {
	PROXY_TRACE();
	PgSQL_Connection_userinfo *client_ui=myds->sess->client_myds->myconn->userinfo;
	async_exit_status = mysql_select_db_start(&interr,pgsql,client_ui->dbname);
}

void PgSQL_Connection_Placeholder::initdb_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_select_db_cont(&interr,pgsql, mysql_status(event, true));
}

void PgSQL_Connection_Placeholder::set_option_start() {
	PROXY_TRACE();

	enum_mysql_set_option set_option;
	set_option=((options.client_flag & CLIENT_MULTI_STATEMENTS) ? MYSQL_OPTION_MULTI_STATEMENTS_ON : MYSQL_OPTION_MULTI_STATEMENTS_OFF);
	async_exit_status = mysql_set_server_option_start(&interr,pgsql,set_option);
}

void PgSQL_Connection_Placeholder::set_option_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_server_option_cont(&interr,pgsql, mysql_status(event, true));
}

void PgSQL_Connection_Placeholder::set_autocommit_start() {
	PROXY_TRACE();
	async_exit_status = mysql_autocommit_start(&ret_bool, pgsql, options.autocommit);
}

void PgSQL_Connection_Placeholder::set_autocommit_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_autocommit_cont(&ret_bool, pgsql, mysql_status(event, true));
}
#endif // 0

void PgSQL_Connection_Placeholder::set_names_start() {
	PROXY_TRACE();
	const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(atoi(pgsql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
	if (!c) {
		// LCOV_EXCL_START
		proxy_error("Not existing charset number %u\n", atoi(pgsql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
		assert(0);
		// LCOV_EXCL_STOP
	}
	async_exit_status = mysql_set_character_set_start(&interr,pgsql, NULL, atoi(pgsql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
}

void PgSQL_Connection_Placeholder::set_names_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_character_set_cont(&interr,pgsql, mysql_status(event, true));
}

void PgSQL_Connection_Placeholder::set_query(char *stmt, unsigned long length) {
	query.length=length;
	query.ptr=stmt;
	if (length > largest_query_length) {
		largest_query_length=length;
	}
	if (query.stmt) {
		query.stmt=NULL;
	}
}

void PgSQL_Connection_Placeholder::stmt_prepare_start() {
	PROXY_TRACE();
	query.stmt=mysql_stmt_init(pgsql);
	my_bool my_arg=true;
	mysql_stmt_attr_set(query.stmt, STMT_ATTR_UPDATE_MAX_LENGTH, &my_arg);
	async_exit_status = mysql_stmt_prepare_start(&interr , query.stmt, query.ptr, query.length);
}

void PgSQL_Connection_Placeholder::stmt_prepare_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_prepare_cont(&interr , query.stmt , mysql_status(event, true));
}

void PgSQL_Connection_Placeholder::stmt_execute_start() {
	PROXY_TRACE();
	int _rc=0;
	assert(query.stmt->mysql); // if we reached here, we hit bug #740
	_rc=mysql_stmt_bind_param(query.stmt, query.stmt_meta->binds); // FIXME : add error handling
	if (_rc) {
		proxy_error("mysql_stmt_bind_param() failed: %s", mysql_stmt_error(query.stmt));
	}
	// if for whatever reason the previous execution failed, state is left to an inconsistent value
	// see bug #3547
	// here we force the state to be MYSQL_STMT_PREPARED
	// it is a nasty hack because we shouldn't change states that should belong to the library
	// I am not sure if this is a bug in the backend library or not
	query.stmt->state= MYSQL_STMT_PREPARED;
	async_exit_status = mysql_stmt_execute_start(&interr , query.stmt);
}

void PgSQL_Connection_Placeholder::stmt_execute_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_execute_cont(&interr , query.stmt , mysql_status(event, true));
}

void PgSQL_Connection_Placeholder::stmt_execute_store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_stmt_store_result_start(&interr, query.stmt);
}

void PgSQL_Connection_Placeholder::stmt_execute_store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_store_result_cont(&interr , query.stmt , mysql_status(event, true));
}

#ifndef PROXYSQL_USE_RESULT
void PgSQL_Connection_Placeholder::store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_store_result_start(&mysql_result, pgsql);
}

void PgSQL_Connection_Placeholder::store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_store_result_cont(&mysql_result , pgsql , mysql_status(event, true));
}
#endif // PROXYSQL_USE_RESULT

void PgSQL_Connection_Placeholder::set_is_client() {
	//-- local_stmts->set_is_client(myds->sess);
}

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

#if 0
void PgSQL_Connection_Placeholder::process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT(unsigned long long& processed_bytes) {
	PROXY_TRACE2();
	// there is more than 1 row
	unsigned long long total_size=0;
	long long unsigned int irs = 0;
	MYSQL_ROWS *ir = query.stmt->result.data;
	for (irs = 0; irs < query.stmt->result.rows -1 ; irs++) {
		// while iterating the rows we also count the bytes
		total_size+=ir->length;
		if (ir->length > 0xFFFFFF) {
			total_size+=(ir->length / 0xFFFFFF) * sizeof(mysql_hdr);
		}
		total_size+=sizeof(mysql_hdr);
		// add the row to the resulset
		unsigned int br=MyRS->add_row(ir);
		// increment counters for the bytes processed
		__sync_fetch_and_add(&parent->bytes_recv,br);
		myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv]+=br;
		myds->bytes_info.bytes_recv += br;
		bytes_info.bytes_recv += br;
		processed_bytes+=br;	// issue #527 : this variable will store the amount of bytes processed during this event

		// we stop when we 'ir->next' will be pointing to the last row
		if (irs <= query.stmt->result.rows - 2) {
			ir = ir->next;
		}
	}
	// at this point, ir points to the last row
	// next, we create a new MYSQL_ROWS that is a copy of the last row
	MYSQL_ROWS *lcopy = (MYSQL_ROWS *)malloc(sizeof(MYSQL_ROWS) + ir->length);
	lcopy->length = ir->length;
	lcopy->data= (MYSQL_ROW)(lcopy + 1);
	memcpy((char *)lcopy->data, (char *)ir->data, ir->length);
	// next we proceed to reset all the buffer

	// this invalidates the local variables inside the coroutines
	// pointing to the previous allocated memory for 'stmt->result'.
	// For more context see: #3324
	ma_free_root(&query.stmt->result.alloc, MYF(MY_KEEP_PREALLOC));
	query.stmt->result.data= NULL;
	query.stmt->result_cursor= NULL;
	query.stmt->result.rows = 0;

	// we will now copy back the last row and make it the only row available
	MYSQL_ROWS *current = (MYSQL_ROWS *)ma_alloc_root(&query.stmt->result.alloc, sizeof(MYSQL_ROWS) + lcopy->length);
	current->data= (MYSQL_ROW)(current + 1);
	// update 'stmt->result.data' to the new allocated memory and copy the backed last row
	query.stmt->result.data = current;
	memcpy((char *)current->data, (char *)lcopy->data, lcopy->length);
	// update the 'current->length' with the length of the copied row
	current->length = lcopy->length;

	// we free the copy
	free(lcopy);
	// change the rows count to 1
	query.stmt->result.rows = 1;
	// we should also configure the cursor, but because we scan it using our own
	// algorithm, this is not needed

	// now we update bytes counter
	__sync_fetch_and_add(&parent->bytes_recv,total_size);
	myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv]+=total_size;
	myds->bytes_info.bytes_recv += total_size;
	bytes_info.bytes_recv += total_size;
}

int PgSQL_Connection_Placeholder::async_set_autocommit(short event, bool ac) {
	PROXY_TRACE();
	assert(pgsql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			return -1;
			break;
		case ASYNC_QUERY_END:
		case ASYNC_IDLE:
			set_autocommit(ac);
			async_state_machine=ASYNC_SET_AUTOCOMMIT_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}
#endif // 0

int PgSQL_Connection_Placeholder::async_set_names(short event, unsigned int c) {
	PROXY_TRACE();
	assert(pgsql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_NAMES_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			/* useless statement. should be removed after thorough testing */
			//set_charset(c, CONNECT_START);
			async_state_machine=ASYNC_SET_NAMES_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_NAMES_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int PgSQL_Connection_Placeholder::async_set_option(short event, bool mask) {
	PROXY_TRACE();
	assert(pgsql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
		case ASYNC_SET_OPTION_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_OPTION_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			if (mask)
				options.client_flag |= CLIENT_MULTI_STATEMENTS;
			else
				options.client_flag &= ~CLIENT_MULTI_STATEMENTS;
			async_state_machine=ASYNC_SET_OPTION_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_OPTION_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_OPTION_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

void PgSQL_Connection_Placeholder::async_free_result() {
	PROXY_TRACE();
	assert(pgsql);
	//assert(ret_mysql);
	//assert(async_state_machine==ASYNC_QUERY_END);
	if (query.ptr) {
		query.ptr=NULL;
		query.length=0;
	}
	if (query.stmt_result) {
		mysql_free_result(query.stmt_result);
		query.stmt_result=NULL;
	}
	if (userinfo) {
		// if userinfo is NULL , the connection is being destroyed
		// because it is reset on destructor ( ~PgSQL_Connection() )
		// therefore this section is skipped completely
		// this should prevent bug #1046
		if (query.stmt) {
			if (query.stmt->mysql) {
				if (query.stmt->mysql == pgsql) { // extra check
					mysql_stmt_free_result(query.stmt);
				}
			}
			// If we reached here from 'ASYNC_STMT_PREPARE_FAILED', the
			// prepared statement was never added to 'local_stmts', thus
			// it will never be freed when 'local_stmts' are purged. If
			// initialized, it must be freed. For more context see #3525.
			if (this->async_state_machine == ASYNC_STMT_PREPARE_FAILED) {
				if (query.stmt != NULL) {
					proxy_mysql_stmt_close(query.stmt);
				}
			}
			query.stmt=NULL;
		}
		if (mysql_result) {
			mysql_free_result(mysql_result);
			mysql_result=NULL;
		}
	}
	compute_unknown_transaction_status();
	async_state_machine=ASYNC_IDLE;
	if (MyRS) {
		if (MyRS_reuse) {
			delete (MyRS_reuse);
		}
		MyRS_reuse = MyRS;
		MyRS=NULL;
	}
}

// This function check if autocommit=0 and if there are any savepoint.
// this is an attempt to mitigate MySQL bug https://bugs.pgsql.com/bug.php?id=107875
bool PgSQL_Connection_Placeholder::AutocommitFalse_AndSavepoint() {
	bool ret=false;
	if (IsAutoCommit() == false) {
		if (get_status(STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT) == true) {
			ret = true;
		}
	}
	return ret;
}

bool PgSQL_Connection_Placeholder::IsAutoCommit() {
	bool ret=false;
	if (pgsql) {
		ret = (pgsql->server_status & SERVER_STATUS_AUTOCOMMIT);
		if (ret) {
			if (options.last_set_autocommit==0) {
				// it seems we hit bug http://bugs.pgsql.com/bug.php?id=66884
				// we last sent SET AUTOCOMMIT = 0 , but the server says it is 1
				// we assume that what we sent last is correct .  #873
				ret = false;
			}
		} else {
			if (options.last_set_autocommit==-1) {
				// if a connection was reset (thus last_set_autocommit==-1)
				// the information related to SERVER_STATUS_AUTOCOMMIT is lost
				// therefore we fall back on the safe assumption that autocommit==1
				ret = true;
			}
		}
	}
	return ret;
}

bool PgSQL_Connection_Placeholder::MultiplexDisabled(bool check_delay_token) {
// status_flags stores information about the status of the connection
// can be used to determine if multiplexing can be enabled or not
	bool ret=false;
	if (status_flags & (STATUS_MYSQL_CONNECTION_USER_VARIABLE | STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT |
		STATUS_MYSQL_CONNECTION_LOCK_TABLES | STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE | STATUS_MYSQL_CONNECTION_GET_LOCK | STATUS_MYSQL_CONNECTION_NO_MULTIPLEX |
		STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0 | STATUS_MYSQL_CONNECTION_FOUND_ROWS | STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG |
		STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT | STATUS_MYSQL_CONNECTION_HAS_WARNINGS) ) {
		ret=true;
	}
	if (check_delay_token && auto_increment_delay_token) return true;
	return ret;
}

bool PgSQL_Connection_Placeholder::IsKeepMultiplexEnabledVariables(char *query_digest_text) {
	if (query_digest_text==NULL) return true;

	char *query_digest_text_filter_select = NULL;
	unsigned long query_digest_text_len=strlen(query_digest_text);
	if (strncasecmp(query_digest_text,"SELECT ",strlen("SELECT "))==0){
		query_digest_text_filter_select=(char*)malloc(query_digest_text_len-7+1);
		memcpy(query_digest_text_filter_select,&query_digest_text[7],query_digest_text_len-7);
		query_digest_text_filter_select[query_digest_text_len-7]='\0';
	} else {
		return false;
	}
	//filter @@session., @@local. and @@
	char *match=NULL;
	char* last_pos=NULL;
	const int at_session_offset = strlen("@@session.");
	const int at_local_offset = strlen("@@local."); // Alias of session
	const int double_at_offset = strlen("@@");
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select,"@@session."))) {
		memmove(match, match + at_session_offset, strlen(match) - at_session_offset);
		last_pos = match + strlen(match) - at_session_offset;
		*last_pos = '\0';
	}
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select, "@@local."))) {
		memmove(match, match + at_local_offset, strlen(match) - at_local_offset);
		last_pos = match + strlen(match) - at_local_offset;
		*last_pos = '\0';
	}
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select,"@@"))) {
		memmove(match, match + double_at_offset, strlen(match) - double_at_offset);
		last_pos = match + strlen(match) - double_at_offset;
		*last_pos = '\0';
	}

	std::vector<char*>query_digest_text_filter_select_v;
	char* query_digest_text_filter_select_tok = NULL;
	char* save_query_digest_text_ptr = NULL;
	if (query_digest_text_filter_select) {
		query_digest_text_filter_select_tok = strtok_r(query_digest_text_filter_select, ",", &save_query_digest_text_ptr);
	}
	while(query_digest_text_filter_select_tok){
		//filter "as"/space/alias,such as select @@version as a, @@version b
		while (1){
			char c = *query_digest_text_filter_select_tok;
			if (!isspace(c)){
				break;
			}
			query_digest_text_filter_select_tok++;
		}
		char* match_as;
		match_as=strcasestr(query_digest_text_filter_select_tok," ");
		if(match_as){
			query_digest_text_filter_select_tok[match_as-query_digest_text_filter_select_tok]='\0';
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}else{
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}
		query_digest_text_filter_select_tok=strtok_r(NULL, ",", &save_query_digest_text_ptr);
	}

	std::vector<char*>keep_multiplexing_variables_v;
	char* keep_multiplexing_variables_tmp;
	char* save_keep_multiplexing_variables_ptr = NULL;
	unsigned long keep_multiplexing_variables_len=strlen(pgsql_thread___keep_multiplexing_variables);
	keep_multiplexing_variables_tmp=(char*)malloc(keep_multiplexing_variables_len+1);
	memcpy(keep_multiplexing_variables_tmp, pgsql_thread___keep_multiplexing_variables, keep_multiplexing_variables_len);
	keep_multiplexing_variables_tmp[keep_multiplexing_variables_len]='\0';
	char* keep_multiplexing_variables_tok=strtok_r(keep_multiplexing_variables_tmp, " ,", &save_keep_multiplexing_variables_ptr);
	while (keep_multiplexing_variables_tok){
		keep_multiplexing_variables_v.push_back(keep_multiplexing_variables_tok);
		keep_multiplexing_variables_tok=strtok_r(NULL, " ,", &save_keep_multiplexing_variables_ptr);
	}

	for (std::vector<char*>::iterator it=query_digest_text_filter_select_v.begin();it!=query_digest_text_filter_select_v.end();it++){
		bool is_match=false;
		for (std::vector<char*>::iterator it1=keep_multiplexing_variables_v.begin();it1!=keep_multiplexing_variables_v.end();it1++){
			//printf("%s,%s\n",*it,*it1);
			if (strncasecmp(*it,*it1,strlen(*it1))==0){
				is_match=true;
				break;
			}
		}
		if(is_match){
			is_match=false;
			continue;
		}else{
			free(query_digest_text_filter_select);
			free(keep_multiplexing_variables_tmp);
			return false;
		}
	}
	free(query_digest_text_filter_select);
	free(keep_multiplexing_variables_tmp);
	return true;
}

void PgSQL_Connection_Placeholder::ProcessQueryAndSetStatusFlags(char *query_digest_text) {
	if (query_digest_text==NULL) return;
	// unknown what to do with multiplex
	int mul=-1;
	if (myds) {
		if (myds->sess) {
			if (myds->sess->qpo) {
				mul=myds->sess->qpo->multiplex;
				if (mul==0) {
					set_status(true, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX);
				} else {
					if (mul==1) {
						set_status(false, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX);
					}
				}
			}
		}
	}
	// checking warnings and disabling multiplexing will be effective only when the pgsql-query_digests is enabled
	if (get_status(STATUS_MYSQL_CONNECTION_HAS_WARNINGS) == false) {
		if (warning_count > 0) {
			// 'warning_in_hg' will be used if the next query is 'SHOW WARNINGS' or
			// 'SHOW COUNT(*) WARNINGS'
			if (myds && myds->sess)
				myds->sess->warning_in_hg = myds->sess->current_hostgroup;
			// enabling multiplexing
			set_status(true, STATUS_MYSQL_CONNECTION_HAS_WARNINGS);
		}
	} else { // reset warning_in_hg 
		const char* dig = query_digest_text;
		const size_t dig_len = strlen(dig);
		// disable multiplexing and reset the 'warning_in_hg' flag only when the current executed query is not 
		// 'SHOW WARNINGS' or 'SHOW COUNT(*) WARNINGS', as these queries do not clear the warning message list
		// on backend.
		if (!((dig_len == 22 && strncasecmp(dig, "SHOW COUNT(*) WARNINGS", 22) == 0) ||
			(dig_len == 13 && strncasecmp(dig, "SHOW WARNINGS", 13) == 0))) {
			if (myds && myds->sess)
				myds->sess->warning_in_hg = -1;
			warning_count = 0;
			// disabling multiplexing
			set_status(false, STATUS_MYSQL_CONNECTION_HAS_WARNINGS);
		}
	}
	
	if (get_status(STATUS_MYSQL_CONNECTION_USER_VARIABLE)==false) { // we search for variables only if not already set
//			if (
//				strncasecmp(query_digest_text,"SELECT @@tx_isolation", strlen("SELECT @@tx_isolation"))
//				&&
//				strncasecmp(query_digest_text,"SELECT @@version", strlen("SELECT @@version"))
		if (strncasecmp(query_digest_text,"SET ",4)==0) {
			// For issue #555 , multiplexing is disabled if --safe-updates is used (see session_vars definition)
			int sqloh = pgsql_thread___set_query_lock_on_hostgroup;
			switch (sqloh) {
				case 0: // old algorithm
					if (mul!=2) {
						if (index(query_digest_text,'@')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
							if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
								set_status(true, STATUS_MYSQL_CONNECTION_USER_VARIABLE);
							}
/* deprecating session_vars[] because we are introducing a better algorithm
						} else {
							for (unsigned int i = 0; i < sizeof(session_vars)/sizeof(char *); i++) {
								if (strcasestr(query_digest_text,session_vars[i])!=NULL)  {
									set_status(true, STATUS_MYSQL_CONNECTION_USER_VARIABLE);
									break;
								}
							}
*/
						}
					}
					break;
				case 1: // new algorithm
					if (myds->sess->locked_on_hostgroup > -1) {
						// locked_on_hostgroup was set, so some variable wasn't parsed
						set_status(true, STATUS_MYSQL_CONNECTION_USER_VARIABLE);
					}
					break;
				default:
					break;
			}
		} else {
			if (mul!=2 && index(query_digest_text,'@')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
				if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
					set_status(true, STATUS_MYSQL_CONNECTION_USER_VARIABLE);
				}
			}
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT)==false) { // we search if prepared was already executed
		if (!strncasecmp(query_digest_text,"PREPARE ", strlen("PREPARE "))) {
			set_status(true, STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE)==false) { // we search for temporary if not already set
		if (!strncasecmp(query_digest_text,"CREATE TEMPORARY TABLE ", strlen("CREATE TEMPORARY TABLE "))) {
			set_status(true, STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_LOCK_TABLES)==false) { // we search for lock tables only if not already set
		if (!strncasecmp(query_digest_text,"LOCK TABLE", strlen("LOCK TABLE"))) {
			set_status(true, STATUS_MYSQL_CONNECTION_LOCK_TABLES);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_LOCK_TABLES)==false) { // we search for lock tables only if not already set
		if (!strncasecmp(query_digest_text,"FLUSH TABLES WITH READ LOCK", strlen("FLUSH TABLES WITH READ LOCK"))) { // issue 613
			set_status(true, STATUS_MYSQL_CONNECTION_LOCK_TABLES);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_LOCK_TABLES)==true) {
		if (!strncasecmp(query_digest_text,"UNLOCK TABLES", strlen("UNLOCK TABLES"))) {
			set_status(false, STATUS_MYSQL_CONNECTION_LOCK_TABLES);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_GET_LOCK)==false) { // we search for get_lock if not already set
		if (strcasestr(query_digest_text,"GET_LOCK(")) {
			set_status(true, STATUS_MYSQL_CONNECTION_GET_LOCK);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_FOUND_ROWS)==false) { // we search for SQL_CALC_FOUND_ROWS if not already set
		if (strcasestr(query_digest_text,"SQL_CALC_FOUND_ROWS")) {
			set_status(true, STATUS_MYSQL_CONNECTION_FOUND_ROWS);
		}
	}
	if (get_status(STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT)==false) {
		if (pgsql) {
			if (
				(pgsql->server_status & SERVER_STATUS_IN_TRANS)
				||
				((pgsql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0)
			) {
				if (!strncasecmp(query_digest_text,"SAVEPOINT ", strlen("SAVEPOINT "))) {
					set_status(true, STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT);
				}
			}
		}
	} else {
		if ( // get_status(STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT) == true
			(
				// make sure we don't have a transaction running
				// checking just for COMMIT and ROLLBACK is not enough, because `SET autocommit=1` can commit too
				(pgsql->server_status & SERVER_STATUS_AUTOCOMMIT)
				&&
				( (pgsql->server_status & SERVER_STATUS_IN_TRANS) == 0 )
			)
			||
			(strcasecmp(query_digest_text,"COMMIT") == 0)
			||
			(strcasecmp(query_digest_text,"ROLLBACK") == 0)
		) {
			set_status(false, STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT);
		}
	}
	if (pgsql) {
		if (myds && myds->sess) {
			if (myds->sess->client_myds && myds->sess->client_myds->myconn) {
				// if SERVER_STATUS_NO_BACKSLASH_ESCAPES is changed it is likely
				// because of sql_mode was changed
				// we set the same on the client connection
				unsigned int ss = pgsql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				myds->sess->client_myds->myconn->set_no_backslash_escapes(ss);
			}
		}
	}
}

void PgSQL_Connection_Placeholder::optimize() {
	if (pgsql->net.max_packet > 65536) { // FIXME: temporary, maybe for very long time . This needs to become a global variable
		if ( ( pgsql->net.buff == pgsql->net.read_pos ) &&  ( pgsql->net.read_pos == pgsql->net.write_pos ) ) {
			free(pgsql->net.buff);
			pgsql->net.max_packet=8192;
			pgsql->net.buff=(unsigned char *)malloc(pgsql->net.max_packet);
			memset(pgsql->net.buff,0,pgsql->net.max_packet);
			pgsql->net.read_pos=pgsql->net.buff;
			pgsql->net.write_pos=pgsql->net.buff;
			pgsql->net.buff_end=pgsql->net.buff+pgsql->net.max_packet;
		}
	}
}

// close_mysql() is a replacement for mysql_close()
// if avoids that a QUIT command stops forever
// FIXME: currently doesn't support encryption and compression
void PgSQL_Connection_Placeholder::close_mysql() {
	if ((send_quit) && (pgsql->net.pvio) && ret_mysql) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=pgsql->net.fd;
#ifdef __APPLE__
		int arg_on=1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
		send(fd, buff, 5, 0);
#else
		send(fd, buff, 5, MSG_NOSIGNAL);
#endif
	}
//	int rc=0;
	mysql_close_no_command(pgsql);
}


// this function is identical to async_query() , with the only exception that MyRS should never be set
int PgSQL_Connection_Placeholder::async_send_simple_command(short event, char *stmt, unsigned long length) {
	PROXY_TRACE();
	assert(pgsql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(parent->status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(parent->status==MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic==true && parent->shunned_and_kill_all_connections==true) // the server is SHUNNED due to a serious issue
	) {
		return -1;
	}
	switch (async_state_machine) {
		case ASYNC_QUERY_END:
			processing_multi_statement=false;	// no matter if we are processing a multi statement or not, we reached the end
			//return 0; <= bug. Do not return here, because we need to reach the if (async_state_machine==ASYNC_QUERY_END) few lines below
			break;
		case ASYNC_IDLE:
			set_query(stmt,length);
			async_state_machine=ASYNC_QUERY_START;
		default:
			handler(event);
			break;
	}
	if (MyRS) {
		// this is a severe mistake, we shouldn't have reach here
		// for now we do not assert but report the error
		// PMC-10003: Retrieved a resultset while running a simple command using async_send_simple_command() .
		// async_send_simple_command() is used by ProxySQL to configure the connection, thus it
		// shouldn't retrieve any resultset.
		// A common issue for triggering this error is to have configure pgsql-init_connect to
		// run a statement that returns a resultset.
		proxy_error2(10003, "PMC-10003: Retrieved a resultset while running a simple command. This is an error!! Simple command: %s\n", stmt);
		return -2;
	}
	if (async_state_machine==ASYNC_QUERY_END) {
		compute_unknown_transaction_status();
		if (mysql_errno(pgsql)) {
			return -1;
		} else {
			async_state_machine=ASYNC_IDLE;
			return 0;
		}
	}
	if (async_state_machine==ASYNC_NEXT_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to MySQL_Session
		processing_multi_statement=true;
		return 2;
	}
	if (processing_multi_statement==true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}
	return 1;
}

void PgSQL_Connection_Placeholder::reset() {
	bool old_no_multiplex_hg = get_status(STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
	bool old_compress = get_status(STATUS_MYSQL_CONNECTION_COMPRESSION);
	status_flags=0;
	// reconfigure STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG
	set_status(old_no_multiplex_hg,STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
	// reconfigure STATUS_MYSQL_CONNECTION_COMPRESSION
	set_status(old_compress,STATUS_MYSQL_CONNECTION_COMPRESSION);
	reusable=true;
	options.last_set_autocommit=-1; // never sent
	warning_count=0;
	delete local_stmts;
	local_stmts=new MySQL_STMTs_local_v14(false);
	creation_time = monotonic_time();

	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		var_hash[i] = 0;
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
			var_hash[i] = 0;
		}
	}
	dynamic_variables_idx.clear();

	if (options.init_connect) {
		free(options.init_connect);
		options.init_connect = NULL;
		options.init_connect_sent = false;
	}
	auto_increment_delay_token = 0;
	if (options.ldap_user_variable) {
		if (options.ldap_user_variable_value) {
			free(options.ldap_user_variable_value);
			options.ldap_user_variable_value = NULL;
		}
		options.ldap_user_variable = NULL;
		options.ldap_user_variable_sent = false;
	}
	options.session_track_gtids_int = 0;
	if (options.session_track_gtids) {
		free (options.session_track_gtids);
		options.session_track_gtids = NULL;
		options.session_track_gtids_sent = false;
	}
}

bool PgSQL_Connection_Placeholder::get_gtid(char *buff, uint64_t *trx_id) {
	// note: current implementation for for OWN GTID only!
	bool ret = false;
	if (buff==NULL || trx_id == NULL) {
		return ret;
	}
	if (pgsql) {
		if (pgsql->net.last_errno==0) { // only if there is no error
			if (pgsql->server_status & SERVER_SESSION_STATE_CHANGED) { // only if status changed
				const char *data;
				size_t length;
				if (mysql_session_track_get_first(pgsql, SESSION_TRACK_GTIDS, &data, &length) == 0) {
					if (length >= (sizeof(gtid_uuid) - 1)) {
						length = sizeof(gtid_uuid) - 1;
					}
					if (memcmp(gtid_uuid,data,length)) {
						// copy to local buffer in PgSQL_Connection
						memcpy(gtid_uuid,data,length);
						gtid_uuid[length]=0;
						// copy to external buffer in MySQL_Backend
						memcpy(buff,data,length);
						buff[length]=0;
						__sync_fetch_and_add(&myds->sess->thread->status_variables.stvar[st_var_gtid_session_collected],1);
						ret = true;
					}
				}
			}
		}
	}
	return ret;
}



PgSQL_Connection::PgSQL_Connection() {
	pgsql_conn = NULL;
	result_type = 0;
	pgsql_result = NULL;
	query_result = NULL;
	query_result_reuse = NULL;
	new_result = true;
	reset_error();
}

PgSQL_Connection::~PgSQL_Connection() {

	if (userinfo) {
		delete userinfo;
		userinfo = NULL;
	}
	if (pgsql_result) {
		PQclear(pgsql_result);
		pgsql_result = NULL;
	}
	if (pgsql_conn) {
		PQfinish(pgsql_conn);
		pgsql_conn = NULL;
	}
	if (query_result) {
		delete query_result;
		query_result = NULL;
	}
	if (query_result_reuse) {
		delete query_result_reuse;
		query_result_reuse = NULL;
	}
	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
			var_hash[i] = 0;
		}
	}

	if (connected_host_details.hostname) {
		free(connected_host_details.hostname);
		connected_host_details.hostname = NULL;
	}
	if (connected_host_details.ip) {
		free(connected_host_details.ip);
		connected_host_details.hostname = NULL;
	}

}

void PgSQL_Connection::next_event(PG_ASYNC_ST new_st) {
#ifdef DEBUG
	int fd;
#endif /* DEBUG */
	wait_events = 0;

	if (async_exit_status & PG_EVENT_READ)
		wait_events |= POLLIN;
	if (async_exit_status & PG_EVENT_WRITE)
		wait_events |= POLLOUT;
	if (wait_events)
#ifdef DEBUG
		fd = PQsocket(pgsql_conn);
#else
		PQsocket(pgsql_conn);
#endif /* DEBUG */
	else
#ifdef DEBUG
		fd = -1;
#endif /* DEBUG */

	proxy_debug(PROXY_DEBUG_NET, 8, "fd=%d, wait_events=%d , old_ST=%d, new_ST=%d\n", fd, wait_events, async_state_machine, new_st);
	async_state_machine = new_st;
};


PG_ASYNC_ST PgSQL_Connection::handler(short event) {
#if ENABLE_TIMER
	Timer timer(myds->sess->thread->Timers.Connections_Handlers);
#endif // ENABLE_TIMER
	unsigned long long processed_bytes = 0;	// issue #527 : this variable will store the amount of bytes processed during this event
	if (pgsql_conn == NULL) {
		// it is the first time handler() is being called
		async_state_machine = ASYNC_CONNECT_START;
		myds->wait_until = myds->sess->thread->curtime + pgsql_thread___connect_timeout_server * 1000;
		if (myds->max_connect_time) {
			if (myds->wait_until > myds->max_connect_time) {
				myds->wait_until = myds->max_connect_time;
			}
		}
	}
handler_again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "async_state_machine=%d\n", async_state_machine);
	switch (async_state_machine) {
	case ASYNC_CONNECT_START:
		connect_start();
		if (async_exit_status) {
			next_event(ASYNC_CONNECT_CONT);
		}
		else {
			NEXT_IMMEDIATE(ASYNC_CONNECT_END);
		}
		break;
	case ASYNC_CONNECT_CONT:
		if (event) {
			connect_cont(event);
		}
		if (async_exit_status) {
			if (myds->sess->thread->curtime >= myds->wait_until) {
				NEXT_IMMEDIATE(ASYNC_CONNECT_TIMEOUT);
			}
			next_event(ASYNC_CONNECT_CONT);
		} else {
			NEXT_IMMEDIATE(ASYNC_CONNECT_END);
		}
		break;
	case ASYNC_CONNECT_END:
		if (myds) {
			if (myds->sess) {
				if (myds->sess->thread) {
					unsigned long long curtime = monotonic_time();
					myds->sess->thread->atomic_curtime = curtime;
				}
			}
		}
		if (is_error_present()) {
			// always increase the counter
			proxy_error("Failed to PQconnectStart() on %u:%s:%d , FD (Conn:%d , MyDS:%d) , %s.\n", parent->myhgc->hid, parent->address, parent->port, PQsocket(pgsql_conn), myds->fd, get_error_code_with_message().c_str());
			NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
		} else {
			if (PQisnonblocking(pgsql_conn) == false) {
				// Set non-blocking mode
				if (PQsetnonblocking(pgsql_conn, 1) != 0) {
					// WARNING: DO NOT RELEASE this PGresult
					const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
					set_error_from_result(result);
					proxy_error("Failed to set non-blocking mode: %s\n", get_error_code_with_message().c_str());
					NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
				}
			}
			NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
		}
		break;
	case ASYNC_CONNECT_SUCCESSFUL:
		if (!is_connected()) 
			assert(0); // shouldn't ever reach here, we have messed up the state machine
		
		__sync_fetch_and_add(&PgHGM->status.server_connections_connected, 1);
		__sync_fetch_and_add(&parent->connect_OK, 1);
		//MySQL_Monitor::update_dns_cache_from_mysql_conn(pgsql);
		break;
	case ASYNC_CONNECT_FAILED:
		//PQfinish(pgsql_conn);//release connection even on error
		//pgsql_conn = NULL;
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(pgsql));
		parent->connect_error(mysql_errno(pgsql));
		break;
	case ASYNC_CONNECT_TIMEOUT:
		// to fix
		//PQfinish(pgsql_conn);//release connection
		//pgsql_conn = NULL;
		proxy_error("Connect timeout on %s:%d : exceeded by %lluus\n", parent->address, parent->port, myds->sess->thread->curtime - myds->wait_until);
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(pgsql));
		parent->connect_error(mysql_errno(pgsql));
		break;
	case ASYNC_QUERY_START:
		query_start();
		__sync_fetch_and_add(&parent->queries_sent, 1);
		update_bytes_sent(query.length + 5);
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_QUERY_CONT);
		} else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_QUERY_CONT:
		if (event) {
			query_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_QUERY_CONT);
		} else {
			if (is_error_present() || 
				!set_single_row_mode()) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_USE_RESULT_START:
		fetch_result_start();
		if (async_exit_status == PG_EVENT_NONE) {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			new_result = true;
			if (myds->sess->mirror == false) {
				if (query_result_reuse == NULL) {
					query_result = new PgSQL_Query_Result();
					query_result->init(&myds->sess->client_myds->myprot, myds, this);
				} else {
					query_result = query_result_reuse;
					query_result_reuse = NULL;
					query_result->init(&myds->sess->client_myds->myprot, myds, this);
				}
			} else {
				if (query_result_reuse == NULL) {
					query_result = new PgSQL_Query_Result();
					query_result->init(NULL, myds, this);
				} else {
					query_result = query_result_reuse;
					query_result_reuse = NULL;
					query_result->init(NULL, myds, this);
				}
			}
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
		} else {
			assert(0); // shouldn't ever reach here
		}
		break;
	case ASYNC_USE_RESULT_CONT:
	{
		if (myds->sess && myds->sess->client_myds && myds->sess->mirror == false /* &&
			myds->sess->status != SHOW_WARNINGS*/) { // see issue#4072
			unsigned int buffered_data = 0;
			buffered_data = myds->sess->client_myds->PSarrayOUT->len * PGSQL_RESULTSET_BUFLEN;
			buffered_data += myds->sess->client_myds->resultset->len * PGSQL_RESULTSET_BUFLEN;
			if (buffered_data > (unsigned int)pgsql_thread___threshold_resultset_size * 8) {
				next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause . See #1232
				break;
			}
		}

		fetch_result_cont(event);
		if (async_exit_status) {
			next_event(ASYNC_USE_RESULT_CONT);
			break;
		}

		if (result_type == 1) {
			std::unique_ptr<PGresult, decltype(&PQclear)> result(get_result(), PQclear);

			if (result) {

				const ExecStatusType exec_status_type = PQresultStatus(result.get());

				if ((query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR))) {
					next_multi_statement_result(result.release());
					next_event(ASYNC_USE_RESULT_START);
					break;
				}

				switch (exec_status_type) {
				case PGRES_COMMAND_OK:
					{
						const unsigned int bytes_recv = query_result->add_command_completion(result.get());
						update_bytes_recv(bytes_recv);
					}
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
				case PGRES_EMPTY_QUERY:
					{
						const unsigned int bytes_recv = query_result->add_empty_query_response(result.get());
						update_bytes_recv(bytes_recv);
					}
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
				case PGRES_TUPLES_OK:
				case PGRES_SINGLE_TUPLE:
					break;
				case PGRES_COPY_OUT:
				case PGRES_COPY_IN:
				case PGRES_COPY_BOTH:
					// NOT IMPLEMENTED
					proxy_error("COPY not supported\n");
					assert(0);
					break;
				case PGRES_BAD_RESPONSE:
				case PGRES_NONFATAL_ERROR:
				case PGRES_FATAL_ERROR:
				default:
					// if on previous call we encountered a FATAL error, we will not process the result, as it will contain residual protocol messages
					// from the broken connection
					if (is_error_present() == true && get_error_severity() == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL) {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					}

					// we don't have a command completion, empty query responseor error packet in the result. This check is here to 
					// handle internal cleanup of libpq that might return residual protocol messages from the broken connection and 
					// may add multiple final packets.
					//if ((query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR)) == 0) {
					set_error_from_result(result.get(), PGSQL_ERROR_FIELD_ALL);
					assert(is_error_present());

					// we will not send FATAL error messages to the client
					const PGSQL_ERROR_SEVERITY severity = get_error_severity();
					if (severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR ||
						severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_WARNING ||
						severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE) {

						const unsigned int bytes_recv = query_result->add_error(result.get());
						update_bytes_recv(bytes_recv);
					}

					const PGSQL_ERROR_CATEGORY error_category = get_error_category();
					if (error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_SYNTAX_ERROR &&
						error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS &&
						error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR) {
						proxy_error("Error: %s, Multi-Statement: %d\n", get_error_code_with_message().c_str(), processing_multi_statement);
					}
					//}
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
				}

				if (new_result == true) {
					const unsigned int bytes_recv = query_result->add_row_description(result.get());
					update_bytes_recv(bytes_recv);
					new_result = false;
				}

				if (PQntuples(result.get()) > 0) {
					const unsigned int bytes_recv = query_result->add_row(result.get());
					update_bytes_recv(bytes_recv);
					processed_bytes += bytes_recv;	// issue #527 : this variable will store the amount of bytes processed during this event
					if (
						(processed_bytes > (unsigned int)pgsql_thread___threshold_resultset_size * 8)
						||
						(pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (unsigned long long)pgsql_thread___throttle_ratio_server_to_client))
						) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
						break;
					} else {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping 
					}
				} else {
					const unsigned int bytes_recv=query_result->add_command_completion(result.get(), false);
					update_bytes_recv(bytes_recv);
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
				}
			}
		} else if (result_type == 2) {
			if (ps_result.id == 'D') {
				unsigned int bytes_recv=query_result->add_row(&ps_result);
				update_bytes_recv(bytes_recv);
				processed_bytes += bytes_recv;	// issue #527 : this variable will store the amount of bytes processed during this event

				if (
					(processed_bytes > (unsigned int)pgsql_thread___threshold_resultset_size * 8)
					||
					(pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (unsigned long long)pgsql_thread___throttle_ratio_server_to_client))
					) {
					next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					break;
				} else {
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping
				}
			} else {
				assert(0);
			}
		} else {
			assert(0);
		}

		if ((query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR)) == 0) {
			// if we reach here we assume that error_info is already set in previous call
			if (!is_error_present())
				assert(0); // we might have missed setting error_info in previous call

			query_result->add_error(NULL);
		}

		// finally add ready for query packet
		query_result->add_ready_status(PQtransactionStatus(pgsql_conn));
		update_bytes_recv(6);
		//processing_multi_statement = false;
		NEXT_IMMEDIATE(ASYNC_QUERY_END);
	}
	break;
	case ASYNC_QUERY_END:
		PROXY_TRACE2();
		if (is_error_present()) {
			compute_unknown_transaction_status();
		} else {
			unknown_transaction_status = false;
		}
		// should be NULL
		assert(!pgsql_result);
		break;
	case ASYNC_RESET_SESSION_START:
		reset_session_start();
		update_bytes_sent((reset_session_in_txn == false ? (sizeof("DISCARD ALL") + 5) : (sizeof("ROLLBACK") + 5)));
		if (async_exit_status) {
			next_event(ASYNC_RESET_SESSION_CONT);
		} else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
			}
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_CONT);
		}
		break;
	case ASYNC_RESET_SESSION_CONT:
	{
		reset_session_cont(event);
		if (async_exit_status) {
			if (myds->wait_until != 0 && myds->sess->thread->curtime >= myds->wait_until) {
				NEXT_IMMEDIATE(ASYNC_RESET_SESSION_TIMEOUT);
			}
			next_event(ASYNC_RESET_SESSION_CONT);
			break;
		}
		if (is_error_present()) {
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
		}
		PGresult* result = get_result();
		if (result) {
			if (PQresultStatus(result) != PGRES_COMMAND_OK) {
				set_error_from_result(result, PGSQL_ERROR_FIELD_ALL);
				assert(is_error_present());
			}
			PQclear(result);
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_CONT);
		}
		if (reset_session_in_txn) {
			//assert(IsKnownActiveTransaction() == false);
			reset_session_in_txn = false;
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_START);
		} 
		NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
	}
		break;
	case ASYNC_RESET_SESSION_END:
		if (is_error_present()) {
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_FAILED);
		}
		NEXT_IMMEDIATE(ASYNC_RESET_SESSION_SUCCESSFUL);
		break;
	case ASYNC_RESET_SESSION_FAILED:
	case ASYNC_RESET_SESSION_SUCCESSFUL:
	case ASYNC_RESET_SESSION_TIMEOUT:
		break;
	default:
		// not implemented yet
		assert(0); 
	}
	return async_state_machine;
}

void PgSQL_Connection::connect_start() {
	PROXY_TRACE();
	assert(pgsql_conn == NULL); // already there is a connection
	reset_error();
	async_exit_status = PG_EVENT_NONE;

	std::ostringstream conninfo;
	conninfo << "user=" << userinfo->username << " "; // username
	conninfo << "password=" << userinfo->password << " "; // password
	conninfo << "host=" << parent->address << " "; // backend address
	conninfo << "port=" << parent->port << " "; // backend port
	conninfo << "dbname=" << userinfo->dbname << " ";
	conninfo << "application_name=proxysql "; // application name
	//conninfo << "require_auth=" << AUTHENTICATION_METHOD_STR[pgsql_thread___authentication_method]; // authentication method
	if (parent->use_ssl) {
		conninfo << "sslmode=require "; // SSL required
		if (pgsql_thread___ssl_p2s_key)
			conninfo << "sslkey=" << pgsql_thread___ssl_p2s_key << " ";
		if (pgsql_thread___ssl_p2s_cert)
			conninfo << "sslcert=" << pgsql_thread___ssl_p2s_cert << " ";
		if (pgsql_thread___ssl_p2s_ca)
			conninfo << "sslrootcert=" << pgsql_thread___ssl_p2s_ca << " ";
		if (pgsql_thread___ssl_p2s_crl)
			conninfo << "sslcrl=" << pgsql_thread___ssl_p2s_crl << " ";
		if (pgsql_thread___ssl_p2s_crlpath)
			conninfo << "sslcrldir=" << pgsql_thread___ssl_p2s_crlpath << " ";
		// Only supported in PostgreSQL Server
		// if (pgsql_thread___ssl_p2s_cipher)
		//	  conninfo << "sslcipher=" << pgsql_thread___ssl_p2s_cipher << " ";
	} else {
		conninfo << "sslmode=disable "; // not supporting SSL
	}

	/*conninfo << "postgres://";
	conninfo << userinfo->username << ":" << userinfo->password; // username and password
	conninfo << "@";
	conninfo << parent->address << ":" << parent->port; // backend address and port
	conninfo << "/";
	conninfo << userinfo->schemaname; // currently schemaname consists of datasename (have to improve this in future). In PostgreSQL database and schema are NOT the same.
	conninfo << "?";
	//conninfo << "require_auth=" << AUTHENTICATION_METHOD_STR[pgsql_thread___authentication_method]; // authentication method
	conninfo << "application_name=proxysql";
	*/

	const std::string& conninfo_str = conninfo.str();
	pgsql_conn = PQconnectStart(conninfo_str.c_str());
	//pgsql_conn = PQconnectdb(conninfo_str.c_str());

	//PQsetErrorVerbosity(pgsql_conn, PQERRORS_VERBOSE);
	//PQsetErrorContextVisibility(pgsql_conn, PQSHOW_CONTEXT_ERRORS);

	if (pgsql_conn == NULL || PQstatus(pgsql_conn) == CONNECTION_BAD) {
		if (pgsql_conn) {
			// WARNING: DO NOT RELEASE this PGresult
			const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
			set_error_from_result(result);
		} else {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "Out of memory", false);
		}
		proxy_error("Connect failed. %s\n", get_error_code_with_message().c_str());
		return;
	}
	if (PQsetnonblocking(pgsql_conn, 1) != 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Failed to set non-blocking mode: %s\n", get_error_code_with_message().c_str());
		return;
	}
	fd = PQsocket(pgsql_conn);
	async_exit_status = PG_EVENT_WRITE;
}

void PgSQL_Connection::connect_cont(short event) {
	PROXY_TRACE();
	assert(pgsql_conn);
	reset_error();
	async_exit_status = PG_EVENT_NONE;

// For troubleshooting connection issue
#if 0
	const char* message = nullptr;
	switch (PQstatus(pgsql_conn))
	{
	case CONNECTION_STARTED:
		message = "Connecting...";
		break;

	case CONNECTION_MADE:
		message = "Connected to server (waiting to send) ...";
		break;

	case CONNECTION_AWAITING_RESPONSE:
		message = "Waiting for a response from the server...";
		break;

	case CONNECTION_AUTH_OK:
		message = "Received authentication; waiting for backend start - up to finish...";
		break;

	case CONNECTION_SSL_STARTUP:
		message = "Negotiating SSL encryption...";
		break;
	
	case CONNECTION_SETENV:
		message = "Negotiating environment-driven parameter settings...";
		break;

	default:
		message = "Connecting...";
	}

	proxy_info("Connection status: %d %s\n", PQsocket(pgsql_conn), message);
#endif

	PostgresPollingStatusType poll_res = PQconnectPoll(pgsql_conn);
	switch (poll_res) {
	case PGRES_POLLING_WRITING:
		async_exit_status = PG_EVENT_WRITE;
		break;
	case PGRES_POLLING_ACTIVE:
	case PGRES_POLLING_READING:
		async_exit_status = PG_EVENT_READ;
		break;
	case PGRES_POLLING_OK:
		async_exit_status = PG_EVENT_NONE;
		break;
	//case PGRES_POLLING_FAILED:
	default:
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Connect failed. %s\n", get_error_code_with_message().c_str());
		return;
	}
}

void PgSQL_Connection::query_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;
	if (PQsendQuery(pgsql_conn, query.ptr) == 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Failed to send query. %s\n", get_error_code_with_message().c_str());
		return;
	}
	flush();
}

void PgSQL_Connection::query_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection::fetch_result_start() {
	PROXY_TRACE();
	reset_error();
	async_exit_status = PG_EVENT_NONE;
}

void PgSQL_Connection::fetch_result_cont(short event) {
	PROXY_TRACE();
	async_exit_status = PG_EVENT_NONE;

	// Avoid fetching a new result if one is already available. 
	// This situation can happen when a multi-statement query has been executed.
	if (pgsql_result)
		return;

	switch (PShandleRowData(pgsql_conn, &ps_result)) {
	case 0:
		result_type = 2;
		return;
	case 1:
		// we already have data available in buffer
		if (PQisBusy(pgsql_conn) == 0) {
			result_type = 1;
			pgsql_result = PQgetResult(pgsql_conn);
			return;
		}
		break;
	}

	if (PQconsumeInput(pgsql_conn) == 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		/* We will only set the error if the result is not NULL or we didn't capture error in last call. If the result is NULL,
		 * it indicates that an error was already captured during a previous PQconsumeInput call,
		 * and we do not want to overwrite that information.
		 */
		if (result || is_error_present() == false) {
			set_error_from_result(result);
			proxy_error("Failed to consume input. %s\n", get_error_code_with_message().c_str());
		}
		return;
	}

	switch (PShandleRowData(pgsql_conn, &ps_result)) {
	case 0:
		result_type = 2;
		return;
	case 1:
		if (PQisBusy(pgsql_conn)) {
			async_exit_status = PG_EVENT_READ;
			return;
		}
		break;
	default:
		async_exit_status = PG_EVENT_READ;
		return;
	}
	result_type = 1;
	pgsql_result = PQgetResult(pgsql_conn);
}

void PgSQL_Connection::flush() {
	reset_error();
	int res = PQflush(pgsql_conn);

	if (res > 0) {
		async_exit_status = PG_EVENT_WRITE;
	}
	else if (res == 0) {
		async_exit_status = PG_EVENT_READ;
	}
	else {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Failed to flush data to backend. %s\n", get_error_code_with_message().c_str());
		async_exit_status = PG_EVENT_NONE;
	}
}

int PgSQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	if (pgsql_conn == NULL && async_state_machine != ASYNC_CONNECT_START) {
		// LCOV_EXCL_START
		assert(0);
		// LCOV_EXCL_STOP
	}
	if (async_state_machine == ASYNC_IDLE) {
		myds->wait_until = 0;
		return 0;
	}
	if (async_state_machine == ASYNC_CONNECT_SUCCESSFUL) {
		compute_unknown_transaction_status();
		async_state_machine = ASYNC_IDLE;
		myds->wait_until = 0;
		creation_time = monotonic_time();
		return 0;
	}
	handler(event);
	switch (async_state_machine) {
	case ASYNC_CONNECT_SUCCESSFUL:
		compute_unknown_transaction_status();
		async_state_machine = ASYNC_IDLE;
		myds->wait_until = 0;
		return 0;
		break;
	case ASYNC_CONNECT_FAILED:
		return -1;
		break;
	case ASYNC_CONNECT_TIMEOUT:
		return -2;
		break;
	default:
		return 1;
	}
	return 1;
}

bool PgSQL_Connection::is_connected() const {
	if (pgsql_conn == nullptr || PQstatus(pgsql_conn) != CONNECTION_OK) {
		return false;
	}
	return true;
}

void PgSQL_Connection::compute_unknown_transaction_status() {
	
	if (pgsql_conn) {
		// make sure we have not missed even a single error
		if (is_error_present() == false) {
			unknown_transaction_status = false;
			return;
		}

		/*if (is_connected() == false) {
			unknown_transaction_status = true;
			return;
		}*/

		switch (PQtransactionStatus(pgsql_conn)) {
		case PQTRANS_INTRANS:
		case PQTRANS_INERROR:
		case PQTRANS_ACTIVE:
			unknown_transaction_status = true;
			break;
		case PQTRANS_UNKNOWN:
		default:
			//unknown_transaction_status = false;
			break;
		}
	}
}

void PgSQL_Connection::async_free_result() {
	PROXY_TRACE();
	//assert(pgsql_conn);

	if (query.ptr) {
		query.ptr = NULL;
		query.length = 0;
	}
	if (query.stmt_result) {
		mysql_free_result(query.stmt_result);
		query.stmt_result = NULL;
	}
	if (userinfo) {
		// if userinfo is NULL , the connection is being destroyed
		// because it is reset on destructor ( ~PgSQL_Connection() )
		// therefore this section is skipped completely
		// this should prevent bug #1046
		//if (query.stmt) {
		//	if (query.stmt->mysql) {
		//		if (query.stmt->mysql == pgsql) { // extra check
		//			mysql_stmt_free_result(query.stmt);
		//		}
		//	}
		//	// If we reached here from 'ASYNC_STMT_PREPARE_FAILED', the
		//	// prepared statement was never added to 'local_stmts', thus
		//	// it will never be freed when 'local_stmts' are purged. If
		//	// initialized, it must be freed. For more context see #3525.
		//	if (this->async_state_machine == ASYNC_STMT_PREPARE_FAILED) {
		//		if (query.stmt != NULL) {
		//			proxy_mysql_stmt_close(query.stmt);
		//		}
		//	}
		//	query.stmt = NULL;
		//}
	}
	if (pgsql_result) {
		PQclear(pgsql_result);
		pgsql_result = NULL;
	}
	compute_unknown_transaction_status();
	async_state_machine = ASYNC_IDLE;
	if (query_result) {
		if (query_result_reuse) {
			delete (query_result_reuse);
		}
		query_result_reuse = query_result;
		query_result = NULL;
	}
	new_result = false;
}

#if 0
int PgSQL_Connection::async_set_autocommit(short event, bool ac) {
	PROXY_TRACE();
	assert(pgsql_conn);
	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
	case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_SET_AUTOCOMMIT_FAILED:
		return -1;
		break;
	case ASYNC_QUERY_END:
	case ASYNC_IDLE:
		set_autocommit(ac);
		async_state_machine = ASYNC_SET_AUTOCOMMIT_START;
	default:
		handler(event);
		break;
	}

	// check again
	switch (async_state_machine) {
	case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_SET_AUTOCOMMIT_FAILED:
		return -1;
		break;
	default:
		return 1;
		break;
	}
	return 1;
}
#endif // 0

bool PgSQL_Connection::IsAutoCommit() {
	bool ret = true;
	/*if (pgsql) {
		ret = (pgsql->server_status & SERVER_STATUS_AUTOCOMMIT);
		if (ret) {
			if (options.last_set_autocommit == 0) {
				// it seems we hit bug http://bugs.pgsql.com/bug.php?id=66884
				// we last sent SET AUTOCOMMIT = 0 , but the server says it is 1
				// we assume that what we sent last is correct .  #873
				ret = false;
			}
		}
		else {
			if (options.last_set_autocommit == -1) {
				// if a connection was reset (thus last_set_autocommit==-1)
				// the information related to SERVER_STATUS_AUTOCOMMIT is lost
				// therefore we fall back on the safe assumption that autocommit==1
				ret = true;
			}
		}
	}*/
	return ret;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_query(short event, char* stmt, unsigned long length, MYSQL_STMT** _stmt, stmt_execute_metadata_t* stmt_meta) {
	PROXY_TRACE();
	PROXY_TRACE2();
	assert(pgsql_conn);

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}
	switch (async_state_machine) {
	case ASYNC_QUERY_END:
		processing_multi_statement = false;	// no matter if we are processing a multi statement or not, we reached the end
		return 0;
		break;
	case ASYNC_IDLE:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions == 0) {
				// every time we start a query (no matter if COM_QUERY, STMT_PREPARE or otherwise)
				// also a transaction starts, even if in autocommit mode
				myds->sess->active_transactions = 1;
				myds->sess->transaction_started_at = myds->sess->thread->curtime;
			}
		}
		if (stmt_meta == NULL)
			set_query(stmt, length);
		async_state_machine = ASYNC_QUERY_START;
		if (_stmt) {
			query.stmt = *_stmt;
			if (stmt_meta == NULL) {
				async_state_machine = ASYNC_STMT_PREPARE_START;
			}
			else {
				if (query.stmt_meta == NULL) {
					query.stmt_meta = stmt_meta;
				}
				async_state_machine = ASYNC_STMT_EXECUTE_START;
			}
		}
	default:
		handler(event);
		break;
	}

	if (async_state_machine == ASYNC_QUERY_END) {
		PROXY_TRACE2();
		compute_unknown_transaction_status();
		if (is_error_present()) {
			return -1;
		}
		else {
			return 0;
		}
	}
	if (async_state_machine == ASYNC_STMT_EXECUTE_END) {
		PROXY_TRACE2();
		query.stmt_meta = NULL;
		async_state_machine = ASYNC_QUERY_END;
		compute_unknown_transaction_status();
		if (mysql_stmt_errno(query.stmt)) {
			return -1;
		}
		else {
			return 0;
		}
	}
	if (async_state_machine == ASYNC_STMT_PREPARE_SUCCESSFUL || async_state_machine == ASYNC_STMT_PREPARE_FAILED) {
		query.stmt_meta = NULL;
		compute_unknown_transaction_status();
		if (async_state_machine == ASYNC_STMT_PREPARE_FAILED) {
			return -1;
		}
		else {
			*_stmt = query.stmt;
			return 0;
		}
	}
	if (async_state_machine == ASYNC_USE_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to MySQL_Session
		processing_multi_statement = true;
		return 2;
	}
	if (processing_multi_statement == true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}
	return 1;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_reset_session(short event) {
	PROXY_TRACE();
	PROXY_TRACE2();
	assert(pgsql_conn);

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	/*if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}*/

	switch (async_state_machine) {
	case ASYNC_RESET_SESSION_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_RESET_SESSION_FAILED:
		return -1;
		break;
	case ASYNC_RESET_SESSION_TIMEOUT:
		return -2;
		break;
	case ASYNC_IDLE:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions == 0) {
				myds->sess->active_transactions = 1;
				myds->sess->transaction_started_at = myds->sess->thread->curtime;
			}
		}
		async_state_machine = ASYNC_RESET_SESSION_START;
	default:
		handler(event);
		break;
	}

	switch (async_state_machine) {
	case ASYNC_RESET_SESSION_SUCCESSFUL:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_RESET_SESSION_FAILED:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		return -1;
		break;
	case ASYNC_RESET_SESSION_TIMEOUT:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		return -2;
		break;
	default:
		break;
	}
	return 1;
}

// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_ping(short event) {
	PROXY_TRACE();
	assert(pgsql_conn);
	switch (async_state_machine) {
	case ASYNC_PING_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_PING_FAILED:
		return -1;
		break;
	case ASYNC_PING_TIMEOUT:
		return -2;
		break;
	case ASYNC_IDLE:
		async_state_machine = ASYNC_PING_START;
	default:
		//handler(event);
		async_state_machine = ASYNC_PING_SUCCESSFUL;
		break;
	}

	// check again
	switch (async_state_machine) {
	case ASYNC_PING_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_PING_FAILED:
		return -1;
		break;
	case ASYNC_PING_TIMEOUT:
		return -2;
		break;
	default:
		return 1;
		break;
	}
	return 1;
}

bool PgSQL_Connection::IsKnownActiveTransaction() {
	bool in_txn = false;
	if (pgsql_conn) {
		// Get the transaction status
		PGTransactionStatusType status = PQtransactionStatus(pgsql_conn);
		if (status == PQTRANS_INTRANS || status == PQTRANS_INERROR) {
			in_txn = true;
		}
	}
	return in_txn;
}

bool PgSQL_Connection::IsActiveTransaction() {
	bool in_txn = false;
	if (pgsql_conn) {

		// Get the transaction status
		PGTransactionStatusType status = PQtransactionStatus(pgsql_conn);

		switch (status) {
		case PQTRANS_INTRANS:
		case PQTRANS_INERROR:
			in_txn = true;
			break;
		case PQTRANS_UNKNOWN:
		case PQTRANS_IDLE:
		case PQTRANS_ACTIVE:
		default:
			in_txn = false;
		}

		if (in_txn == false && is_error_present() && unknown_transaction_status == true) {
			in_txn = true;
		} 
		/*if (ret == false) {
			//bool r = ( mysql_thread___autocommit_false_is_transaction || mysql_thread___forward_autocommit ); // deprecated , see #3253
			bool r = (mysql_thread___autocommit_false_is_transaction);
			if (r && (IsAutoCommit() == false)) {
				ret = true;
			}
		}*/
	}
	return in_txn;
}

bool PgSQL_Connection::IsServerOffline() {
	bool ret = false;
	if (parent == NULL)
		return ret;
	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(server_status == MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(server_status == MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic == true && parent->shunned_and_kill_all_connections == true) // the server is SHUNNED due to a serious issue
		||
		(server_status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
		) {
		ret = true;
	}
	return ret;
}

bool PgSQL_Connection::is_connection_in_reusable_state() const {
	const PGTransactionStatusType txn_status = PQtransactionStatus(pgsql_conn);
	const bool conn_usable = !(txn_status == PQTRANS_UNKNOWN || txn_status == PQTRANS_ACTIVE);
	assert(!(conn_usable == false && is_error_present() == false));
	return conn_usable;
}

PGresult* PgSQL_Connection::get_result() {
	PGresult* result_tmp = pgsql_result;
	pgsql_result = nullptr;
	return result_tmp;
}

bool PgSQL_Connection::set_single_row_mode() {
	assert(pgsql_conn);
	if (PQsetSingleRowMode(pgsql_conn) == 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Failed to set single row mode. %s\n", get_error_code_with_message().c_str());
		return false;
	}
	return true;
}

void PgSQL_Connection::next_multi_statement_result(PGresult* result) {
	// set unprocessed result to pgsql_result
	pgsql_result = result;
	// copy buffer to PSarrayOut
	query_result->buffer_to_PSarrayOut();
}

void PgSQL_Connection::reset_session_start() {
	PROXY_TRACE();
	assert(pgsql_conn);
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	reset_session_in_txn = IsKnownActiveTransaction();
	if (PQsendQuery(pgsql_conn, (reset_session_in_txn == false ? "DISCARD ALL" : "ROLLBACK")) == 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		set_error_from_result(result);
		proxy_error("Failed to send query. %s\n", get_error_code_with_message().c_str());
		return;
	}
	flush();
}

void PgSQL_Connection::reset_session_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
		return;
	}

	if (PQconsumeInput(pgsql_conn) == 0) {
		// WARNING: DO NOT RELEASE this PGresult
		const PGresult* result = PQgetResultFromPGconn(pgsql_conn);
		/* We will only set the error if the result is not NULL or we didn't capture error in last call. If the result is NULL,
		 * it indicates that an error was already captured during a previous PQconsumeInput call,
		 * and we do not want to overwrite that information.
		 */
		if (result || is_error_present() == false) {
			set_error_from_result(result);
			proxy_error("Failed to consume input. %s\n", get_error_code_with_message().c_str());
		}
		return;
	}

	if (PQisBusy(pgsql_conn)) {
		async_exit_status = PG_EVENT_READ;
		return;
	}

	pgsql_result = PQgetResult(pgsql_conn);
}

bool PgSQL_Connection::requires_RESETTING_CONNECTION(const PgSQL_Connection* client_conn) {
	for (auto i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (client_conn->var_hash[i] == 0) {
			if (var_hash[i]) {
				// this connection has a variable set that the
				// client connection doesn't have.
				// Since connection cannot be unset , this connection
				// needs to be reset with CHANGE_USER
				return true;
			}
		}
	}
	if (client_conn->dynamic_variables_idx.size() < dynamic_variables_idx.size()) {
		// the server connection has more variables set than the client
		return true;
	}
	std::vector<uint32_t>::const_iterator it_c = client_conn->dynamic_variables_idx.begin(); // client connection iterator
	std::vector<uint32_t>::const_iterator it_s = dynamic_variables_idx.begin();              // server connection iterator
	for (; it_s != dynamic_variables_idx.end(); it_s++) {
		while (it_c != client_conn->dynamic_variables_idx.end() && (*it_c < *it_s)) {
			it_c++;
		}
		if (it_c != client_conn->dynamic_variables_idx.end() && *it_c == *it_s) {
			// the backend variable idx matches the frontend variable idx
		}
		else {
			// we are processing a backend variable but there are
			// no more frontend variables
			return true;
		}
	}
	return false;
}

bool PgSQL_Connection::has_same_connection_options(const PgSQL_Connection* client_conn) {
	if (userinfo->hash != client_conn->userinfo->hash) {
		if (strcmp(userinfo->username, client_conn->userinfo->username)) {
			return false;
		}
		if (strcmp(userinfo->dbname, client_conn->userinfo->dbname)) {
			return false;
		}
	}
	return true;
}

unsigned int PgSQL_Connection::get_memory_usage() const {
	// TODO: need to create new function in libpq
	unsigned int memory_bytes = (16 * 1024) * 2; //PSgetMemoryUsage(pgsql_conn);
	return /*sizeof(PGconn) +*/ memory_bytes;
}

void PgSQL_Connection::update_bytes_recv(uint64_t bytes_recv) {
	__sync_fetch_and_add(&parent->bytes_recv, bytes_recv);
	myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv] += bytes_recv;
	myds->bytes_info.bytes_recv += bytes_recv;
	bytes_info.bytes_recv += bytes_recv;
}

void PgSQL_Connection::update_bytes_sent(uint64_t bytes_sent) {
	__sync_fetch_and_add(&parent->bytes_sent, bytes_sent);
	myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_sent] += bytes_sent;
	myds->bytes_info.bytes_sent += bytes_sent;
	bytes_info.bytes_sent += bytes_sent;
}

const char* PgSQL_Connection::get_pg_server_version_str(char* buff, int buff_size) {
	const int postgresql_version = get_pg_server_version();
	snprintf(buff, buff_size, "%d.%d.%d", postgresql_version / 10000, (postgresql_version / 100) % 100, postgresql_version % 100);
	return buff;
}

const char* PgSQL_Connection::get_pg_connection_status_str() {
	switch (get_pg_connection_status()) {
	case CONNECTION_OK:
		return "OK";
	case CONNECTION_BAD:
		return "BAD";
	case CONNECTION_STARTED:
		return "STARTED";
	case CONNECTION_MADE:
		return "MADE";
	case CONNECTION_AWAITING_RESPONSE:
		return "AWAITING_RESPONSE";
	case CONNECTION_AUTH_OK:
		return "AUTH_OK";
	case CONNECTION_SETENV:
		return "SETENV";
	case CONNECTION_SSL_STARTUP:
		return "SSL_STARTUP";
	case CONNECTION_NEEDED:
		return "NEEDED";
	case CONNECTION_CHECK_WRITABLE:
		return "CHECK_WRITABLE";
	case CONNECTION_CONSUME:
		return "CONSUME";
	case CONNECTION_GSS_STARTUP:
		return "GSS_STARTUP";
	case CONNECTION_CHECK_TARGET:
		return "CHECK_TARGET";
	case CONNECTION_CHECK_STANDBY:
		return "CHECK_STANDBY";
	}
	return "UNKNOWN";
}

const char* PgSQL_Connection::get_pg_transaction_status_str() {
	switch (get_pg_transaction_status()) {
	case PQTRANS_IDLE:
		return "IDLE";
	case PQTRANS_ACTIVE:
		return "ACTIVE";
	case PQTRANS_INTRANS:
		return "IN-TRANSACTION";
	case PQTRANS_INERROR:
		return "IN-ERROR-TRANSACTION";
	case PQTRANS_UNKNOWN:
		return "UNKNOWN";
	}
	return "INVALID";
}
