#include "MySQL_HostGroups_Manager.h"
#include "proxysql.h"
#include "cpp.h"
//#include "SpookyV2.h"
#include <fcntl.h>
#include <sstream>

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "MySQL_Variables.h"

#include <atomic>

// some of the code that follows is from mariadb client library memory allocator
typedef int     myf;    // Type of MyFlags in my_funcs
#define MYF(v)      (myf) (v)
#define MY_KEEP_PREALLOC    1
#define MY_ALIGN(A,L)    (((A) + (L) - 1) & ~((L) - 1))
#define ALIGN_SIZE(A)    MY_ALIGN((A),sizeof(double))
void ma_free_root(MA_MEM_ROOT *root, myf MyFLAGS);
void *ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size);
#define MAX(a,b) (((a) > (b)) ? (a) : (b))


void * ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size)
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


void ma_free_root(MA_MEM_ROOT *root, myf MyFlags)
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

extern char * binary_sha1;

extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name);

void Variable::fill_server_internal_session(json &j, int conn_num, int idx) {
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

void Variable::fill_client_internal_session(json &j, int idx) {
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

MySQL_Connection_userinfo::MySQL_Connection_userinfo() {
	username=NULL;
	password=NULL;
	sha1_pass=NULL;
	schemaname=NULL;
	fe_username=NULL;
	hash=0;
}

MySQL_Connection_userinfo::~MySQL_Connection_userinfo() {
	if (username) free(username);
	if (fe_username) free(fe_username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (schemaname) free(schemaname);
}

void MySQL_Connection::compute_unknown_transaction_status() {
	if (mysql) {
		int _myerrno=mysql_errno(mysql);
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

uint64_t MySQL_Connection_userinfo::compute_hash() {
	int l=0;
	if (username)
		l+=strlen(username);
	if (password)
		l+=strlen(password);
	if (schemaname)
		l+=strlen(schemaname);
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
	if (schemaname) {
		strcpy(buf+l,schemaname);
		l+=strlen(schemaname);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL2_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	hash=SpookyHash::Hash64(buf,l,0);
	free(buf);
	return hash;
}

void MySQL_Connection_userinfo::set(char *u, char *p, char *s, char *sh1) {
	if (u) {
		if (username) {
			if (strcmp(u,username)) {
				free(username);
				username=strdup(u);
			}
		} else {
			username=strdup(u);
		}
	}
	if (p) {
		if (password) {
			if (strcmp(p,password)) {
				free(password);
				password=strdup(p);
			}
		} else {
			password=strdup(p);
		}
	}
	if (s) {
		if (schemaname) free(schemaname);
		schemaname=strdup(s);
	}
	if (sh1) {
		if (sha1_pass) {
			free(sha1_pass);
		}
		sha1_pass=strdup(sh1);
	}
	compute_hash();
}

void MySQL_Connection_userinfo::set(MySQL_Connection_userinfo *ui) {
	set(ui->username, ui->password, ui->schemaname, ui->sha1_pass);
}


bool MySQL_Connection_userinfo::set_schemaname(char *_new, int l) {
	int _l=0;
	if (schemaname) {
		_l=strlen(schemaname); // bug fix for #609
	}
	if ((schemaname==NULL) || (l != _l) || (strncmp(_new,schemaname, l ))) {
		if (schemaname) {
			free(schemaname);
			schemaname=NULL;
		}
		if (l) {
			schemaname=(char *)malloc(l+1);
			memcpy(schemaname,_new,l);
			schemaname[l]=0;
		} else {
			int k=strlen(mysql_thread___default_schema);
			schemaname=(char *)malloc(k+1);
			memcpy(schemaname,mysql_thread___default_schema,k);
			schemaname[k]=0;
		}
		compute_hash();
		return true;
	}
	return false;
}



MySQL_Connection::MySQL_Connection() {
	mysql=NULL;
	async_state_machine=ASYNC_CONNECT_START;
	ret_mysql=NULL;
	send_quit=true;
	myds=NULL;
	inserted_into_pool=0;
	reusable=false;
	parent=NULL;
	userinfo=new MySQL_Connection_userinfo();
	fd=-1;
	status_flags=0;
	last_time_used=0;

	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		variables[i].value = NULL;
		var_hash[i] = 0;
	}

	options.client_flag = 0;
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
	multiplex_delayed=false;
	MyRS=NULL;
	MyRS_reuse=NULL;
	unknown_transaction_status = false;
	creation_time=0;
	auto_increment_delay_token = 0;
	processing_multi_statement=false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new MySQL_Connection %p\n", this);
	local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
	bytes_info.bytes_recv = 0;
	bytes_info.bytes_sent = 0;
	statuses.questions = 0;
	statuses.myconnpoll_get = 0;
	statuses.myconnpoll_put = 0;
	memset(gtid_uuid,0,sizeof(gtid_uuid));
	memset(&connected_host_details, 0, sizeof(connected_host_details));
};

MySQL_Connection::~MySQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying MySQL_Connection %p\n", this);
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
	if (mysql) {
		// always decrease the counter
		if (ret_mysql) {
			__sync_fetch_and_sub(&MyHGM->status.server_connections_connected,1);
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
		close_mysql(); // this take care of closing mysql connection
		mysql=NULL;
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

	if (connected_host_details.hostname)
		free(connected_host_details.hostname);

	if (connected_host_details.ip)
		free(connected_host_details.ip);
};

bool MySQL_Connection::set_autocommit(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting autocommit %d\n", _ac);
	options.autocommit=_ac;
	return _ac;
}

bool MySQL_Connection::set_no_backslash_escapes(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting no_backslash_escapes %d\n", _ac);
	options.no_backslash_escapes=_ac;
	return _ac;
}

void print_backtrace(void);

unsigned int MySQL_Connection::set_charset(unsigned int _c, enum charset_action action) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting charset %d\n", _c);

	// SQL_CHARACTER_SET should be set befor setting SQL_CHRACTER_ACTION
	std::stringstream ss;
	ss << _c;
	mysql_variables.client_set_value(myds->sess, SQL_CHARACTER_SET, ss.str());

	// When SQL_CHARACTER_ACTION is set character set variables are set according to
	// SQL_CHRACTER_SET value
	ss.str(std::string());
	ss.clear();
	ss << action;
	mysql_variables.client_set_value(myds->sess, SQL_CHARACTER_ACTION, ss.str());

	return _c;
}

bool MySQL_Connection::is_expired(unsigned long long timeout) {
// FIXME: here the check should be a sanity check
// FIXME: for now this is just a temporary (and stupid) check
	return false;
}

void MySQL_Connection::set_status(bool set, uint32_t status_flag) {
	if (set) {
		this->status_flags |= status_flag;
	} else {
		this->status_flags &= ~status_flag;
	}
}

bool MySQL_Connection::get_status(uint32_t status_flag) {
	return this->status_flags & status_flag;
}

void MySQL_Connection::set_status_sql_log_bin0(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	}
}

bool MySQL_Connection::get_status_sql_log_bin0() {
	return status_flags & STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
}

bool MySQL_Connection::requires_CHANGE_USER(const MySQL_Connection *client_conn) {
	char *username = client_conn->userinfo->username;
	if (strcmp(userinfo->username,username)) {
		// the two connections use different usernames
		// The connection need to be reset with CHANGE_USER
		return true;
	}
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
	for ( ; it_s != dynamic_variables_idx.end() ; it_s++) {
		while ( it_c != client_conn->dynamic_variables_idx.end() && ( *it_c < *it_s ) ) {
			it_c++;
		}
		if ( it_c != client_conn->dynamic_variables_idx.end() && *it_c == *it_s) {
			// the backend variable idx matches the frontend variable idx
		} else {
			// we are processing a backend variable but there are
			// no more frontend variables
			return true;
		}
	}
	return false;
}

unsigned int MySQL_Connection::reorder_dynamic_variables_idx() {
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

unsigned int MySQL_Connection::number_of_matching_session_variables(const MySQL_Connection *client_conn, unsigned int& not_matching) {
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


bool MySQL_Connection::match_tracked_options(const MySQL_Connection *c) {
	uint32_t cf1 = options.client_flag; // own client flags
	uint32_t cf2 = c->options.client_flag; // other client flags
	if ((cf1 & CLIENT_FOUND_ROWS) == (cf2 & CLIENT_FOUND_ROWS)) {
		if ((cf1 & CLIENT_MULTI_STATEMENTS) == (cf2 & CLIENT_MULTI_STATEMENTS)) {
			if ((cf1 & CLIENT_MULTI_RESULTS) == (cf2 & CLIENT_MULTI_RESULTS)) {
				if ((cf1 & CLIENT_IGNORE_SPACE) == (cf2 & CLIENT_IGNORE_SPACE)) {
					return true;
				}
			}
		}
	}
	return false;
}

// non blocking API
void MySQL_Connection::connect_start() {
	PROXY_TRACE();
	mysql=mysql_init(NULL);
	assert(mysql);
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql");
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_server_host", parent->address);
	{
		time_t __timer;
		char __buffer[25];
		struct tm *__tm_info;
		time(&__timer);
		__tm_info = localtime(&__timer);
		strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "connection_creation_time", __buffer);
		unsigned long long t1=monotonic_time();
		sprintf(__buffer,"%llu",(t1-GloVars.global.start_time)/1000/1000);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "proxysql_uptime", __buffer);
		sprintf(__buffer,"%d", parent->myhgc->hid);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "hostgroup_id", __buffer);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "compile_time", __TIMESTAMP__);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "proxysql_version", PROXYSQL_VERSION);
		if (binary_sha1) {
			mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "proxysql_sha1", binary_sha1);
		} else {
			mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "proxysql_sha1", "unknown");
		}
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "mysql_bug_102266", "Avoid MySQL bug https://bugs.mysql.com/bug.php?id=102266 , https://github.com/sysown/proxysql/issues/3276");
	}
	if (parent->use_ssl) {
		mysql_ssl_set(mysql,
				mysql_thread___ssl_p2s_key,
				mysql_thread___ssl_p2s_cert,
				mysql_thread___ssl_p2s_ca,
				mysql_thread___ssl_p2s_capath,
				mysql_thread___ssl_p2s_cipher);
		mysql_options(mysql, MYSQL_OPT_SSL_CRL, mysql_thread___ssl_p2s_crl);
		mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, mysql_thread___ssl_p2s_crlpath);
	}
	unsigned int timeout= 1;
	const char *csname = NULL;
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
	/* Take client character set and use it to connect to backend */
	if (myds && myds->sess) {
		csname = mysql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET);
	}

	const MARIADB_CHARSET_INFO * c = NULL;
	if (csname)
		c = proxysql_find_charset_nr(atoi(csname));
	else
		c = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);

	if (!c) {
		// LCOV_EXCL_START
		proxy_error("Not existing charset number %s\n", mysql_thread___default_variables[SQL_CHARACTER_SET]);
		assert(0);
		// LCOV_EXCL_STOP
	}
	{
		/* We are connecting to backend setting charset in mysql_options.
		 * Client already has sent us a character set and client connection variables have been already set.
		 * Now we store this charset in server connection variables to avoid updating this variables on backend.
		 */
		std::stringstream ss;
		ss << c->nr;

		mysql_variables.server_set_value(myds->sess, SQL_CHARACTER_SET, ss.str().c_str());
		mysql_variables.server_set_value(myds->sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
		mysql_variables.server_set_value(myds->sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
		mysql_variables.server_set_value(myds->sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
		mysql_variables.server_set_value(myds->sess, SQL_COLLATION_CONNECTION, ss.str().c_str());
	}
	//mysql_options(mysql, MYSQL_SET_CHARSET_NAME, c->csname);
	mysql->charset = c;
	unsigned long client_flags = 0;
	if (parent->compression)
		client_flags |= CLIENT_COMPRESS;

	if (myds) {
		if (myds->sess) {
			if (myds->sess->client_myds) {
				if (myds->sess->client_myds->myconn) {
					uint32_t orig_client_flags = myds->sess->client_myds->myconn->options.client_flag;
					if (orig_client_flags & CLIENT_FOUND_ROWS) {
						client_flags |= CLIENT_FOUND_ROWS;
					}
					if (orig_client_flags & CLIENT_MULTI_STATEMENTS) {
						client_flags |= CLIENT_MULTI_STATEMENTS;
					}
					if (orig_client_flags & CLIENT_MULTI_RESULTS) {
						client_flags |= CLIENT_MULTI_RESULTS;
					}
					if (orig_client_flags & CLIENT_IGNORE_SPACE) {
						client_flags |= CLIENT_IGNORE_SPACE;
					}
				}
			}
		}
	}

	// set 'CLIENT_DEPRECATE_EOF' flag if explicitly stated by 'mysql-enable_server_deprecate_eof'.
	// Capability is disabled by default in 'mariadb_client', so setting this option is not optional
	// for having 'CLIENT_DEPRECATE_EOF' in the connection to be stablished.
	if (mysql_thread___enable_server_deprecate_eof) {
		mysql->options.client_flag |= CLIENT_DEPRECATE_EOF;
	}

	if (myds != NULL) {
		if (myds->sess != NULL) {
			if (myds->sess->session_fast_forward == true) { // this is a fast_forward connection
				assert(myds->sess->client_myds != NULL);
				MySQL_Connection * c = myds->sess->client_myds->myconn;
				assert(c != NULL);
				mysql->options.client_flag &= ~(CLIENT_DEPRECATE_EOF); // we disable it by default
				// if both client_flag and server_capabilities (used for client) , set CLIENT_DEPRECATE_EOF
				if (c->options.client_flag & CLIENT_DEPRECATE_EOF) {
					if (c->options.server_capabilities & CLIENT_DEPRECATE_EOF) {
						mysql->options.client_flag |= CLIENT_DEPRECATE_EOF;
					}
				}
				// In case of 'fast_forward', we only enable compression if both, client and backend matches. Otherwise,
				// we honor the behavior of a regular connection of when a connection doesn't agree on using compression
				// during handshake, and we fallback to an uncompressed connection.
				client_flags &= ~(CLIENT_COMPRESS); // we disable it by default
				if (c->options.client_flag & CLIENT_COMPRESS) {
					if (c->options.server_capabilities & CLIENT_COMPRESS) {
						client_flags |= CLIENT_COMPRESS;
					}
				}
			}
		}
	}

	char *auth_password=NULL;
	if (userinfo->password) {
		if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
			auth_password=userinfo->sha1_pass;
		} else {
			auth_password=userinfo->password;
		}
	}
	if (parent->port) {

		char* host_ip = NULL;
		const std::string& res_ip = MySQL_Monitor::dns_lookup(parent->address, false);

		if (!res_ip.empty()) {
			if (connected_host_details.hostname) {
				if (strcmp(connected_host_details.hostname, parent->address) != 0) {
					free(connected_host_details.hostname);
					connected_host_details.hostname = strdup(parent->address);
				}
			}
			else {
				connected_host_details.hostname = strdup(parent->address);
			}

			if (connected_host_details.ip) {
				if (strcmp(connected_host_details.ip, res_ip.c_str()) != 0) {
					free(connected_host_details.ip);
					connected_host_details.ip = strdup(res_ip.c_str());
				}
			}
			else {
				connected_host_details.ip = strdup(res_ip.c_str());
			}

			host_ip = connected_host_details.ip;
		}
		else {
			host_ip = parent->address;
		}

		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, host_ip, userinfo->username, auth_password, userinfo->schemaname, parent->port, NULL, client_flags);
	} else {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, "localhost", userinfo->username, auth_password, userinfo->schemaname, parent->port, parent->address, client_flags);
	}
	fd=mysql_get_socket(mysql);
//	{
//		// FIXME: THIS IS FOR TESTING PURPOSE ONLY
//		// DO NOT ENABLE THIS CODE FOR PRODUCTION USE
//		// we drastically reduce the receive buffer to make sure that
//		// mysql_stmt_store_result_[start|continue] doesn't complete
//		// in a single call
//		int rcvbuf = 10240;
//		if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
//			proxy_error("Failed to call setsockopt\n");
//			exit(EXIT_FAILURE);
//		}
//	}
}

void MySQL_Connection::connect_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_real_connect_cont(&ret_mysql, mysql, mysql_status(event, true));
}

void MySQL_Connection::change_user_start() {
	PROXY_TRACE();
	//fprintf(stderr,"change_user_start FD %d\n", fd);
	MySQL_Connection_userinfo *_ui = NULL;
	if (myds->sess->client_myds == NULL) {
		// if client_myds is not defined, we are using CHANGE_USER to reset the connection
		_ui = userinfo;
	} else {
		_ui = myds->sess->client_myds->myconn->userinfo;
		userinfo->set(_ui);	// fix for bug #605
	}
	char *auth_password=NULL;
	if (userinfo->password) {
		if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
			auth_password=userinfo->sha1_pass;
		} else {
			auth_password=userinfo->password;
		}
	}
	// we first reset the charset to a default one.
	// this to solve the problem described here:
	// https://github.com/sysown/proxysql/pull/3249#issuecomment-761887970
	if (mysql->charset->nr >= 255)
		mysql_options(mysql, MYSQL_SET_CHARSET_NAME, mysql->charset->csname);
	async_exit_status = mysql_change_user_start(&ret_bool,mysql,_ui->username, auth_password, _ui->schemaname);
}

void MySQL_Connection::change_user_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_change_user_cont(&ret_bool, mysql, mysql_status(event, true));
}

void MySQL_Connection::ping_start() {
	PROXY_TRACE();
	//fprintf(stderr,"ping_start FD %d\n", fd);
	async_exit_status = mysql_ping_start(&interr,mysql);
}

void MySQL_Connection::ping_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	//fprintf(stderr,"ping_cont FD %d, event %d\n", fd, event);
	async_exit_status = mysql_ping_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::initdb_start() {
	PROXY_TRACE();
	MySQL_Connection_userinfo *client_ui=myds->sess->client_myds->myconn->userinfo;
	async_exit_status = mysql_select_db_start(&interr,mysql,client_ui->schemaname);
}

void MySQL_Connection::initdb_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_select_db_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_option_start() {
	PROXY_TRACE();

	enum_mysql_set_option set_option;
	set_option=((options.client_flag & CLIENT_MULTI_STATEMENTS) ? MYSQL_OPTION_MULTI_STATEMENTS_ON : MYSQL_OPTION_MULTI_STATEMENTS_OFF);
	async_exit_status = mysql_set_server_option_start(&interr,mysql,set_option);
}

void MySQL_Connection::set_option_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_server_option_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_autocommit_start() {
	PROXY_TRACE();
	async_exit_status = mysql_autocommit_start(&ret_bool, mysql, options.autocommit);
}

void MySQL_Connection::set_autocommit_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_autocommit_cont(&ret_bool, mysql, mysql_status(event, true));
}

void MySQL_Connection::set_names_start() {
	PROXY_TRACE();
	const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(atoi(mysql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
	if (!c) {
		// LCOV_EXCL_START
		proxy_error("Not existing charset number %u\n", atoi(mysql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
		assert(0);
		// LCOV_EXCL_STOP
	}
	async_exit_status = mysql_set_character_set_start(&interr,mysql, NULL, atoi(mysql_variables.client_get_value(myds->sess, SQL_CHARACTER_SET)));
}

void MySQL_Connection::set_names_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_character_set_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_query(char *stmt, unsigned long length) {
	query.length=length;
	query.ptr=stmt;
	if (length > largest_query_length) {
		largest_query_length=length;
	}
	if (query.stmt) {
		query.stmt=NULL;
	}
}

void MySQL_Connection::real_query_start() {
	PROXY_TRACE();
	async_exit_status = mysql_real_query_start(&interr , mysql, query.ptr, query.length);
}

void MySQL_Connection::real_query_cont(short event) {
	if (event == 0) return;
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_real_query_cont(&interr ,mysql , mysql_status(event, true));
}

void MySQL_Connection::stmt_prepare_start() {
	PROXY_TRACE();
	query.stmt=mysql_stmt_init(mysql);
	my_bool my_arg=true;
	mysql_stmt_attr_set(query.stmt, STMT_ATTR_UPDATE_MAX_LENGTH, &my_arg);
	async_exit_status = mysql_stmt_prepare_start(&interr , query.stmt, query.ptr, query.length);
}

void MySQL_Connection::stmt_prepare_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_prepare_cont(&interr , query.stmt , mysql_status(event, true));
}

void MySQL_Connection::stmt_execute_start() {
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

void MySQL_Connection::stmt_execute_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_execute_cont(&interr , query.stmt , mysql_status(event, true));
}

void MySQL_Connection::stmt_execute_store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_stmt_store_result_start(&interr, query.stmt);
}

void MySQL_Connection::stmt_execute_store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_store_result_cont(&interr , query.stmt , mysql_status(event, true));
}

#ifndef PROXYSQL_USE_RESULT
void MySQL_Connection::store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_store_result_start(&mysql_result, mysql);
}

void MySQL_Connection::store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_store_result_cont(&mysql_result , mysql , mysql_status(event, true));
}
#endif // PROXYSQL_USE_RESULT

void MySQL_Connection::set_is_client() {
	local_stmts->set_is_client(myds->sess);
}

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

MDB_ASYNC_ST MySQL_Connection::handler(short event) {
	unsigned long long processed_bytes=0;	// issue #527 : this variable will store the amount of bytes processed during this event
	if (mysql==NULL) {
		// it is the first time handler() is being called
		async_state_machine=ASYNC_CONNECT_START;
		myds->wait_until=myds->sess->thread->curtime+mysql_thread___connect_timeout_server*1000;
		if (myds->max_connect_time) {
			if (myds->wait_until > myds->max_connect_time) {
				myds->wait_until = myds->max_connect_time;
			}
		}
	}
handler_again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"async_state_machine=%d\n", async_state_machine);
	switch (async_state_machine) {
		case ASYNC_CONNECT_START:
			connect_start();
			if (async_exit_status) {
				next_event(ASYNC_CONNECT_CONT);
			} else {
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
			break;
		case ASYNC_CONNECT_END:
			if (myds) {
				if (myds->sess) {
					if (myds->sess->thread) {
						unsigned long long curtime = monotonic_time();
						myds->sess->thread->atomic_curtime=curtime;
					}
				}
			}
			if (!ret_mysql) {
				// always increase the counter
				proxy_error("Failed to mysql_real_connect() on %u:%s:%d , FD (Conn:%d , MyDS:%d) , %d: %s.\n", parent->myhgc->hid, parent->address, parent->port, mysql->net.fd , myds->fd, mysql_errno(mysql), mysql_error(mysql));
    		NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
			} else {
    		NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
			}
    	break;
		case ASYNC_CONNECT_SUCCESSFUL:
			if (mysql && ret_mysql) {
				// PMC-10005
				// we handle encryption for backend
				//
				// we have a similar code in MySQL_Data_Stream::attach_connection()
				// see there for further details
				if (mysql->options.use_ssl == 1)
					if (myds)
						if (myds->sess != NULL)
							if (myds->sess->session_fast_forward == true) {
								assert(myds->ssl==NULL);
								if (myds->ssl == NULL) {
									// check the definition of P_MARIADB_TLS
									P_MARIADB_TLS * matls = (P_MARIADB_TLS *)mysql->net.pvio->ctls;
									if (matls != NULL) {
										myds->encrypted = true;
										myds->ssl = (SSL *)matls->ssl;
										myds->rbio_ssl = BIO_new(BIO_s_mem());
										myds->wbio_ssl = BIO_new(BIO_s_mem());
										SSL_set_bio(myds->ssl, myds->rbio_ssl, myds->wbio_ssl);
									} else {
										// if mysql->options.use_ssl == 1 but matls == NULL
										// it means that ProxySQL tried to use SSL to connect to the backend
										// but the backend didn't support SSL
									}
								}
							}
			}
			__sync_fetch_and_add(&MyHGM->status.server_connections_connected,1);
			__sync_fetch_and_add(&parent->connect_OK,1);
			options.client_flag = mysql->client_flag;
			//assert(mysql->net.vio->async_context);
			//mysql->net.vio->async_context= mysql->options.extension->async_context;
			//if (parent->use_ssl) {
			{
				// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
				mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
				int f=fcntl(mysql->net.fd, F_GETFL);
#ifdef FD_CLOEXEC
				// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
				fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK|FD_CLOEXEC);
#else
				fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK);
#endif /* FD_CLOEXEC */
			}
			//if (parent->use_ssl) {
				// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
				//mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
				//ioctl_FIONBIO(mysql->net.fd,1);
				//vio_blocking(mysql->net.vio, FALSE, 0);
				//fcntl(mysql->net.vio->sd, F_SETFL, O_RDWR|O_NONBLOCK);
			//}
			MySQL_Monitor::dns_cache_update_socket(mysql->host, mysql->net.fd);
			break;
		case ASYNC_CONNECT_FAILED:
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			parent->connect_error(mysql_errno(mysql));
			break;
		case ASYNC_CONNECT_TIMEOUT:
			//proxy_error("Connect timeout on %s:%d : %llu - %llu = %llu\n",  parent->address, parent->port, myds->sess->thread->curtime , myds->wait_until, myds->sess->thread->curtime - myds->wait_until);
			proxy_error("Connect timeout on %s:%d : exceeded by %lluus\n", parent->address, parent->port, myds->sess->thread->curtime - myds->wait_until);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			parent->connect_error(mysql_errno(mysql));
			break;
		case ASYNC_CHANGE_USER_START:
			change_user_start();
			if (async_exit_status) {
				next_event(ASYNC_CHANGE_USER_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_END);
			}
			break;
		case ASYNC_CHANGE_USER_CONT:
			assert(myds->sess->status==CHANGING_USER_SERVER || myds->sess->status==RESETTING_CONNECTION);
			change_user_cont(event);
			if (async_exit_status) {
				if (myds->sess->thread->curtime >= myds->wait_until) {
					NEXT_IMMEDIATE(ASYNC_CHANGE_USER_TIMEOUT);
				} else {
					next_event(ASYNC_CHANGE_USER_CONT);
				}
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_END);
			}
			break;
		case ASYNC_CHANGE_USER_END:
			if (ret_bool) {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_SUCCESSFUL);
			}
			break;
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			mysql->server_status = SERVER_STATUS_AUTOCOMMIT; // we reset this due to bug https://jira.mariadb.org/browse/CONC-332
			break;
		case ASYNC_CHANGE_USER_FAILED:
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			break;
		case ASYNC_PING_START:
			ping_start();
			if (async_exit_status) {
				next_event(ASYNC_PING_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_END);
			}
			break;
		case ASYNC_PING_CONT:
			assert(myds->sess->status==PINGING_SERVER);
			if (event) {
				ping_cont(event);
			}
			if (async_exit_status) {
				if (myds->sess->thread->curtime >= myds->wait_until) {
					NEXT_IMMEDIATE(ASYNC_PING_TIMEOUT);
				} else {
					next_event(ASYNC_PING_CONT);
				}
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_END);
			}
			break;
		case ASYNC_PING_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_PING_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_SUCCESSFUL);
			}
			break;
		case ASYNC_PING_SUCCESSFUL:
			break;
		case ASYNC_PING_FAILED:
			break;
		case ASYNC_PING_TIMEOUT:
			break;
		case ASYNC_QUERY_START:
			real_query_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.length);
			statuses.questions++;
			myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_sent]+=query.length;
			myds->bytes_info.bytes_sent += query.length;
			bytes_info.bytes_sent += query.length;
			if (myds->sess->with_gtid == true) {
				__sync_fetch_and_add(&parent->queries_gtid_sync,1);
			}
			if (async_exit_status) {
				next_event(ASYNC_QUERY_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;
		case ASYNC_QUERY_CONT:
			real_query_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_QUERY_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_STMT_PREPARE_START:
			stmt_prepare_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.length);
			myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_sent]+=query.length;
			myds->bytes_info.bytes_sent += query.length;
			bytes_info.bytes_sent += query.length;
			if (async_exit_status) {
				next_event(ASYNC_STMT_PREPARE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			break;
		case ASYNC_STMT_PREPARE_CONT:
			stmt_prepare_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STMT_PREPARE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			break;

		case ASYNC_STMT_PREPARE_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_SUCCESSFUL);
			}
			break;
		case ASYNC_STMT_PREPARE_SUCCESSFUL:
			break;
		case ASYNC_STMT_PREPARE_FAILED:
			break;

		case ASYNC_STMT_EXECUTE_START:
			PROXY_TRACE2();
			stmt_execute_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.stmt_meta->size);
			myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_sent]+=query.stmt_meta->size;
			myds->bytes_info.bytes_sent += query.stmt_meta->size;
			bytes_info.bytes_sent += query.stmt_meta->size;
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_STORE_RESULT_START);
			}
			break;
		case ASYNC_STMT_EXECUTE_CONT:
			PROXY_TRACE2();
			stmt_execute_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_STORE_RESULT_START);
			}
			break;

		case ASYNC_STMT_EXECUTE_STORE_RESULT_START:
			PROXY_TRACE2();
			if (mysql_stmt_errno(query.stmt)) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			{
				query.stmt_result=mysql_stmt_result_metadata(query.stmt);
				if (query.stmt_result==NULL) {
					NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
				} else {
					if (myds->sess->mirror==false) {
						if (MyRS_reuse == NULL) {
							MyRS = new MySQL_ResultSet();
							MyRS->init(&myds->sess->client_myds->myprot, query.stmt_result, mysql, query.stmt);
						} else {
							MyRS = MyRS_reuse;
							MyRS_reuse = NULL;
							MyRS->init(&myds->sess->client_myds->myprot, query.stmt_result, mysql, query.stmt);
						}
					} else {
/*
						// we do not support mirroring with prepared statements
						if (MyRS_reuse == NULL) {
							MyRS = new MySQL_ResultSet();
							MyRS->init(NULL, mysql_result, mysql);
						} else {
							MyRS = MyRS_reuse;
							MyRS_reuse = NULL;
							MyRS->init(NULL, mysql_result, mysql);
						}
*/
					}
					//async_fetch_row_start=false;
				}
			}
			stmt_execute_store_result_start();
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			break;
		case ASYNC_STMT_EXECUTE_STORE_RESULT_CONT:
			PROXY_TRACE2();
			{ // this copied mostly from ASYNC_USE_RESULT_CONT
				if (myds->sess && myds->sess->client_myds && myds->sess->mirror==false) {
					unsigned int buffered_data=0;
					buffered_data = myds->sess->client_myds->PSarrayOUT->len * RESULTSET_BUFLEN;
					buffered_data += myds->sess->client_myds->resultset->len * RESULTSET_BUFLEN;
					if (buffered_data > (unsigned int)mysql_thread___threshold_resultset_size*8) {
						next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT); // we temporarily pause . See #1232
						break;
					}
				}
			}
			stmt_execute_store_result_cont(event);
			//if (async_fetch_row_start==false) {
			//	async_fetch_row_start=true;
			//}
			if (async_exit_status) {
				// this copied mostly from ASYNC_USE_RESULT_CONT
				MYSQL_ROWS *r=query.stmt->result.data;
				long long unsigned int rows_read_inner = 0;

				if (r) {
					rows_read_inner++;
					while(rows_read_inner < query.stmt->result.rows) {
						// it is very important to check rows_read_inner FIRST
						// because r->next could point to an invalid memory
						rows_read_inner++;
						r = r->next;
					}
					if (rows_read_inner > 1) {
						process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT(processed_bytes);
						if (
							(processed_bytes > (unsigned int)mysql_thread___threshold_resultset_size*8)
								||
							( mysql_thread___throttle_ratio_server_to_client && mysql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)mysql_thread___throttle_max_bytes_per_second_to_client/10*(unsigned long long)mysql_thread___throttle_ratio_server_to_client) )
						) {
							next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT); // we temporarily pause
						} else {
							NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT); // we continue looping
						}
					}
				}
				next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			break;
		case ASYNC_STMT_EXECUTE_END:
			PROXY_TRACE2();
			{
				if (query.stmt_result) {
					unsigned long long total_size=0;
					MYSQL_ROWS *r=query.stmt->result.data;
					if (r) {
						total_size+=r->length;
						if (r->length > 0xFFFFFF) {
							total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
						}
						total_size+=sizeof(mysql_hdr);
						while(r->next) {
							r=r->next;
							total_size+=r->length;
							if (r->length > 0xFFFFFF) {
								total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
							}
							total_size+=sizeof(mysql_hdr);
						}
					}
					__sync_fetch_and_add(&parent->bytes_recv,total_size);
					myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv]+=total_size;
					myds->bytes_info.bytes_recv += total_size;
					bytes_info.bytes_recv += total_size;
				}
			}
/*
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_SUCCESSFUL);
			}
*/
			break;
//		case ASYNC_STMT_EXECUTE_SUCCESSFUL:
//			break;
//		case ASYNC_STMT_EXECUTE_FAILED:
//			break;

		case ASYNC_NEXT_RESULT_START:
			async_exit_status = mysql_next_result_start(&interr, mysql);
			if (async_exit_status) {
				next_event(ASYNC_NEXT_RESULT_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_NEXT_RESULT_CONT:
			if (event) {
				async_exit_status = mysql_next_result_cont(&interr, mysql, mysql_status(event, true));
			}
			if (async_exit_status) {
				next_event(ASYNC_NEXT_RESULT_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_NEXT_RESULT_END:
			break;
#ifndef PROXYSQL_USE_RESULT
		case ASYNC_STORE_RESULT_START:
			if (mysql_errno(mysql)) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			store_result_start();
			if (async_exit_status) {
				next_event(ASYNC_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			break;
		case ASYNC_STORE_RESULT_CONT:
			store_result_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			break;
#endif // PROXYSQL_USE_RESULT
		case ASYNC_USE_RESULT_START:
			if (mysql_errno(mysql)) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			mysql_result=mysql_use_result(mysql);
			if (mysql_result==NULL) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			} else {
				if (myds->sess->mirror==false) {
					if (MyRS_reuse == NULL) {
						MyRS = new MySQL_ResultSet();
						MyRS->init(&myds->sess->client_myds->myprot, mysql_result, mysql);
					} else {
						MyRS = MyRS_reuse;
						MyRS_reuse = NULL;
						MyRS->init(&myds->sess->client_myds->myprot, mysql_result, mysql);
					}
				} else {
					if (MyRS_reuse == NULL) {
						MyRS = new MySQL_ResultSet();
						MyRS->init(NULL, mysql_result, mysql);
					} else {
						MyRS = MyRS_reuse;
						MyRS_reuse = NULL;
						MyRS->init(NULL, mysql_result, mysql);
					}
				}
				async_fetch_row_start=false;
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
			}
			break;
		case ASYNC_USE_RESULT_CONT:
			{
				if (myds->sess && myds->sess->client_myds && myds->sess->mirror==false &&
					myds->sess->status != SHOW_WARNINGS) { // see issue#4072
					unsigned int buffered_data=0;
					buffered_data = myds->sess->client_myds->PSarrayOUT->len * RESULTSET_BUFLEN;
					buffered_data += myds->sess->client_myds->resultset->len * RESULTSET_BUFLEN;
					if (buffered_data > (unsigned int)mysql_thread___threshold_resultset_size*8) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause . See #1232
						break;
					}
				}
			}
			if (async_fetch_row_start==false) {
				async_exit_status=mysql_fetch_row_start(&mysql_row,mysql_result);
				async_fetch_row_start=true;
			} else {
				async_exit_status=mysql_fetch_row_cont(&mysql_row,mysql_result, mysql_status(event, true));
			}
			if (async_exit_status) {
				next_event(ASYNC_USE_RESULT_CONT);
			} else {
				async_fetch_row_start=false;
				if (mysql_row) {
					if (myds && myds->sess && myds->sess->status == SHOW_WARNINGS) {
						if (mysql_thread___verbose_query_error) {
							MySQL_Data_Stream* client_myds = myds->sess->client_myds;
							const char* username = "";
							const char* schema = "";
							const char* client_addr = "";
							const char* digest_text = myds->sess->CurrentQuery.show_warnings_prev_query_digest.c_str();

							if (client_myds) {
								client_addr = client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown";

								if (client_myds->myconn && client_myds->myconn->userinfo) {
									username = client_myds->myconn->userinfo->username;
									schema = client_myds->myconn->userinfo->schemaname;
								}
							}

							proxy_warning(
								"Warning during query on (%d,%s,%d,%lu). User '%s@%s', schema '%s', digest_text '%s', level '%s', code '%s', message '%s'\n",
								parent->myhgc->hid, parent->address, parent->port, get_mysql_thread_id(), username, client_addr,
								schema, digest_text, mysql_row[0], mysql_row[1], mysql_row[2]
							);
						} else {
							proxy_warning(
								"Warning during query on (%d,%s,%d,%lu). Level '%s', code '%s', message '%s'\n",
								parent->myhgc->hid, parent->address, parent->port, get_mysql_thread_id(), mysql_row[0], mysql_row[1],
								mysql_row[2]
							);
						}
					}
					unsigned int br=MyRS->add_row(mysql_row);
					__sync_fetch_and_add(&parent->bytes_recv,br);
					myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv]+=br;
					myds->bytes_info.bytes_recv += br;
					bytes_info.bytes_recv += br;
					processed_bytes+=br;	// issue #527 : this variable will store the amount of bytes processed during this event
					if (
						(processed_bytes > (unsigned int)mysql_thread___threshold_resultset_size*8)
							||
						( mysql_thread___throttle_ratio_server_to_client && mysql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)mysql_thread___throttle_max_bytes_per_second_to_client/10*(unsigned long long)mysql_thread___throttle_ratio_server_to_client) )
					) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					} else {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping
					}
				} else {
					if (mysql) {
						int _myerrno=mysql_errno(mysql);
						if (_myerrno) {
							if (myds) {
								MyRS->add_err(myds);
								NEXT_IMMEDIATE(ASYNC_QUERY_END);
							}
						}
					}
					// we reach here if there was no error
					MyRS->add_eof();
					NEXT_IMMEDIATE(ASYNC_QUERY_END);
				}
			}
			break;
		case ASYNC_QUERY_END:
			PROXY_TRACE2();
			if (mysql) {
				int _myerrno=mysql_errno(mysql);
				if (_myerrno == 0) {
					unknown_transaction_status = false;
				} else {
					compute_unknown_transaction_status();
				}
				if (_myerrno < 2000) {
					// we can continue only if the error is coming from the backend.
					// (or if zero)
					// if the error comes from the client library, something terribly
					// wrong happened and we cannot continue
					if (mysql->server_status & SERVER_MORE_RESULTS_EXIST) {
						async_state_machine=ASYNC_NEXT_RESULT_START;
					}
				}
			}
			if (mysql_result) {
				mysql_free_result(mysql_result);
				mysql_result=NULL;
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_START:
			set_autocommit_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_AUTOCOMMIT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_END);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_CONT:
			set_autocommit_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_AUTOCOMMIT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_END);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_END:
			if (ret_bool) {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			options.last_set_autocommit = ( options.autocommit ? 1 : 0 ) ; // we successfully set autocommit
			if ((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) && options.autocommit==false) {
				proxy_warning("It seems we are hitting bug http://bugs.mysql.com/bug.php?id=66884\n");
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			//fprintf(stderr,"%s\n",mysql_error(mysql));
			proxy_error("Failed SET AUTOCOMMIT: %s\n",mysql_error(mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			break;
		case ASYNC_SET_NAMES_START:
			set_names_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_NAMES_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_END);
			}
			break;
		case ASYNC_SET_NAMES_CONT:
			set_names_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_NAMES_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_END);
			}
			break;
		case ASYNC_SET_NAMES_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_NAMES_SUCCESSFUL:
			break;
		case ASYNC_SET_NAMES_FAILED:
			//fprintf(stderr,"%s\n",mysql_error(mysql));
			proxy_error("Failed SET NAMES: %s\n",mysql_error(mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			break;
		case ASYNC_INITDB_START:
			initdb_start();
			if (async_exit_status) {
				next_event(ASYNC_INITDB_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_END);
			}
			break;
		case ASYNC_INITDB_CONT:
			initdb_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_INITDB_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_END);
			}
			break;
		case ASYNC_INITDB_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_INITDB_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_SUCCESSFUL);
			}
			break;
		case ASYNC_INITDB_SUCCESSFUL:
			break;
		case ASYNC_INITDB_FAILED:
			proxy_error("Failed INITDB: %s\n",mysql_error(mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			//fprintf(stderr,"%s\n",mysql_error(mysql));
			break;
		case ASYNC_SET_OPTION_START:
			set_option_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_OPTION_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_END);
			}
			break;
		case ASYNC_SET_OPTION_CONT:
			set_option_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_OPTION_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_END);
			}
			break;
		case ASYNC_SET_OPTION_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_OPTION_SUCCESSFUL:
			break;
		case ASYNC_SET_OPTION_FAILED:
			proxy_error("Error setting MYSQL_OPTION_MULTI_STATEMENTS : %s\n", mysql_error(mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, parent->myhgc->hid, parent->address, parent->port, mysql_errno(mysql));
			break;

		default:
			// LCOV_EXCL_START
			assert(0); //we should never reach here
			break;
			// LCOV_EXCL_STOP
		}
	return async_state_machine;
}

void MySQL_Connection::process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT(unsigned long long& processed_bytes) {
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

void MySQL_Connection::next_event(MDB_ASYNC_ST new_st) {
#ifdef DEBUG
	int fd;
#endif /* DEBUG */
	wait_events=0;

	if (async_exit_status & MYSQL_WAIT_READ)
		wait_events |= POLLIN;
	if (async_exit_status & MYSQL_WAIT_WRITE)
		wait_events|= POLLOUT;
	if (wait_events)
#ifdef DEBUG
		fd= mysql_get_socket(mysql);
#else
		mysql_get_socket(mysql);
#endif /* DEBUG */
	else
#ifdef DEBUG
		fd= -1;
#endif /* DEBUG */
	if (async_exit_status & MYSQL_WAIT_TIMEOUT) {
	timeout=10000;
	//tv.tv_sec= 0;
	//tv.tv_usec= 10000;
      //ptv= &tv;
	} else {
      //ptv= NULL;
	}
    //event_set(ev_mysql, fd, wait_event, state_machine_handler, this);
    //if (ev_mysql==NULL) {
    //  ev_mysql=event_new(base, fd, wait_event, state_machine_handler, this);
      //event_add(ev_mysql, ptv);
	//}
    //event_del(ev_mysql);
    //event_assign(ev_mysql, base, fd, wait_event, state_machine_handler, this);
    //event_add(ev_mysql, ptv);
	proxy_debug(PROXY_DEBUG_NET, 8, "fd=%d, wait_events=%d , old_ST=%d, new_ST=%d\n", fd, wait_events, async_state_machine, new_st);
	async_state_machine = new_st;
};


int MySQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	if (mysql==NULL && async_state_machine!=ASYNC_CONNECT_START) {
		// LCOV_EXCL_START
		assert(0);
		// LCOV_EXCL_STOP
	}
	if (async_state_machine==ASYNC_IDLE) {
		myds->wait_until=0;
		return 0;
	}
	if (async_state_machine==ASYNC_CONNECT_SUCCESSFUL) {
		compute_unknown_transaction_status();
		async_state_machine=ASYNC_IDLE;
		myds->wait_until=0;
		creation_time = monotonic_time();
		return 0;
	}
	handler(event);
	switch (async_state_machine) {
		case ASYNC_CONNECT_SUCCESSFUL:
			compute_unknown_transaction_status();
			async_state_machine=ASYNC_IDLE;
			myds->wait_until=0;
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


bool MySQL_Connection::IsServerOffline() {
	bool ret=false;
	if (parent==NULL)
		return ret;
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(server_status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic==true && parent->shunned_and_kill_all_connections==true) // the server is SHUNNED due to a serious issue
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
	) {
		ret=true;
	}
	return ret;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt, stmt_execute_metadata_t *stmt_meta) {
	PROXY_TRACE();
	PROXY_TRACE2();
	assert(mysql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}
	switch (async_state_machine) {
		case ASYNC_QUERY_END:
			processing_multi_statement=false;	// no matter if we are processing a multi statement or not, we reached the end
			return 0;
			break;
		case ASYNC_IDLE:
			if (stmt_meta==NULL)
				set_query(stmt,length);
			async_state_machine=ASYNC_QUERY_START;
			if (_stmt) {
				query.stmt=*_stmt;
				if (stmt_meta==NULL) {
					async_state_machine=ASYNC_STMT_PREPARE_START;
				} else {
					if (query.stmt_meta==NULL) {
						query.stmt_meta=stmt_meta;
					}
					async_state_machine=ASYNC_STMT_EXECUTE_START;
				}
			}
		default:
			handler(event);
			break;
	}
	
	if (async_state_machine==ASYNC_QUERY_END) {
		PROXY_TRACE2();
		compute_unknown_transaction_status();
		if (mysql_errno(mysql)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_EXECUTE_END) {
		PROXY_TRACE2();
		query.stmt_meta=NULL;
		async_state_machine=ASYNC_QUERY_END;
		compute_unknown_transaction_status();
		if (mysql_stmt_errno(query.stmt)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_PREPARE_SUCCESSFUL || async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
		query.stmt_meta=NULL;
		compute_unknown_transaction_status();
		if (async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
			return -1;
		} else {
			*_stmt=query.stmt;
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


// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_ping(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_PING_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_PING_FAILED:
			return -1;
			break;
		case ASYNC_PING_TIMEOUT:
			return -2;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_PING_START;
		default:
			handler(event);
			break;
	}
	
	// check again
	switch (async_state_machine) {
		case ASYNC_PING_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
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

int MySQL_Connection::async_change_user(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			return -2;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_CHANGE_USER_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			return -2;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_select_db(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
		case ASYNC_INITDB_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_INITDB_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_INITDB_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_INITDB_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_INITDB_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_set_autocommit(short event, bool ac) {
	PROXY_TRACE();
	assert(mysql);
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

int MySQL_Connection::async_set_names(short event, unsigned int c) {
	PROXY_TRACE();
	assert(mysql);
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

int MySQL_Connection::async_set_option(short event, bool mask) {
	PROXY_TRACE();
	assert(mysql);
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

void MySQL_Connection::async_free_result() {
	PROXY_TRACE();
	assert(mysql);
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
		// because it is reset on destructor ( ~MySQL_Connection() )
		// therefore this section is skipped completely
		// this should prevent bug #1046
		if (query.stmt) {
			if (query.stmt->mysql) {
				if (query.stmt->mysql == mysql) { // extra check
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
// this is an attempt to mitigate MySQL bug https://bugs.mysql.com/bug.php?id=107875
bool MySQL_Connection::AutocommitFalse_AndSavepoint() {
	bool ret=false;
	if (IsAutoCommit() == false) {
		if (get_status(STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT) == true) {
			ret = true;
		}
	}
	return ret;
}

bool MySQL_Connection::IsActiveTransaction() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_IN_TRANS);
		if (ret == false && (mysql)->net.last_errno && unknown_transaction_status == true) {
			ret = true;
		}
		if (ret == false) {
			//bool r = ( mysql_thread___autocommit_false_is_transaction || mysql_thread___forward_autocommit ); // deprecated , see #3253
			bool r = ( mysql_thread___autocommit_false_is_transaction);
			if ( r && (IsAutoCommit() == false) ) {
				ret = true;
			}
		}
		// in the past we were incorrectly checking STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT
		// and returning true in case there were any savepoint.
		// Although flag STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT was not reset in
		// case of no transaction, thus the check was incorrect.
		// We can ignore STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT for multiplexing
		// purpose in IsActiveTransaction() because it is also checked
		// in MultiplexDisabled()
	}
	return ret;
}


bool MySQL_Connection::IsAutoCommit() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
		if (ret) {
			if (options.last_set_autocommit==0) {
				// it seems we hit bug http://bugs.mysql.com/bug.php?id=66884
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

bool MySQL_Connection::MultiplexDisabled(bool check_delay_token) {
// status_flags stores information about the status of the connection
// can be used to determine if multiplexing can be enabled or not
	bool ret=false;
	if (status_flags & (STATUS_MYSQL_CONNECTION_TRANSACTION|STATUS_MYSQL_CONNECTION_USER_VARIABLE|STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT|STATUS_MYSQL_CONNECTION_LOCK_TABLES|STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE|STATUS_MYSQL_CONNECTION_GET_LOCK|STATUS_MYSQL_CONNECTION_NO_MULTIPLEX|STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0|STATUS_MYSQL_CONNECTION_FOUND_ROWS|STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG|STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT) ) {
		ret=true;
	}
	if (check_delay_token && auto_increment_delay_token) return true;
	return ret;
}

bool MySQL_Connection::IsKeepMultiplexEnabledVariables(char *query_digest_text) {
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
	unsigned long keep_multiplexing_variables_len=strlen(mysql_thread___keep_multiplexing_variables);
	keep_multiplexing_variables_tmp=(char*)malloc(keep_multiplexing_variables_len+1);
	memcpy(keep_multiplexing_variables_tmp, mysql_thread___keep_multiplexing_variables, keep_multiplexing_variables_len);
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

void MySQL_Connection::ProcessQueryAndSetStatusFlags(char *query_digest_text) {
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
	if (get_status(STATUS_MYSQL_CONNECTION_USER_VARIABLE)==false) { // we search for variables only if not already set
//			if (
//				strncasecmp(query_digest_text,"SELECT @@tx_isolation", strlen("SELECT @@tx_isolation"))
//				&&
//				strncasecmp(query_digest_text,"SELECT @@version", strlen("SELECT @@version"))
		if (strncasecmp(query_digest_text,"SET ",4)==0) {
			// For issue #555 , multiplexing is disabled if --safe-updates is used (see session_vars definition)
			int sqloh = mysql_thread___set_query_lock_on_hostgroup;
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
		if (mysql) {
			if (
				(mysql->server_status & SERVER_STATUS_IN_TRANS)
				||
				((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) == 0)
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
				(mysql->server_status & SERVER_STATUS_AUTOCOMMIT)
				&&
				( (mysql->server_status & SERVER_STATUS_IN_TRANS) == 0 )
			)
			||
			(strcasecmp(query_digest_text,"COMMIT") == 0)
			||
			(strcasecmp(query_digest_text,"ROLLBACK") == 0)
		) {
			set_status(false, STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT);
		}
	}
	if (mysql) {
		if (myds && myds->sess) {
			if (myds->sess->client_myds && myds->sess->client_myds->myconn) {
				// if SERVER_STATUS_NO_BACKSLASH_ESCAPES is changed it is likely
				// because of sql_mode was changed
				// we set the same on the client connection
				unsigned int ss = mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				myds->sess->client_myds->myconn->set_no_backslash_escapes(ss);
			}
		}
	}
}

void MySQL_Connection::optimize() {
	if (mysql->net.max_packet > 65536) { // FIXME: temporary, maybe for very long time . This needs to become a global variable
		if ( ( mysql->net.buff == mysql->net.read_pos ) &&  ( mysql->net.read_pos == mysql->net.write_pos ) ) {
			free(mysql->net.buff);
			mysql->net.max_packet=8192;
			mysql->net.buff=(unsigned char *)malloc(mysql->net.max_packet);
			memset(mysql->net.buff,0,mysql->net.max_packet);
			mysql->net.read_pos=mysql->net.buff;
			mysql->net.write_pos=mysql->net.buff;
			mysql->net.buff_end=mysql->net.buff+mysql->net.max_packet;
		}
	}
}

// close_mysql() is a replacement for mysql_close()
// if avoids that a QUIT command stops forever
// FIXME: currently doesn't support encryption and compression
void MySQL_Connection::close_mysql() {
	if ((send_quit) && (mysql->net.pvio) && ret_mysql) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=mysql->net.fd;
#ifdef __APPLE__
		int arg_on=1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
		send(fd, buff, 5, 0);
#else
		send(fd, buff, 5, MSG_NOSIGNAL);
#endif
	}
//	int rc=0;
	mysql_close_no_command(mysql);
}


// this function is identical to async_query() , with the only exception that MyRS should never be set
int MySQL_Connection::async_send_simple_command(short event, char *stmt, unsigned long length) {
	PROXY_TRACE();
	assert(mysql);
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
		// A common issue for triggering this error is to have configure mysql-init_connect to
		// run a statement that returns a resultset.
		proxy_error2(10003, "PMC-10003: Retrieved a resultset while running a simple command. This is an error!! Simple command: %s\n", stmt);
		return -2;
	}
	if (async_state_machine==ASYNC_QUERY_END) {
		compute_unknown_transaction_status();
		if (mysql_errno(mysql)) {
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

void MySQL_Connection::reset() {
	bool old_no_multiplex_hg = get_status(STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
	status_flags=0;
	// reconfigure STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG
	set_status(old_no_multiplex_hg,STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
	reusable=true;
	options.last_set_autocommit=-1; // never sent

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

bool MySQL_Connection::get_gtid(char *buff, uint64_t *trx_id) {
	// note: current implementation for for OWN GTID only!
	bool ret = false;
	if (buff==NULL || trx_id == NULL) {
		return ret;
	}
	if (mysql) {
		if (mysql->net.last_errno==0) { // only if there is no error
			if (mysql->server_status & SERVER_SESSION_STATE_CHANGED) { // only if status changed
				const char *data;
				size_t length;
				if (mysql_session_track_get_first(mysql, SESSION_TRACK_GTIDS, &data, &length) == 0) {
					if (length >= (sizeof(gtid_uuid) - 1)) {
						length = sizeof(gtid_uuid) - 1;
					}
					if (memcmp(gtid_uuid,data,length)) {
						// copy to local buffer in MySQL_Connection
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
