#include "proxysql.h"

extern pthread_key_t tsd_key;

static admin_sqlite_table_def_t table_defs[] = 
{
//	{ "server_status" , ADMIN_SQLITE_TABLE_SERVER_STATUS , ADMIN_SQLITE_DUMP_TABLE_SERVER_STATUS , {NULL, NULL, NULL}},
//	{ "servers" , ADMIN_SQLITE_TABLE_SERVERS , ADMIN_SQLITE_DUMP_TABLE_SERVERS , {NULL, NULL, NULL}},
//	{ "hostgroups" , ADMIN_SQLITE_TABLE_HOSTGROUPS , ADMIN_SQLITE_DUMP_TABLE_HOSTGROUPS , {NULL, NULL, NULL}}, 
//	{ "users" , ADMIN_SQLITE_TABLE_USERS , ADMIN_SQLITE_DUMP_TABLE_USERS, {NULL, NULL, NULL}},
//	{ "global_variables" , ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES , NULL, {NULL, NULL, NULL}},
//	{ "debug_levels" , ADMIN_SQLITE_TABLE_DEBUG_LEVELS , ADMIN_SQLITE_DUMP_TABLE_DEBUG_LEVELS , {NULL, NULL, NULL}},
//	{ "query_rules" , ADMIN_SQLITE_TABLE_QUERY_RULES , ADMIN_SQLITE_DUMP_TABLE_QUERY_RULES , {NULL, NULL, NULL}}
	{ "server_status" , ADMIN_SQLITE_TABLE_SERVER_STATUS }, 
	{ "servers" , ADMIN_SQLITE_TABLE_SERVERS },
	{ "hostgroups" , ADMIN_SQLITE_TABLE_HOSTGROUPS },
	{ "users" , ADMIN_SQLITE_TABLE_USERS }, 
	{ "default_hostgroups" , ADMIN_SQLITE_TABLE_DEFAULT_HOSTGROUPS },
	{ "global_variables" , ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES },
	{ "debug_levels" , ADMIN_SQLITE_TABLE_DEBUG_LEVELS },
	{ "query_rules" , ADMIN_SQLITE_TABLE_QUERY_RULES }
};


static admin_sqlite_table_def_t table_defs_statsdb[] =
{
	{ "query_stats", STATSDB_QUERY_STATS }
};
static admin_sqlite_table_def_t table_defs_debugdb[] =
{
	{ "debug_log", DEBUGDB_DEBUG_LOG }
};

static void __admin_sqlite3__validate_data(sqlite3 *db) {
	char *query;
	sqlite3_stmt *statement;
	int rc;
	query="SELECT 'Error in hostgroup ' || hostgroup_id || ' : Server ' || hostgroups.hostname || ' port ' || hostgroups.port || ' does not exist in servers table' FROM hostgroups LEFT OUTER JOIN servers ON hostgroups.hostname=servers.hostname AND hostgroups.port=servers.port WHERE servers.hostname IS NULL";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	while((rc=sqlite3_step(statement))==SQLITE_ROW) {
		proxy_error("[ERROR]: %s\n", sqlite3_column_text(statement,0)); 
	}
	sqlite3_finalize(statement);
}


/*
static void __admin_sqlite3__load_table(admin_sqlite_table_def_t *td, sqlite3 *db, int offset){
	sqlite3_stmt *statement;
	int rc;
	if (td->dumps[offset]) {
		while(td->dumps[offset]->len) {
			char *a=g_ptr_array_remove_index_fast(td->dumps[offset],0);
			g_free(a);
		}
		g_ptr_array_free(td->dumps[offset],TRUE);
	}
	td->dumps[offset]=g_ptr_array_new();
	//fprintf(stderr,"%s\n",dumpcmd);
	if (td->dumpcmd) {
		rc=sqlite3_prepare_v2(db, td->dumpcmd, -1, &statement, 0);
		assert(rc==SQLITE_OK);
	  while((rc=sqlite3_step(statement))==SQLITE_ROW) {
			char *a=g_strdup((const char *)sqlite3_column_text(statement,0));
			g_ptr_array_add(td->dumps[offset],a);
		}
		sqlite3_finalize(statement);
	}
}

static void __admin_sqlite3__insert_table(admin_sqlite_table_def_t *td, sqlite3 *db, int offset){
	int i;
	if (td->dumps[offset]==NULL) return;
	for (i=0; i<td->dumps[offset]->len; i++) {
		char *a=g_ptr_array_index(td->dumps[offset],i);
		sqlite3_exec_exit_on_failure(db,a);
	}		
}
*/

static void __admin_sqlite3__insert_or_ignore_maintable_select_disktable() {
	sqlite3_exec_exit_on_failure(sqlite3admindb, "PRAGMA foreign_keys = OFF");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR IGNORE INTO main.servers SELECT * FROM disk.servers");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR IGNORE INTO main.hostgroups SELECT * FROM disk.hostgroups");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR IGNORE INTO main.query_rules SELECT * FROM disk.query_rules");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR IGNORE INTO main.users SELECT * FROM disk.users");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR IGNORE INTO main.default_hostgroups SELECT * FROM disk.default_hostgroups");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "PRAGMA foreign_keys = ON");
}

static void __admin_sqlite3__delete_disktable() {
	sqlite3_exec_exit_on_failure(sqlite3admindb, "DELETE FROM disk.servers");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "DELETE FROM disk.hostgroups");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "DELETE FROM disk.query_rules");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "DELETE FROM disk.users");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "DELETE FROM disk.default_hostgroups");
}

static void __admin_sqlite3__insert_or_replace_disktable_select_maintable() {
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR REPLACE INTO disk.servers SELECT * FROM main.servers");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR REPLACE INTO disk.hostgroups SELECT * FROM main.hostgroups");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR REPLACE INTO disk.query_rules SELECT * FROM main.query_rules");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR REPLACE INTO disk.users SELECT * FROM main.users");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "INSERT OR REPLACE INTO disk.default_hostgroups SELECT * FROM main.default_hostgroups");
}


int sqlite3_config_sync_mem_to_disk() {
	sqlite3_exec_exit_on_failure(sqlite3admindb, "PRAGMA foreign_keys = OFF");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "BEGIN");
	__admin_sqlite3__delete_disktable();
	__admin_sqlite3__insert_or_replace_disktable_select_maintable();
	sqlite3_exec_exit_on_failure(sqlite3admindb, "COMMIT");
	sqlite3_exec_exit_on_failure(sqlite3admindb, "PRAGMA foreign_keys = ON");
	return 0;
}


void mysql_pkt_err_from_sqlite(pkt *p, const char *s) {
	int l=strlen(s)+1+6;
	char *b=malloc(l);
	//if (b==NULL) { exit(EXIT_FAILURE); }
	assert(b!=NULL);
	b[l-1]='\0';
	// because we don't know the error from SQL we send ER_UNKNOWN_COM_ERROR
	sprintf(b,"%s%s","#08S01",s); 
	create_err_packet(p, 1, 1047, b);
	free(b);
}

int mysql_pkt_to_sqlite_exec(pkt *p, mysql_session_t *sess) {
	sqlite3 *db;
	sqlite3_stmt *statement;
	proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	if (thrLD->thread_id>glovars.mysql_threads) {
		db=sqlite3monitordb;
		sqlite3_exec_exit_on_failure(db,"PRAGMA query_only = ON");
	} else {
		db=sqlite3admindb;
	}
	//sqlite3 *db=sqlite3configdb;
//	sqlite3 *db; //=sqlite3admindb;
	//int rc;
	void *query=p->data+sizeof(mysql_hdr)+1;
	int length=p->length-sizeof(mysql_hdr)-1;
	char *query_copy=NULL;
	query_copy=malloc(length+1);
//	if (query_copy==NULL) { exit(EXIT_FAILURE); }
	assert(query_copy!=NULL);
	query_copy[length]='\0';
	memcpy(query_copy,query,length);
	proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: running query \"%s\"\n", query_copy);
	if(sqlite3_prepare_v2(db, query_copy, -1, &statement, 0) != SQLITE_OK) {
		pkt *ep=mypkt_alloc();
		mysql_pkt_err_from_sqlite(ep,sqlite3_errmsg(db));
		MY_SESS_ADD_PKT_OUT_CLIENT(ep);
		//l_ptr_array_add(sess->client_myds->output.pkts, ep);
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", query_copy, sqlite3_errmsg(db));
		free(query_copy);
		if (thrLD->thread_id>glovars.mysql_threads) { sqlite3_exec_exit_on_failure(db,"PRAGMA query_only = OFF"); }
		return 0;
	}
	int cols = sqlite3_column_count(statement);
	if (cols==0) {
		// not a SELECT
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: not a SELECT\n");
		int rc;
		pkt *p=mypkt_alloc();
		rc=sqlite3_step(statement);
		if (rc==SQLITE_DONE) {
			int affected_rows=sqlite3_changes(db);
			proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: %d rows affected\n", affected_rows);
			myproto_ok_pkt(p,1,affected_rows,0,2,0);
		} else {
			mysql_pkt_err_from_sqlite(p,sqlite3_errmsg(db));
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_step() running query \"%s\" : %s\n", query_copy, sqlite3_errmsg(db));
		}
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
		sqlite3_finalize(statement);
		free(query_copy);
		if (thrLD->thread_id>glovars.mysql_threads) { sqlite3_exec_exit_on_failure(db,"PRAGMA query_only = OFF"); }
		return 0;
	}
	{
		pkt *p=mypkt_alloc();
		myproto_column_count(p,1,cols);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);	
	}
	int col;
	for(col = 0; col < cols; col++) {
		// add empty spaces
		pkt *p=NULL;
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	{
		pkt *p=mypkt_alloc();
		myproto_eof(p,2+cols,0,34);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	int result = 0;
	int rownum = 0;
	int *maxcolsizes=g_slice_alloc0(sizeof(int)*cols);
	while ((result=sqlite3_step(statement))==SQLITE_ROW) {
		char **row=g_slice_alloc0(sizeof(char *)*cols);
		int *len=g_slice_alloc0(sizeof(int)*cols);
		int rowlen=0;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLite row %d :", rownum);
		for(col = 0; col < cols; col++) {
			//int t=sqlite3_column_type(statement, col);
			row[col]=(char *)sqlite3_column_text(statement, col);
			int l=sqlite3_column_bytes(statement, col);
			if (l==0) { // NULL
				l=1;
			} else {
				l+=lencint(l);
			}
			rowlen+=l;
			proxy_debug(PROXY_DEBUG_SQLITE, 6, "Col%d (%d,%d,%s) ", col, sqlite3_column_type(statement, col), l, row[col]);
		}
		pkt *p=mypkt_alloc();
		p->length=sizeof(mysql_hdr)+rowlen;
		//p->data=l_alloc(thrLD->sfp, p->length);
		p->data=l_alloc(p->length);
		//p->data=g_slice_alloc(p->length);
		mysql_hdr hdr;
		hdr.pkt_length=rowlen;
		hdr.pkt_id=cols+3+rownum;
		memcpy(p->data,&hdr,sizeof(mysql_hdr));
		int i=sizeof(mysql_hdr);
		for(col = 0; col < cols; col++) {
			row[col]=(char *)sqlite3_column_text(statement, col);
			//int l=sqlite3_column_bytes(statement, col);
			i+=writeencstrnull(p->data+i,row[col]);
		}
		proxy_debug(PROXY_DEBUG_SQLITE, 6, ". %d cols , %d bytes\n", cols, rowlen);
		g_slice_free1(sizeof(char *)*cols,row);
		g_slice_free1(sizeof(int)*cols,len);
		rownum++;
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	for(col = 0; col < cols; col++) {
		pkt *p=mypkt_alloc();
		const char *s=sqlite3_column_name(statement, col);
		myproto_column_def(p, col+2, "", "", "", s, "", 100, MYSQL_TYPE_VARCHAR, 0, 0);
		// this is a trick: insert at the end, and remove fast from the position we want to insert
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
		l_ptr_array_remove_index_fast(sess->client_myds->output.pkts,col+1);
	}
	{
		pkt *p=mypkt_alloc();
		myproto_eof(p,3+cols+rownum,0,34);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	
	g_slice_free1(sizeof(int)*cols,maxcolsizes);
	sqlite3_finalize(statement);
	free(query_copy);
	if (thrLD->thread_id>glovars.mysql_threads) { sqlite3_exec_exit_on_failure(db,"PRAGMA query_only = OFF"); }
	return 0;


}

/*
void sqlite3_exec_exit_on_failure(sqlite3 *db, const char *str) {
	char *err=NULL;
	sqlite3_exec(db, str, NULL, 0, &err);
	if(err!=NULL) {
		proxy_error("SQLITE error: %s --- %s\n", err, str);
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on %s : %s\n",str, err); 
		//exit(EXIT_FAILURE);
		assert(err==NULL);
	}
}
*/

void sqlite3_flush_servers_mem_to_db(sqlite3 *db, int replace) {
	sqlite3_stmt *statement;
	int i;
	int rc;	
	char *a=NULL;
	{
		a="SELECT COUNT(*) FROM server_status";
		rc=sqlite3_prepare_v2(db, a, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement);
		assert(rc==SQLITE_ROW);
		rc=sqlite3_column_int(statement,0);
		sqlite3_finalize(statement);
		if (rc==0) {
			sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (0, \"OFFLINE_HARD\")");
			sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (1, \"OFFLINE_SOFT\")");
			sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (2, \"SHUNNED\")");
			sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (3, \"ONLINE\")");
		}
	}
	{
		a="SELECT COUNT(*) FROM servers";
		rc=sqlite3_prepare_v2(db, a, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement);
		assert(rc==SQLITE_ROW);
		rc=sqlite3_column_int(statement,0);
		sqlite3_finalize(statement);
		if (rc==0) {
			char *query="INSERT INTO servers VALUES (?1 , ?2 , ?3 , ?4)";
			rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			for (i=0;i<glomysrvs.servers->len;i++) {
				mysql_server *ms=g_ptr_array_index(glomysrvs.servers,i);
				if (ms->status==MYSQL_SERVER_STATUS_ONLINE) {
					if (ms->read_only==0 || ms->read_only==1) {
						rc=sqlite3_bind_text(statement, 1, ms->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_int(statement, 2, ms->port); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_int(statement, 3, ms->read_only); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_int(statement, 4, ms->status); assert(rc==SQLITE_OK);
						rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
						rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
						rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
					}
				}
			}
			sqlite3_finalize(statement);
		}
		else {
			proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: table servers is already populated, ignoring whatever is in memory\n"); 
		}
	}
	{
		char *a="SELECT COUNT(*) FROM hostgroups";
		rc=sqlite3_prepare_v2(db, a, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement);
		assert(rc==SQLITE_ROW);
		rc=sqlite3_column_int(statement,0);
		sqlite3_finalize(statement);	
		if (rc==0) {
			char *query="INSERT INTO hostgroups VALUES (?1 , ?2 , ?3)";
			rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			//LPtrArray *sl0=l_ptr_array_index(glomysrvs.mysql_hostgroups,0);
			//LPtrArray *sl1=l_ptr_array_index(glomysrvs.mysql_hostgroups,1);
			for (i=0;i<glomysrvs.servers->len;i++) {
				mysql_server *ms=g_ptr_array_index(glomysrvs.servers,i);
				if (ms->status==MYSQL_SERVER_STATUS_ONLINE) {
					if (ms->read_only==0 || ms->read_only==1) {
						rc=sqlite3_bind_int(statement, 1, 1); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_text(statement, 2, ms->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_int(statement, 3, ms->port); assert(rc==SQLITE_OK);
						rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
						rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
						rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
					}
					if (ms->read_only==0) {
						rc=sqlite3_bind_int(statement, 1, 0); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_text(statement, 2, ms->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
						rc=sqlite3_bind_int(statement, 3, ms->port); assert(rc==SQLITE_OK);
						rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
						rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
						rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
					}
				}
			}
			sqlite3_finalize(statement);	
		}
	}
	
}

int sqlite3_flush_default_hostgroups_db_to_mem(sqlite3 *db) {
//	int i;
	int rc;
	int rownum=0;
	sqlite3_stmt *statement;

	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Resetting default hostgroups for MySQL\n");
	pthread_rwlock_wrlock(&gloDefHG.rwlock);

	gloDefHG.delete_all(&gloDefHG);
	
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 4, "Loading default hostgroups\n");
	rc=sqlite3_prepare_v2(db, "SELECT username, schemaname, hostgroup_id FROM default_hostgroups", -1, &statement, 0); assert(rc==SQLITE_OK);
	while ((rc=sqlite3_step(statement))==SQLITE_ROW) {
		rownum++;
		gloDefHG.add_defHG(&gloDefHG, sqlite3_column_text(statement,0), sqlite3_column_text(statement,1), sqlite3_column_int(statement,2));
	}
	gloDefHG.version++;
	pthread_rwlock_unlock(&gloDefHG.rwlock);	
	sqlite3_finalize(statement);	
	return rownum;
}


int sqlite3_flush_servers_db_to_mem(sqlite3 *db, int populate_if_empty) {
	int i;
	int rc;
	int rownum=0;
	sqlite3_stmt *statement;



	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Resetting %d hostgroups for MySQL\n", glovars.mysql_hostgroups);
	for(i=0;i<glovars.mysql_hostgroups;i++) {
		GPtrArray *sl=g_ptr_array_index(glomysrvs.mysql_hostgroups,i);
		while (sl->len) {
			MSHGE *ms=g_ptr_array_index(sl,0);
			g_free(ms);
			g_ptr_array_remove_index_fast(sl,0);
		}
		g_ptr_array_add(glomysrvs.mysql_hostgroups,sl);
	}
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 4, "Loading MySQL servers\n");
	//rc=sqlite3_prepare_v2(sqlite3configdb, "SELECT h.hostgroup_id , h.hostname , h.port , sr.read_only , sr.status FROM hostgroups h JOIN servers sr ON h.hostname=sr.hostname AND h.port=sr.port JOIN server_status ss ON ss.status=sr.status WHERE ss.status_desc LIKE 'ONLINE%'", -1, &statement, 0); assert(rc==SQLITE_OK);
	rc=sqlite3_prepare_v2(db, "SELECT h.hostgroup_id , h.hostname , h.port , sr.read_only , sr.status FROM hostgroups h JOIN servers sr ON h.hostname=sr.hostname AND h.port=sr.port JOIN server_status ss ON ss.status=sr.status", -1, &statement, 0); assert(rc==SQLITE_OK);
	while ((rc=sqlite3_step(statement))==SQLITE_ROW) {
		int hostgroup_id=sqlite3_column_int(statement,0);
		char *address=g_strdup((const char *)sqlite3_column_text(statement,1));
		uint16_t port=sqlite3_column_int(statement,2);
		int read_only=sqlite3_column_int(statement,3);
		enum mysql_server_status status=sqlite3_column_int(statement,4);
		mysql_server *ms=NULL;
		ms=find_server_ptr(address,port);
		if (ms==NULL) {
			// add
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Loading MySQL server %s:%d\n", address, port);
			ms=mysql_server_entry_create(address, port, read_only, status);
			mysql_server_entry_add(ms);
		} else {
			// update
			ms->read_only=read_only;
			ms->status=status;
		}
		if (status==MYSQL_SERVER_STATUS_ONLINE) {
			mysql_server_entry_add_hostgroup(ms,hostgroup_id);
		}
		rownum++;
		g_free(address);
	}
	sqlite3_finalize(statement);	
	pthread_rwlock_unlock(&glomysrvs.rwlock);
	return rownum;
}

void sqlite3_flush_debug_levels_mem_to_db(sqlite3 *db, int replace) {
	int i;
	char *a=NULL;
//	if (delete) {
//	}
	sqlite3_exec_exit_on_failure(db,"DELETE FROM debug_levels WHERE verbosity=0");
	if (replace) {
		a="REPLACE INTO debug_levels(module,verbosity) VALUES(\"%s\",%d)";
	} else {
		a="INSERT OR IGNORE INTO debug_levels(module,verbosity) VALUES(\"%s\",%d)";
	}
	int l=strlen(a)+100;
	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		char *buff=g_malloc0(l);
		sprintf(buff,a, gdbg_lvl[i].name, gdbg_lvl[i].verbosity);
		proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n",buff);
		sqlite3_exec_exit_on_failure(db,buff);
		g_free(buff);
	}
}

int sqlite3_flush_debug_levels_db_to_mem(sqlite3 *db) {
	int i;
	char *query="SELECT verbosity FROM debug_levels WHERE module=\"%s\"";
	int l=strlen(query)+100;
	int rownum=0;
	int result;
	for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
		sqlite3_stmt *statement;
		char *buff=g_malloc0(l);
		sprintf(buff,query,gdbg_lvl[i].name);
		if(sqlite3_prepare_v2(db, buff, -1, &statement, 0) != SQLITE_OK) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", buff, sqlite3_errmsg(db));
			sqlite3_finalize(statement);
			g_free(buff);
			return 0;
		}
		while ((result=sqlite3_step(statement))==SQLITE_ROW) {
			gdbg_lvl[i].verbosity=sqlite3_column_int(statement,0);
			rownum++;
		}
		sqlite3_finalize(statement);
		g_free(buff);
	}
	return rownum;
}

void sqlite3_flush_users_mem_to_db(sqlite3 *db, int replace, int active) {
//	if (delete) {
//		sqlite3_exec_exit_on_failure(sqlite3configdb,"DELETE FROM users");
//	}
	char *a=NULL;
	if (replace) {
		a="REPLACE INTO users(username,password,active) VALUES(\"%s\",\"%s\",%d)";
	} else {
		a="INSERT OR IGNORE INTO users(username,password,active) VALUES(\"%s\",\"%s\",%d)";
	}
	int i;
	pthread_rwlock_rdlock(&glovars.rwlock_usernames);
	for (i=0;i<glovars.mysql_users_name->len;i++) {
		int l=strlen(a)+strlen(g_ptr_array_index(glovars.mysql_users_name,i))+strlen(g_ptr_array_index(glovars.mysql_users_pass,i));
		char *buff=g_malloc0(l);
		memset(buff,0,l);
		sprintf(buff,a, g_ptr_array_index(glovars.mysql_users_name,i), g_ptr_array_index(glovars.mysql_users_pass,i), active);
		proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n",buff);
		sqlite3_exec_exit_on_failure(db,buff);
		g_free(buff);
	}
	pthread_rwlock_unlock(&glovars.rwlock_usernames);
}


int sqlite3_flush_users_db_to_mem(sqlite3 *db) {
	sqlite3_stmt *statement;
	char *query="SELECT username, password FROM users WHERE active=1";
	if(sqlite3_prepare_v2(db, query, -1, &statement, 0) != SQLITE_OK) {
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", query, sqlite3_errmsg(db));
		sqlite3_finalize(statement);
		return 0;
	}
	pthread_rwlock_wrlock(&glovars.rwlock_usernames);
	// remove all users
	while (glovars.mysql_users_name->len) {
		char *p=g_ptr_array_remove_index_fast(glovars.mysql_users_name,0);
		g_hash_table_remove(glovars.usernames,p);
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 6, "Removing user %s\n", p);
		g_free(p);
	}
	// remove all passwords
	while (glovars.mysql_users_pass->len) {
		char *p=g_ptr_array_remove_index_fast(glovars.mysql_users_pass,0);
		g_free(p);
	}
	int rownum = 0;
	int result = 0;
	while ((result=sqlite3_step(statement))==SQLITE_ROW) {
		gpointer user=g_strdup((const char *)sqlite3_column_text(statement,0));
		gpointer pass=g_strdup((const char *)sqlite3_column_text(statement,1));
		g_ptr_array_add(glovars.mysql_users_name,user);
		g_ptr_array_add(glovars.mysql_users_pass,pass);
		g_hash_table_insert(glovars.usernames, user, pass);
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 6, "Adding user %s , password _OMITTED_\n", user);
		rownum++;
	}
	pthread_rwlock_unlock(&glovars.rwlock_usernames);
	sqlite3_finalize(statement);
	return rownum;
}


static void __admin_sqlite3__fill_table__server_status(sqlite3 *db) {
	sqlite3_exec_exit_on_failure(db,"DELETE FROM server_status");
	sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (0, \"OFFLINE_HARD\")");
	sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (1, \"OFFLINE_SOFT\")");
	sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (2, \"SHUNNED\")");
	sqlite3_exec_exit_on_failure(db,"INSERT INTO server_status VALUES (3, \"ONLINE\")");
}

static void __admin_sqlite3__fill_table__debug_levels(sqlite3 *db) {
	sqlite3_exec_exit_on_failure(db,"DELETE FROM debug_levels WHERE module NOT IN ('debug_generic','debug_net','debug_pkt_array','debug_poll','debug_mysql_com','debug_mysql_server','debug_mysql_connection','debug_mysql_rw_split','debug_mysql_auth','debug_memory','debug_admin','debug_sqlite','debug_ipc','debug_query_cache','debug_query_statistics')");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_generic',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_net',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_pkt_array',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_poll',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_mysql_com',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_mysql_server',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_mysql_connection',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_mysql_rw_split',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_mysql_auth',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_memory',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_admin',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_sqlite',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_ipc',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_query_cache',0)");
	sqlite3_exec_exit_on_failure(db,"INSERT OR IGNORE INTO debug_levels VALUES ('debug_query_statistics',0)");
}

static int __admin_sqlite3__check_table_structure(sqlite3 *db, char *table_name, char *table_def) {
	char *q1="SELECT COUNT(*) FROM sqlite_master WHERE type=\"table\" AND name=\"%s\" AND sql=\"%s\"";
	int count=0;
	int l=strlen(q1)+strlen(table_name)+strlen(table_def)+1;
	sqlite3_stmt *statement;
	char *buff=g_malloc0(l);
	sprintf(buff, q1, table_name , table_def);
	if(sqlite3_prepare_v2(db, buff, -1, &statement, 0) != SQLITE_OK) {
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", buff, sqlite3_errmsg(db));
		sqlite3_finalize(statement);
		g_free(buff);
		assert(0);
	}
	int result=0;
	while ((result=sqlite3_step(statement))==SQLITE_ROW) {
		count+=sqlite3_column_int(statement,0);
	}
	sqlite3_finalize(statement);
	g_free(buff);
	return count;
}


static void __admin_sqlite3__build_table_structure(sqlite3 *db, char *table_name, char *table_def) {
	char *q2="DROP TABLE IF EXISTS %s";
	int l=strlen(q2)+strlen(table_name)+1;
	char *buff=g_malloc0(l);
	sprintf(buff,q2,table_name);
	proxy_debug(PROXY_DEBUG_SQLITE, 5, "SQLITE: dropping table: %s\n", buff);
	sqlite3_exec_exit_on_failure(db, buff);
	g_free(buff);
	proxy_debug(PROXY_DEBUG_SQLITE, 5, "SQLITE: creating table: %s\n", table_def);
	sqlite3_exec_exit_on_failure(db, table_def);
}

static void __admin_sqlite3__check_and_build_standard_tables(sqlite3 *db) {
	int i;
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = OFF");
	for (i=0;i<sizeof(table_defs)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: checking definition of table %s against \"%s\"\n" , table_def->table_name , table_def->table_def);
		int match=__admin_sqlite3__check_table_structure(db, table_def->table_name , table_def->table_def);
		if (match==0) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Table %s does not exist or is corrupted. Creating!\n", table_def->table_name);
			__admin_sqlite3__build_table_structure(db, table_def->table_name , table_def->table_def);
		}
	}
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = ON");
}

static void __admin_sqlite3__check_and_build_statsdb_tables(sqlite3 *db) {
	int i;
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = OFF");
	for (i=0;i<sizeof(table_defs_statsdb)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs_statsdb+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: checking definition of table %s against \"%s\"\n" , table_def->table_name , table_def->table_def);
		int match=__admin_sqlite3__check_table_structure(db, table_def->table_name , table_def->table_def);
		if (match==0) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Table %s does not exist or is corrupted. Creating!\n", table_def->table_name);
			__admin_sqlite3__build_table_structure(db, table_def->table_name , table_def->table_def);
		}
	}
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = ON");
}

static void __admin_sqlite3__check_and_build_debugdb_tables(sqlite3 *db) {
	int i;
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = OFF");
	for (i=0;i<sizeof(table_defs_debugdb)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs_debugdb+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: checking definition of table %s against \"%s\"\n" , table_def->table_name , table_def->table_def);
		int match=__admin_sqlite3__check_table_structure(db, table_def->table_name , table_def->table_def);
		if (match==0) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Table %s does not exist or is corrupted. Creating!\n", table_def->table_name);
			__admin_sqlite3__build_table_structure(db, table_def->table_name , table_def->table_def);
		}
	}
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = ON");
}

void admin_init_sqlite3() {
	int i;
	char *s[4];
	s[0]="PRAGMA journal_mode = WAL";
	s[1]="PRAGMA synchronous = NORMAL";
	//s[2]="PRAGMA locking_mode = EXCLUSIVE";
	s[2]="PRAGMA locking_mode = NORMAL";
	s[3]="PRAGMA foreign_keys = ON";
//  proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE:     
//    sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA journal_mode = WAL");
//  pragma_exit_on_failure(sqlite3configdb, "PRAGMA journal_mode = OFF");
//    sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA synchronous = NORMAL");
//  pragma_exit_on_failure(sqlite3configdb, "PRAGMA synchronous = 0");
//    sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA locking_mode = EXCLUSIVE");
//    sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA foreign_keys = ON");
//  pragma_exit_on_failure(sqlite3configdb, "PRAGMA PRAGMA wal_autocheckpoint=10000");


	i=sqlite3_config(SQLITE_CONFIG_URI, 1);
	assert(i==SQLITE_OK);

	// create sqlite3admindb DB
	//i = sqlite3_open_v2(":memory:", &sqlite3admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX , NULL);
	i = sqlite3_open_v2("file:memadmindb?mode=memory&cache=shared", &sqlite3admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX , NULL);
	if(i){
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open(): %s\n", sqlite3_errmsg(sqlite3admindb));
		assert(i==0);
	}

	// create sqlite3monitordb DB
	//i = sqlite3_open_v2(":memory:", &sqlite3monitordb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX , NULL);
	i = sqlite3_open_v2("file:memmonitordb?mode=memory&cache=shared", &sqlite3monitordb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX , NULL);
	if(i){
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open(): %s\n", sqlite3_errmsg(sqlite3monitordb));
		assert(i==0);
	}
	sqlite3_exec_exit_on_failure(sqlite3admindb, "ATTACH DATABASE 'file:memmonitordb?mode=memory&cache=shared' AS mon");	

	// create sqlite3configdb DB
	i = sqlite3_open_v2(glovars.proxy_admin_pathdb, &sqlite3configdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX , NULL);
	if(i){
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open(): %s\n", sqlite3_errmsg(sqlite3configdb));
		assert(i==0);
	}

	// create sqlite3statsdb DB
	i = sqlite3_open_v2(glovars.persistent_statistics_pathdb, &sqlite3statsdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX , NULL);
	if(i){
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open(): %s\n", sqlite3_errmsg(sqlite3statsdb));
		assert(i==0);
	}

	// create sqlite3debugdb DB
	i = sqlite3_open_v2(glovars.debug_pathdb, &sqlite3debugdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX , NULL);
	if(i){
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_open(): %s\n", sqlite3_errmsg(sqlite3debugdb));
		assert(i==0);
	}



	// apply PRAGMAs to sqlite3configdb
	for (i=0;i<4;i++) {
		proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n", s[i]);
		sqlite3_exec_exit_on_failure(sqlite3configdb, s[i]);
	}

	// apply PRAGMAs to sqlite3statsdb
	for (i=0;i<4;i++) {
		proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n", s[i]);
		sqlite3_exec_exit_on_failure(sqlite3statsdb, s[i]);
	}

	// apply PRAGMAs to sqlite3debugdb
	for (i=0;i<4;i++) {
		proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n", s[i]);
		sqlite3_exec_exit_on_failure(sqlite3debugdb, s[i]);
	}

	// set DBs as never updated
	sqlite3admindb_lastupdate=0;
	sqlite3monitordb_lastupdate=0;

	sqlite3monitordb_rebuild=0;


	// apply PRAGMAs to sqlite3admindb
	// sqlite3_exec_exit_on_failure(sqlite3admindb, s[3]);


/*
	// recreate all tables if they don't exist in sqlite3configdb
	for (i=0;i<sizeof(table_defs)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: checking definition of table %s against \"%s\"\n" , table_def->table_name , table_def->table_def);
		int match=__admin_sqlite3__check_table_structure(sqlite3configdb, table_def->table_name , table_def->table_def);
		if (match==0) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Table %s does not exist or is corrupted. Creating!\n", table_def->table_name);
			__admin_sqlite3__build_table_structure(sqlite3configdb, table_def->table_name , table_def->table_def);
		}
	}
*/

	// recreate all tables if they don't exist in all DBs
	__admin_sqlite3__check_and_build_standard_tables(sqlite3configdb);
	__admin_sqlite3__check_and_build_standard_tables(sqlite3admindb);
	__admin_sqlite3__check_and_build_standard_tables(sqlite3monitordb);

	__admin_sqlite3__check_and_build_statsdb_tables(sqlite3statsdb);
	__admin_sqlite3__check_and_build_debugdb_tables(sqlite3debugdb);

	sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA foreign_keys = OFF");
	__admin_sqlite3__fill_table__server_status(sqlite3configdb);
	__admin_sqlite3__fill_table__debug_levels(sqlite3configdb);
	sqlite3_exec_exit_on_failure(sqlite3configdb, "PRAGMA foreign_keys = ON");
//	__admin_sqlite3__fill_table_server_status(sqlite3admindb);
//	__admin_sqlite3__fill_table_server_status(sqlite3monitordb);

/*
	for (i=0;i<sizeof(table_defs)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: loading table %s from configdb\n" , table_def->table_name);
		__admin_sqlite3__load_table(table_def,sqlite3configdb,0);
	}
	sqlite3_exec_exit_on_failure(sqlite3admindb, "PRAGMA foreign_keys = OFF");
	for (i=0;i<sizeof(table_defs)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: inserting table %s into admindb\n" , table_def->table_name);
		__admin_sqlite3__insert_table(table_def,sqlite3admindb,0);
	}
*/

	




	{
		const char *a="ATTACH DATABASE '%s' AS disk";
		char *cmd=g_malloc0(strlen(a)+strlen(glovars.proxy_admin_pathdb)+5);
		sprintf(cmd,a,glovars.proxy_admin_pathdb);
		sqlite3_exec_exit_on_failure(sqlite3admindb, cmd);
		g_free(cmd);
	}
	{
		const char *a="ATTACH DATABASE '%s' AS statsdb";
		char *cmd=g_malloc0(strlen(a)+strlen(glovars.persistent_statistics_pathdb)+5);
		sprintf(cmd,a,glovars.persistent_statistics_pathdb);
		sqlite3_exec_exit_on_failure(sqlite3admindb, cmd);
		g_free(cmd);
	}


	__admin_sqlite3__insert_or_ignore_maintable_select_disktable();

	__admin_sqlite3__validate_data(sqlite3admindb);	

}

int sqlite3_dump_runtime_default_hostgroups(sqlite3 *db) {
	int i;
	int rc;
	int numrow=0;
	sqlite3_stmt *statement;
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Dropping table runtime_default_hostgroups\n");
	sqlite3_exec_exit_on_failure(db,"DROP TABLE IF EXISTS runtime_default_hostgroups");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Creating table runtime_default_hostgroups\n");
	sqlite3_exec_exit_on_failure(db,"CREATE TABLE runtime_default_hostgroups (username VARCHAR, schemaname VARCHAR, hostgroup_id INT NOT NULL, PRIMARY KEY (username, schemaname))");
	char *query="INSERT INTO runtime_default_hostgroups(username, schemaname, hostgroup_id) VALUES (?1 , ?2, ?3)";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	pthread_rwlock_rdlock(&gloDefHG.rwlock);
	for(i=0;i<gloDefHG.default_hostgroups->len;i++) {
		default_hostgroup_t *dhg=g_ptr_array_index(gloDefHG.default_hostgroups,i);
		rc=sqlite3_bind_text(statement, 1, dhg->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 1, dhg->schemaname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 3, dhg->hostgroup_id); assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		numrow++;	
	}
	sqlite3_finalize(statement);
	pthread_rwlock_unlock(&gloDefHG.rwlock);
	return numrow;
}

int sqlite3_dump_runtime_query_rules(sqlite3 *db) {
	int i;
	int rc;
	int numrow=0;
	sqlite3_stmt *statement;
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Dropping table runtime_query_rules\n");
	sqlite3_exec_exit_on_failure(db,"DROP TABLE IF EXISTS runtime_query_rules");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Creating table runtime_query_rules\n");
	sqlite3_exec_exit_on_failure(db,"CREATE TABLE runtime_query_rules (rule_id INT NOT NULL PRIMARY KEY, hits INT NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR NOT NULL, negate_match_pattern INT NOT NULL DEFAULT 0, flagOUT INT NOT NULL DEFAULT 0, replace_pattern VARCHAR, destination_hostgroup INT NOT NULL DEFAULT 0, audit_log INT NOT NULL DEFAULT 0, performance_log INT NOT NULL DEFAULT 0, cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_pattern VARCHAR, cache_ttl INT NOT NULL DEFAULT 0)");
	char *query="INSERT INTO runtime_query_rules(rule_id, hits, flagIN, username, schemaname, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, audit_log, performance_log, cache_tag, invalidate_cache_tag, invalidate_cache_pattern, cache_ttl) VALUES (?1 , ?2, ?3 , ?4 , ?5 , ?6 , ?7 , ?8 , ?9 , ?10 , ?11 , ?12 , ?13 , ?14 , ?15 , ?16 )";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	pthread_rwlock_rdlock(&gloQR.rwlock);
	for(i=0;i<gloQR.query_rules->len;i++) {
		query_rule_t *qr = g_ptr_array_index(gloQR.query_rules,i);
		rc=sqlite3_bind_int(statement, 1, qr->rule_id); 	assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 2, qr->hits); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 3, qr->flagIN); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 4, qr->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 5, qr->schemaname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 6, qr->match_pattern, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 7, qr->negate_match_pattern); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 8, qr->flagOUT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 9, qr->replace_pattern, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 10, qr->destination_hostgroup); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 11, qr->audit_log); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 12, qr->performance_log); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 13, qr->cache_tag); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 14, qr->invalidate_cache_tag); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 15, qr->invalidate_cache_pattern, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 16, qr->cache_ttl); assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		numrow++;
	}
	sqlite3_finalize(statement);
	pthread_rwlock_unlock(&gloQR.rwlock);
	return numrow;
}

int sqlite3_flush_query_rules_db_to_mem(sqlite3 *db) {
	// before calling this function we should so some input data validation to verify the content of the table
	//int i;
	{
		int rc;
		char *a="SELECT COUNT(*) FROM query_rules";
		sqlite3_stmt *statement;
		rc=sqlite3_prepare_v2(db, a, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_step(statement);
		assert(rc==SQLITE_ROW);
		rc=sqlite3_column_int(statement,0);
		sqlite3_finalize(statement);
		if (rc==0) {
			sqlite3_exec_exit_on_failure(db,"INSERT INTO query_rules VALUES(10,1,NULL,NULL,0,'^SELECT',1,0,NULL,0,0,0,0,0,NULL,-1)");
			sqlite3_exec_exit_on_failure(db,"INSERT INTO query_rules VALUES(20,1,NULL,NULL,0,'\\s+FOR\\s+UPDATE\\s*$',0,0,NULL,0,0,0,0,0,NULL,-1)");
			char *query="INSERT INTO query_rules (rule_id, active, username, schemaname, flagIN, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, audit_log, performance_log, cache_tag, invalidate_cache_tag, invalidate_cache_pattern, cache_ttl) VALUES(10000,1,NULL,NULL,0,'.*',0,0,NULL,1,0,0,0,0,NULL, ?1)";
			rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int(statement, 1, glovars.mysql_query_cache_default_timeout); assert(rc==SQLITE_OK);
			rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
		}
	}
	proxy_debug(PROXY_DEBUG_SQLITE, 1, "Loading query rules from db\n");
	sqlite3_stmt *statement;
	//char *query="SELECT rule_id, flagIN, username, schemaname, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, audit_log, performance_log, caching_ttl FROM query_rules ORDER BY rule_id";
	char *query="SELECT rule_id, flagIN, username, schemaname, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, audit_log, performance_log, cache_tag, invalidate_cache_tag, invalidate_cache_pattern, cache_ttl FROM query_rules WHERE active=1 ORDER BY rule_id";
	if(sqlite3_prepare_v2(db, query, -1, &statement, 0) != SQLITE_OK) {
		proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", query, sqlite3_errmsg(db));
		sqlite3_finalize(statement);
		proxy_error("Error loading query rules");
		assert(0);
	}
	pthread_rwlock_wrlock(&gloQR.rwlock);
	// remove all QC rules
	reset_query_rules();
	int rownum = 0;
	int result = 0;
	while ((result=sqlite3_step(statement))==SQLITE_ROW) {
		query_rule_t *qr=g_slice_alloc0(sizeof(query_rule_t));
		qr->rule_id=sqlite3_column_int(statement,0);
		qr->flagIN=sqlite3_column_int(statement,1);
		//some sanity check
		if (qr->flagIN < 0) {
			proxy_error("Out of range value for flagIN (%d) on rule_id %d\n", qr->flagIN, qr->rule_id);
			qr->flagIN=0;
		}
		qr->username=g_strdup((const char *)sqlite3_column_text(statement,2));
		qr->schemaname=g_strdup((const char *)sqlite3_column_text(statement,3));
		qr->match_pattern=g_strdup((const char *)sqlite3_column_text(statement,4));
		qr->negate_match_pattern=sqlite3_column_int(statement,5);
		//some sanity check
		if (qr->negate_match_pattern > 1) {
			proxy_error("Out of range value for negate_match_pattern (%d) on rule_id %d\n", qr->negate_match_pattern, qr->rule_id);
			qr->negate_match_pattern=1;
		}
		if (qr->negate_match_pattern < 0) {
			proxy_error("Out of range value for negate_match_pattern (%d) on rule_id %d\n", qr->negate_match_pattern, qr->rule_id);
			qr->negate_match_pattern=0;
		}
		qr->flagOUT=sqlite3_column_int(statement,6);
		//some sanity check
		if (qr->flagOUT < 0) {
			proxy_error("Out of range value for flagOUT (%d) on rule_id %d\n", qr->flagOUT, qr->rule_id);
			qr->flagOUT=0;
		}
		qr->replace_pattern=g_strdup((const char *)sqlite3_column_text(statement,7));
		qr->destination_hostgroup=sqlite3_column_int(statement,8);
		//some sanity check
		if (qr->destination_hostgroup < 0) {
			proxy_error("Out of range value for destination_hostgroup (%d) on rule_id %d\n", qr->destination_hostgroup, qr->rule_id);
			qr->destination_hostgroup=0;
		}
		qr->audit_log=sqlite3_column_int(statement,9);
		//some sanity check
		if (qr->audit_log < 0 || qr->audit_log > 1) {
			proxy_error("Out of range value for audit_log (%d) on rule_id %d\n", qr->audit_log, qr->rule_id);
			qr->audit_log= ( qr->audit_log < 0 ? 0 : 1 );
		}
		qr->performance_log=sqlite3_column_int(statement,10);
		//some sanity check
		if (qr->performance_log < 0 || qr->performance_log > 1) {
			proxy_error("Out of range value for performance_log (%d) on rule_id %d\n", qr->performance_log, qr->rule_id);
			qr->performance_log= ( qr->performance_log < 0 ? 0 : 1 );
		}
		qr->cache_tag=sqlite3_column_int(statement,11);
		//some sanity check
		if (qr->cache_tag < 0) {
			proxy_error("Out of range value for cache_tag (%d) on rule_id %d\n", qr->cache_tag, qr->rule_id);
			qr->cache_tag=0;
		}
		qr->invalidate_cache_tag=sqlite3_column_int(statement,12);
		//some sanity check
		if (qr->invalidate_cache_tag < 0) {
			proxy_error("Out of range value for invalidate_cache_tag (%d) on rule_id %d\n", qr->invalidate_cache_tag, qr->rule_id);
			qr->invalidate_cache_tag=0;
		}
		qr->invalidate_cache_pattern=g_strdup((const char *)sqlite3_column_text(statement,13));
		qr->cache_ttl=sqlite3_column_int(statement,14);
		//some sanity check
		if (qr->cache_ttl < -1) {
			proxy_error("Out of range value for cache_ttl (%d) on rule_id %d\n", qr->cache_ttl, qr->rule_id);
			qr->cache_ttl=-1;
		}
		qr->hits=0;
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Adding query rules with id %d : flagIN %d ; username \"%s\" ; schema \"%s\" ; match_pattern \"%s\" ; negate_match_pattern %d ; flagOUT %d ; replace_pattern \"%s\" ; destination_hostgroup %d ; audit_log %d ; performance_log %d ; cache_tag %d ; invalidate_cache_tag %d ; invalidate_cache_pattern \"%s\" ; cache_ttl %d\n", qr->rule_id, qr->flagIN , qr->username , qr->schemaname , qr->match_pattern , qr->negate_match_pattern , qr->flagOUT , qr->replace_pattern , qr->destination_hostgroup , qr->audit_log , qr->performance_log , qr->cache_tag, qr->invalidate_cache_tag , qr->invalidate_cache_pattern , qr->cache_ttl);
		qr->regex=g_regex_new(qr->match_pattern, G_REGEX_CASELESS | G_REGEX_OPTIMIZE, 0, NULL);
		if (qr->destination_hostgroup < glovars.mysql_hostgroups) {
			g_ptr_array_add(gloQR.query_rules, qr);
			rownum++;
		} else {
			reset_query_rule(qr);
		}
	}
	pthread_rwlock_unlock(&gloQR.rwlock);
	sqlite3_finalize(statement);
	return rownum;
};

int sqlite3_dump_runtime_hostgroups(sqlite3 *db) {
	int i;
	int j;
	int numrow=0;
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Dropping table runtime_hostgroups\n");
	sqlite3_exec_exit_on_failure(db,"DROP TABLE IF EXISTS runtime_hostgroups");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Creating table runtime_hostgroups\n");
	//sqlite3_exec_exit_on_failure(sqlite3configdb,"CREATE TABLE runtime_hostgroups ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, PRIMARY KEY (hostgroup_id, hostname, port) )");
	sqlite3_exec_exit_on_failure(db,"CREATE TABLE runtime_hostgroups ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, connections_active INT NOT NULL, connections_created INT NOT NULL, bytes_sent INT NOT NULL, bytes_recv INT NOT NULL, PRIMARY KEY (hostgroup_id, hostname, port) )");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Dropping table runtime_servers\n");
	sqlite3_exec_exit_on_failure(db,"DROP TABLE IF EXISTS runtime_servers");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Creating table runtime_servers\n");
	sqlite3_exec_exit_on_failure(db,"CREATE TABLE runtime_servers ( hostname VARCHAR NOT NULL , port INT NOT NULL, read_only INT NOT NULL, status NOT NULL )");
	char *query1="INSERT INTO runtime_hostgroups VALUES (%d ,\"%s\", %d, %llu, %llu, %llu, %llu)";
	char *query2="INSERT INTO runtime_servers VALUES (\"%s\", %d, %d, %d)";
	int l;
	pthread_rwlock_rdlock(&glomysrvs.rwlock);
	for(i=0;i<glovars.mysql_hostgroups;i++) {
		proxy_debug(PROXY_DEBUG_SQLITE, 5, "Populating runtime_hostgroups with hosts from hostgroup %d", i);
		LPtrArray *sl=g_ptr_array_index(glomysrvs.mysql_hostgroups,i);
		for(j=0;j<sl->len;j++) {
			//mysql_server *ms=l_ptr_array_index(sl,j);
			MSHGE *ms=g_ptr_array_index(sl,j);
			l=strlen(query1)+strlen(ms->MSptr->address)+14+80;
			char *buff=g_malloc0(l);
			//sprintf(buff,query1,i,ms->address,ms->port);
			sprintf(buff,query1,i,ms->MSptr->address,ms->MSptr->port, ms->connections_active, ms->connections_created, ms->server_bytes.bytes_sent, ms->server_bytes.bytes_recv);
			sqlite3_exec_exit_on_failure(db,buff);
			g_free(buff);
			numrow++;
		}
	}
	for(i=0;i<glomysrvs.servers->len;i++) {
		proxy_debug(PROXY_DEBUG_SQLITE, 5, "Populating runtime_hosts with host # %d", i);
		mysql_server *ms=g_ptr_array_index(glomysrvs.servers, i);
		l=strlen(query2)+strlen(ms->address)+24;
		char *buff=g_malloc0(l);
		sprintf(buff,query2,ms->address,ms->port,ms->read_only,ms->status);
		sqlite3_exec_exit_on_failure(db,buff);
		g_free(buff);
		numrow++;
	}
	pthread_rwlock_unlock(&glomysrvs.rwlock);
	return numrow;
}

int sqlite3_dump_runtime_query_cache(sqlite3 *db) {
	int i;
	int rc;
	int numrow=0;
	sqlite3_stmt *statement;
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Dropping table runtime_query_cache\n");
	sqlite3_exec_exit_on_failure(db,"DROP TABLE IF EXISTS runtime_query_cache");
	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Creating table runtime_query_cache\n");
	sqlite3_exec_exit_on_failure(db,"CREATE TABLE runtime_query_cache ( current_entries INT NOT NULL, size_keys INT NOT NULL, size_values INT NOT NULL, size_metas INT NOT NULL, count_SET INT NOT NULL, count_SET_ERR INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_purged INT NOT NULL, dataIN INT NOT NULL, dataOUT INT NOT NULL)");
	char *query="INSERT INTO runtime_query_cache VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6 , ?7 , ?8 , ?9 , ?10 , ?11)";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	int QC_entries=0;
	for (i=0; i<QC.size; i++) QC_entries+=QC.fdb_hashes[i]->ptrArray->len;
	rc=sqlite3_bind_int(statement, 1, QC_entries); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 2, QC.size_keys); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 3, QC.size_values); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 4, QC.size_metas); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 5, QC.cntSet); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 6, QC.cntSetERR); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 7, QC.cntGet); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 8, QC.cntGetOK); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 9, QC.cntPurge); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 10, QC.dataIN); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 11, QC.dataOUT); assert(rc==SQLITE_OK);
	rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
	rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
	numrow++;
	sqlite3_finalize(statement);
	return numrow;
}


void __sqlite3_statsdb__flush_query_stats(gpointer key, gpointer user_data) {
	int rc;
	sqlite3 *db=sqlite3statsdb;
	sqlite3_stmt *statement;
	qr_hash_t *ht = &QR_HASH_T;
	qr_hash_entry *entry = g_hash_table_lookup(ht->p_hash, key);
	char *query="INSERT INTO query_stats (timestamp, query_digest_md5, query_digest_text, username, schemaname, hostgroup_id, server_address, server_port, query_time, exec_cnt) VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6 , ?7 , ?8 , ?9 , ?10)";
	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	int curtime=*(time_t *)user_data;
	rc=sqlite3_bind_int(statement, 1, (curtime)); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 2, entry->query_digest_md5, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 3, entry->query_digest_text, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 4, entry->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 5, entry->schemaname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 6, entry->hostgroup_id); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 7, entry->mysql_server_address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 8, entry->mysql_server_port); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 9, entry->query_time); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 10, entry->exec_cnt); assert(rc==SQLITE_OK);
	rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
	rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);

	sqlite3_finalize(statement);
}

void __sqlite3_debugdb__flush_debugs(sqlite3_stmt *statement, dbg_msg_t *dbg_msg) {
	int rc;
//	sqlite3 *db=sqlite3debugdb;
//	sqlite3_stmt *statement;
//	qr_hash_t *ht = &QR_HASH_T;
//	qr_hash_entry *entry = g_hash_table_lookup(ht->p_hash, key);
//	char *query="INSERT INTO query_stats (timestamp, query_digest_md5, query_digest_text, username, schemaname, hostgroup_id, server_address, server_port, query_time, exec_cnt) VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6 , ?7 , ?8 , ?9 , ?10)";
//	rc=sqlite3_prepare_v2(db, query, -1, &statement, 0);
//	assert(rc==SQLITE_OK);
//	int curtime=*(time_t *)user_data;
	unsigned long long montime=(((unsigned long long) dbg_msg->tv.tv_sec) * 1000000) + (dbg_msg->tv.tv_usec);
	rc=sqlite3_bind_int64(statement, 1, montime); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 2, dbg_msg->thr); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 3, gdbg_lvl[dbg_msg->module].name, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 4, dbg_msg->file, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 5, dbg_msg->line); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 6, dbg_msg->func, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 7, dbg_msg->verb); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 8, dbg_msg->msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_step(statement); assert(rc==SQLITE_DONE);
	rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);

//	sqlite3_finalize(statement);
}

