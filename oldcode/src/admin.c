#include "proxysql.h"

//int static_lock=0;


void sighup_handler(int sig) {
	GKeyFile *keyfile;
	GError *error = NULL;
	int rc;
	// TODO: handle also closing/reopening of log files and databases
  proxy_error("Received HUP signal: reloading config file...\n");
#ifdef DEBUG
	//g_mem_profile();
	malloc_stats_print(NULL, NULL, "");
#endif
	char *config_file=glovars.proxy_configfile;
	rc=config_file_is_readable(config_file);
	if (rc==0) {
  	proxy_error("Config file %s is not readable\n", config_file);
		return;
	}

	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, config_file, G_KEY_FILE_NONE, &error)) {
  	proxy_error("Error loading configuration from config file %s\n", config_file);
		g_key_file_free(keyfile);
		return;
	}

  // initialize variables and process config file
	init_global_variables(keyfile,1);

	g_key_file_free(keyfile);

}

void term_handler(int sig) {
  proxy_error("Received TERM signal: shutdown in progress...\n");
#ifdef DEBUG
	//g_mem_profile();
	malloc_stats_print(NULL, NULL, "");
#endif
  glovars.shutdown=1;
	sleep(5);
	exit(0);
}

static inline pkt * admin_version_comment_pkt(mysql_session_t *sess) {
	pkt *p;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	p=mypkt_alloc();
	// hardcoded, we send " (ProxySQL) "
	p->length=81;
	//p->data=l_alloc(thrLD->sfp, p->length);
	p->data=l_alloc(p->length);
	//p->data=g_slice_alloc0(p->length);
	memcpy(p->data,"\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a\x28\x50\x72\x6f\x78\x79\x53\x51\x4c\x29\x05\x00\x00\x05\xfe\x00\x00\x02\x00",p->length);
	return p;
}

static void update_runtime_statistics(int admin) {
	sqlite3 *db=NULL;
	time_t t=time(NULL);
//	SPIN_LOCK(static_lock);

	if (admin==1) {
		if (t<glovars.proxy_admin_refresh_status_interval+sqlite3admindb_lastupdate) {
//			SPIN_UNLOCK(static_lock);
			return;
		}
		db=sqlite3admindb;
		sqlite3admindb_lastupdate=t;
	}
	if (admin==2) {

		if (t<glovars.proxy_monitor_refresh_status_interval+sqlite3monitordb_lastupdate) {
//			SPIN_UNLOCK(static_lock);
			return;
		}
		db=sqlite3monitordb;
		sqlite3monitordb_lastupdate=t;
	}
	sqlite3_dump_runtime_hostgroups(db);
	sqlite3_dump_runtime_query_rules(db);
	sqlite3_dump_runtime_query_cache(db);
//	SPIN_UNLOCK(static_lock);
}

void admin_COM_QUERY(mysql_session_t *sess, pkt *p) {
	int rc;
	sqlite3 *defaultdb;
	if (sess->admin==1) {
		defaultdb=sqlite3admindb;
	} else { //admin==2
		defaultdb=sqlite3monitordb;
	}
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	// enter admin mode
	// configure the session to not send data to servers using a hack: pretend the result set is cached
	sess->mysql_query_cache_hit=TRUE;
	sess->query_to_cache=FALSE;
	update_runtime_statistics(sess->admin);	
	if (strncasecmp("SHOW TABLES", p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
		char *str="SELECT name AS tables FROM sqlite_master WHERE type='table'";
		//g_slice_free1(p->length, p->data);
		//l_free(thrLD->sfp,p->length, p->data);
		l_free(p->length, p->data);
		int l=strlen(str);
		//p->data=l_alloc(thrLD->sfp, l+sizeof(mysql_hdr)+1);
		p->data=l_alloc(l+sizeof(mysql_hdr)+1);
		//p->data=g_slice_alloc0(l+sizeof(mysql_hdr)+1);
		p->length=l+sizeof(mysql_hdr)+1;
		memset(p->data+sizeof(mysql_hdr), MYSQL_COM_QUERY, 1);
		memcpy(p->data+sizeof(mysql_hdr)+1,str,l);
	}
	{
		static char *strA="SHOW CREATE TABLE ";
		static char *strB="SELECT name AS 'table' , sql AS 'Create Table' FROM sqlite_master WHERE type='table' AND name='%s'";
		int strAl=strlen(strA);	
		if (strncasecmp("SHOW CREATE TABLE ", p->data+sizeof(mysql_hdr)+1, strAl)==0) {
			int strBl=strlen(strB);
			int tblnamelen=p->length-sizeof(mysql_hdr)-1-strAl;
			int l=strBl+tblnamelen-2;
			char *buff=g_malloc0(l);
			snprintf(buff,l,strB,p->data+sizeof(mysql_hdr)+1+strAl);
			buff[l-1]='\'';
			//g_slice_free1(p->length, p->data);
			//l_free(thrLD->sfp,p->length, p->data);
			l_free(p->length, p->data);
			//p->data=l_alloc(thrLD->sfp, l+sizeof(mysql_hdr)+1);
			p->data=l_alloc(l+sizeof(mysql_hdr)+1);
			//p->data=g_slice_alloc0(l+sizeof(mysql_hdr)+1);
			p->length=l+sizeof(mysql_hdr)+1;
			memset(p->data+sizeof(mysql_hdr), MYSQL_COM_QUERY, 1);
			memcpy(p->data+sizeof(mysql_hdr)+1,buff,l);
			g_free(buff);
		}
	}
	if (strncmp("select @@version_comment limit 1", p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
		// mysql client in interactive mode sends "select @@version_comment limit 1" : we treat this as a special case

		// drop the packet from client
		mypkt_free1(p);

		// prepare a new packet to send to the client
		pkt *np=NULL;
		np=admin_version_comment_pkt(sess);
		MY_SESS_ADD_PKT_OUT_CLIENT(np);
		//l_ptr_array_add(sess->client_myds->output.pkts, np);
		return;
	}
	if (sess->admin==1) {  // in the admin module, not in the monitoring module
		if (strncasecmp("FLUSH QUERY CACHE",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=fdb_truncate_all(&QC);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			return;
		}
		if (strncasecmp("FLUSH DEBUG",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_flush_debug_levels_db_to_mem(sqlite3admindb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			if (glovars.admin_sync_disk_on_flush==1) sqlite3_config_sync_mem_to_disk();
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
		if (strncasecmp("FLUSH USERS",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_flush_users_db_to_mem(sqlite3admindb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			if (glovars.admin_sync_disk_on_flush==1) sqlite3_config_sync_mem_to_disk();
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
		if (strncasecmp("FLUSH QUERY RULES",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_flush_query_rules_db_to_mem(sqlite3admindb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			if (glovars.admin_sync_disk_on_flush==1) sqlite3_config_sync_mem_to_disk();
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
		if (strncasecmp("FLUSH DEFAULT HOSTGROUPS",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_flush_default_hostgroups_db_to_mem(sqlite3admindb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			if (glovars.admin_sync_disk_on_flush==1) sqlite3_config_sync_mem_to_disk();
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
		if (strncasecmp("FLUSH HOSTGROUPS",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_flush_servers_db_to_mem(sqlite3admindb,0);
			int warnings=force_remove_servers();
			if ( affected_rows>=0 ) {
				pkt *ok=mypkt_alloc();
				myproto_ok_pkt(ok,1,affected_rows,0,2,warnings);
				MY_SESS_ADD_PKT_OUT_CLIENT(ok);
				if (glovars.admin_sync_disk_on_flush==1) sqlite3_config_sync_mem_to_disk();
				//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			} else {
				// TODO: send some error
			}
			return;
		}
	//	if (strncasecmp("REMOVE SERVERS",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
	//	}
		if (strncasecmp("SHUTDOWN",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			glovars.shutdown=1;
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,0,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			if (glovars.admin_sync_disk_on_shutdown==1) sqlite3_config_sync_mem_to_disk();
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
/*
		if (strncasecmp("DUMP RUNTIME HOSTGROUPS",  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			//int affected_rows=sqlite3_dump_runtime_hostgroups();
			int affected_rows;
			affected_rows=sqlite3_dump_runtime_hostgroups(sqlite3configdb);
			affected_rows=sqlite3_dump_runtime_hostgroups(sqlite3admindb);
			affected_rows=sqlite3_dump_runtime_hostgroups(sqlite3monitordb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
*/

		if (strncasecmp(DUMP_RUNTIME_QUERY_RULES,  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows;
			//int affected_rows=sqlite3_dump_runtime_query_rules();
			affected_rows=sqlite3_dump_runtime_query_rules(defaultdb);
			//affected_rows=sqlite3_dump_runtime_query_rules(sqlite3configdb);
			//affected_rows=sqlite3_dump_runtime_query_rules(sqlite3admindb);
			//affected_rows=sqlite3_dump_runtime_query_rules(sqlite3monitordb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}

		if (strncasecmp(DUMP_RUNTIME_QUERY_CACHE,  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows;
			affected_rows=sqlite3_dump_runtime_query_cache(defaultdb);
			//affected_rows=sqlite3_dump_runtime_query_cache(sqlite3configdb);
			//affected_rows=sqlite3_dump_runtime_query_cache(sqlite3admindb);
			//affected_rows=sqlite3_dump_runtime_query_cache(sqlite3monitordb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}
		if (strncasecmp(DUMP_RUNTIME_DEFAULT_HOSTGROUPS,  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_dump_runtime_default_hostgroups(defaultdb);
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			return;
		}
		if (strncasecmp(CONFIG_SYNC_MEM_TO_DISK,  p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1)==0) {
			int affected_rows=sqlite3_config_sync_mem_to_disk();
			pkt *ok=mypkt_alloc();
			myproto_ok_pkt(ok,1,affected_rows,0,2,0);
			MY_SESS_ADD_PKT_OUT_CLIENT(ok);
			//l_ptr_array_add(sess->client_myds->output.pkts, ok);
			return;
		}

	}
	rc=mysql_pkt_to_sqlite_exec(p, sess);
	mypkt_free1(p);

	if (rc==-1) {
		sess->healthy=0;
	}
//	sess->healthy=0; // for now, always
	return;
}


int force_remove_servers() { 
	int i;
	int warnings=0;
	// temporary change poll_timeout
	int default_mysql_poll_timeout=glovars.mysql_poll_timeout;
	glovars.mysql_poll_timeout=glovars.mysql_poll_timeout_maintenance;
	for (i=0; i<glovars.mysql_threads; i++) {
		gpointer admincmd=g_malloc0(20);
		sprintf(admincmd,"%s", "REMOVE SERVER");
		proxy_debug(PROXY_DEBUG_IPC, 3, "Sending REMOVE SERVER to thread #%d\n", i);
		g_async_queue_push(proxyipc.queue[i],admincmd);
	}
	char c;
	for (i=0; i<glovars.mysql_threads; i++) {
		proxy_debug(PROXY_DEBUG_IPC, 4, "Writing 1 bytes to thread #%d on fd %d\n", i, proxyipc.fdOut[i]);
		int r;
		r=write(proxyipc.fdOut[i],&c,sizeof(char));
		assert(r>=1);
	}
	for (i=0; i<glovars.mysql_threads; i++) {
		gpointer ack;
		proxy_debug(PROXY_DEBUG_IPC, 4, "Waiting ACK on thread #%d\n", i);
		ack=g_async_queue_pop(proxyipc.queue[glovars.mysql_threads]);
		int w=atoi(ack);
		warnings+=w;
		g_free(ack);
	}
	// we are done, all threads disabled the removed hosts!

	// reconfigure the correct poll() timeout
	default_mysql_poll_timeout=glovars.mysql_poll_timeout=default_mysql_poll_timeout;
//		// send OK pkt
//		pkt *ok=mypkt_alloc(sess);
//		myproto_ok_pkt(ok,1,0,0,2,0);
//		g_ptr_array_add(sess->client_myds->output.pkts, ok);
	return warnings;
}


