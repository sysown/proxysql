#include "proxysql.h"




void reset_query_rule(query_rule_t *qr) {
	if (qr->regex) {
		g_regex_unref(qr->regex);
	}
	if (qr->username) {
		g_free(qr->username);
	}
	if (qr->schemaname) {
		g_free(qr->schemaname);
	}
	if (qr->match_pattern) {
		g_free(qr->match_pattern);
	}
	if (qr->replace_pattern) {
		g_free(qr->replace_pattern);
	}
	if (qr->invalidate_cache_pattern) {
		g_free(qr->invalidate_cache_pattern);
	}
	g_slice_free1(sizeof(query_rule_t), qr);
}

void reset_query_rules() {
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "Resetting query rules\n");
	if (gloQR.query_rules == NULL) {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "Initializing query rules\n");
		gloQR.query_rules=g_ptr_array_new();
		return;
	}
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "%d query rules to reset\n", gloQR.query_rules->len);
	while ( gloQR.query_rules->len ) {
		query_rule_t *qr = g_ptr_array_remove_index_fast(gloQR.query_rules,0);
		reset_query_rule(qr);
	}
}

void init_gloQR() {
	pthread_rwlock_init(&gloQR.rwlock, NULL);
	gloQR.query_rules=NULL;
	reset_query_rules();
}


void init_query_metadata(mysql_session_t *sess, pkt *p) {
	sess->query_info.p=p;
	if (sess->query_info.query_checksum) {
		g_checksum_free(sess->query_info.query_checksum);
		sess->query_info.query_checksum=NULL;
	}
	sess->query_info.flagOUT=0;
	sess->query_info.rewritten=0;
	sess->query_info.cache_ttl=0;
	sess->query_info.destination_hostgroup=-1;	// the destination hostgroup is set to unknown
	sess->query_info.audit_log=0;
	sess->query_info.performance_log=0;
	sess->query_info.mysql_query_cache_hit=0;
	if (sess->query_info.query_stats) {
		// If we hit here, the query statistics were disabled while being processed or this session is being closed.
		// We need to clean up
		cleanup_query_stats(sess->query_info.query_stats);
	}
	if (p) {
		sess->query_info.query=p->data+sizeof(mysql_hdr)+1;
		sess->query_info.query_len=p->length-sizeof(mysql_hdr)-1;
		// Added by chan
		if (glovars.mysql_query_statistics) {
			sess->query_info.query_stats=g_malloc0(sizeof(qr_hash_entry));
			sess->query_info.query_stats->query_time=monotonic_time();
			//process_query_stats(sess);
			sess->query_info.query_stats->query_digest_text=mysql_query_digest(sess);
			sess->query_info.query_stats->query_digest_md5=str2md5(sess->query_info.query_stats->query_digest_text);
			sess->query_info.query_stats->username=g_strdup(sess->mysql_username);
			sess->query_info.query_stats->schemaname=g_strdup(sess->mysql_schema_cur);
		}
	} else {
		sess->query_info.query=NULL;
		sess->query_info.query_len=0;
	}
}

void process_query_rules(mysql_session_t *sess) {
	int i;
	int flagIN=0;
	gboolean rc;
	//GMatchInfo *match_info;
	pthread_rwlock_rdlock(&gloQR.rwlock);
	for (i=0;i<gloQR.query_rules->len;i++) {
		query_rule_t *qr=g_ptr_array_index(gloQR.query_rules, i);
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 6, "Processing rule %d\n", qr->rule_id);
		if (qr->flagIN != flagIN) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has no matching flagIN\n", qr->rule_id);
			continue;
		}
		if (qr->username) {
			if (strcmp(qr->username,sess->mysql_username)!=0) {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has no matching username\n", qr->rule_id);
				continue;
			}
		}
		if (qr->schemaname) {
			if (strcmp(qr->schemaname,sess->mysql_schema_cur)!=0) {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has no matching schema\n", qr->rule_id);
				continue;
			}
		}
		//rc = g_regex_match_full(qr->regex, sess->query_info.query , sess->query_info.query_len, 0, 0, &match_info, NULL);
		rc = g_regex_match_full(qr->regex, sess->query_info.query , sess->query_info.query_len, 0, 0, NULL, NULL);
		if (
			(rc==TRUE && qr->negate_match_pattern==1) || ( rc==FALSE && qr->negate_match_pattern==0 )
		) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has no matching pattern\n", qr->rule_id);
			//g_match_info_free(match_info);
			continue;
		}
		// if we arrived here, we have a match
		__sync_fetch_and_add(&qr->hits,1);
		if (qr->replace_pattern) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d on match_pattern \"%s\" has a replace_pattern \"%s\" to apply\n", qr->rule_id, qr->match_pattern, qr->replace_pattern);
			GError *error=NULL;
			char *new_query;
			new_query=g_regex_replace(qr->regex, sess->query_info.query , sess->query_info.query_len, 0, qr->replace_pattern, 0, &error);
			if (error) {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 3, "g_regex_replace() on query rule %d generated error %d\n", qr->rule_id, error->message);
				g_error_free(error);
				if (new_query) {
					g_free(new_query);
				}
				//g_match_info_free(match_info);
				continue;
			}
			sess->query_info.rewritten=1;
			if (sess->query_info.query_checksum) {
				g_checksum_free(sess->query_info.query_checksum); // remove checksum, as it may needs to be computed again
				sess->query_info.query_checksum=NULL;
			}
			mysql_new_payload_select(sess->query_info.p, new_query, -1);
			pkt *p=sess->query_info.p;
			sess->query_info.query=p->data+sizeof(mysql_hdr)+1;
			sess->query_info.query_len=p->length-sizeof(mysql_hdr)-1;
			g_free(new_query);
		}
		if (qr->flagOUT) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has changed flagOUT\n", qr->rule_id);
			flagIN=qr->flagOUT;
			sess->query_info.flagOUT=flagIN;
		}
		if (qr->cache_ttl) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has non-zero cache_ttl: %d. Query will%s hit the cache\n", qr->rule_id, qr->cache_ttl, (qr->cache_ttl < 0 ? " NOT" : "" ));
			sess->query_info.cache_ttl=qr->cache_ttl;
		}
		//g_match_info_free(match_info);
		//sess->query_info.destination_hostgroup=-1; // default
		if (qr->destination_hostgroup>=0) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has changed destination_hostgroup %d\n", qr->rule_id, qr->destination_hostgroup);
			sess->query_info.destination_hostgroup=qr->destination_hostgroup;
		}
		if (qr->audit_log==1) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has set audit_log\n", qr->rule_id);
			sess->query_info.audit_log=qr->audit_log;
		}
		if (qr->performance_log==1) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 5, "query rule %d has set performance_log\n", qr->rule_id);
			sess->query_info.performance_log=qr->performance_log;
		}
		if (sess->query_info.cache_ttl) {
			goto exit_process_query_rules;
		}
	}
	exit_process_query_rules:
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 6, "End processing query rules\n");
	pthread_rwlock_unlock(&gloQR.rwlock);
	// if the query reached this point with cache_ttl==0 , we set it to the default
	if (sess->query_info.cache_ttl==0) {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 6, "Query has no caching TTL, setting the default\n");
		sess->query_info.cache_ttl=glovars.mysql_query_cache_default_timeout;
	}
	// if the query reached this point with cache_ttl==-1 , we set it to 0
	if (sess->query_info.cache_ttl==-1) {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 6, "Query won't be cached\n");
		sess->query_info.cache_ttl=0;
	}
	// if the query is flagged to be cached but mysql_query_cache_enabled=0 , the query needs to be flagged to NOT be cached
	if (glovars.mysql_query_cache_enabled==FALSE) {
		sess->query_info.cache_ttl=0;
	}
	// if destination_hostgroup didn't change from default (-1) we apply sess->default_hostgroup, setting it first if necessary
	if (sess->query_info.destination_hostgroup==-1) {
		if ( (sess->default_hostgroup==-1) || (sess->default_hostgroup_version != __sync_fetch_and_add(&gloDefHG.version,0)) ) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p has default_hostgroup %d version %d, system version %d\n", sess, sess->default_hostgroup, sess->default_hostgroup_version, gloDefHG.version);
			sess->query_info.destination_hostgroup=sess->default_hostgroup_func(sess);
		} else {
			sess->query_info.destination_hostgroup=sess->default_hostgroup;
		}
	}
}


mysql_server * find_server_ptr(const char *address, const uint16_t port) {
	mysql_server *ms=NULL;
	int i;
//	if (lock) pthread_rwlock_wrlock(&glomysrvs.rwlock);
	for (i=0;i<glomysrvs.servers->len;i++) {
		mysql_server *mst=g_ptr_array_index(glomysrvs.servers,i);
		if (mst->port==port && (strcmp(mst->address,address)==0)) {
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 6, "MySQL server %s:%d found in servers list\n", address, port);
			i=glomysrvs.servers->len;
			ms=mst;
		}
	}
//	if (lock) pthread_rwlock_unlock(&glomysrvs.rwlock);
	return ms;
}


mysql_server * mysql_server_entry_create(const char *address, const uint16_t port, int read_only, enum mysql_server_status status) {
	mysql_server *ms=g_slice_alloc0(sizeof(mysql_server));
	ms->address=g_strdup(address);
	ms->port=port;
	ms->read_only=read_only;
	ms->status=status;
	return ms;
}

inline void mysql_server_entry_add(mysql_server *ms) {
	g_ptr_array_add(glomysrvs.servers,ms);
}

void mysql_server_entry_add_hostgroup(mysql_server *MSptr, int hostgroup_id) {
	if (hostgroup_id >= glovars.mysql_hostgroups) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 4, "Server %s:%d not inserted in hostgroup %d as this is an invalid hostgroup\n", MSptr->address, MSptr->port, hostgroup_id);
		return;
	}
	GPtrArray *hg=g_ptr_array_index(glomysrvs.mysql_hostgroups, hostgroup_id);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Adding server %s:%d in hostgroup %d\n", MSptr->address, MSptr->port, hostgroup_id);
	MSHGE *ms;
	ms=g_malloc0(sizeof(MSHGE));
	ms->MSptr=MSptr;
	g_ptr_array_add(hg,ms);
}

MSHGE * mysql_server_random_entry_from_hostgroup__lock(int hostgroup_id) {
	MSHGE *ms;
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	ms=mysql_server_random_entry_from_hostgroup__nolock(hostgroup_id);
	pthread_rwlock_unlock(&glomysrvs.rwlock);
	return ms;
}

MSHGE * mysql_server_random_entry_from_hostgroup__nolock(int hostgroup_id) {
	assert(hostgroup_id < glovars.mysql_hostgroups);
	GPtrArray *hg=g_ptr_array_index(glomysrvs.mysql_hostgroups, hostgroup_id);
	if (hg->len==0) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Server not found from hostgroup %d\n", hostgroup_id);
		return NULL;
	}
	int i=rand()%hg->len;
	MSHGE *ms;
	ms=g_ptr_array_index(hg,i);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Returning server %s:%d from hostgroup %d\n", ms->MSptr->address, ms->MSptr->port, hostgroup_id);
	return ms;
}

int	mysql_session_create_backend_for_hostgroup(mysql_session_t *sess, int hostgroup_id) {
	assert(hostgroup_id < glovars.mysql_hostgroups);
	mysql_backend_t *mybe=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Retrieving backend for session %p hostgroup %d\n", sess, hostgroup_id);
	mybe=l_ptr_array_index(sess->mybes,hostgroup_id);
	int retries=10;
	//mysql_backend_t *tmp_mybe=NULL;
	//tmp_mybe=glomybepools.get(sess->mysql_username, sess->mysql_password, sess->mysql_schema_cur, hostgroup_id);
	//if (tmp_mybe) {
	//	mysql_backend_delete(mybe);
	//	*mybe=*tmp_mybe;
	//	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Recycling backend for sess %p , hostgroup %d , fd %d\n", sess , hostgroup_id , mybe->fd);
	//	mybe->server_myds->sess=sess;
	//	return 1;
	//}
	mysql_session_create_backend_for_hostgroup__label1:
	if (mybe->mshge == NULL || mybe->mshge->MSptr==NULL) {
		//--mysql_server *ms=NULL;
		//ms=mysql_server_random_entry_from_hostgroup__lock(hostgroup_id);
		if (mybe->mshge==NULL)
		{ // FIXME : temporary hack, and memory leak
			//--mybe->mshge=g_malloc0(sizeof(MSHGE));
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Backend for session %p hostgroup %d has no mshge\n", sess, hostgroup_id);
			mybe->mshge=mysql_server_random_entry_from_hostgroup__lock(hostgroup_id);
		}
		//--mybe->mshge->MSptr=ms;
		if (mybe->mshge==NULL) {
			// this is a severe condition, needs to be handled
			return 0;
		}
	}
	if (mybe->server_mycpe==NULL) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Backend for session %p hostgroup %d has no server_mycpe\n", sess, hostgroup_id);
		mybe->server_mycpe=mysql_connpool_get_connection(MYSQL_CONNPOOL_LOCAL, &mybe->last_mysql_connpool, mybe->mshge->MSptr->address, sess->mysql_username, sess->mysql_password, sess->mysql_schema_cur, mybe->mshge->MSptr->port);
		if (mybe->server_mycpe==NULL) {
			if (--retries) {
				proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Unable to connect to %s:%d from hostgroup %d, %s retries left\n", mybe->mshge->MSptr->address, mybe->mshge->MSptr->port, hostgroup_id, retries);
				mybe->mshge=NULL;
				goto mysql_session_create_backend_for_hostgroup__label1;
			}
			// handle error!!
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "We failed to created a server_mycpe for backend for session %p hostgroup %d, we will generate an error\n", sess, hostgroup_id);
			authenticate_mysql_client_send_ERR(sess, 1045, "#28000Access denied for user");
			// this is a severe condition, needs to be handled
			return -1;
		}
	}
	mybe->fd=mybe->server_mycpe->conn->net.fd;
	//mybe->server_myds=mysql_data_stream_init(mybe->fd, sess);
	if (mybe->server_myds==NULL) {
		mybe->server_myds=mysql_data_stream_new(sess,mybe);
	} else {
		mybe->server_myds->mybe=mybe;
	}
	mysql_data_stream_t *myds=mybe->server_myds;
	myds->setfd(myds, mybe->fd);
//	mybe->server_myds->fd=mybe->fd;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Created new connection for sess %p , hostgroup %d , fd %d\n", sess , hostgroup_id , mybe->fd);
	return 1;
}
