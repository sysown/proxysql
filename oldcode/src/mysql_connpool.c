#include "proxysql.h"

/*
 * need to add several
 * #ifdef DEBUG_mysql_conn
 * for debugging
*/



int glock;



static inline void close_expired_mysql_connection(mysql_cp_entry_t *mc) {
	mysql_close(mc->conn);	// ... close it
	g_free(mc);	
}


static mysql_cp_entry_t *create_new_mysql_connection(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	mysql_cp_entry_t *mycpe=NULL;
	MYSQL *mysql_con = mysql_init(NULL);
//		my_bool  my_true = 1;
//		mysql_options(mysql_con, MYSQL_OPT_RECONNECT, &my_true);
	if (mysql_real_connect(mysql_con, hostname, username, password, db, port, NULL, 0) == NULL) {
		// we aren't able to connect
		fprintf(stderr, "%s\n", mysql_error(mysql_con));
		// we don't abort because the called may decide to connect to another slave if available
	} else {
		mycpe=g_malloc(sizeof(mysql_cp_entry_t));
		mycpe->reusable=1;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Created new connection for %s %s %s %d\n", hostname, username, db, port);
		mycpe->conn=mysql_con;
		unsigned long long curr_time=(unsigned long long) (gloconnpool.tv.tv_sec) * 1000000 + (gloconnpool.tv.tv_usec);
		mycpe->expire = curr_time + glovars.mysql_wait_timeout;
/* NEW STUFF
	While testing auto-reconnect features with hundreds of connections being constantly killed,
	I noticed that connections stay in CLOSE_WAIT state for very long time
	It should be related to the fact that mysql_real_connect() call setsockopt() with SO_KEEPALIVE
	By default a keepalive is sent every tcp_keepalive_time seconds (defaults to 2 hours).
	We are not changing it to 10 minutes, hardcoded for now, configurable later on.
	We also need to add error control.
*/
		int tcp_keepalive_time=600;
		setsockopt(mysql_con->net.fd, SOL_TCP,  TCP_KEEPIDLE, (char *)&tcp_keepalive_time, sizeof(tcp_keepalive_time));
		ioctl_FIONBIO(mysql_con->net.fd, 1);
	}
	return mycpe;
}


//gboolean reconnect_server_on_shut_fd(mysql_session_t *sess, mysql_cp_entry_t **myc) {
gboolean reconnect_server_on_shut_fd(mysql_session_t *sess) {
	if ( (sess->server_mybe==NULL) || (sess->server_mybe->server_myds==NULL) // the backend is not initialized, return
		|| ( sess->server_mybe->server_myds->active==TRUE )) {
		return TRUE;
    }
	if (
		( sess->server_mybe->server_myds->active==FALSE ) // connection is not active
		&& (glovars.mysql_auto_reconnect_enabled==FALSE) // auto-reconnect is globally disabled
	) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "mysql_auto_reconnect_enabled is OFF\n");
		return FALSE;
	}

	// FIXME: temporary workaround for issue #57
	return FALSE;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Entering reconnect_server_on_shut_fd\n");
	mysql_cp_entry_t *mycpe=NULL;
	if (
		( sess->server_mybe->server_myds->active==FALSE ) // connection is not active
		&& ( sess->mysql_server_reconnect==TRUE ) // the session is configured to reconnect
		&& ( sess->server_bytes_at_cmd.bytes_sent==sess->server_mybe->server_myds->bytes_info.bytes_sent) // no bytes sent so far
		&& ( sess->server_bytes_at_cmd.bytes_recv==sess->server_mybe->server_myds->bytes_info.bytes_recv) // no bytes recv so far
	) {
		int tries=10;
		while (tries--) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Trying to reconnect...\n");
			if (sess->server_mybe && sess->server_mybe->server_mycpe) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Closing mysql connection on fd %d\n", sess->server_mybe->server_mycpe->conn->net.fd);
				if (sess->server_mybe->server_mycpe->conn->net.fd==0) {
					// for some unknown reason, conn->net.fd may be 0. This seems a bug!
					sess->server_mybe->server_mycpe->conn->net.vio=0;
				}
				mysql_close(sess->server_mybe->server_mycpe->conn);  // drop the connection
				sess->server_mybe->server_mycpe=NULL;
			}
//			mycpe=mysql_connpool_get_connection(MYSQL_CONNPOOL_LOCAL, &sess->last_mysql_connpool, sess->server_mybe->mshge->MSptr->address, sess->mysql_username, sess->mysql_password, sess->mysql_schema_cur, sess->server_mybe->mshge->MSptr->port);   // re-establish a new connection	--- FIXME: bugged
			// try it
			if (mycpe) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Obtained mysql connection on fd %d\n", mycpe->conn->net.fd);
				ioctl_FIONBIO(mycpe->conn->net.fd, 0);
				if (mysql_query(mycpe->conn,"SELECT 1")) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 3, "SELECT 1 failed on fd %d\n", mycpe->conn->net.fd);
					//shutdown(mycpe->conn->net.fd, SHUT_RDWR);
					close_expired_mysql_connection(mycpe);
					mycpe=NULL;
					continue;
				}
				MYSQL_RES *result = mysql_store_result(mycpe->conn);
				mysql_free_result(result);
				tries=0;
				ioctl_FIONBIO(mycpe->conn->net.fd, 1);
				continue;
			}
		}
		if (mycpe==NULL) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 3, "Unable to return a connection. Reconnection FAILED\n");
			// maybe is better if the calling function sends the error to the client. The follow 3 lines should be moved out of here
			pkt *hs;
			hs=mypkt_alloc();
			create_err_packet(hs, 2, 1045, "#28000Access denied for user");
			write_one_pkt_to_net(sess->client_myds,hs);
			return FALSE;
		} else {
			sess->fds[1].fd=sess->server_mybe->server_myds->fd;
			sess->server_mybe->server_myds->active=TRUE;
		}
	}
	return TRUE;
}


void local_mysql_connpool_init() {
	__thr_myconnpool.connpools=g_ptr_array_new();
	__thr_myconnpool.enabled=gloconnpool.enabled;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Per-thread connection pool struct created\n");
}

void mysql_connpool_init(global_variable_entry_t *gve) {
	glock=0;
	pthread_mutex_init(&gloconnpool.mutex, NULL);
	gloconnpool.connpools=g_ptr_array_new();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Main connection pool struct created\n");
}


static mysql_connpool *mysql_connpool_find(myConnPools *cp, const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
//	NOTE: the calling function must lock the mutex
	//myConnPools *cp=&__thr_myconnpool;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Searching a connection for %s %s %s %d\n", hostname, username, db, port);
	guint l;
	for (l=0; l<cp->connpools->len; l++) {
		mysql_connpool *mcp=g_ptr_array_index(cp->connpools,l);
		if (
			(strcmp(hostname,mcp->hostname)==0) &&
			(strcmp(username,mcp->username)==0) &&
			(strcmp(password,mcp->password)==0) &&
			(strcmp(db,mcp->db)==0) &&
			(port==mcp->port)
		) {	// we found the matching hostname/username/password/port
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Found connection for %s %s %s %d\n", hostname, username, db, port);
			return mcp;
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "NOT found connection for %s %s %s %d\n", hostname, username, db, port);
	return NULL; // no match found
}

static mysql_connpool *mysql_connpool_create(myConnPools *cp, const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
//	NOTE: the calling function must lock the mutex
	//myConnPools *cp=&__thr_myconnpool;
	mysql_connpool *mcp;
	mcp=g_malloc(sizeof(mysql_connpool));	
	mcp->hostname=g_strdup(hostname);
	mcp->username=g_strdup(username);
	mcp->password=g_strdup(password);
	mcp->db=g_strdup(db);
	mcp->port=port;
	mcp->free_conns=g_ptr_array_new();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Created connection pool for %s %s %s %d\n", hostname, username, db, port);
	g_ptr_array_add(cp->connpools,mcp);
	return mcp;
}

static inline mysql_connpool *mysql_connpool_find_or_create(myConnPools *cp, const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	mysql_connpool *mcp=mysql_connpool_find(cp, hostname, username, password, db, port);
	if (mcp==NULL) {
		mcp=mysql_connpool_create(cp, hostname, username, password, db, port);
	}
	return mcp;
}


mysql_connpool *mysql_connpool_exists_global(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	mysql_connpool *mcp=mysql_connpool_find(&__thr_myconnpool, hostname, username, password, db, port);
	if (mcp) return mcp;
	SPIN_LOCK(glock);
	mcp=mysql_connpool_find(&gloconnpool, hostname, username, password, db, port);
	SPIN_UNLOCK(glock);
	return mcp;
}

mysql_cp_entry_t *mysql_connpool_get_connection(int cp_scope, mysql_connpool **mcp_ref, const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	myConnPools	*cp;
	if (cp_scope==MYSQL_CONNPOOL_GLOBAL) {
		cp=&gloconnpool;
	} else {
		cp=&__thr_myconnpool;
	}
//	NOTE: this function locks the mutex
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Getting a connection for %s %s %s %d\n", hostname, username, db, port);
	//guint l;
	mysql_cp_entry_t *mycpe=NULL;
	//struct timeval tv;
	//gettimeofday(&tv, NULL);
	unsigned long long curr_time=(unsigned long long) (gloconnpool.tv.tv_sec) * 1000000 + (gloconnpool.tv.tv_usec);
	if (cp->enabled==TRUE) {
		if (cp_scope==MYSQL_CONNPOOL_GLOBAL) SPIN_LOCK(glock);
		//pthread_mutex_lock(&cp->mutex);
		mysql_connpool *mcp=NULL;
		if ((cp_scope==MYSQL_CONNPOOL_LOCAL) && (*mcp_ref)) {
			mcp=*mcp_ref;
		} else {
			mcp=mysql_connpool_find_or_create(cp, hostname, username, password, db, port);
		}
		while (mcp->free_conns->len) {
			mysql_cp_entry_t *mc=g_ptr_array_index(mcp->free_conns,0);	// get the first connection
			g_ptr_array_remove_index_fast(mcp->free_conns,0);	// remove it
			if (mc->expire <= curr_time) {	// if the connection is expired ...
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Closing expired connection for %s %s %s %d\n", hostname, username, db, port);
				close_expired_mysql_connection(mc);
			} else { // found a potential good connection
				mc->expire=curr_time + glovars.mysql_wait_timeout;
			// mysql_ping seems bugged, as it re-establishes a connection, disabling
//			if (mysql_ping(mc->conn)!=0) { // the conn is dead
//				fprintf(stderr, "%s\n", mysql_error(mc->conn));
//				mysql_close(mc->conn);
//				free(mc);
//			} else { // the connection is really good
//				g_ptr_array_add(mcp->used_conns,mc);	
				mycpe=mc;
				break;
//			}
			}
		}
		if (cp_scope==MYSQL_CONNPOOL_LOCAL) { *mcp_ref=mcp; }
		if (cp_scope==MYSQL_CONNPOOL_GLOBAL) SPIN_UNLOCK(glock);
		//pthread_mutex_unlock(&cp->mutex); // free the lock now!
	}	/* (cp->enabled==TRUE) */
	if (mycpe==NULL) {
	// if we reached here it means we couldn't find any connection

	// try to get a connection from global pool
		if (cp_scope==MYSQL_CONNPOOL_LOCAL) {
			mycpe=mysql_connpool_get_connection(MYSQL_CONNPOOL_GLOBAL, NULL, hostname, username, password, db, port);
			if (mycpe==NULL) {
				mycpe=create_new_mysql_connection(hostname, username, password, db, port);	
			}
		}
	}
	if (mycpe) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Returning connection with fd %d\n", mycpe->conn->net.fd);
	}
	return mycpe;
}

void mysql_connpool_detach_connection(int cp_scope, mysql_connpool **mcp_ref, mysql_cp_entry_t *mc, int force_close) {
	myConnPools	*cp;
	if (cp_scope==MYSQL_CONNPOOL_GLOBAL) {
		cp=&gloconnpool;
	} else {
		cp=&__thr_myconnpool;
	}
	if (cp->enabled==FALSE) {
		close_expired_mysql_connection(mc);
		return;
	}
	if (mc->reusable==0) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 3, "Detaching not reusable connection for %s %s %s %d\n", mc->conn->host, mc->conn->user, mc->conn->db, mc->conn->port);
		close_expired_mysql_connection(mc);
		return;
	}
	if (force_close==1) {
		// we assume the connection is not healthy, drop it immediately
		//MYSQL *mysql_con;
		//mysql_con=mc->conn;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 3, "Detaching unhealthy(?) connection for %s %s %s %d\n", mc->conn->host, mc->conn->user, mc->conn->db, mc->conn->port);
		close_expired_mysql_connection(mc);
		return;
	}
	MYSQL *mysql_con;
	mysql_con=mc->conn;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Detaching connection for %s %s %s %d, fd %d\n", mc->conn->host, mc->conn->user, mc->conn->db, mc->conn->port, mc->conn->net.fd);
	mysql_connpool *mcp=NULL;
	if (*mcp_ref==NULL) {
		mcp=mysql_connpool_find_or_create(cp, mysql_con->host, mysql_con->user, mysql_con->passwd, mysql_con->db, mysql_con->port);
	} else {
		mcp=*mcp_ref;
	}
	// we may not find the connection if an INITDB was issued, thus changing db
	// we temporary (?) remove the used_conns array
	// maybe a global implementation is better
	if (mcp) {
		//g_ptr_array_remove_fast(mcp->used_conns,mc);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned long long curr_time=(unsigned long long) (tv.tv_sec) * 1000000 + (tv.tv_usec);
		if (mc->expire <= curr_time) {	// if the connection is expired ...
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Closing expired connection for %s %s %s %d\n", mysql_con->host, mysql_con->user, mysql_con->db, mysql_con->port);
			close_expired_mysql_connection(mc);	
		} else {
			g_ptr_array_add(mcp->free_conns,mc);
		}	
	}
//	*mcp_ref=mcp;
}


void * mysql_connpool_purge_thread() {
	my_init();
	mysql_server_init(0, NULL, NULL);
//	GPtrArray *conns=g_ptr_array_new();
	while(glovars.shutdown==0) {
		usleep(1000000);
		if (gloconnpool.enabled==0) {
			continue;
		}
//		unsigned int i;
		//struct timeval tv;
		gettimeofday(&gloconnpool.tv, NULL);
/*
		unsigned long long curr_time=(unsigned long long)(gloconnpool.tv.tv_sec) * 1000000 + (gloconnpool.tv.tv_usec);
		spin_lock(glock);
		//pthread_mutex_lock(&gloconnpool.mutex);
		for (i=0; i<gloconnpool.connpools->len; i++) {
			mysql_connpool *mcp=g_ptr_array_index(gloconnpool.connpools,i);
			int l=mcp->free_conns->len;
			while (l>0) {
				l--;
				mysql_cp_entry_t *mc=g_ptr_array_index(mcp->free_conns,l);
				if (mc->expire <= curr_time) {
					g_ptr_array_add(conns,mc);
					g_ptr_array_remove_index_fast(mcp->free_conns,l);
					l--;
				}
			}
		}
		spin_unlock(glock);
		//pthread_mutex_unlock(&gloconnpool.mutex);
		for (i=0; i<conns->len; i++) {
			mysql_cp_entry_t *mc=g_ptr_array_index(conns,0);
			g_ptr_array_remove_index_fast(conns,0);
			mysql_close(mc->conn);
			free(mc);
		}
*/
	}
	proxy_error("Shutdown mysql_connpool_purge_thread\n");
	return NULL;
}
