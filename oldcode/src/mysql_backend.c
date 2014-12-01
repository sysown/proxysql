#include "proxysql.h"

#define RESET_MYBE_STATS(__mybe) { memset(&__mybe->server_bytes_at_cmd,0,sizeof(bytes_stats)); }

static inline void backend_reset_server_mycpe(mysql_backend_t *mybe, mysql_connpool **mcp, int fc) {
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset server_mycpe for MySQL backend %p\n", mybe);
	if (mybe->server_mycpe) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset server_mycpe %p for MySQL backend %p\n", mybe->server_mycpe, mybe);
		mysql_connpool_detach_connection(MYSQL_CONNPOOL_LOCAL, mcp, mybe->server_mycpe, fc);
	}
	mybe->server_mycpe=NULL;	
}

static inline int backend_reset_server_myds(mysql_backend_t *mybe) {
	int rc=0;
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset myds for MySQL backend %p\n", mybe);
	if (mybe->server_myds) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset myds %p for MySQL backend %p\n", mybe->server_myds, mybe);
		if (mybe->server_myds->active==FALSE) rc=1;
		mysql_data_stream_delete(mybe->server_myds);
		mybe->server_myds=NULL;
	}
	return rc;
}

static void backend_detach(mysql_backend_t *mybe, mysql_connpool **mcp, int fc) {
	mybe->last_mysql_connpool=NULL;
	/* for optimization, the calling function should check that
	if (glovars.mysql_share_connections==0) {
		return;
	} */
	if (mybe->server_mycpe && mybe->server_mycpe->reusable) {
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Detach MySQL backend, server %s:%d , fd %d\n", mybe->mshge->MSptr->address, mybe->mshge->MSptr->port, mybe->fd);
		backend_reset_server_mycpe(mybe, mcp, fc);
	}
}

static void backend_reset(mysql_backend_t *mybe, mysql_connpool **mcp, int force_close) {
	mybe->fd=0;
	int fc=force_close;
	int rc;
	mybe->last_mysql_connpool=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset MySQL backend %p\n", mybe);
	if (mybe->mshge && mybe->mshge->MSptr) {
		// without the IF , this can cause SIGSEGV
		proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Reset MySQL backend, server %s:%d , fd %d\n", mybe->mshge->MSptr->address, mybe->mshge->MSptr->port, mybe->fd);
		__sync_fetch_and_sub(&mybe->mshge->connections_active,1);
	}
	//if (mybe->mshge) mybe->mshge->MSptr=NULL;
	mybe->mshge=NULL;

	rc=backend_reset_server_myds(mybe);
	if (fc==0 && rc==1) { fc=1; } // close an inactive data stream
	backend_reset_server_mycpe(mybe, mcp, fc);
	RESET_MYBE_STATS(mybe);
	mybe->fd=0;
	//memset(&mybe->server_bytes_at_cmd,0,sizeof(bytes_stats));
}

mysql_backend_t *mysql_backend_new() {
	mysql_backend_t *mybe=g_slice_alloc0(sizeof(mysql_backend_t));
	mybe->bereset=backend_reset;
	mybe->bedetach=backend_detach;
	mybe->last_mysql_connpool=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "Created new MySQL backend, addr %p\n", mybe);
	return mybe;
}

void mysql_backend_delete(mysql_backend_t *mybe) {
	g_slice_free1(sizeof(mysql_backend_t),mybe);
}



/*
static mysql_backend_pool_t * mysql_backend_pool_create(const char *username, const char *password, const char *schema, int hostgroup) {
//  NOTE: the calling function must lock the mutex
	mysql_backend_pool_t *mbep;
	mbep=g_malloc0(sizeof(mysql_backend_pool_t));
	mbep->username=g_strdup(username);
	mbep->password=g_strdup(password);
	mbep->schema=g_strdup(schema);
	mbep->hostgroup=hostgroup;
	mbep->free_backends=g_ptr_array_new();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Created mysql backend pool for user u=%s p=%s D=%s hg=%d\n", username, password, schema, hostgroup);
	return mbep;
}

static mysql_backend_pool_t * mysql_backend_pool_find(const char *username, const char *password, const char *schema, int hostgroup) {
//  NOTE: the calling function must lock the mutex
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Searching a backend for u=%s p=%s D=%s hg=%d\n", username, password, schema, hostgroup);
	guint l;
	for (l=0; l<glomybepools.mybepools->len; l++) {
		mysql_backend_pool_t *mbep=g_ptr_array_index(glomybepools.mybepools,l);
		if (
			(strcmp(username,mbep->username)==0) &&
			(strcmp(password,mbep->password)==0) &&
			(strcmp(schema,mbep->schema)==0) &&
			(hostgroup==mbep->hostgroup)
		) { // we found the matching username/password/schema/hostgroup
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Found a backend for u=%s p=%s D=%s hg=%d\n", username, password, schema, hostgroup);
			return mbep;
		}// else {
		//	return NULL;
		//}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Found a backend for u=%s p=%s D=%s hg=%d\n", username, password, schema, hostgroup);
	return NULL; // no match found
}

static mysql_backend_t * mysql_backend_pool_get(const char *username, const char *password, const char *schema, int hostgroup) {
//  NOTE: this function locks the mutex
	return NULL;
	mysql_backend_t *mybe=NULL;
	pthread_mutex_lock(&glomybepools.mutex);
	mysql_backend_pool_t *mbep=mysql_backend_pool_find(username, password, schema, hostgroup);
	if (mbep==NULL) {
		mbep=mysql_backend_pool_create(username, password, schema, hostgroup);
		g_ptr_array_add(glomybepools.mybepools,mbep);
	}
	if (mbep->free_backends->len) {
		mybe=g_ptr_array_index(mbep->free_backends,0);
		g_ptr_array_remove_index_fast(mbep->free_backends,0);
	}
	pthread_mutex_unlock(&glomybepools.mutex);
	return mybe;
}

static void mysql_backend_pool_detach(mysql_backend_t *mybe, int hostgroup, int force_close) {
	return;
	if (mybe->mshge==NULL || mybe->mshge->MSptr==NULL) return;
	pthread_mutex_lock(&glomybepools.mutex);
	mysql_backend_pool_t *mbep=mysql_backend_pool_find(mybe->server_mycpe->conn->user, mybe->server_mycpe->conn->passwd, mybe->server_mycpe->conn->db, hostgroup);
	g_ptr_array_add(mbep->free_backends,mybe);
	pthread_mutex_unlock(&glomybepools.mutex);	
}

void glomybepools_init() {
	//glomybepools.mutex=0;
	pthread_mutex_init(&glomybepools.mutex, NULL);
	glomybepools.enabled=1;
	glomybepools.mybepools=g_ptr_array_new();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Main mysql backend pool struct created\n");
	glomybepools.get=mysql_backend_pool_get;
	glomybepools.detach=mysql_backend_pool_detach;
//	glomybepools.create=mysql_backend_pool_create;
}
*/
