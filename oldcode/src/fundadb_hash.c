#include "proxysql.h"



pkt * fdb_get(fdb_hashes_group_t *hg, const char *kp, mysql_session_t *sess) {
	//void *value=NULL;
	pkt * result=NULL;
	//unsigned int vl=0;
	int kl=strlen(kp);
	unsigned char i;
	i=*((unsigned char *)kp);
	if((kl)>2) i=i+(*((unsigned char *)kp+1))+(*((unsigned char *)kp+2));
	i=i%hg->size;
	pthread_rwlock_rdlock(&hg->fdb_hashes[i]->lock);
	fdb_hash_entry *entry=g_hash_table_lookup(hg->fdb_hashes[i]->hash, kp);
	if (entry!=NULL) { __sync_fetch_and_add(&entry->ref_count,1);	}
  pthread_rwlock_unlock(&hg->fdb_hashes[i]->lock);
	if (entry!=NULL) {
		time_t t=hg->now;
		if (entry->expire > t) {
				//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
			result=mypkt_alloc();
				//result=mypkt_alloc(sess);
				//result->data=g_slice_alloc(entry->length);
				//result->data=l_alloc(thrLD->sfp, entry->length);
			result->data=l_alloc(entry->length);
			memcpy(result->data,entry->value,entry->length);
			result->length=entry->length;
			__sync_fetch_and_add(&hg->cntGetOK,1);
			__sync_fetch_and_add(&hg->dataOUT,result->length);
			if (t > entry->access) entry->access=t;
		} else {
		// this was a bug. Altering an entry should not possible when the lock is rdlock
		//	g_hash_table_remove (hg->fdb_hashes[i]->hash,kp);
		}
			__sync_fetch_and_sub(&entry->ref_count,1);	
    }
	__sync_fetch_and_add(&hg->cntGet,1);
	return result;
}

gboolean fdb_set(fdb_hashes_group_t *hg, void *kp, unsigned int kl, void *vp, unsigned int vl, time_t expire, gboolean copy) {
	//fdb_hash_entry *entry = g_malloc(sizeof(fdb_hash_entry));
	fdb_hash_entry *entry = g_slice_alloc(sizeof(fdb_hash_entry));
	entry->klen=kl;
	entry->length=vl;
	entry->ref_count=0;
    if (copy) {
		//entry->key=g_malloc(kl);
		entry->key=g_slice_alloc(kl);
		//memcpy(entry->key,kp,kl);
		MEM_COPY_FWD(entry->key,kp,kl);
		entry->value=g_malloc(vl);
		memcpy(entry->value,vp,vl);
	} else {
		entry->key=kp;
		entry->value=vp;
	}
    entry->self=entry;
	entry->access=hg->now;

	if (expire>0) {
		if (expire > fdb_system_var.hash_expire_max) {
			entry->expire=expire; // expire is a unix timestamp
		} else {
			entry->expire=hg->now+expire; // expire is seconds
		}
	} else entry->expire=hg->now+hg->hash_expire_default; // set default expire

	unsigned char i;
	i=*((unsigned char *)kp);
    if((kl)>2) i=i+(*((unsigned char *)kp+1))+(*((unsigned char *)kp+2));
    i=i%hg->size;
    pthread_rwlock_wrlock(&hg->fdb_hashes[i]->lock);
    g_ptr_array_add(hg->fdb_hashes[i]->ptrArray, entry);
    g_hash_table_replace(hg->fdb_hashes[i]->hash, entry->key, entry);
    pthread_rwlock_unlock(&hg->fdb_hashes[i]->lock);
	//int s;
    __sync_fetch_and_add(&hg->cntSet,1);
	__sync_fetch_and_add(&hg->size_keys,kl);
	__sync_fetch_and_add(&hg->size_values,vl);
    __sync_fetch_and_add(&hg->dataIN,vl);
	__sync_fetch_and_add(&hg->size_metas,sizeof(fdb_hash_entry)+sizeof(fdb_hash_entry *));
//    __sync_fetch_and_add(&fdb_system_var.cntSet,1);
    return 0;
}

my_bool fdb_del_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT)
    {
        strcpy(message, "fdb_del() can only accept one string argument");
        return 1;
    }
    return 0;
}

long long fdb_del(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    long long ret;
    unsigned char i=(unsigned char) (args->args[0][0]);
    if((args->lengths[0])>2) i=i+args->args[0][1]+args->args[0][2];
    i=i%num_hashes;
    pthread_rwlock_wrlock(&fdb_hashes[i]->lock);
    ret=g_hash_table_remove (fdb_hashes[i]->hash,args->args[0]);
//    __sync_fetch_and_add(&fdb_hashes[i]->cntDel,1);
    pthread_rwlock_unlock(&fdb_hashes[i]->lock);
    return ret;
}

void hash_value_destroy_func(void * hash_entry) {
    fdb_hash_entry *entry= (fdb_hash_entry *) hash_entry;
    entry->expire=EXPIRE_DROPIT;
}



void fdb_hashes_new(fdb_hashes_group_t *hg, size_t size, unsigned int hash_expire_default, unsigned long long max_memory_size) {
    unsigned int i;
	hg->now=time(NULL);
	hg->size=size;
	hg->hash_expire_default=hash_expire_default;
	hg->max_memory_size=max_memory_size;
	hg->fdb_hashes=g_slice_alloc(sizeof(fdb_hash_t)*hg->size);
    for (i=0; i<hg->size; i++) {
        hg->fdb_hashes[i]=malloc(sizeof(fdb_hash_t));
        hg->fdb_hashes[i]->hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, hash_value_destroy_func);
        hg->fdb_hashes[i]->purgeIdx = 0;
        pthread_rwlock_init(&(hg->fdb_hashes[i]->lock), NULL);
		hg->fdb_hashes[i]->ptrArray=g_ptr_array_new();
		hg->fdb_hashes[i]->purgeChunkSize=0; // unnecessary. Here to avoid errors in valgrind 
    }
	hg->cntDel = 0;
	hg->cntGet = 0;
	hg->cntGetOK = 0;
	hg->cntSet = 0;
	hg->cntSetERR = 0;
	hg->size_keys=0;
	hg->size_values=0;
	hg->size_metas=0;
	hg->dataIN=0;
	hg->dataOUT=0;
}


long long fdb_truncate_all(fdb_hashes_group_t *hg) {
	unsigned char i;
	long long totsize=0;
	for (i=0; i<hg->size; i++) {
		pthread_rwlock_wrlock(&hg->fdb_hashes[i]->lock);
	}
	for (i=0; i<hg->size; i++) {
		totsize+=g_hash_table_size(hg->fdb_hashes[i]->hash);
		g_hash_table_remove_all(hg->fdb_hashes[i]->hash);
	}
	for (i=0; i<hg->size; i++) {	
		pthread_rwlock_unlock(&hg->fdb_hashes[i]->lock);
	}
	return totsize;
}

void *purgeHash_thread(void *arg) {
	long long min_idx=0;
	fdb_hashes_group_t *hg=arg;
	while(glovars.shutdown==0) {
		usleep(fdb_system_var.hash_purge_loop);
		hg->now=time(NULL);
		if ( fdb_hashes_group_used_mem_pct(hg) < fdb_system_var.purge_threshold_pct_min ) continue;
		unsigned char i;
		for (i=0; i<hg->size; i++) {
			pthread_rwlock_wrlock(&hg->fdb_hashes[i]->lock);
			if (hg->fdb_hashes[i]->purgeIdx==0) {
				if (hg->fdb_hashes[i]->ptrArray->len) {
					hg->fdb_hashes[i]->purgeIdx=hg->fdb_hashes[i]->ptrArray->len;
					hg->fdb_hashes[i]->purgeChunkSize=hg->fdb_hashes[i]->ptrArray->len*fdb_system_var.hash_purge_loop/fdb_system_var.hash_purge_time;
					if (hg->fdb_hashes[i]->purgeChunkSize < 10) { hg->fdb_hashes[i]->purgeChunkSize=hg->fdb_hashes[i]->ptrArray->len; } // this should prevent a bug with few entries left in the cache
				}
			}
			time_t t=hg->now;
			min_idx=( hg->fdb_hashes[i]->purgeIdx > hg->fdb_hashes[i]->purgeChunkSize ? hg->fdb_hashes[i]->purgeIdx - hg->fdb_hashes[i]->purgeChunkSize : 0 ) ;
			if (min_idx < hg->fdb_hashes[i]->purgeChunkSize )  min_idx=0;
			if (hg->fdb_hashes[i]->purgeIdx) while( --hg->fdb_hashes[i]->purgeIdx > min_idx) {
				fdb_hash_entry *entry=g_ptr_array_index(hg->fdb_hashes[i]->ptrArray,hg->fdb_hashes[i]->purgeIdx);
				if (( entry->expire!=EXPIRE_DROPIT) && entry->expire <= t) {
					g_hash_table_remove(hg->fdb_hashes[i]->hash,entry->key);
				}
				if ( (entry->expire==EXPIRE_DROPIT)
					&& (__sync_fetch_and_add(&entry->ref_count,0)==0) 
				) {
					__sync_fetch_and_sub(&hg->size_keys,entry->klen);
					__sync_fetch_and_sub(&hg->size_values,entry->length);
					__sync_fetch_and_sub(&hg->size_metas,sizeof(fdb_hash_entry)+sizeof(fdb_hash_entry *));
					g_free(entry->key);
					//g_slice_free1(entry->klen,entry->key);
					g_free(entry->value);
					entry->self=NULL;
					//g_free(entry);
					g_slice_free1(sizeof(fdb_hash_entry),entry);

					__sync_fetch_and_add(&hg->cntPurge,1);
					g_ptr_array_remove_index_fast(hg->fdb_hashes[i]->ptrArray,hg->fdb_hashes[i]->purgeIdx);
				}
			}

			pthread_rwlock_unlock(&hg->fdb_hashes[i]->lock);
		}
	}
	proxy_error("Shutdown purgeHash_thread\n");
	return NULL;
}

long long fdb_hashes_group_free_mem(fdb_hashes_group_t *hg) {
	// note: this check is not 100% accurate as it is performed before locking any structure
	//       this lack of accuracy is by design and not a bug
	long long cur_size=hg->size_keys+hg->size_values+hg->size_metas;
	long long max_size=hg->max_memory_size;
	return (cur_size > max_size ? 0 : max_size-cur_size);
}

int fdb_hashes_group_used_mem_pct(fdb_hashes_group_t *hg) {
	long long cur_size=hg->size_keys+hg->size_values+hg->size_metas;
	long long max_size=hg->max_memory_size;
	float pctf = (float) cur_size*100/max_size;
	if (pctf > 100) return 100;
	int pct=pctf;
	return pct;
}

// Added by chan ----------------------------------
// Destory hash value function
void qr_hash_value_destroy_func(void * hash_entry) {
	cleanup_query_stats(hash_entry);
/*	qr_hash_entry *entry= (qr_hash_entry *) hash_entry;
	g_free(entry->key);
	g_free(entry->value);
	g_free(entry);*/
}

// Create new hash struct
void qr_hashes_new(qr_hash_t *ht){
	ht->modify = time(NULL);
	ht->c_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, qr_hash_value_destroy_func);
	ht->p_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, qr_hash_value_destroy_func);
	pthread_rwlock_init(&(ht->lock), NULL);
}

// Increase executed count - search target with hash key
// last changed at 20140418 - by chan
void qr_set(char * key, char * value){
	qr_hash_t *ht = &QR_HASH_T;
	pthread_rwlock_wrlock(&(ht->lock));
	qr_hash_entry *entry = g_hash_table_lookup(ht->c_hash, key);
	if(entry == NULL){
		entry = g_malloc(sizeof(qr_hash_entry));
		entry->key = key;
		//FIXME: entry->value = value;
		entry->exec_cnt = 0;
		g_hash_table_insert(ht->c_hash, entry->key, entry);
	}else{
		// free duplicated key and value
		// added by chan
		g_free(key);
		g_free(value);
	}
	entry->exec_cnt++;
	pthread_rwlock_unlock(&(ht->lock));
}

// Print query stats - needed to write on log file
// last changed at 20140418 - by chan
void flush_query_stats (gpointer key, gpointer user_data){
#ifdef DEBUG
	qr_hash_t *ht = &QR_HASH_T;
	qr_hash_entry *entry = g_hash_table_lookup(ht->p_hash, key);
	//fprintf(stderr, "%s\t%d\t%p\n", entry->key, entry->exec_cnt, entry->value);
	//fprintf(stderr, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%d\n" , entry->exec_cnt, entry->key, key, entry->query_digest_md5, entry->query_digest_text, entry->hostgroup_id, entry->mysql_server_address, entry->mysql_server_port);
	proxy_debug(PROXY_DEBUG_QUERY_STATISTICS, 4, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%ld\n" , entry->exec_cnt, entry->username, entry->schemaname, entry->query_digest_md5, entry->query_digest_text, entry->hostgroup_id, ( entry->mysql_server_address ? entry->mysql_server_address : "NULL" ) , entry->mysql_server_port, entry->query_time);
#endif
}

// Report query stat result 
// last changed at 20140418 - by chan
void *qr_report_thread(void *arg){
	qr_hash_t *ht = arg;
	while(glovars.shutdown==0) {
		sleep(glovars.mysql_query_statistics_interval);
		if (glovars.mysql_query_statistics) {
			char __buffer[25];
			time_t curtime = time (NULL);
			struct tm *__tm_info=localtime(&curtime);
			strftime(__buffer, 25, "%Y-%m-%d %H:%M:%S", __tm_info);
			//fprintf(stderr, "%s\n", __buffer);
			proxy_debug(PROXY_DEBUG_QUERY_STATISTICS, 7, "Reporting queries\n");
			pthread_rwlock_wrlock(&(ht->lock));
			GHashTable *t_hash = ht->p_hash;
			ht->p_hash = ht->c_hash;
			ht->c_hash = t_hash;
			pthread_rwlock_unlock(&(ht->lock));

			// Print current stats
			GList *keysList = g_hash_table_get_keys(ht->p_hash);
#ifdef DEBUG
			g_list_foreach (keysList, flush_query_stats, NULL);
#endif
			g_list_foreach (keysList, __sqlite3_statsdb__flush_query_stats, &curtime);
			g_list_free(keysList);

			// Remove all entry in p_hash
			g_hash_table_remove_all(ht->p_hash);
		}
	}
	return NULL;
}
// Added by chan end.
