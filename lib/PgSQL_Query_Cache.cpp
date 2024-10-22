#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Query_Cache.h"

extern PgSQL_Threads_Handler* GloPTH;

bool PgSQL_Query_Cache::set(uint64_t user_hash, const unsigned char* kp, uint32_t kl, unsigned char* vp, 
	uint32_t vl, uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms) {

	PgSQL_QC_entry_t* entry = (PgSQL_QC_entry_t*)malloc(sizeof(PgSQL_QC_entry_t)); 
	return Query_Cache::set(entry, user_hash, kp, kl, vp, vl, create_ms, curtime_ms, expire_ms);
}

const std::shared_ptr<PgSQL_QC_entry_t> PgSQL_Query_Cache::get(uint64_t user_hash, const unsigned char* kp, 
	const uint32_t kl, uint64_t curtime_ms, uint64_t cache_ttl) {

	const std::shared_ptr<PgSQL_QC_entry_t> entry_shared = std::static_pointer_cast<PgSQL_QC_entry_t>(
		Query_Cache::get(user_hash, kp, kl, curtime_ms, cache_ttl)
	);
	return entry_shared;
}

/*
void* PgSQL_Query_Cache::purgeHash_thread(void*) {

	unsigned int PgSQL_Monitor__thread_PgSQL_Thread_Variables_version;
	PgSQL_Thread* pgsql_thr = new PgSQL_Thread();
	PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = GloPTH->get_global_version();
	set_thread_name("PgQCPurge");
	pgsql_thr->refresh_variables();
	max_memory_size = static_cast<uint64_t>(pgsql_thread___query_cache_size_MB*1024ULL*1024ULL);
	while (shutting_down == false) {
		usleep(purge_loop_time);
		unsigned int glover = GloPTH->get_global_version();
		if (GloPTH) {
			if (PgSQL_Monitor__thread_PgSQL_Thread_Variables_version < glover) {
				PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = glover;
				pgsql_thr->refresh_variables();
				max_memory_size = static_cast<uint64_t>(pgsql_thread___query_cache_size_MB*1024ULL*1024ULL);
			}
		}
		const unsigned int curr_pct = current_used_memory_pct();
		if (curr_pct < purge_threshold_pct_min) continue;
		Query_Cache::purgeHash((monotonic_time()/1000ULL), curr_pct);
	}
	delete pgsql_thr;
	return NULL;
}*/
