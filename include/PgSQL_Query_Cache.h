#ifndef __CLASS_PGSQL_QUERY_CACHE_H
#define __CLASS_PGSQL_QUERY_CACHE_H

#include "proxysql.h"
#include "cpp.h"
#include "query_cache.hpp"

typedef struct _PgSQL_QC_entry : public QC_entry_t {} PgSQL_QC_entry_t;

class PgSQL_Query_Cache : public Query_Cache<PgSQL_Query_Cache> {
public:
	PgSQL_Query_Cache() = default;
	~PgSQL_Query_Cache() = default;

	bool set(uint64_t user_hash, const unsigned char* kp, uint32_t kl, unsigned char* vp, uint32_t vl, 
		uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms);
	const std::shared_ptr<PgSQL_QC_entry_t> get(uint64_t user_hash, const unsigned char* kp, const uint32_t kl, 
		uint64_t curtime_ms, uint64_t cache_ttl);
	//void* purgeHash_thread(void*);
};

#endif /* __CLASS_PGSQL_QUERY_CACHE_H */
