#ifndef __CLASS_MYSQL_QUERY_CACHE_H
#define __CLASS_MYSQL_QUERY_CACHE_H

#include "proxysql.h"
#include "cpp.h"
#include "query_cache.hpp"

typedef struct _MySQL_QC_entry : public QC_entry_t {
	uint32_t column_eof_pkt_offset;
	uint32_t row_eof_pkt_offset;
	uint32_t ok_pkt_offset;
} MySQL_QC_entry_t;

class MySQL_Query_Cache : public Query_Cache<MySQL_Query_Cache> {
public:
	MySQL_Query_Cache() = default;
	~MySQL_Query_Cache() = default;

	bool set(uint64_t user_hash, const unsigned char* kp, uint32_t kl, unsigned char* vp, uint32_t vl, 
		uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms, bool deprecate_eof_active);
	unsigned char* get(uint64_t user_hash, const unsigned char* kp, const uint32_t kl, uint32_t* lv, 
		uint64_t curtime_ms, uint64_t cache_ttl, bool deprecate_eof_active);
	//void* purgeHash_thread(void*);
};

#endif /* __CLASS_MYSQL_QUERY_CACHE_H */
