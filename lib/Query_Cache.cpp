#include "prometheus/counter.h"
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "query_cache.hpp"
#include "proxysql_atomic.h"
//#include "SpookyV2.h"
#include "prometheus_helpers.h"
#include "MySQL_Protocol.h"

#define THR_UPDATE_CNT(__a, __b, __c, __d) \
	do {\
		__a+=__c; \
		if (__a>=__d) { \
			__sync_fetch_and_add(&__b, __a - __a % __d); __a = __a % __d; \
		} \
	} while(0) 

#define THR_DECREASE_CNT(__a, __b, __c, __d) \
	do {\
		__a+=__c; \
		if (__a>=__d) { \
			__sync_fetch_and_sub(&__b, __a - __a % __d); __a = __a % __d; \
		} \
	} while(0) 


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_CACHE_VERSION "1.2.0905" DEB
#define PROXYSQL_QC_PTHREAD_MUTEX

extern MySQL_Threads_Handler *GloMTH;

typedef btree::btree_map<uint64_t, QC_entry_t *> BtMap_cache;

class KV_BtreeArray {
	private:
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_t lock;
#else
	rwlock_t lock;
#endif
	BtMap_cache bt_map;
	PtrArray *ptrArray;
	uint64_t purgeChunkSize;
	uint64_t purgeIdx;
	bool __insert(uint64_t, void *);
	uint64_t freeable_memory;
	public:
	uint64_t tottopurge;
	KV_BtreeArray();
	~KV_BtreeArray();
	uint64_t get_data_size();
	void purge_some(unsigned long long, bool);
	int cnt();
	bool replace(uint64_t key, QC_entry_t *entry);
	QC_entry_t *lookup(uint64_t key);
	void empty();
};

__thread uint64_t __thr_cntSet=0;
__thread uint64_t __thr_cntGet=0;
__thread uint64_t __thr_cntGetOK=0;
__thread uint64_t __thr_dataIN=0;
__thread uint64_t __thr_dataOUT=0;
__thread uint64_t __thr_num_entries=0;
__thread uint64_t __thr_num_deleted=0;
__thread uint64_t __thr_size_values=0;
//__thread uint64_t __thr_freeable_memory=0;

#define DEFAULT_SQC_size  4*1024*1024


static uint64_t Glo_cntSet=0;
static uint64_t Glo_cntGet=0;
static uint64_t Glo_cntGetOK=0;
static uint64_t Glo_num_entries=0;
static uint64_t Glo_dataIN=0;
static uint64_t Glo_dataOUT=0;
static uint64_t Glo_cntPurge=0;
static uint64_t Glo_size_values=0;
static uint64_t Glo_total_freed_memory;

KV_BtreeArray::KV_BtreeArray() {
	freeable_memory=0;
	tottopurge=0;
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_init(&lock, NULL);
#else
	spinlock_rwlock_init(&lock);
#endif
	ptrArray = new PtrArray;
};

KV_BtreeArray::~KV_BtreeArray() {
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 3, "Size of  KVBtreeArray:%d , ptrArray:%u\n", cnt() , ptrArray->len);
	empty();
	QC_entry_t *qce=NULL;
	while (ptrArray->len) {
		qce=(QC_entry_t *)ptrArray->remove_index_fast(0);
		free(qce->value);
		free(qce);
	}
	delete ptrArray;
};


uint64_t KV_BtreeArray::get_data_size() {
	uint64_t r = __sync_fetch_and_add(&Glo_num_entries,0) * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2); // +  __sync_fetch_and_add(&Glo_size_values,0) ;
	return r;
};

void KV_BtreeArray::purge_some(unsigned long long QCnow_ms, bool aggressive) {
	uint64_t ret=0, i, _size=0;
	QC_entry_t *qce;
	unsigned long long access_ms_min=0;
	unsigned long long access_ms_max=0;
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&lock);
#else
	spin_rdlock(&lock);
#endif
	for (i=0; i<ptrArray->len;i++) {
		qce=(QC_entry_t *)ptrArray->index(i);
		if (aggressive) { // we have been asked to do aggressive purging
			if (access_ms_min==0) {
				access_ms_min = qce->access_ms;
			} else {
				if (access_ms_min > qce->access_ms) {
					access_ms_min = qce->access_ms;
				}
			}
			if (access_ms_max==0) {
				access_ms_max = qce->access_ms;
			} else {
				if (access_ms_max < qce->access_ms) {
					access_ms_max = qce->access_ms;
				}
			}
		} else { // no aggresssive purging , legacy algorithm
			if (qce->expire_ms==EXPIRE_DROPIT || qce->expire_ms<QCnow_ms) {
				ret++;
				_size+=qce->length;
			}
		}
	}
	freeable_memory=_size;
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_unlock(&lock);
#else
	spin_rdunlock(&lock);
#endif
	bool cond_freeable_memory=false;
	if (aggressive==false) {
		uint64_t total_freeable_memory=0;
		total_freeable_memory=freeable_memory + ret * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2);
		if ( total_freeable_memory > get_data_size()*0.01 ) {
			cond_freeable_memory=true;	// there is memory that can be freed
		}
	}
	//if ( freeable_memory + ret * (sizeof(QC_entry_t) > get_data_size()*0.01) {
	if ( aggressive || cond_freeable_memory ) {
		uint64_t removed_entries=0;
		uint64_t freed_memory=0;
		unsigned long long access_ms_lower_mark=0;
		if (aggressive) {
			access_ms_lower_mark=access_ms_min+(access_ms_max-access_ms_min)*0.1; // hardcoded for now. Remove the entries with access time in the 10% range closest to access_ms_min
		}
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&lock);
#else
  	spin_wrlock(&lock);
#endif
		for (i=0; i<ptrArray->len;i++) {
			qce=(QC_entry_t *)ptrArray->index(i);
			bool drop_entry=false;
			if (__sync_fetch_and_add(&qce->ref_count,0)<=1) { // currently not in use
				if (qce->expire_ms==EXPIRE_DROPIT || qce->expire_ms<QCnow_ms) { //legacy algorithm
					drop_entry=true;
				}
				if (aggressive) { // we have been asked to do aggressive purging
					if (drop_entry==false) { // if the entry is already marked to be dropped, no further check
						if (qce->access_ms < access_ms_lower_mark) {
							drop_entry=true;
						}
					}
				}
			}
			if (drop_entry) {
				qce=(QC_entry_t *)ptrArray->remove_index_fast(i);

		    btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  				lookup = bt_map.find(qce->key);
     		if (lookup != bt_map.end()) {
					bt_map.erase(lookup);
				}
				i--;
				freed_memory+=qce->length;
				removed_entries++;
				free(qce->value);
				free(qce);
			}
		}
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
		pthread_rwlock_unlock(&lock);
#else
		spin_wrunlock(&lock);
#endif
		THR_DECREASE_CNT(__thr_num_deleted,Glo_num_entries,removed_entries,1);
		if (removed_entries) {
			__sync_fetch_and_add(&Glo_total_freed_memory,freed_memory);
			__sync_fetch_and_sub(&Glo_size_values,freed_memory);
			__sync_fetch_and_add(&Glo_cntPurge,removed_entries);
		}
	}
};

int KV_BtreeArray::cnt() {
	return bt_map.size();
};

bool KV_BtreeArray::replace(uint64_t key, QC_entry_t *entry) {
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&lock);
#else
	spin_wrlock(&lock);
#endif
	THR_UPDATE_CNT(__thr_cntSet,Glo_cntSet,1,1);
	THR_UPDATE_CNT(__thr_size_values,Glo_size_values,entry->length,1);
	THR_UPDATE_CNT(__thr_dataIN,Glo_dataIN,entry->length,1);
	THR_UPDATE_CNT(__thr_num_entries,Glo_num_entries,1,1);

	entry->ref_count=1;
  ptrArray->add(entry);
  btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
		lookup->second->expire_ms=EXPIRE_DROPIT;
		__sync_fetch_and_sub(&lookup->second->ref_count,1);
		bt_map.erase(lookup);
 	}
	bt_map.insert(std::make_pair(key,entry));
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_unlock(&lock);
#else
	spin_wrunlock(&lock);
#endif
	return true;
}

QC_entry_t * KV_BtreeArray::lookup(uint64_t key) {
	QC_entry_t *entry=NULL;
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&lock);
#else
	spin_rdlock(&lock);
#endif
	THR_UPDATE_CNT(__thr_cntGet,Glo_cntGet,1,1);
  btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
		entry=lookup->second;
		__sync_fetch_and_add(&entry->ref_count,1);
 	}	
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_unlock(&lock);
#else
	spin_rdunlock(&lock);
#endif
	return entry;
};

void KV_BtreeArray::empty() {
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&lock);
#else
	spin_wrlock(&lock);
#endif
	btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;

	while (bt_map.size()) {
		lookup = bt_map.begin();
		if ( lookup != bt_map.end() ) {
			lookup->second->expire_ms=EXPIRE_DROPIT;
			bt_map.erase(lookup);
		}
	}
#ifdef PROXYSQL_QC_PTHREAD_MUTEX
	pthread_rwlock_unlock(&lock);
#else
	spin_wrunlock(&lock);
#endif
};

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using qc_counter_tuple =
	std::tuple<
		p_qc_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using qc_gauge_tuple =
	std::tuple<
		p_qc_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using qc_counter_vector = std::vector<qc_counter_tuple>;
using qc_gauge_vector = std::vector<qc_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'Query_Cache' module.
 *
 * @note Many metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<qc_counter_vector, qc_gauge_vector>
qc_metrics_map = std::make_tuple(
	qc_counter_vector {
		// ====================================================================
		std::make_tuple (
			p_qc_counter::query_cache_count_get,
			"proxysql_query_cache_count_get_total",
			"Number of failed read requests.",
			metric_tags {
				{ "status", "err" }
			}
		),
		std::make_tuple (
			p_qc_counter::query_cache_count_get_ok,
			"proxysql_query_cache_count_get_total",
			"Number of successful read requests.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_qc_counter::query_cache_count_set,
			"proxysql_query_cache_count_set_total",
			"Number of write requests.",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			p_qc_counter::query_cache_bytes_in,
			"proxysql_query_cache_bytes_total",
			"Number of bytes (read|written) into the Query Cache.",
			metric_tags {
				{ "op", "written" }
			}
		),
		std::make_tuple (
			p_qc_counter::query_cache_bytes_out,
			"proxysql_query_cache_bytes_total",
			"Number of bytes (read|written) into the Query Cache.",
			metric_tags {
				{ "op", "read" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_qc_counter::query_cache_purged,
			"proxysql_query_cache_purged_total",
			"Number of entries purged by the Query Cache due to TTL expiration.",
			metric_tags {}
		),
		std::make_tuple (
			p_qc_counter::query_cache_entries,
			"proxysql_query_cache_entries_total",
			"Number of entries currently stored in the query cache.",
			metric_tags {}
		)
	},
	qc_gauge_vector {
		std::make_tuple (
			p_qc_gauge::query_cache_memory_bytes,
			"proxysql_query_cache_memory_bytes",
			"Memory currently used by the query cache.",
			metric_tags {}
		)
	}
);

uint64_t Query_Cache::get_data_size_total() {
	uint64_t r=0;
	int i;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		r+=KVs[i]->get_data_size();
	}
	r += __sync_fetch_and_add(&Glo_size_values,0);
	return r;
};

unsigned int Query_Cache::current_used_memory_pct() {
	uint64_t cur_size=get_data_size_total();
	float pctf = (float) cur_size*100/max_memory_size;
	if (pctf > 100) return 100;
	int pct=pctf;
	return pct;
}

Query_Cache::Query_Cache() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		KVs[i]=new KV_BtreeArray();
	}
	QCnow_ms=monotonic_time()/1000;
	size=SHARED_QUERY_CACHE_HASH_TABLES;
	shutdown=0;
	purge_loop_time=DEFAULT_purge_loop_time;
	purge_total_time=DEFAULT_purge_total_time;
	purge_threshold_pct_min=DEFAULT_purge_threshold_pct_min;
	purge_threshold_pct_max=DEFAULT_purge_threshold_pct_max;
	max_memory_size=DEFAULT_SQC_size;

	// Initialize prometheus metrics
	init_prometheus_counter_array<qc_metrics_map_idx, p_qc_counter>(qc_metrics_map, this->metrics.p_counter_array);
	init_prometheus_gauge_array<qc_metrics_map_idx, p_qc_gauge>(qc_metrics_map, this->metrics.p_gauge_array);
};

void Query_Cache::p_update_metrics() {
	this->metrics.p_gauge_array[p_qc_gauge::query_cache_memory_bytes]->Set(get_data_size_total());
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_get], Glo_cntGet - Glo_cntGetOK);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_get_ok], Glo_cntGetOK);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_set], Glo_cntSet);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_bytes_in], Glo_dataIN);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_bytes_out], Glo_dataOUT);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_purged], Glo_cntPurge);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_entries], Glo_num_entries);
}

void Query_Cache::print_version() {
	fprintf(stderr,"In memory Standard Query Cache (SQC) rev. %s -- %s -- %s\n", QUERY_CACHE_VERSION, __FILE__, __TIMESTAMP__);
};

Query_Cache::~Query_Cache() {
	unsigned int i;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		delete KVs[i];
	}
};

const int eof_to_ok_dif = static_cast<const int>(- (sizeof(mysql_hdr) + 5) + 2);
const int ok_to_eof_dif = static_cast<const int>(+ (sizeof(mysql_hdr) + 5) - 2);

/**
 * @brief Converts a 'EOF_Packet' to holded inside a 'QC_entry_t' into a 'OK_Packet'.
 * Warning: This function assumes that the supplied 'QC_entry_t' holds a valid
 * 'EOF_Packet'.
 *
 * @param entry The 'QC_entry_t' holding a 'OK_Packet' to be converted into
 *  a 'EOF_Packet'.
 * @return The converted packet.
 */
unsigned char* eof_to_ok_packet(QC_entry_t* entry) {
	unsigned char* result = (unsigned char*)malloc(entry->length + eof_to_ok_dif);
	unsigned char* vp = result;
	char* it = entry->value;

	// Copy until the first EOF
	memcpy(vp, entry->value, entry->column_eof_pkt_offset);
	it += entry->column_eof_pkt_offset;
	vp += entry->column_eof_pkt_offset;

	// Skip the first EOF after columns def
	mysql_hdr hdr;
	memcpy(&hdr, it, sizeof(mysql_hdr));
	it += sizeof(mysql_hdr) + hdr.pkt_length;

	// Copy all the rows
	uint64_t u_entry_val = reinterpret_cast<uint64_t>(entry->value);
	uint64_t u_it_pos = reinterpret_cast<uint64_t>(it);
	uint64_t rows_length = (u_entry_val + entry->row_eof_pkt_offset) - u_it_pos;
	memcpy(vp, it, rows_length);
	vp += rows_length;
	it += rows_length;

	// Replace final EOF in favor of OK packet
	// =======================================
	// Copy the mysql header
	memcpy(&hdr, it, sizeof(mysql_hdr));
	hdr.pkt_length = 7;
	memcpy(vp, &hdr, sizeof(mysql_hdr));
	vp += sizeof(mysql_hdr);
	it += sizeof(mysql_hdr);

	// OK packet header
	*vp = 0xfe;
	vp++;
	it++;
	// Initialize affected_rows and last_insert_id to zero
	memset(vp, 0, 2);
	vp += 2;
	// Extract warning flags and status from 'EOF_packet'
	char* eof_packet = entry->value + entry->row_eof_pkt_offset;
	eof_packet += sizeof(mysql_hdr);
	// Skip the '0xFE EOF packet header'
	eof_packet += 1;
	uint16_t warnings;
	memcpy(&warnings, eof_packet, sizeof(uint16_t));
	eof_packet += 2;
	uint16_t status_flags;
	memcpy(&status_flags, eof_packet, sizeof(uint16_t));
	// Copy warnings an status flags
	memcpy(vp, &status_flags, sizeof(uint16_t));
	vp += 2;
	memcpy(vp, &warnings, sizeof(uint16_t));
	// =======================================

	// Decrement ids after the first EOF
	unsigned char* dp = result + entry->column_eof_pkt_offset;
	mysql_hdr decrement_hdr;
	for (;;) {
		memcpy(&decrement_hdr, dp, sizeof(mysql_hdr));
		decrement_hdr.pkt_id--;
		memcpy(dp, &decrement_hdr, sizeof(mysql_hdr));
		dp += sizeof(mysql_hdr) + decrement_hdr.pkt_length;
		if (dp >= vp)
			break;
	}

	return result;
}

/**
 * @brief Converts a 'OK_Packet' holded inside 'QC_entry_t' into a 'EOF_Packet'.
 *  Warning: This function assumes that the supplied 'QC_entry_t' holds a valid
 *  'OK_Packet'.
 *
 * @param entry The 'QC_entry_t' holding a 'EOF_Packet' to be converted into
 *  a 'OK_Packet'.
 * @return The converted packet.
 */
unsigned char* ok_to_eof_packet(QC_entry_t* entry) {
	unsigned char* result = (unsigned char*)malloc(entry->length + ok_to_eof_dif);
	unsigned char* vp = result;
	char* it = entry->value;

	// Extract warning flags and status from 'OK_packet'
	char* ok_packet = it + entry->ok_pkt_offset;
	mysql_hdr ok_hdr;
	memcpy(&ok_hdr, ok_packet, sizeof(mysql_hdr));
	ok_packet += sizeof(mysql_hdr);
	// Skip the 'OK packet header', 'affected_rows' and 'last_insert_id'
	ok_packet += 3;
	uint16_t status_flags;
	memcpy(&status_flags, ok_packet, sizeof(uint16_t));
	ok_packet += 2;
	uint16_t warnings;
	memcpy(&warnings, ok_packet, sizeof(uint16_t));

	// Find the spot in which the first EOF needs to be placed
	it += sizeof(mysql_hdr);
	uint64_t c_count = 0;
	int c_count_len = mysql_decode_length(reinterpret_cast<unsigned char*>(it), &c_count);
	it += c_count_len;

	mysql_hdr column_hdr;
	for (uint64_t i = 0; i < c_count; i++) {
		memcpy(&column_hdr, it ,sizeof(mysql_hdr));
		it += sizeof(mysql_hdr) + column_hdr.pkt_length;
	}

	// Location for 'column_eof'
	uint64_t column_eof_offset =
		reinterpret_cast<unsigned char*>(it) -
		reinterpret_cast<unsigned char*>(entry->value);
	memcpy(vp, entry->value, column_eof_offset);
	vp += column_eof_offset;

	// Write 'column_eof_packet' header
	column_hdr.pkt_id = column_hdr.pkt_id + 1;
	column_hdr.pkt_length = 5;
	memcpy(vp, &column_hdr, sizeof(mysql_hdr));
	vp += sizeof(mysql_hdr);

	// Write 'column_eof_packet' contents
	*vp = 0xfe;
	vp++;
	memcpy(vp, &warnings, sizeof(uint16_t));
	vp += 2;
	memcpy(vp, &status_flags, sizeof(uint16_t));
	vp += 2;

	// Find the OK packet
	for (;;) {
		mysql_hdr hdr;
		memcpy(&hdr, it ,sizeof(mysql_hdr));
		unsigned char* payload =
			reinterpret_cast<unsigned char*>(it) +
			sizeof(mysql_hdr);

		if (hdr.pkt_length < 9 && *payload == 0xfe) {
			mysql_hdr ok_hdr;
			ok_hdr.pkt_id = hdr.pkt_id + 1;
			ok_hdr.pkt_length = 5;
			memcpy(vp, &ok_hdr, sizeof(mysql_hdr));
			vp += sizeof(mysql_hdr);

			*vp = 0xfe;
			vp++;
			memcpy(vp, &warnings, sizeof(uint16_t));
			vp += 2;
			memcpy(vp, &status_flags, sizeof(uint16_t));
			break;
		} else {
			// Increment the package id by one due to 'column_eof_packet'
			hdr.pkt_id += 1;
			memcpy(vp, &hdr, sizeof(mysql_hdr));
			vp += sizeof(mysql_hdr);
			it += sizeof(mysql_hdr);
			memcpy(vp, it, hdr.pkt_length);
			vp += hdr.pkt_length;
			it += hdr.pkt_length;
		}
	}

	return result;
}

unsigned char * Query_Cache::get(uint64_t user_hash, const unsigned char *kp, const uint32_t kl, uint32_t *lv, unsigned long long curtime_ms, unsigned long long cache_ttl, bool deprecate_eof_active) {
	unsigned char *result=NULL;

	uint64_t hk=SpookyHash::Hash64(kp, kl, user_hash);
	unsigned char i=hk%SHARED_QUERY_CACHE_HASH_TABLES;

	QC_entry_t *entry=KVs[i]->lookup(hk);

	if (entry!=NULL) {
		unsigned long long t=curtime_ms;
		if (entry->expire_ms > t && entry->create_ms + cache_ttl > t) {
			if (
				mysql_thread___query_cache_soft_ttl_pct && !entry->refreshing &&
				entry->create_ms + cache_ttl * mysql_thread___query_cache_soft_ttl_pct / 100 <= t
			) {
				// If the Query Cache entry reach the soft_ttl but do not reach
				// the cache_ttl, the next query hit the backend and refresh
				// the entry, including ResultSet and TTLs. While the
				// refreshing is in process, other queries keep using the "old"
				// Query Cache entry.
				// soft_ttl_pct with value 0 and 100 disables the functionality.
				entry->refreshing = true;
			} else {
				THR_UPDATE_CNT(__thr_cntGetOK,Glo_cntGetOK,1,1);
				THR_UPDATE_CNT(__thr_dataOUT,Glo_dataOUT,entry->length,1);

				if (deprecate_eof_active && entry->column_eof_pkt_offset) {
					result = eof_to_ok_packet(entry);
					*lv = entry->length + eof_to_ok_dif;
				} else if (!deprecate_eof_active && entry->ok_pkt_offset){
					result = ok_to_eof_packet(entry);
					*lv = entry->length + ok_to_eof_dif;
				} else {
					result = (unsigned char *)malloc(entry->length);
					memcpy(result, entry->value, entry->length);
					*lv = entry->length;
				}

				if (t > entry->access_ms) entry->access_ms=t;
			}
		}
		__sync_fetch_and_sub(&entry->ref_count,1);
	}
	return result;
}

bool Query_Cache::set(uint64_t user_hash, const unsigned char *kp, uint32_t kl, unsigned char *vp, uint32_t vl, unsigned long long create_ms, unsigned long long curtime_ms, unsigned long long expire_ms, bool deprecate_eof_active) {
	QC_entry_t *entry = (QC_entry_t *)malloc(sizeof(QC_entry_t));
	entry->klen=kl;
	entry->length=vl;
	entry->ref_count=0;
	entry->column_eof_pkt_offset=0;
	entry->row_eof_pkt_offset=0;
	entry->ok_pkt_offset=0;
	entry->refreshing=false;

	// Find the first EOF location
	unsigned char* it = vp;
	it += sizeof(mysql_hdr);
	uint64_t c_count = 0;
	int c_count_len = mysql_decode_length(const_cast<unsigned char*>(it), &c_count);
	it += c_count_len;

	for (uint64_t i = 0; i < c_count; i++) {
		mysql_hdr hdr;
		memcpy(&hdr, it ,sizeof(mysql_hdr));
		it += sizeof(mysql_hdr) + hdr.pkt_length;
	}

	if (deprecate_eof_active == false) {
		// Store EOF position and jump to rows
		entry->column_eof_pkt_offset = it - vp;
		mysql_hdr hdr;
		memcpy(&hdr, it, sizeof(mysql_hdr));
		it += sizeof(mysql_hdr) + hdr.pkt_length;
	}

	// Find the second EOF location or the OK packet
	for (;;) {
		mysql_hdr hdr;
		memcpy(&hdr, it ,sizeof(mysql_hdr));
		unsigned char* payload = it + sizeof(mysql_hdr);

		if (hdr.pkt_length < 9 && *payload == 0xfe) {
			if (deprecate_eof_active) {
				entry->ok_pkt_offset = it - vp;

				// Reset the warning flags to zero before storing resultset in the cache
				// Reason: When a warning flag is set, it may prompt the client to invoke "SHOW WARNINGS" or "SHOW COUNT(*) FROM WARNINGS". 
				// However, when retrieving data from the cache, it's possible that there are no warnings present
				// that might be associated with previous interactions.
				unsigned char* payload_temp = payload+1;

				// skip affected_rows
				payload_temp += mysql_decode_length(payload_temp, nullptr);
				
				// skip last_insert_id
				payload_temp += mysql_decode_length(payload_temp, nullptr);

				// skip stats_flags
				payload_temp += sizeof(uint16_t);

				uint16_t warnings = 0;
				memcpy(payload_temp, &warnings, sizeof(uint16_t));

			} else {
				entry->row_eof_pkt_offset = it - vp;

				// Reset the warning flags to zero before storing resultset in the cache
				// Reason: When a warning flag is set, it may prompt the client to invoke "SHOW WARNINGS" or "SHOW COUNT(*) FROM WARNINGS".  
				// However, when retrieving data from the cache, it's possible that there are no warnings present
				// that might be associated with previous interactions.
				uint16_t warnings = 0;
				memcpy((payload + 1), &warnings, sizeof(uint16_t));
			}
			break;
		} else {
			it += sizeof(mysql_hdr) + hdr.pkt_length;
		}
	}

	entry->value=(char *)malloc(vl);
	memcpy(entry->value,vp,vl);
	entry->self=entry;
	entry->create_ms=create_ms;
	entry->access_ms=curtime_ms;
	entry->expire_ms=expire_ms;
	uint64_t hk=SpookyHash::Hash64(kp, kl, user_hash);
	unsigned char i=hk%SHARED_QUERY_CACHE_HASH_TABLES;
	entry->key=hk;
	KVs[i]->replace(hk, entry);

	return true;
}

uint64_t Query_Cache::flush() {
	int i;
	uint64_t total_count=0;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		total_count+=KVs[i]->cnt();
		KVs[i]->empty();
	}
	return total_count;
};

void * Query_Cache::purgeHash_thread(void *) {
	unsigned int i;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	set_thread_name("QueryCachePurge");
	mysql_thr->refresh_variables();
	max_memory_size = (uint64_t) mysql_thread___query_cache_size_MB*1024*1024;
	while (shutdown==0) {
		usleep(purge_loop_time);
		unsigned long long t=monotonic_time()/1000;
		QCnow_ms=t;
		unsigned int glover=GloMTH->get_global_version();
		if (GloMTH) {
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
				max_memory_size = (uint64_t) mysql_thread___query_cache_size_MB*1024*1024;
			}
		}
		unsigned int curr_pct=current_used_memory_pct();
		if (curr_pct < purge_threshold_pct_min ) continue;
		for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
			KVs[i]->purge_some(QCnow_ms, (curr_pct > purge_threshold_pct_max));
		}
	}
	delete mysql_thr;
	return NULL;
};

SQLite3_result * Query_Cache::SQL3_getStats() {
	const int colnum=2;
	char buf[256];
	char **pta=(char **)malloc(sizeof(char *)*colnum);
	//Get_Memory_Stats();
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"Variable_Name");
	result->add_column_definition(SQLITE_TEXT,"Variable_Value");
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
	{ // Used Memoery
		pta[0]=(char *)"Query_Cache_Memory_bytes";
		sprintf(buf,"%lu", get_data_size_total());
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntGet
		pta[0]=(char *)"Query_Cache_count_GET";
		sprintf(buf,"%lu", Glo_cntGet);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntGetOK
		pta[0]=(char *)"Query_Cache_count_GET_OK";
		sprintf(buf,"%lu", Glo_cntGetOK);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntSet
		pta[0]=(char *)"Query_Cache_count_SET";
		sprintf(buf,"%lu", Glo_cntSet);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_dataIN
		pta[0]=(char *)"Query_Cache_bytes_IN";
		sprintf(buf,"%lu", Glo_dataIN);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_dataOUT
		pta[0]=(char *)"Query_Cache_bytes_OUT";
		sprintf(buf,"%lu", Glo_dataOUT);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntPurge
		pta[0]=(char *)"Query_Cache_Purged";
		sprintf(buf,"%lu", Glo_cntPurge);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_num_entries
		pta[0]=(char *)"Query_Cache_Entries";
		sprintf(buf,"%lu", Glo_num_entries);
		pta[1]=buf;
		result->add_row(pta);
	}
	free(pta);
	return result;
}
