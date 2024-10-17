#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Protocol.h"
#include "MySQL_Query_Cache.h"

extern MySQL_Threads_Handler* GloMTH;

const int eof_to_ok_dif = static_cast<const int>(-(sizeof(mysql_hdr) + 5) + 2);
const int ok_to_eof_dif = static_cast<const int>(+(sizeof(mysql_hdr) + 5) - 2);

/**
 * @brief Converts a 'EOF_Packet' to holded inside a 'QC_entry_t' into a 'OK_Packet'.
 * Warning: This function assumes that the supplied 'QC_entry_t' holds a valid
 * 'EOF_Packet'.
 *
 * @param entry The 'QC_entry_t' holding a 'OK_Packet' to be converted into
 *  a 'EOF_Packet'.
 * @return The converted packet.
 */
unsigned char* eof_to_ok_packet(const MySQL_QC_entry_t* entry) {
	unsigned char* result = (unsigned char*)malloc(entry->length + eof_to_ok_dif);
	unsigned char* vp = result;
	unsigned char* it = entry->value;

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
	unsigned char* eof_packet = entry->value + entry->row_eof_pkt_offset;
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
unsigned char* ok_to_eof_packet(const MySQL_QC_entry_t* entry) {
	unsigned char* result = (unsigned char*)malloc(entry->length + ok_to_eof_dif);
	unsigned char* vp = result;
	unsigned char* it = entry->value;

	// Extract warning flags and status from 'OK_packet'
	unsigned char* ok_packet = it + entry->ok_pkt_offset;
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
		memcpy(&column_hdr, it, sizeof(mysql_hdr));
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
		memcpy(&hdr, it, sizeof(mysql_hdr));
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
		}
		else {
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

bool MySQL_Query_Cache::set(uint64_t user_hash, const unsigned char* kp, uint32_t kl, unsigned char* vp, 
	uint32_t vl, uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms, bool deprecate_eof_active) {
	MySQL_QC_entry_t* entry = (MySQL_QC_entry_t*)malloc(sizeof(MySQL_QC_entry_t));

	entry->column_eof_pkt_offset = 0;
	entry->row_eof_pkt_offset = 0;
	entry->ok_pkt_offset = 0;

	// Find the first EOF location
	unsigned char* it = vp;
	it += sizeof(mysql_hdr);
	uint64_t c_count = 0;
	int c_count_len = mysql_decode_length(const_cast<unsigned char*>(it), &c_count);
	it += c_count_len;

	for (uint64_t i = 0; i < c_count; i++) {
		mysql_hdr hdr;
		memcpy(&hdr, it, sizeof(mysql_hdr));
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
		memcpy(&hdr, it, sizeof(mysql_hdr));
		unsigned char* payload = it + sizeof(mysql_hdr);

		if (hdr.pkt_length < 9 && *payload == 0xfe) {
			if (deprecate_eof_active) {
				entry->ok_pkt_offset = it - vp;

				// Reset the warning flags to zero before storing resultset in the cache
				// Reason: When a warning flag is set, it may prompt the client to invoke "SHOW WARNINGS" or "SHOW COUNT(*) FROM WARNINGS". 
				// However, when retrieving data from the cache, it's possible that there are no warnings present
				// that might be associated with previous interactions.
				unsigned char* payload_temp = payload + 1;

				// skip affected_rows
				payload_temp += mysql_decode_length(payload_temp, nullptr);

				// skip last_insert_id
				payload_temp += mysql_decode_length(payload_temp, nullptr);

				// skip stats_flags
				payload_temp += sizeof(uint16_t);

				uint16_t warnings = 0;
				memcpy(payload_temp, &warnings, sizeof(uint16_t));

			}
			else {
				entry->row_eof_pkt_offset = it - vp;

				// Reset the warning flags to zero before storing resultset in the cache
				// Reason: When a warning flag is set, it may prompt the client to invoke "SHOW WARNINGS" or "SHOW COUNT(*) FROM WARNINGS".  
				// However, when retrieving data from the cache, it's possible that there are no warnings present
				// that might be associated with previous interactions.
				uint16_t warnings = 0;
				memcpy((payload + 1), &warnings, sizeof(uint16_t));
			}
			break;
		}
		else {
			it += sizeof(mysql_hdr) + hdr.pkt_length;
		}
	}

	return Query_Cache::set(entry, user_hash, kp, kl, vp, vl, create_ms, curtime_ms, expire_ms);
}

unsigned char* MySQL_Query_Cache::get(uint64_t user_hash, const unsigned char* kp, const uint32_t kl, uint32_t* lv, 
	uint64_t curtime_ms, uint64_t cache_ttl, bool deprecate_eof_active) {
	unsigned char* result = NULL;

	std::shared_ptr<MySQL_QC_entry_t> entry_shared = std::static_pointer_cast<MySQL_QC_entry_t>(
		Query_Cache::get(user_hash, kp, kl, curtime_ms, cache_ttl)
	);

	if (entry_shared) {
		if (deprecate_eof_active && entry_shared->column_eof_pkt_offset) {
			result = eof_to_ok_packet(entry_shared.get());
			*lv = entry_shared->length + eof_to_ok_dif;
		}
		else if (!deprecate_eof_active && entry_shared->ok_pkt_offset) {
			result = ok_to_eof_packet(entry_shared.get());
			*lv = entry_shared->length + ok_to_eof_dif;
		}
		else {
			result = (unsigned char*)malloc(entry_shared->length);
			memcpy(result, entry_shared->value, entry_shared->length);
			*lv = entry_shared->length;
		}
		//__sync_fetch_and_sub(&entry->ref_count, 1);
	}
	return result;
}

/*void* MySQL_Query_Cache::purgeHash_thread(void*) {
	
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread* mysql_thr = new MySQL_Thread();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version = GloMTH->get_global_version();
	set_thread_name("MyQCPurge");
	mysql_thr->refresh_variables();
	max_memory_size = static_cast<uint64_t>(mysql_thread___query_cache_size_MB*1024ULL*1024ULL);
	while (shutting_down == false) {
		usleep(purge_loop_time);
		unsigned int glover = GloMTH->get_global_version();
		if (GloMTH) {
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
				mysql_thr->refresh_variables();
				max_memory_size = static_cast<uint64_t>(mysql_thread___query_cache_size_MB*1024ULL*1024ULL);
			}
		}
		const unsigned int curr_pct = current_used_memory_pct();
		if (curr_pct < purge_threshold_pct_min) continue;
		Query_Cache::purgeHash((monotonic_time()/1000ULL), curr_pct);
	}
	delete mysql_thr;
	return NULL;
}*/
