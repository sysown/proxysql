#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <fstream>
#include <map>
#include "proxysql.h"
#include "cpp.h"

#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Logger.hpp"
#include "log_utils.h"

#include <dirent.h>
#include <libgen.h>
#include <vector>


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_PGSQL_LOGGER_VERSION "2.5.0421" DEB

extern PgSQL_Logger *GloPgSQL_Logger;
extern PgSQL_Threads_Handler* GloPTH;

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using pl_counter_tuple =
	std::tuple<
		p_pl_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using pl_gauge_tuple =
	std::tuple<
		p_pl_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using pl_counter_vector = std::vector<pl_counter_tuple>;
using pl_gauge_vector = std::vector<pl_gauge_tuple>;

const std::tuple<pl_counter_vector, pl_gauge_vector>
pl_metrics_map = std::make_tuple(
	pl_counter_vector {
		std::make_tuple(
			p_pl_counter::memory_copy_count,
			"proxysql_pgsql_logger_copy_total",
			"Number of times events were copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple(
			p_pl_counter::disk_copy_count,
			"proxysql_pgsql_logger_copy_total",
			"Number of times events were copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple(
			p_pl_counter::get_all_events_calls_count,
			"proxysql_pgsql_logger_get_all_events_calls_total",
			"Number of times the 'get_all_events' method was called.",
			metric_tags {}
		),
		std::make_tuple(
			p_pl_counter::get_all_events_events_count,
			"proxysql_pgsql_logger_get_all_events_events_total",
			"Number of events retrieved by the `get_all_events` method.",
			metric_tags {}
		),
		std::make_tuple(
			p_pl_counter::total_memory_copy_time_us,
			"proxysql_pgsql_logger_copy_seconds_total",
			"Total time spent copying events to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple(
			p_pl_counter::total_disk_copy_time_us,
			"proxysql_pgsql_logger_copy_seconds_total",
			"Total time spent copying events to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple(
			p_pl_counter::total_get_all_events_time_us,
			"proxysql_pgsql_logger_get_all_events_seconds_total",
			"Total time spent in `get_all_events` method.",
			metric_tags {}
		),
		std::make_tuple(
			p_pl_counter::total_events_copied_to_memory,
			"proxysql_pgsql_logger_events_copied_total",
			"Total number of events copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple(
			p_pl_counter::total_events_copied_to_disk,
			"proxysql_pgsql_logger_events_copied_total",
			"Total number of events copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple(
			p_pl_counter::circular_buffer_events_added_count,
			"proxysql_pgsql_logger_circular_buffer_events_total",
			"The total number of events added/dropped to/from the circular buffer.",
			metric_tags { { "type", "added" } }
		),
		std::make_tuple(
			p_pl_counter::circular_buffer_events_dropped_count,
			"proxysql_pgsql_logger_circular_buffer_events_total",
			"The total number of events added/dropped to/from the circular buffer.",
			metric_tags { { "type", "dropped" } }
		),
	},
	pl_gauge_vector {
		std::make_tuple(
			p_pl_gauge::circular_buffer_events_size,
			"proxysql_pgsql_logger_circular_buffer_events",
			"Number of events currently present in the circular buffer.",
			metric_tags {}
		),
	}
);

static uint8_t encode_length(uint64_t len, unsigned char *hd) {
	if (len < 251) return 1;
	if (len < 65536) { if (hd) { *hd=0xfc; }; return 3; }
	if (len < 16777216) { if (hd) { *hd=0xfd; }; return 4; }
	if (hd) { *hd=0xfe; }
	return 9;
}

static inline int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix) {
	if (len==1) {
		*p=(char)val;
		return 1;
	}
	*p=prefix;
	p++;
	memcpy(p,&val,len-1);
	return len;
}

/**
 * @brief Returns runtime max query length for PostgreSQL events buffer copies.
 *
 * @details The PGSQL events dump commands can run from either Admin protocol
 * endpoint (MySQL/6032 or PostgreSQL/6132). To keep behavior identical across
 * both, this helper reads the canonical runtime value from `GloPTH->variables`
 * when available, instead of relying on protocol-thread TLS state.
 */
static size_t get_pgsql_eventslog_buffer_max_query_length_runtime() {
	if (GloPTH != nullptr) {
		return static_cast<size_t>(GloPTH->variables.eventslog_buffer_max_query_length);
	}
	return static_cast<size_t>(pgsql_thread___eventslog_buffer_max_query_length);
}

/**
 * @brief Returns runtime max in-memory rows for `stats_pgsql_query_events`.
 *
 * @details See `get_pgsql_eventslog_buffer_max_query_length_runtime()` for
 * rationale on using `GloPTH->variables` rather than protocol-thread TLS.
 */
static size_t get_pgsql_eventslog_table_memory_size_runtime() {
	if (GloPTH != nullptr) {
		return static_cast<size_t>(GloPTH->variables.eventslog_table_memory_size);
	}
	return static_cast<size_t>(pgsql_thread___eventslog_table_memory_size);
}

PgSQL_Event::PgSQL_Event (PGSQL_LOG_EVENT_TYPE _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	username_len=0;
	schemaname_len=0;
	client_stmt_name_len=0;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
	query_ptr = NULL;
	query_len = 0;
	client=_client;
	client_len=_client_len;
	et=_et;
	hid=UINT64_MAX;
	server=NULL;
	server_len=0;
	extra_info = NULL;
	have_affected_rows=false;
	affected_rows=0;
	have_rows_sent=false;
	rows_sent=0;
	client_stmt_name=NULL;
	sqlstate = NULL;
	errmsg = NULL;
	free_on_delete = false; // do not own pointers by default
	free_error_on_delete = false; // only error fields can be independently owned
	memset(buf, 0, sizeof(buf));
}

PgSQL_Event::PgSQL_Event(const PgSQL_Event& other) {
	memcpy(this, &other, sizeof(PgSQL_Event));

	if (other.username != nullptr) {
		username = strdup(other.username);
	}
	if (other.schemaname != nullptr) {
		schemaname = strdup(other.schemaname);
	}
	if (other.query_ptr != nullptr) {
		size_t maxQueryLen = get_pgsql_eventslog_buffer_max_query_length_runtime();
		size_t lenToCopy = std::min(other.query_len, maxQueryLen);
		query_ptr = (char*)malloc(lenToCopy + 1);
		memcpy(query_ptr, other.query_ptr, lenToCopy);
		query_ptr[lenToCopy] = '\0';
		query_len = lenToCopy;
	}
	if (other.server != nullptr) {
		server = (char*)malloc(server_len + 1);
		memcpy(server, other.server, server_len);
		server[server_len] = '\0';
	}
	if (other.client != nullptr) {
		client = (char*)malloc(client_len + 1);
		memcpy(client, other.client, client_len);
		client[client_len] = '\0';
	}
	if (other.extra_info != nullptr) {
		extra_info = strdup(other.extra_info);
	}
	if (other.client_stmt_name != nullptr) {
		client_stmt_name = strdup(other.client_stmt_name);
	}
	if (other.sqlstate != nullptr) {
		sqlstate = strdup(other.sqlstate);
	}
	if (other.errmsg != nullptr) {
		errmsg = strdup(other.errmsg);
	}

	free_on_delete = true;
	free_error_on_delete = false;
}

PgSQL_Event::~PgSQL_Event() {
	if (free_on_delete == true) {
		if (username != nullptr) {
			free(username); username = nullptr;
		}
		if (schemaname != nullptr) {
			free(schemaname); schemaname = nullptr;
		}
		if (query_ptr != nullptr) {
			free(query_ptr); query_ptr = nullptr;
		}
		if (server != nullptr) {
			free(server); server = nullptr;
		}
		if (client != nullptr) {
			free(client); client = nullptr;
		}
		if (extra_info != nullptr) {
			free(extra_info); extra_info = nullptr;
		}
		if (client_stmt_name != nullptr) {
			free(client_stmt_name); client_stmt_name = nullptr;
		}
		if (sqlstate != nullptr) {
			free(sqlstate); sqlstate = nullptr;
		}
		if (errmsg != nullptr) {
			free(errmsg); errmsg = nullptr;
		}
	} else if (free_error_on_delete == true) {
		if (sqlstate != nullptr) {
			free(sqlstate); sqlstate = nullptr;
		}
		if (errmsg != nullptr) {
			free(errmsg); errmsg = nullptr;
		}
	}
}

void PgSQL_Event::set_client_stmt_name(char* client_stmt_name) {
	this->client_stmt_name = client_stmt_name;
}

// if affected rows is set, last_insert_id is set too.
// They are part of the same OK packet
void PgSQL_Event::set_affected_rows(uint64_t ar) {
	have_affected_rows=true;
	affected_rows=ar;
}

void PgSQL_Event::set_rows_sent(uint64_t rs) {
	have_rows_sent=true;
	rows_sent=rs;
}

void PgSQL_Event::set_extra_info(char *_err) {
	extra_info = _err;
}

void PgSQL_Event::set_query(const char *ptr, int len) {
	query_ptr=(char *)ptr;
	// Adjust length: input length includes the null terminator
	if (len > 0) {
		len--;  // exclude '\0'
	}
	query_len=len;
}

void PgSQL_Event::set_server(int _hid, const char *ptr, int len) {
	server=(char *)ptr;
	server_len=len;
	hid=_hid;
}

void PgSQL_Event::set_error(const char* _sqlstate, const char* _errmsg) {
	if (free_on_delete == true || free_error_on_delete == true) {
		if (sqlstate != nullptr) {
			free(sqlstate);
			sqlstate = nullptr;
		}
		if (errmsg != nullptr) {
			free(errmsg);
			errmsg = nullptr;
		}
	}
	sqlstate = (_sqlstate != nullptr) ? strdup(_sqlstate) : nullptr;
	errmsg = (_errmsg != nullptr) ? strdup(_errmsg) : nullptr;
	free_error_on_delete = true;
}

uint64_t PgSQL_Event::write(LogBuffer *f, PgSQL_Session *sess) {
	uint64_t total_bytes=0;
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::SIMPLE_QUERY:
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
			if (pgsql_thread___eventslog_format==1) { // format 1 , binary
				total_bytes=write_query_format_1(f);
			} else { // format 2 , json
				total_bytes=write_query_format_2_json(f);
			}
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
		case PGSQL_LOG_EVENT_TYPE::INITDB:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT:
			write_auth(f, sess);
			break;
		default:
			break;
	}
	return total_bytes;
}

void PgSQL_Event::write_auth(LogBuffer *f, PgSQL_Session *sess) {
	json j = {};
	j["timestamp"] = start_time/1000;
	{
		time_t timer=start_time/1000/1000;
		struct tm tm_info;
		char buffer1[36];
		char buffer2[64];
		if (localtime_r(&timer, &tm_info)) {
 			strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
			snprintf(buffer2, sizeof(buffer2), "%s.%03u", buffer1, (unsigned)(start_time%1000000)/1000);
 		} else {
 			snprintf(buffer2, sizeof(buffer2), "invalid_date");
 		}
		j["time"] = buffer2;
	}
	j["thread_id"] = thread_id;
	if (username) {
		j["username"] = username;
	} else {
		j["username"] = "";
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	} else {
		j["schemaname"] = "";
	}
	if (client) {
		j["client_addr"] = client;
	} else {
		j["client_addr"] = "";
	}
	if (server) {
		j["server_addr"] = server;
	}
	if (extra_info) {
		j["extra_info"] = extra_info;
	}
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
			j["event"]="PGSQL_Client_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
			j["event"]="PGSQL_Client_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
			j["event"]="PGSQL_Client_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
			j["event"]="PGSQL_Client_Quit";
			break;
		case PGSQL_LOG_EVENT_TYPE::INITDB:
			j["event"]="PGSQL_Client_Init_DB";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK:
			j["event"]="PGSQL_Admin_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR:
			j["event"]="PGSQL_Admin_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
			j["event"]="PGSQL_Admin_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT:
			j["event"]="PGSQL_Admin_Quit";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK:
			j["event"]="PGSQL_SQLite3_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR:
			j["event"]="PGSQL_SQLite3_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
			j["event"]="PGSQL_SQLite3_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT:
			j["event"]="PGSQL_SQLite3_Quit";
			break;
		default:
			break;
	}
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
			{
				uint64_t curtime_real=realtime_time();
				uint64_t curtime_mono=sess->thread->curtime;
				uint64_t timediff = curtime_mono - sess->start_time;
				uint64_t orig_time = curtime_real - timediff;
				time_t timer= (orig_time)/1000/1000;
				struct tm tm_info;
				char buffer1[36];
				char buffer2[64];
				if (localtime_r(&timer, &tm_info)) {
 					strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
					snprintf(buffer2, sizeof(buffer2), "%s.%03u", buffer1, (unsigned)(orig_time%1000000)/1000);
 				} else {
 					snprintf(buffer2, sizeof(buffer2), "invalid_date");
 				}
				j["creation_time"] = buffer2;
				//unsigned long long life = sess->thread->curtime - sess->start_time;
				//life/=1000;
				float f = timediff;
				f /= 1000;
				snprintf(buffer1, sizeof(buffer1), "%.3fms", f);
				j["duration"] = buffer1;
			}
			break;
		default:
			break;
	}
	if (sess->client_myds) {
		if (sess->client_myds->proxy_addr.addr) {
			std::string s = sess->client_myds->proxy_addr.addr;
			s += ":" + std::to_string(sess->client_myds->proxy_addr.port);
			j["proxy_addr"] = s;
		}
		j["ssl"] = sess->client_myds->encrypted;
	}
	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
	//move wrlock() function to log_audit_entry() function, avoid to get a null pointer in a multithreaded environment
	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << '\n';
}

uint64_t PgSQL_Event::write_query_format_1(LogBuffer *f) {
	uint64_t total_bytes=0;
	total_bytes+=1; // et
	total_bytes+=encode_length(thread_id, NULL);
	username_len=strlen(username);
	total_bytes+=encode_length(username_len,NULL)+username_len;
	schemaname_len=strlen(schemaname);
	total_bytes+=encode_length(schemaname_len,NULL)+schemaname_len;

	total_bytes+=encode_length(client_len,NULL)+client_len;

	total_bytes+=encode_length(hid, NULL);
	if (hid!=UINT64_MAX) {
		total_bytes+=encode_length(server_len,NULL)+server_len;
	}

	total_bytes+=encode_length(start_time,NULL);
	total_bytes+=encode_length(end_time,NULL);
	client_stmt_name_len=client_stmt_name ? strlen(client_stmt_name) : 0;
	total_bytes+=encode_length(client_stmt_name_len,NULL)+client_stmt_name_len;
	total_bytes+=encode_length(affected_rows,NULL);
	total_bytes+=encode_length(rows_sent,NULL);

	total_bytes+=encode_length(query_digest,NULL);

	total_bytes+=encode_length(query_len,NULL)+query_len;

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	// write total length , fixed size
	f->write((const char *)&total_bytes,sizeof(uint64_t));
	//char prefix;
	uint8_t len;

	f->write((char *)&et,1);

	len=encode_length(thread_id,buf);
	write_encoded_length(buf,thread_id,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(username_len,buf);
	write_encoded_length(buf,username_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(username,username_len);

	len=encode_length(schemaname_len,buf);
	write_encoded_length(buf,schemaname_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(schemaname,schemaname_len);

	len=encode_length(client_len,buf);
	write_encoded_length(buf,client_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(client,client_len);

	len=encode_length(hid,buf);
	write_encoded_length(buf,hid,len,buf[0]);
	f->write((char *)buf,len);

	if (hid!=UINT64_MAX) {
		len=encode_length(server_len,buf);
		write_encoded_length(buf,server_len,len,buf[0]);
		f->write((char *)buf,len);
		f->write(server,server_len);
	}

	len=encode_length(start_time,buf);
	write_encoded_length(buf,start_time,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(end_time,buf);
	write_encoded_length(buf,end_time,len,buf[0]);
	f->write((char *)buf,len);

	if (et == PGSQL_LOG_EVENT_TYPE::STMT_PREPARE || et == PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE || et == PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		len = encode_length(client_stmt_name_len, buf);
		write_encoded_length(buf, client_stmt_name_len, len, buf[0]);
		f->write((char*)buf, len);
		f->write(client_stmt_name, client_stmt_name_len);
	}

	len=encode_length(affected_rows,buf);
	write_encoded_length(buf,affected_rows,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(rows_sent,buf);
	write_encoded_length(buf,rows_sent,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(query_digest,buf);
	write_encoded_length(buf,query_digest,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(query_len,buf);
	write_encoded_length(buf,query_len,len,buf[0]);
	f->write((char *)buf,len);
	if (query_len) {
		f->write(query_ptr,query_len);
	}

	return total_bytes;
}

uint64_t PgSQL_Event::write_query_format_2_json(LogBuffer *f) {
	json j = {};
	uint64_t total_bytes=0;
	if (hid!=UINT64_MAX) {
		j["hostgroup_id"] = hid;
	} else {
		j["hostgroup_id"] = -1;
	}
	j["thread_id"] = thread_id;
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
			j["event"]="PGSQL_STMT_EXECUTE";
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
			j["event"]="PGSQL_STMT_PREPARE";
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
			j["event"]="PGSQL_STMT_DESCRIBE";
			break;
		default:
			j["event"]="PGSQL_SIMPLE_QUERY";
			break;
	}
	if (username) {
		j["username"] = username;
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	}
	if (client) {
		j["client"] = client;
	}
	if (hid!=UINT64_MAX) {
		if (server) {
			j["server"] = server;
		}
	}
	if (have_affected_rows == true) {
		// in JSON format we only log rows_affected and last_insert_id
		// if they are present.
		// rows_affected is logged also if 0, while
		// last_insert_id is log logged if 0
		j["rows_affected"] = affected_rows;
	}
	if (have_rows_sent == true) {
		j["rows_sent"] = rows_sent;
	}
	if (sqlstate != nullptr) {
		j["sqlstate"] = sqlstate;
	}
	if (errmsg != nullptr) {
		j["error"] = errmsg;
	}
	j["query"] = string(query_ptr, query_len);
	j["starttime_timestamp_us"] = start_time;
	{
		time_t timer=start_time/1000/1000;
		struct tm tm_info;
		char buffer1[36];
		char buffer2[64];
		if (localtime_r(&timer, &tm_info)) {
 			strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
			snprintf(buffer2, sizeof(buffer2), "%s.%06u", buffer1, (unsigned)(start_time%1000000));
 		} else {
 			snprintf(buffer2, sizeof(buffer2), "invalid_date");
 		}
		j["starttime"] = buffer2;
	}
	j["endtime_timestamp_us"] = end_time;
	{
		time_t timer=end_time/1000/1000;
		struct tm tm_info;
		char buffer1[36];
		char buffer2[64];
		if (localtime_r(&timer, &tm_info)) {
 			strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
			snprintf(buffer2, sizeof(buffer2), "%s.%06u", buffer1, (unsigned)(end_time%1000000));
 		} else {
 			snprintf(buffer2, sizeof(buffer2), "invalid_date");
 		}
		j["endtime"] = buffer2;
	}
	j["duration_us"] = end_time-start_time;
	char digest_hex[20];
	snprintf(digest_hex, sizeof(digest_hex), "0x%016llX", (long long unsigned int)query_digest);
	j["digest"] = digest_hex;

	if (et == PGSQL_LOG_EVENT_TYPE::STMT_PREPARE || et == PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE || et == PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		if (client_stmt_name) {
			j["client_stmt_name"] = client_stmt_name;
		}
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << '\n';
	return total_bytes; // always 0
}

extern PgSQL_Query_Processor* GloPgQPro;

PgSQL_Logger::PgSQL_Logger() : metrics{0, 0, 0, 0, 0, 0, 0, 0, 0} {
	events.enabled=false;
	events.base_filename=NULL;
	events.datadir=NULL;
	events.base_filename=strdup((char *)"");
	audit.enabled=false;
	audit.base_filename=NULL;
	audit.datadir=NULL;
	audit.base_filename=strdup((char *)"");
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_init(&wmutex,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	events.logfile=NULL;
	events.log_file_id=0;
	events.current_log_size=0;
	events.max_log_file_size=100*1024*1024;
	audit.logfile=NULL;
	audit.log_file_id=0;
	audit.current_log_size=0;
	audit.max_log_file_size=100*1024*1024;
	PgLogCB = new PgSQL_Logger_CircularBuffer(0);

	init_prometheus_counter_array<pl_metrics_map_idx, p_pl_counter>(
		pl_metrics_map, this->prom_metrics.p_counter_array
	);
	init_prometheus_gauge_array<pl_metrics_map_idx, p_pl_gauge>(
		pl_metrics_map, this->prom_metrics.p_gauge_array
	);
};

PgSQL_Logger::~PgSQL_Logger() {
	// Flush all per-thread buffers before destroying the logger
 	{
 		std::lock_guard<std::mutex> lock(log_thread_contexts_lock);
 		for (const auto& kv : log_thread_contexts) {
 			LogBufferThreadContext* log_ctx = kv.second.get();
			std::lock_guard<std::mutex> ctx_lock(log_ctx->buffer_lock);
			if (!log_ctx->events.empty()) {
				flush_and_rotate(log_ctx->events, events.logfile, events.current_log_size, events.max_log_file_size,
					[this]() { wrlock(); },
					[this]() { wrunlock(); },
					nullptr,
					0
				);
			}
			if (!log_ctx->audit.empty()) {
				flush_and_rotate(log_ctx->audit, audit.logfile, audit.current_log_size, audit.max_log_file_size,
					[this]() { wrlock(); },
					[this]() { wrunlock(); },
					nullptr,
					0
				);
			}
 		}
 	}

	if (events.datadir) {
		free(events.datadir);
	}
	free(events.base_filename);
	if (audit.datadir) {
		free(audit.datadir);
	}
	free(audit.base_filename);
	delete PgLogCB;
};

void PgSQL_Logger::wrlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_lock(&wmutex);
#else
  spin_wrlock(&rwlock);
#endif
};

void PgSQL_Logger::wrunlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_unlock(&wmutex);
#else
  spin_wrunlock(&rwlock);
#endif
};

void PgSQL_Logger::flush_log() {
	if (audit.enabled==false && events.enabled==false) return;
	flush(true);
	wrlock();
	events_flush_log_unlocked();
	audit_flush_log_unlocked();
	wrunlock();
}

bool PgSQL_Logger::is_events_logfile_open() const {
	return events.logfile_open.load();
}

void PgSQL_Logger::set_events_logfile_open(bool open) {
	events.logfile_open.store(open);
}

bool PgSQL_Logger::is_audit_logfile_open() const {
	return audit.logfile_open.load();
}

void PgSQL_Logger::set_audit_logfile_open(bool open) {
	audit.logfile_open.store(open);
}

void PgSQL_Logger::events_close_log_unlocked() {
	if (events.logfile) {
		events.logfile->flush();
		events.logfile->close();
		delete events.logfile;
		events.logfile=NULL;
		set_events_logfile_open(false);
	}
}

void PgSQL_Logger::audit_close_log_unlocked() {
	if (audit.logfile) {
		audit.logfile->flush();
		audit.logfile->close();
		delete audit.logfile;
		audit.logfile=NULL;
		set_audit_logfile_open(false);
	}
}

void PgSQL_Logger::events_flush_log_unlocked() {
	if (events.enabled==false) return;
	events_close_log_unlocked();
	events_open_log_unlocked();
}

void PgSQL_Logger::audit_flush_log_unlocked() {
	if (audit.enabled==false) return;
	audit_close_log_unlocked();
	audit_open_log_unlocked();
}

void PgSQL_Logger::events_open_log_unlocked() {
	events.log_file_id=events_find_next_id();
	if (events.log_file_id!=0) {
		events.log_file_id=events_find_next_id()+1;
	} else {
		events.log_file_id++;
	}
	char *filen=NULL;
	if (events.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(events.base_filename)+11);
		sprintf(filen,"%s.%08d",events.base_filename,events.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(events.datadir)+strlen(events.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",events.datadir,events.base_filename,events.log_file_id);
	}
	events.logfile=new std::fstream();
	events.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		events.logfile->open(filen , std::ios::out | std::ios::binary);
		events.current_log_size = 0;
 		set_events_logfile_open(true);
		proxy_info("Starting new pgsql event log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new pgsql event log file %s\n", filen);
		delete events.logfile;
		events.logfile=NULL;
		events.current_log_size = 0;
 		set_events_logfile_open(false);
	}
	free(filen);
};

void PgSQL_Logger::audit_open_log_unlocked() {
	audit.log_file_id=audit_find_next_id();
	if (audit.log_file_id!=0) {
		audit.log_file_id=audit_find_next_id()+1;
	} else {
		audit.log_file_id++;
	}
	char *filen=NULL;
	if (audit.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(audit.base_filename)+11);
		sprintf(filen,"%s.%08d",audit.base_filename,audit.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(audit.datadir)+strlen(audit.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",audit.datadir,audit.base_filename,audit.log_file_id);
	}
	audit.logfile=new std::fstream();
	audit.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		audit.logfile->open(filen , std::ios::out | std::ios::binary);
		audit.current_log_size = 0;
 		set_audit_logfile_open(true);
		proxy_info("Starting new pgsql audit log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new pgsql audit log file %s\n", filen);
		delete audit.logfile;
		audit.logfile=NULL;
		audit.current_log_size = 0;
 		set_audit_logfile_open(false);
	}
	free(filen);
};

void PgSQL_Logger::events_set_base_filename() {
	// if filename is the same, return
	wrlock();
	events.max_log_file_size=pgsql_thread___eventslog_filesize;
	if (strcmp(events.base_filename,pgsql_thread___eventslog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	events_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	events.log_file_id=0;
	free(events.base_filename);
	events.base_filename=strdup(pgsql_thread___eventslog_filename);
	if (strlen(events.base_filename)) {
		events.enabled=true;
		events_open_log_unlocked();
	} else {
		events.enabled=false;
	}
	wrunlock();
}

void PgSQL_Logger::events_set_datadir(char *s) {
	if (events.datadir)
		free(events.datadir);
	events.datadir=strdup(s);
	flush_log();
};

void PgSQL_Logger::audit_set_base_filename() {
	// if filename is the same, return
	wrlock();
	audit.max_log_file_size=pgsql_thread___auditlog_filesize;
	if (strcmp(audit.base_filename,pgsql_thread___auditlog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	audit_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	audit.log_file_id=0;
	free(audit.base_filename);
	audit.base_filename=strdup(pgsql_thread___auditlog_filename);
	if (strlen(audit.base_filename)) {
		audit.enabled=true;
		audit_open_log_unlocked();
	} else {
		audit.enabled=false;
	}
	wrunlock();
}

void PgSQL_Logger::audit_set_datadir(char *s) {
	if (audit.datadir)
		free(audit.datadir);
	audit.datadir=strdup(s);
	flush_log();
};

void PgSQL_Logger::log_request(PgSQL_Session *sess, PgSQL_Data_Stream *myds) {
	int elmhs = pgsql_thread___eventslog_buffer_history_size;
	if (events.enabled == false && elmhs == 0) return;
	// 'PgSQL_Session::client_myds' could be NULL in case of 'RequestEnd' being called over a freshly created session
	// due to a failed 'CONNECTION_RESET'. Because this scenario isn't a client request, we just return.
	if (sess->client_myds==NULL || sess->client_myds->myconn== NULL) return;

	// Obtain current thread's log ctx
 	LogBufferThreadContext* log_ctx = get_log_thread_context();

 	// Sample event logs. Set pgsql-eventslog_rate_limit=1 (default) to log all events
 	if (pgsql_thread___eventslog_rate_limit > 1)
 		if (!log_ctx->should_log(pgsql_thread___eventslog_rate_limit)) 
 			return;

	PgSQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

	uint64_t curtime_real=realtime_time();
	uint64_t curtime_mono=sess->thread->curtime;
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);
	PGSQL_LOG_EVENT_TYPE let = PGSQL_LOG_EVENT_TYPE::SIMPLE_QUERY; // default
	// Named-portal Close (PROCESSING_STMT_CLOSE) has no query text; when true the query
	// branch below logs an empty query instead of a stale CurrentQuery.QueryPointer.
	bool c_stmt_close_no_query = false;
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE;
			break;
		case PROCESSING_STMT_PREPARE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_PREPARE;
			break;
		case PROCESSING_STMT_DESCRIBE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE;
			break;
		case PROCESSING_STMT_BIND:
			// Named-portal Bind took the backend round-trip path (Task P1/P2). There is
			// no dedicated BIND eventslog type; classify it as STMT_EXECUTE so the digest
			// and query text are sourced from the RESOLVED global statement
			// (extended_query_info.stmt_info, always valid for a Bind) exactly like
			// DESCRIBE/EXECUTE — NOT from the stale CurrentQuery.QueryPointer left over
			// on the statement-reuse path (a Bind carries no query text of its own; the
			// old SIMPLE_QUERY default read that stale/garbage pointer, a UAF risk).
			let = PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE;
			break;
		case PROCESSING_STMT_CLOSE:
			// Named-portal Close round-trip (Task P2): a Close carries no query text and
			// its extended_query_info.stmt_info may be null in some paths — keep the
			// SIMPLE_QUERY default but log an empty query (guarded below) rather than a
			// stale QueryPointer. Do NOT classify as STMT_EXECUTE (that path dereferences
			// stmt_info unconditionally).
			c_stmt_close_no_query = true;
			break;
		case WAITING_CLIENT_DATA:
		case PROCESSING_EXTENDED_QUERY_SYNC:
		{
			switch (sess->get_extended_query_phase() & EXTQ_PHASE_PROCESSING_MASK) {
			case EXTQ_PHASE_PROCESSING_PARSE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_PREPARE;
				break;
			case EXTQ_PHASE_PROCESSING_DESCRIBE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE;
				break;
			case EXTQ_PHASE_PROCESSING_EXECUTE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE;
				break;
			default:
				break;
			}
		}
			break;
		default:
			break;
	}

	uint64_t query_digest = 0;

	if (let != PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE && let != PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		query_digest = GloPgQPro->get_digest(&sess->CurrentQuery.QueryParserArgs);
	} else {
		query_digest = sess->CurrentQuery.extended_query_info.stmt_info->digest;
	}

	PgSQL_Event me(let,
		sess->thread_session_id,ui->username,ui->dbname,
		sess->CurrentQuery.start_time + curtime_real - curtime_mono,
		sess->CurrentQuery.end_time + curtime_real - curtime_mono,
		query_digest,
		ca, cl
	);
	char *c = NULL;
	int ql = 0;
	switch (let) {
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
			c = sess->CurrentQuery.extended_query_info.stmt_info->query;
			ql = sess->CurrentQuery.extended_query_info.stmt_info->query_length;
			me.set_client_stmt_name((char*)sess->CurrentQuery.extended_query_info.stmt_client_name);
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
		default:
			c = c_stmt_close_no_query ? NULL : (char *)sess->CurrentQuery.QueryPointer;
			ql = c_stmt_close_no_query ? 0 : sess->CurrentQuery.QueryLength;
			// NOTE: This needs to be located in the 'default' case because otherwise will miss state
			// 'WAITING_CLIENT_DATA'. This state is possible when the prepared statement is found in the
			// global cache and due to that we immediately reply to the client and session doesn't reach
			// 'PROCESSING_STMT_PREPARE' state. 'stmt_client_id' is expected to be '0' for anything that isn't
			// a prepared statement, still, logging should rely 'PGSQL_LOG_EVENT_TYPE' instead of this value.
			me.set_client_stmt_name((char*)sess->CurrentQuery.extended_query_info.stmt_client_name);
			break;
	}
	if (c) {
		me.set_query(c,ql);
	} else {
		me.set_query("",0);
	}

	if (sess->CurrentQuery.have_affected_rows) {
		me.set_affected_rows(sess->CurrentQuery.affected_rows);
	}
	me.set_rows_sent(sess->CurrentQuery.rows_sent);
	if (myds && myds->myconn && myds->myconn->is_error_present()) {
		me.set_error(myds->myconn->get_error_code_str(), myds->myconn->get_error_message().c_str());
	}

	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);
	if (sl) {
		int hid=-1;
		hid=myds->myconn->parent->myhgc->hid;
		me.set_server(hid,sa,sl);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();
	
	if (events.enabled) {
		std::lock_guard<std::mutex> ctx_lock(log_ctx->buffer_lock);
		me.write(&log_ctx->events, sess);
		prom_metrics.total_queries_logged.fetch_add(1, std::memory_order_relaxed);
		if (log_ctx->events.size() > static_cast<size_t>(pgsql_thread___eventslog_flush_size)) {
			//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
			flush_and_rotate(log_ctx->events, events.logfile, events.current_log_size, events.max_log_file_size,
				[this]() { wrlock(); },
				[this]() { wrunlock(); },
				[this]() { events_flush_log_unlocked(); },
				monotonic_time()
			);
		}
	}
	if (PgLogCB->buffer_size.load(std::memory_order_relaxed) != 0) {
		PgSQL_Event* me2 = new PgSQL_Event(me);
		PgLogCB->insert(me2);
	}

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void PgSQL_Logger::log_audit_entry(PGSQL_LOG_EVENT_TYPE _et, PgSQL_Session *sess, PgSQL_Data_Stream *myds, char *xi) {
	if (audit.enabled==false) return;

	if (sess == NULL) return;
	if (sess->client_myds == NULL)  return; 

	// Obtain current thread's log ctx
 	LogBufferThreadContext* log_ctx = get_log_thread_context();

	PgSQL_Connection_userinfo *ui= NULL;
	if (sess) {
		if (sess->client_myds) {
			if (sess->client_myds->myconn) {
				ui = sess->client_myds->myconn->userinfo;
			}
		}
	}
	if (sess) {
		// to reduce complexing in the calling function, we do some changes here
		switch (_et) {
			case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE;
					default:
						break;
				}
				break;
			default:
				break;
		}
	}

	uint64_t curtime_real=realtime_time();
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);

	char *un = (char *)"";
	char *sn = (char *)"";
	if (ui) {
		if (ui->username) {
			un = ui->username;
		}
		if (ui->dbname) {
			sn = ui->dbname;
		}
	}
	PgSQL_Event me(_et, sess->thread_session_id,
		un, sn, 
		curtime_real, 0, 0,
		ca, cl
	);
/*
	char *c=(char *)sess->CurrentQuery.QueryPointer;
	if (c) {
		me.set_query(c,sess->CurrentQuery.QueryLength);
	} else {
		me.set_query("",0);
	}
*/
	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);

	if (xi) {
		me.set_extra_info(xi);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();

	if (audit.enabled) {
		std::lock_guard<std::mutex> ctx_lock(log_ctx->buffer_lock);
		me.write(&log_ctx->audit, sess);
		if (log_ctx->audit.size() > static_cast<size_t>(pgsql_thread___auditlog_flush_size)) {
			//add a mutex lock in a multithreaded environment, avoid to get a null pointer of audit.logfile that leads to the program coredump
			flush_and_rotate(log_ctx->audit, audit.logfile, audit.current_log_size, audit.max_log_file_size,
				[this]() { wrlock(); },
				[this]() { wrunlock(); },
				[this]() { audit_flush_log_unlocked(); },
				monotonic_time());
		}
	}

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void PgSQL_Logger::flush(bool force) {
	const uint64_t current_time = monotonic_time();

	if (force) {
		std::vector<LogBufferThreadContext*> contexts;
		{
			std::lock_guard<std::mutex> lock(log_thread_contexts_lock);
			contexts.reserve(log_thread_contexts.size());
			for (const auto& kv : log_thread_contexts) {
				contexts.push_back(kv.second.get());
			}
		}

		for (LogBufferThreadContext* ctx : contexts) {
			std::lock_guard<std::mutex> ctx_lock(ctx->buffer_lock);
			if (is_events_logfile_open() && !ctx->events.empty()) {
				flush_and_rotate(
					ctx->events,
					events.logfile,
					events.current_log_size,
					events.max_log_file_size,
					[this]() { wrlock(); },
					[this]() { wrunlock(); },
					nullptr,
					current_time
				);
			}
			if (is_audit_logfile_open() && !ctx->audit.empty()) {
				flush_and_rotate(
					ctx->audit,
					audit.logfile,
					audit.current_log_size,
					audit.max_log_file_size,
					[this]() { wrlock(); },
					[this]() { wrunlock(); },
					nullptr,
					current_time
				);
			}
		}
		return;
	}

	LogBufferThreadContext* log_ctx = get_log_thread_context();
	std::lock_guard<std::mutex> ctx_lock(log_ctx->buffer_lock);

	// eventslog
	if (is_events_logfile_open()) {
		if (log_ctx->events.size() > 0 &&
			(current_time - log_ctx->events.get_last_flush_time()) > static_cast<uint64_t>(pgsql_thread___eventslog_flush_timeout) * 1000) {
			flush_and_rotate(
				log_ctx->events,
				events.logfile,
				events.current_log_size,
				events.max_log_file_size,
				[this]() { wrlock(); },
				[this]() { wrunlock(); },
				[this]() { events_flush_log_unlocked(); },
				current_time
			);
		}
	}

	// auditlogs
	if (is_audit_logfile_open()) {
		if (log_ctx->audit.size() > 0 &&
			(current_time - log_ctx->audit.get_last_flush_time()) > static_cast<uint64_t>(pgsql_thread___auditlog_flush_timeout) * 1000) {
			flush_and_rotate(
				log_ctx->audit,
				audit.logfile,
				audit.current_log_size,
				audit.max_log_file_size,
				[this]() { wrlock(); },
				[this]() { wrunlock(); },
				[this]() { audit_flush_log_unlocked(); },
				current_time
			);
		}
	}
}

unsigned int PgSQL_Logger::events_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(events.base_filename);
	if (events.base_filename[0] == '/') {
		eval_pathname = strdup(events.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(events.datadir);
		eval_filename = strdup(events.base_filename);
		eval_dirname = strdup(events.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (events.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}

unsigned int PgSQL_Logger::audit_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(audit.base_filename);
	if (audit.base_filename[0] == '/') {
		eval_pathname = strdup(audit.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(audit.datadir);
		eval_filename = strdup(audit.base_filename);
		eval_dirname = strdup(audit.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (audit.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}

void PgSQL_Logger::print_version() {
	fprintf(stderr,"Standard ProxySQL PgSQL Logger rev. %s -- %s -- %s\n", PROXYSQL_PGSQL_LOGGER_VERSION, __FILE__, __TIMESTAMP__);
}

LogBufferThreadContext* PgSQL_Logger::get_log_thread_context() {
	return GetLogBufferThreadContext(log_thread_contexts, log_thread_contexts_lock, monotonic_time());
}

PgSQL_Logger_CircularBuffer::PgSQL_Logger_CircularBuffer(size_t size) :
	event_buffer(),
	eventsAddedCount(0), eventsDroppedCount(0),
	buffer_size(size) {}

PgSQL_Logger_CircularBuffer::~PgSQL_Logger_CircularBuffer() {
	std::lock_guard<std::mutex> lock(mutex);
	for (PgSQL_Event* event : event_buffer) {
		delete event;
	}
}

void PgSQL_Logger_CircularBuffer::insert(PgSQL_Event* event) {
	std::lock_guard<std::mutex> lock(mutex);
	eventsAddedCount++;
	const size_t current_buffer_size = buffer_size.load(std::memory_order_relaxed);
	if (current_buffer_size == 0) {
		delete event;
		eventsDroppedCount++;
		return;
	}
	while (event_buffer.size() >= current_buffer_size) {
		delete event_buffer.front();
		event_buffer.pop_front();
		eventsDroppedCount++;
	}
	event_buffer.push_back(event);
}

void PgSQL_Logger_CircularBuffer::get_all_events(std::vector<PgSQL_Event*>& events) {
	std::lock_guard<std::mutex> lock(mutex);
	events.reserve(event_buffer.size());
	events.insert(events.end(), event_buffer.begin(), event_buffer.end());
	event_buffer.clear();
}

size_t PgSQL_Logger_CircularBuffer::size() {
	std::lock_guard<std::mutex> lock(mutex);
	return event_buffer.size();
}

size_t PgSQL_Logger_CircularBuffer::getBufferSize() const {
	return buffer_size.load(std::memory_order_relaxed);
}

void PgSQL_Logger_CircularBuffer::setBufferSize(size_t newSize) {
	std::lock_guard<std::mutex> lock(mutex);
	buffer_size.store(newSize, std::memory_order_relaxed);
	while (event_buffer.size() > newSize) {
		delete event_buffer.front();
		event_buffer.pop_front();
		eventsDroppedCount++;
	}
}

void PgSQL_Logger::insertPgSQLEventsIntoDb(SQLite3DB* db, const std::string& tableName, size_t numEvents, std::vector<PgSQL_Event*>::const_iterator begin) {
	int rc = 0;
	const int numcols = 17;

	std::string coldefs = "(thread_id, username, database, start_time, end_time, query_digest, query, server, client, event_type, hid, extra_info, affected_rows, rows_sent, client_stmt_name, sqlstate, error)";
	std::string query1s = "INSERT INTO " + tableName + coldefs + " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)";
	std::string query32s = "INSERT INTO " + tableName + coldefs + " VALUES " + generate_multi_rows_query(32, numcols);

	auto [rc1, statement1_unique] = db->prepare_v2(query1s.c_str());
	ASSERT_SQLITE_OK(rc1, db);
	auto [rc2, statement32_unique] = db->prepare_v2(query32s.c_str());
	ASSERT_SQLITE_OK(rc2, db);
	sqlite3_stmt* statement1 = statement1_unique.get();
	sqlite3_stmt* statement32 = statement32_unique.get();

	auto bind_text_or_null = [&](sqlite3_stmt* stmt, int idx, const char* v) {
		if (v) {
			rc = (*proxy_sqlite3_bind_text)(stmt, idx, v, -1, SQLITE_TRANSIENT);
		} else {
			rc = (*proxy_sqlite3_bind_null)(stmt, idx);
		}
		ASSERT_SQLITE_OK(rc, db);
	};

	char digest_hex_str[20];
	db->execute("BEGIN");

	int row_idx = 0;
	int max_bulk_row_idx = (numEvents / 32) * 32;
	for (std::vector<PgSQL_Event*>::const_iterator it = begin; it != begin + numEvents; ++it) {
		PgSQL_Event* event = *it;
		int idx = row_idx % 32;
		sqlite3_stmt* stmt = (row_idx < max_bulk_row_idx ? statement32 : statement1);
		int base = (row_idx < max_bulk_row_idx ? idx * numcols : 0);

		rc = (*proxy_sqlite3_bind_int)(stmt, base + 1, event->thread_id); ASSERT_SQLITE_OK(rc, db);
		bind_text_or_null(stmt, base + 2, event->username);
		bind_text_or_null(stmt, base + 3, event->schemaname);
		rc = (*proxy_sqlite3_bind_int64)(stmt, base + 4, event->start_time); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(stmt, base + 5, event->end_time); ASSERT_SQLITE_OK(rc, db);
		snprintf(digest_hex_str, sizeof(digest_hex_str), "0x%016llX", (long long unsigned int)event->query_digest);
		bind_text_or_null(stmt, base + 6, digest_hex_str);
		bind_text_or_null(stmt, base + 7, event->query_ptr);
		bind_text_or_null(stmt, base + 8, event->server);
		bind_text_or_null(stmt, base + 9, event->client);
		rc = (*proxy_sqlite3_bind_int)(stmt, base + 10, (int)event->et); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(stmt, base + 11, event->hid); ASSERT_SQLITE_OK(rc, db);
		bind_text_or_null(stmt, base + 12, event->extra_info);
		rc = (*proxy_sqlite3_bind_int64)(stmt, base + 13, event->affected_rows); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(stmt, base + 14, event->rows_sent); ASSERT_SQLITE_OK(rc, db);
		bind_text_or_null(stmt, base + 15, event->client_stmt_name);
		bind_text_or_null(stmt, base + 16, event->sqlstate);
		bind_text_or_null(stmt, base + 17, event->errmsg);

		if (row_idx < max_bulk_row_idx) {
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, db);
				rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, db);
			}
		} else {
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
		}

		row_idx++;
	}

	db->execute("COMMIT");
}

int PgSQL_Logger::processEvents(SQLite3DB* statsdb, SQLite3DB* statsdb_disk) {
	unsigned long long startTimeMicros = monotonic_time();
	std::vector<PgSQL_Event*> events = {};
	PgLogCB->get_all_events(events);
	metrics.getAllEventsCallsCount++;
	if (events.empty()) return 0;

	unsigned long long afterGetAllEventsTimeMicros = monotonic_time();
	metrics.getAllEventsEventsCount += events.size();
	metrics.totalGetAllEventsTimeMicros += (afterGetAllEventsTimeMicros - startTimeMicros);

	if (statsdb_disk != nullptr) {
		unsigned long long diskStartTimeMicros = monotonic_time();
		insertPgSQLEventsIntoDb(statsdb_disk, "history_pgsql_query_events", events.size(), events.begin());
		unsigned long long diskEndTimeMicros = monotonic_time();
		metrics.diskCopyCount++;
		metrics.totalDiskCopyTimeMicros += (diskEndTimeMicros - diskStartTimeMicros);
		metrics.totalEventsCopiedToDisk += events.size();
	}

	if (statsdb != nullptr) {
		unsigned long long memoryStartTimeMicros = monotonic_time();
		size_t maxInMemorySize = get_pgsql_eventslog_table_memory_size_runtime();
		size_t numEventsToInsert = std::min(events.size(), maxInMemorySize);

		if (events.size() >= maxInMemorySize) {
			statsdb->execute("DELETE FROM stats_pgsql_query_events");
		} else {
			int current_rows_i = statsdb->return_one_int((char*)"SELECT COUNT(*) FROM stats_pgsql_query_events");
			size_t current_rows = (current_rows_i > 0) ? static_cast<size_t>(current_rows_i) : 0;
			size_t rows_to_keep = maxInMemorySize - events.size();
			if (current_rows > rows_to_keep) {
				size_t rows_to_delete = (current_rows - rows_to_keep);
				std::string query = "SELECT MAX(id) FROM (SELECT id FROM stats_pgsql_query_events ORDER BY id LIMIT " + std::to_string(rows_to_delete) + ")";
				int maxIdToDelete = statsdb->return_one_int(query.c_str());
				std::string delete_stmt = "DELETE FROM stats_pgsql_query_events WHERE id <= " + std::to_string(maxIdToDelete);
				statsdb->execute(delete_stmt.c_str());
			}
		}
		if (numEventsToInsert > 0) {
			auto begin_it = events.begin();
			if (events.size() > numEventsToInsert) {
				begin_it = events.end() - numEventsToInsert;
			}
			insertPgSQLEventsIntoDb(statsdb, "stats_pgsql_query_events", numEventsToInsert, begin_it);
		}
		unsigned long long memoryEndTimeMicros = monotonic_time();
		metrics.memoryCopyCount++;
		metrics.totalMemoryCopyTimeMicros += (memoryEndTimeMicros - memoryStartTimeMicros);
		metrics.totalEventsCopiedToMemory += numEventsToInsert;
	}

	for (PgSQL_Event* event : events) {
		delete event;
	}

	return events.size();
}

std::unordered_map<std::string, unsigned long long> PgSQL_Logger::getAllMetrics() const {
	std::unordered_map<std::string, unsigned long long> allMetrics;

	allMetrics["memoryCopyCount"] = metrics.memoryCopyCount;
	allMetrics["diskCopyCount"] = metrics.diskCopyCount;
	allMetrics["getAllEventsCallsCount"] = metrics.getAllEventsCallsCount;
	allMetrics["getAllEventsEventsCount"] = metrics.getAllEventsEventsCount;
	allMetrics["totalMemoryCopyTimeMicros"] = metrics.totalMemoryCopyTimeMicros;
	allMetrics["totalDiskCopyTimeMicros"] = metrics.totalDiskCopyTimeMicros;
	allMetrics["totalGetAllEventsTimeMicros"] = metrics.totalGetAllEventsTimeMicros;
	allMetrics["totalEventsCopiedToMemory"] = metrics.totalEventsCopiedToMemory;
	allMetrics["totalEventsCopiedToDisk"] = metrics.totalEventsCopiedToDisk;
	allMetrics["circularBufferEventsAddedCount"] = PgLogCB->getEventsAddedCount();
	allMetrics["circularBufferEventsDroppedCount"] = PgLogCB->getEventsDroppedCount();
	allMetrics["circularBufferEventsSize"] = PgLogCB->size();

	return allMetrics;
}

void PgSQL_Logger::p_update_metrics() {
	using pl_c = p_pl_counter;
	const auto& counters { this->prom_metrics.p_counter_array };

	p_update_counter(counters[pl_c::memory_copy_count], metrics.memoryCopyCount);
	p_update_counter(counters[pl_c::disk_copy_count], metrics.diskCopyCount);
	p_update_counter(counters[pl_c::get_all_events_calls_count], metrics.getAllEventsCallsCount);
	p_update_counter(counters[pl_c::get_all_events_events_count], metrics.getAllEventsEventsCount);
	p_update_counter(counters[pl_c::total_memory_copy_time_us], metrics.totalMemoryCopyTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[pl_c::total_disk_copy_time_us], metrics.totalDiskCopyTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[pl_c::total_get_all_events_time_us], metrics.totalGetAllEventsTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[pl_c::total_events_copied_to_memory], metrics.totalEventsCopiedToMemory);
	p_update_counter(counters[pl_c::total_events_copied_to_disk], metrics.totalEventsCopiedToDisk);
	p_update_counter(counters[pl_c::circular_buffer_events_added_count], PgLogCB->getEventsAddedCount());
	p_update_counter(counters[pl_c::circular_buffer_events_dropped_count], PgLogCB->getEventsDroppedCount());

	using pl_g = p_pl_gauge;
	const auto& gauges { this->prom_metrics.p_gauge_array };
	gauges[pl_g::circular_buffer_events_size]->Set(PgLogCB->size());

	if (this->prom_metrics.p_queries_logged_total == nullptr) {
		this->prom_metrics.p_queries_logged_total = get_logger_queries_logged_counter("pgsql");
	}
	if (this->prom_metrics.p_queries_logged_total != nullptr) {
		p_update_counter(
			this->prom_metrics.p_queries_logged_total,
			this->prom_metrics.total_queries_logged.load(std::memory_order_relaxed)
		);
	}
}
