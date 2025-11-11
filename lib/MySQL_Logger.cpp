#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <fstream>
#include "proxysql.h"
#include "cpp.h"
#include <string.h>

#include "MySQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Logger.hpp"

#include <dirent.h>
#include <libgen.h>

#include <unordered_map>
#include <string>

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_MYSQL_LOGGER_VERSION "2.5.0421" DEB

extern MySQL_Logger *GloMyLogger;

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using ml_counter_tuple =
	std::tuple<
		p_ml_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using ml_gauge_tuple =
	std::tuple<
		p_ml_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using qc_counter_vector = std::vector<ml_counter_tuple>;
using qc_gauge_vector = std::vector<ml_gauge_tuple>;


#include <functional>

using ValueConverter = std::function<void(const MYSQL_BIND*, unsigned long, std::string&)>;

struct BufferTypeInfo {
	std::string typeName;
	ValueConverter converter; // Callback to convert the value.
};


// Helper lambda to convert binary data to a hex string.
auto binaryToHex = [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
	std::ostringstream oss;
	oss << "0x";
	const unsigned char* data = reinterpret_cast<const unsigned char*>(bind->buffer);
	for (unsigned long i = 0; i < len; i++) {
		oss << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
	}
	out = oss.str();
};

static const std::unordered_map<unsigned int, BufferTypeInfo> bufferTypeInfoMap = {
	{ MYSQL_TYPE_DECIMAL,
		{ "DECIMAL", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_TINY,
		{ "TINY", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(static_cast<int>(*reinterpret_cast<int8_t*>(bind->buffer)));
		}}
	},
	{ MYSQL_TYPE_SHORT,
		{ "SHORT", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<int16_t*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_LONG,
		{ "LONG", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<int32_t*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_FLOAT,
		{ "FLOAT", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<float*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_DOUBLE,
		{ "DOUBLE", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<double*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_NULL,
		{ "NULL", [](const MYSQL_BIND* /*bind*/, unsigned long /*len*/, std::string &out) {
			out = "NULL";
		}}
	},
	{ MYSQL_TYPE_TIMESTAMP,
		{ "TIMESTAMP", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, sizeof(MYSQL_TIME), out);
		}}
	},
	{ MYSQL_TYPE_LONGLONG,
		{ "LONGLONG", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<int64_t*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_INT24,
		{ "INT24", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			// INT24: stored in 32 bits
			out = std::to_string(*reinterpret_cast<int32_t*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_DATE,
		{ "DATE", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, sizeof(MYSQL_TIME), out);
		}}
	},
	{ MYSQL_TYPE_TIME,
		{ "TIME", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, sizeof(MYSQL_TIME), out);
		}}
	},
	{ MYSQL_TYPE_DATETIME,
		{ "DATETIME", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, sizeof(MYSQL_TIME), out);
		}}
	},
	{ MYSQL_TYPE_YEAR,
		{ "YEAR", [](const MYSQL_BIND* bind, unsigned long /*len*/, std::string &out) {
			out = std::to_string(*reinterpret_cast<int16_t*>(bind->buffer));
		}}
	},
	{ MYSQL_TYPE_NEWDATE,
		{ "NEWDATE", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_VARCHAR,
		{ "VARCHAR", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_BIT,
		{ "BIT", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			// For simplicity, treat BIT as hex.
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_TIMESTAMP2,
		{ "TIMESTAMP2", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_DATETIME2,
		{ "DATETIME2", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_TIME2,
		{ "TIME2", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_JSON,
		{ "JSON", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_NEWDECIMAL,
		{ "NEWDECIMAL", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_ENUM,
		{ "ENUM", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_SET,
		{ "SET", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			out.assign(reinterpret_cast<char*>(bind->buffer), len);
		}}
	},
	{ MYSQL_TYPE_TINY_BLOB,
		{ "TINY_BLOB", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_MEDIUM_BLOB,
		{ "MEDIUM_BLOB", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_LONG_BLOB,
		{ "LONG_BLOB", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_BLOB,
		{ "BLOB", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_VAR_STRING,
		{ "VAR_STRING", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_STRING,
		{ "STRING", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	},
	{ MYSQL_TYPE_GEOMETRY,
		{ "GEOMETRY", [](const MYSQL_BIND* bind, unsigned long len, std::string &out) {
			binaryToHex(bind, len, out);
		}}
	}
};

/*
static inline std::string getBufferTypeName(unsigned int buffer_type) {
	auto it = bufferTypeNameMap.find(buffer_type);
	return (it != bufferTypeNameMap.end()) ? it->second : "unknown";
}
*/

static inline std::pair<std::string, std::string> getValueForBind(const MYSQL_BIND* bind, unsigned long len) {
	auto it = bufferTypeInfoMap.find(bind->buffer_type);
	std::string convertedValue;
	if (it != bufferTypeInfoMap.end()) {
		it->second.converter(bind, len, convertedValue);
		return { it->second.typeName, convertedValue };
	}
	// Fallback if type is not found.
	return { "unknown", "unknown" };
}

const std::tuple<qc_counter_vector, qc_gauge_vector>
ml_metrics_map = std::make_tuple(
	qc_counter_vector {
		std::make_tuple (
			p_ml_counter::memory_copy_count,
			"proxysql_mysql_logger_copy_total",
			"Number of times events were copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple (
			p_ml_counter::disk_copy_count,
			"proxysql_mysql_logger_copy_total",
			"Number of times events were copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple (
			p_ml_counter::get_all_events_calls_count,
			"proxysql_mysql_logger_get_all_events_calls_total",
			"Number of times the 'get_all_events' method was called.",
			metric_tags {}
		),
		std::make_tuple (
			p_ml_counter::get_all_events_events_count,
			"proxysql_mysql_logger_get_all_events_events_total",
			"Number of events retrieved by the `get_all_events` method.",
			metric_tags {}
		),
		std::make_tuple (
			p_ml_counter::total_memory_copy_time_us,
			"proxysql_mysql_logger_copy_seconds_total",
			"Total time spent copying events to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple (
			p_ml_counter::total_disk_copy_time_us,
			"proxysql_mysql_logger_copy_seconds_total",
			"Total time spent copying events to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple (
			p_ml_counter::total_get_all_events_time_us,
			"proxysql_mysql_logger_get_all_events_seconds_total",
			"Total time spent in `get_all_events` method.",
			metric_tags {}
		),
		std::make_tuple (
			p_ml_counter::total_events_copied_to_memory,
			"proxysql_mysql_logger_events_copied_total",
			"Total number of events copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "memory" } }
		),
		std::make_tuple (
			p_ml_counter::total_events_copied_to_disk,
			"proxysql_mysql_logger_events_copied_total",
			"Total number of events copied to the in-memory/on-disk databases.",
			metric_tags { { "target", "disk" } }
		),
		std::make_tuple (
			p_ml_counter::circular_buffer_events_added_count,
			"proxysql_mysql_logger_circular_buffer_events_total",
			"The total number of events added/dropped to/from the circular buffer.",
			metric_tags { { "type", "added" } }
		),
		std::make_tuple (
			p_ml_counter::circular_buffer_events_dropped_count,
			"proxysql_mysql_logger_circular_buffer_events_total",
			"The total number of events added/dropped to/from the circular buffer.",
			metric_tags { { "type", "dropped" } }
		),
	},
	qc_gauge_vector {
		std::make_tuple (
			p_ml_gauge::circular_buffer_events_size,
			"proxysql_mysql_logger_circular_buffer_events",
			"Number of events currently present in the circular buffer.",
			metric_tags {}
		),
	}
);

static uint8_t mysql_encode_length(uint64_t len, unsigned char *hd) {
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

MySQL_Event::MySQL_Event (log_event_type _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len, MySQL_Session *sess_ptr) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
	client=_client;
	client_len=_client_len;
	et=_et;
	hid=UINT64_MAX;
	server=NULL;
	extra_info = NULL;
	have_affected_rows=false;
	affected_rows=0;
	last_insert_id = 0;
	have_rows_sent=false;
	have_gtid=false;
	rows_sent=0;
	client_stmt_id=0;
	gtid = NULL;
	session = sess_ptr;
	errmsg = nullptr;
	myerrno = 0;
	free_on_delete = false; // by default, this is false. This because pointers do not belong to this object
}

MySQL_Event::MySQL_Event(const MySQL_Event &other) {

	// Initialize basic members using memcpy
	memcpy(this, &other, sizeof(MySQL_Event));

	// Copy char pointers using strdup (if not null)
	if (other.username != nullptr) {
		username = strdup(other.username);
	}
	if (other.schemaname != nullptr) {
		schemaname = strdup(other.schemaname);
	}
	// query_ptr is NOT null terminated
	if (other.query_ptr != nullptr) {
		size_t maxQueryLen = mysql_thread___eventslog_buffer_max_query_length;
		size_t lenToCopy = std::min(other.query_len, maxQueryLen);
		query_ptr = (char*)malloc(lenToCopy + 1); // +1 for null terminator
		memcpy(query_ptr, other.query_ptr, lenToCopy);
		query_ptr[lenToCopy] = '\0'; // Null-terminate the copied string
		query_len = lenToCopy;
	}
	// server is NOT null terminated
	if (other.server != nullptr) {
		server = (char *)malloc(server_len+1);
		memcpy(server, other.server, server_len);
		server[server_len] = '\0';
	}
	// client is NOT null terminated
	if (other.client != nullptr) {
		client = (char *)malloc(client_len+1);
		memcpy(client, other.client, client_len);
		client[client_len] = '\0';
	}
	if (other.extra_info != nullptr) {
		extra_info = strdup(other.extra_info);
	}
	if (other.gtid != nullptr) {
		gtid = strdup(other.gtid);
	}
	if (other.errmsg != nullptr) {
		errmsg = strdup(other.errmsg);
	}
	free_on_delete = true; // pointers belong to this object
}

MySQL_Event::~MySQL_Event() {
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
		if (gtid != nullptr) {
			free(gtid); gtid = nullptr;
		}
		if (errmsg != nullptr) {
			free(errmsg); errmsg = nullptr;
		}
	}
}

void MySQL_Event::set_client_stmt_id(uint32_t client_stmt_id) {
	this->client_stmt_id = client_stmt_id;
}

// if affected rows is set, last_insert_id is set too.
// They are part of the same OK packet
void MySQL_Event::set_affected_rows(uint64_t ar, uint64_t lid) {
	have_affected_rows=true;
	affected_rows=ar;
	last_insert_id=lid;
}

void MySQL_Event::set_rows_sent(uint64_t rs) {
	have_rows_sent=true;
	rows_sent=rs;
}

void MySQL_Event::set_gtid(MySQL_Session *sess) {
	if (sess != NULL) {
		if (sess->gtid_buf[0] != 0) {
			have_gtid = true;
			gtid = sess->gtid_buf;
		}
	}
}

void MySQL_Event::set_errmsg(const unsigned int _myerrno, const char * _errmsg) {
	myerrno = _myerrno;
	if (_errmsg != nullptr)
		errmsg = strdup(_errmsg);
}

void MySQL_Event::set_extra_info(char *_err) {
	extra_info = _err;
}

void MySQL_Event::set_query(const char *ptr, int len) {
	query_ptr=(char *)ptr;
	query_len=len;
}

void MySQL_Event::set_server(int _hid, const char *ptr, int len) {
	server=(char *)ptr;
	server_len=len;
	hid=_hid;
}

uint64_t MySQL_Event::write(std::fstream *f, MySQL_Session *sess) {
	uint64_t total_bytes=0;
	switch (et) {
		case PROXYSQL_COM_QUERY:
		case PROXYSQL_COM_STMT_EXECUTE:
		case PROXYSQL_COM_STMT_PREPARE:
			if (mysql_thread___eventslog_format==1) { // format 1 , binary
				total_bytes=write_query_format_1(f);
			} else { // format 2 , json
				total_bytes=write_query_format_2_json(f);
			}
			break;
		case PROXYSQL_MYSQL_AUTH_OK:
		case PROXYSQL_MYSQL_AUTH_ERR:
		case PROXYSQL_MYSQL_AUTH_CLOSE:
		case PROXYSQL_MYSQL_AUTH_QUIT:
		case PROXYSQL_MYSQL_INITDB:
		case PROXYSQL_ADMIN_AUTH_OK:
		case PROXYSQL_ADMIN_AUTH_ERR:
		case PROXYSQL_ADMIN_AUTH_CLOSE:
		case PROXYSQL_ADMIN_AUTH_QUIT:
		case PROXYSQL_SQLITE_AUTH_OK:
		case PROXYSQL_SQLITE_AUTH_ERR:
		case PROXYSQL_SQLITE_AUTH_CLOSE:
		case PROXYSQL_SQLITE_AUTH_QUIT:
			write_auth(f, sess);
			break;
		case PROXYSQL_METADATA:
			if (mysql_thread___eventslog_format==1) { // format 1 , binary
				total_bytes=write_query_format_1(f);
			}
			break;
		default:
			break;
	}
	return total_bytes;
}

void MySQL_Event::write_auth(std::fstream *f, MySQL_Session *sess) {
	json j = {};
	j["timestamp"] = start_time/1000;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(start_time%1000000)/1000);
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
		case PROXYSQL_MYSQL_AUTH_OK:
			j["event"]="MySQL_Client_Connect_OK";
			break;
		case PROXYSQL_MYSQL_AUTH_ERR:
			j["event"]="MySQL_Client_Connect_ERR";
			break;
		case PROXYSQL_MYSQL_AUTH_CLOSE:
			j["event"]="MySQL_Client_Close";
			break;
		case PROXYSQL_MYSQL_AUTH_QUIT:
			j["event"]="MySQL_Client_Quit";
			break;
		case PROXYSQL_MYSQL_INITDB:
			j["event"]="MySQL_Client_Init_DB";
			break;
		case PROXYSQL_ADMIN_AUTH_OK:
			j["event"]="Admin_Connect_OK";
			break;
		case PROXYSQL_ADMIN_AUTH_ERR:
			j["event"]="Admin_Connect_ERR";
			break;
		case PROXYSQL_ADMIN_AUTH_CLOSE:
			j["event"]="Admin_Close";
			break;
		case PROXYSQL_ADMIN_AUTH_QUIT:
			j["event"]="Admin_Quit";
			break;
		case PROXYSQL_SQLITE_AUTH_OK:
			j["event"]="SQLite3_Connect_OK";
			break;
		case PROXYSQL_SQLITE_AUTH_ERR:
			j["event"]="SQLite3_Connect_ERR";
			break;
		case PROXYSQL_SQLITE_AUTH_CLOSE:
			j["event"]="SQLite3_Close";
			break;
		case PROXYSQL_SQLITE_AUTH_QUIT:
			j["event"]="SQLite3_Quit";
			break;
		default:
			break;
	}
	switch (et) {
		case PROXYSQL_MYSQL_AUTH_CLOSE:
		case PROXYSQL_ADMIN_AUTH_CLOSE:
		case PROXYSQL_SQLITE_AUTH_CLOSE:
			{
				uint64_t curtime_real=realtime_time();
				uint64_t curtime_mono=sess->thread->curtime;
				uint64_t timediff = curtime_mono - sess->start_time;
				uint64_t orig_time = curtime_real - timediff;
				time_t timer= (orig_time)/1000/1000;
				struct tm* tm_info;
				tm_info = localtime(&timer);
				char buffer1[36];
				char buffer2[64];
				strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
				sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(orig_time%1000000)/1000);
				j["creation_time"] = buffer2;
				//unsigned long long life = sess->thread->curtime - sess->start_time;
				//life/=1000;
				float f = timediff;
				f /= 1000;
				sprintf(buffer1, "%.3fms", f);
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
	//GloMyLogger->wrlock();
	//move wrlock() function to log_audit_entry() function, avoid to get a null pointer in a multithreaded environment
	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
}

/**
 * @brief Writes a query event to the given file stream in a specifically encoded format.
 *
 * This function assembles and writes a MySQL query event record to the provided std::fstream.
 * It computes the total byte size of the record by encoding various fields (such as thread ID, username, schema name,
 * client information, timestamps, and the actual query) and then writes the record in binary format, prefixed by its total length.
 *
 * Detailed Process:
 *   - The function begins by initializing a total_bytes counter, incrementing it by the number of bytes each field will occupy
 *     after being encoded.
 *   - It encodes fundamental fields including:
 *       • Event type (et) encoded in 1 byte.
 *       • Thread ID, whose encoded length is computed using mysql_encode_length.
 *       • Username and schema name: their lengths are determined via strlen(), then the lengths are encoded, and finally the raw
 *         string data is accounted for.
 *       • Client and server information: similar encoding is applied. For the server details, encoding is conditionally applied only if
 *         the host id (hid) is not UINT64_MAX.
 *       • Timestamps (start_time and end_time) along with other numeric fields such as client statement ID, affected_rows, last_insert_id,
 *         and rows_sent are also encoded based on their variable-length representation.
 *
 *   - If a non-standard SQL statement type is detected (specifically, if the event type is PROXYSQL_COM_STMT_EXECUTE),
 *     additional processing is performed:
 *       • The function accesses statement execution metadata (stmt_execute_metadata_t) from the current session.
 *       • It calculates and writes the encoded count of parameters.
 *       • A null bitmap is constructed to indicate which parameters are NULL, with one bit per parameter.
 *       • For each parameter, the function writes:
 *            - The parameter type (2 bytes).
 *            - The length of the parameter value (using a custom encoding scheme with mysql_encode_length),
 *              followed by the raw parameter value bytes, which are obtained through a conversion function (getValueForBind)
 *              producing a string representation.
 *
 *   - Before writing the actual data, the total length of the event (total_bytes) is written as a fixed-size 8-byte field.
 *     Then, each encoded part (event type, field lengths, raw data, and any additional parameters) is sequentially written to the stream.
 *
 * Thread Safety & Performance Considerations:
 *   - The critical write lock (wrlock) for accessing the underlying file or resource is acquired just before writing to disk,
 *     minimizing the duration for which the resource is locked.
 *   - The function depends on external helper routines:
 *       • mysql_encode_length: to determine the number of bytes required to store an integer in a variable-length format.
 *       • write_encoded_length: to actually write the encoded lengths to the buffer and then to the file stream.
 *       • getValueForBind: to convert parameter data bound to a query into a string representation.
 *
 * @param f[in,out] Pointer to a std::fstream object representing the file stream to write the query event record.
 *
 * @return Returns the total size in bytes (as a uint64_t) that was written to the file stream.
 *
 * @note The function assumes that the session and associated metadata for prepared statements (stmt_meta) are valid and
 *       available when processing a COM_STMT_EXECUTE event.
 *
 * @warning Ensure that the passed file stream pointer is valid and opened for writing, as no internal checks on the stream's state
 *          are performed.
 *
 * @see mysql_encode_length, write_encoded_length, getValueForBind, stmt_execute_metadata_t, MYSQL_BIND
 *
 * Returns:
 *   The total number of bytes written for the event log.
 */
uint64_t MySQL_Event::write_query_format_1(std::fstream *f) {
	uint64_t total_bytes=0;
	total_bytes+=1; // et
	total_bytes+=mysql_encode_length(thread_id, NULL);
	username_len=strlen(username);
	total_bytes+=mysql_encode_length(username_len,NULL)+username_len;
	schemaname_len=strlen(schemaname);
	total_bytes+=mysql_encode_length(schemaname_len,NULL)+schemaname_len;

	total_bytes+=mysql_encode_length(client_len,NULL)+client_len;

	total_bytes+=mysql_encode_length(hid, NULL);
	if (hid!=UINT64_MAX) {
		total_bytes+=mysql_encode_length(server_len,NULL)+server_len;
	}

	total_bytes+=mysql_encode_length(start_time,NULL);
	total_bytes+=mysql_encode_length(end_time,NULL);
	total_bytes+=mysql_encode_length(client_stmt_id,NULL);
	total_bytes+=mysql_encode_length(affected_rows,NULL);
	total_bytes+=mysql_encode_length(last_insert_id,NULL); // as in MySQL Protocol, last_insert_id is immediately after affected_rows
	total_bytes+=mysql_encode_length(rows_sent,NULL);

	total_bytes+=mysql_encode_length(query_digest,NULL);

	total_bytes+=mysql_encode_length(query_len,NULL)+query_len;

	// --- Account for extra parameters for COM_STMT_EXECUTE ---
	// When the event type (et) is PROXYSQL_COM_STMT_EXECUTE:
	if (et == PROXYSQL_COM_STMT_EXECUTE) {
		// Validate Session and Statement Metadata:
		// The code checks whether the session pointer and the current query's statement metadata (stmt_meta)
		// are non-null to ensure that parameter details are available.
		if (mysql_thread___eventslog_stmt_parameters > 0 && session != nullptr && session->CurrentQuery.stmt_meta != nullptr) {
			stmt_execute_metadata_t *meta = session->CurrentQuery.stmt_meta;
			uint16_t num_params = meta->num_params;
			// Add bytes for encoded parameter count.
			uint8_t paramCountLen = mysql_encode_length(num_params, NULL);
			total_bytes += paramCountLen;
			// Add bytes for the null bitmap.
			size_t bitmap_size = (num_params + 7) / 8;
			total_bytes += bitmap_size;
			// For each parameter:
			for (uint16_t i = 0; i < num_params; i++) {
				// 2 bytes for parameter type.
				total_bytes += sizeof(uint16_t);
				std::string convertedValue;
				const MYSQL_BIND *bind = meta->binds ? &meta->binds[i] : nullptr;
				if (bind != nullptr && !(meta->is_nulls && meta->is_nulls[i])) {
					unsigned long len = meta->lengths ? meta->lengths[i] : 0;
					auto bt = bind->buffer_type;
					switch (bt) {
						case MYSQL_TYPE_TIMESTAMP:
						case MYSQL_TYPE_DATE:
						case MYSQL_TYPE_TIME:
						case MYSQL_TYPE_DATETIME:
							len = sizeof(MYSQL_TIME);
							break;
						default:
							break;
					}
					// Use getValueForBind() to produce a string representation.
					auto[valType, convVal] = getValueForBind(bind, len);
					convertedValue = convVal;
				}
				uint64_t value_len = convertedValue.size();
				// Add bytes for the encoded length of the value.
				uint8_t valueLenEnc = mysql_encode_length(value_len, NULL);
				total_bytes += valueLenEnc;
				// Add the raw bytes of the parameter value.
				total_bytes += value_len;
			}
		} else {
			// Deterministic binary logging: always report 0 parameters.
			uint16_t num_params = 0;
			uint8_t paramCountLen = mysql_encode_length(num_params, buf);
			total_bytes += paramCountLen;
		}
	}


	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloMyLogger->wrlock();
		//move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	// write total length , fixed size
	f->write((const char *)&total_bytes,sizeof(uint64_t));
	//char prefix;
	uint8_t len;

	f->write((char *)&et,1);

	len=mysql_encode_length(thread_id,buf);
	write_encoded_length(buf,thread_id,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(username_len,buf);
	write_encoded_length(buf,username_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(username,username_len);

	len=mysql_encode_length(schemaname_len,buf);
	write_encoded_length(buf,schemaname_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(schemaname,schemaname_len);

	len=mysql_encode_length(client_len,buf);
	write_encoded_length(buf,client_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(client,client_len);

	len=mysql_encode_length(hid,buf);
	write_encoded_length(buf,hid,len,buf[0]);
	f->write((char *)buf,len);

	if (hid!=UINT64_MAX) {
		len=mysql_encode_length(server_len,buf);
		write_encoded_length(buf,server_len,len,buf[0]);
		f->write((char *)buf,len);
		f->write(server,server_len);
	}

	len=mysql_encode_length(start_time,buf);
	write_encoded_length(buf,start_time,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(end_time,buf);
	write_encoded_length(buf,end_time,len,buf[0]);
	f->write((char *)buf,len);

	if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
		len=mysql_encode_length(client_stmt_id,buf);
		write_encoded_length(buf,client_stmt_id,len,buf[0]);
		f->write((char *)buf,len);
	}

	len=mysql_encode_length(affected_rows,buf);
	write_encoded_length(buf,affected_rows,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(last_insert_id,buf);
	write_encoded_length(buf,last_insert_id,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(rows_sent,buf);
	write_encoded_length(buf,rows_sent,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(query_digest,buf);
	write_encoded_length(buf,query_digest,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(query_len,buf);
	write_encoded_length(buf,query_len,len,buf[0]);
	f->write((char *)buf,len);
	if (query_len) {
		f->write(query_ptr,query_len);
	}

	// --- Now write the parameters block for COM_STMT_EXECUTE ---
	// This section ensures that all parameter-related information for COM_STMT_EXECUTE events are logged
	// in a consistent and efficiently decodable format. The careful handling of variable-length encoded values,
	// null bitmap construction, and per-parameter processing facilitates accurate reconstruction of the original
	// query parameters during later analysis.
	if (et == PROXYSQL_COM_STMT_EXECUTE) {
		// Ensure stmt_meta is available.
		// Validate Session and Statement Metadata:
		// The code checks whether the session pointer and the current query's statement metadata (stmt_meta)
		// are non-null to ensure that parameter details are available.
		if (mysql_thread___eventslog_stmt_parameters > 0 && session != nullptr && session->CurrentQuery.stmt_meta != nullptr) {
			stmt_execute_metadata_t *meta = session->CurrentQuery.stmt_meta;
			// Write the number of parameters.
			// Writing the Encoded Parameter Count:
			// - Retrieves the number of parameters (num_params) from stmt_meta.
			// - Encodes the parameter count using mysql_encode_length() and writes the resulting bytes.
			uint16_t num_params = meta->num_params;
			uint8_t paramCountLen = mysql_encode_length(num_params, buf);
			write_encoded_length(buf, num_params, paramCountLen, buf[0]);
			f->write((char *)buf, paramCountLen);

			if (num_params) {
				// Build and write the null bitmap.
				// Constructing and Writing the Null Bitmap:
				// - Calculates the required bitmap size as (num_params + 7) / 8 bytes where each bit represents
				//   whether a parameter value is null.
				// - Iterates over each parameter, setting the corresponding bit in the bitmap if the parameter is null.
				// - Writes the complete null bitmap to the file stream.
				size_t bitmap_size = (num_params + 7) / 8;  // one bit per parameter
				std::vector<unsigned char> null_bitmap(bitmap_size, 0);
				for (uint16_t i = 0; i < num_params; i++) {
					if (meta->is_nulls && meta->is_nulls[i]) {
						null_bitmap[i / 8] |= (1 << (i % 8));
					}
				}
				f->write(reinterpret_cast<char*>(null_bitmap.data()), bitmap_size);

				// For each parameter, write:
				// - Parameter type as 2 bytes.
				// - Encoded parameter value (first length, then raw bytes)
				for (uint16_t i = 0; i < num_params; i++) {
					// - Writes the parameter type:
					//   * Retrieves a 2-byte parameter type from the MYSQL_BIND structure associated with the current parameter.
					//   * Writes these 2 bytes directly to the file stream.
					const MYSQL_BIND *bind = meta->binds ? &meta->binds[i] : nullptr;
					uint16_t param_type = (bind ? bind->buffer_type : 0);
					// Write parameter type (2 bytes).
					f->write(reinterpret_cast<char*>(&param_type), sizeof(uint16_t));

					// - Logging the Parameter Value:
					//   * If the parameter is not null (as determined by the null bitmap), the code uses getValueForBind() to
					//       obtain a string representation of the parameter value.
					//   * Determines the length of this converted value.
					// * Encodes the length using mysql_encode_length() and writes the encoded length.
					// * Finally, writes the raw bytes representing the parameter value.
					std::string convertedValue;
					if (bind && bind->buffer && !(meta->is_nulls && meta->is_nulls[i])) {
						unsigned long len = meta->lengths ? meta->lengths[i] : 0;
						auto bt = bind->buffer_type;
						switch (bt) {
							case MYSQL_TYPE_TIMESTAMP:
							case MYSQL_TYPE_DATE:
							case MYSQL_TYPE_TIME:
							case MYSQL_TYPE_DATETIME:
								len = sizeof(MYSQL_TIME);
								break;
							default:
								break;
						}
						auto[valType, convVal] = getValueForBind(bind, len);
						convertedValue = convVal;
					} else {
						convertedValue = "";
					}
					// Write the length of the parameter value.
					uint64_t value_len = convertedValue.size();
					uint8_t valueLenEnc = mysql_encode_length(value_len, buf);
					write_encoded_length(buf, value_len, valueLenEnc, buf[0]);
					f->write((char *)buf, valueLenEnc);
					// Write the parameter value bytes.
					if (value_len > 0) {
						f->write(convertedValue.data(), value_len);
					}
				}
			}
		} else {
			// Deterministic binary logging: always report 0 parameters.
			uint16_t num_params = 0;
			uint8_t paramCountLen = mysql_encode_length(num_params, buf);
			write_encoded_length(buf, num_params, paramCountLen, buf[0]);
			f->write((char *)buf, paramCountLen);
		}
	}

	return total_bytes;
}

/**
 * @brief Writes the MySQL event details in JSON format to a file stream.
 *
 * This method generates a JSON object containing various details about the MySQL event,
 * including query information, timestamps, execution metadata, error information, and
 * performance metrics. The resulting JSON string is then written to the provided file stream.
 *
 * The JSON object includes the following keys (when applicable):
 * - "hostgroup_id": The hostgroup identifier if set; otherwise, it defaults to -1.
 * - "thread_id": The identifier of the thread where the event was logged.
 * - "event": A string representing the type of event (e.g., "COM_STMT_EXECUTE", "COM_STMT_PREPARE", or "COM_QUERY").
 * - "username": The username associated with the event.
 * - "schemaname": The name of the schema related to the event.
 * - "client": The client information.
 * - "server": The server details, only logged if the hostgroup ID is valid.
 * - "rows_affected": Number of rows affected by the query, logged if related data is present.
 * - "last_insert_id": The last insert identifier if it is non-zero.
 * - "rows_sent": The number of rows sent in the response.
 * - "last_gtid": The last GTID (Global Transaction Identifier) if it is available.
 * - "errno": The error number associated with the event.
 * - "error": A string describing the error message, if one exists.
 * - "query": The full SQL query associated with the event, constructed from a pointer and length.
 * - "starttime_timestamp_us": The event start time in microseconds.
 * - "starttime": Human-readable start time with microseconds precision.
 * - "endtime_timestamp_us": The event end time in microseconds.
 * - "endtime": Human-readable end time with microseconds precision.
 * - "duration_us": The duration of the event in microseconds.
 * - "digest": A hexadecimal string representation of the query digest.
 * - "client_stmt_id": Identifier for the client statement (logged for prepared or executed statements), if present.
 *
 * Additionally, for executed statements (PROXYSQL_COM_STMT_EXECUTE), if session data is available,
 * prepared statement parameters and added to the JSON.
 *
 * The generated JSON is dumped into the given file stream with error replacement settings to ensure
 * proper serialization even in the presence of encoding errors.
 *
 * @param[out] f Pointer to a std::fstream where the JSON string will be written.
 * @return uint64_t Always returns 0, as the current implementation does not compute total bytes written.
 */
uint64_t MySQL_Event::write_query_format_2_json(std::fstream *f) {
	json j = {};
	uint64_t total_bytes=0;
	if (hid!=UINT64_MAX) {
		j["hostgroup_id"] = hid;
	} else {
		j["hostgroup_id"] = -1;
	}
	j["thread_id"] = thread_id;
	switch (et) {
		case PROXYSQL_COM_STMT_EXECUTE:
			j["event"]="COM_STMT_EXECUTE";
			break;
		case PROXYSQL_COM_STMT_PREPARE:
			j["event"]="COM_STMT_PREPARE";
			break;
		default:
			j["event"]="COM_QUERY";
			break;
	}
	if (username) {
		j["username"] = username;
	//} else {
	//	j["username"] = "";
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	//} else {
	//	j["schemaname"] = "";
	}
	if (client) {
		j["client"] = client;
	//} else {
	//	j["client"] = "";
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
		if (last_insert_id != 0) {
			j["last_insert_id"] = last_insert_id;
		}
	}
	if (have_rows_sent == true) {
		j["rows_sent"] = rows_sent;
	}
	if (have_gtid == true) {
		j["last_gtid"] = gtid;
	}
	j["errno"] = myerrno;
	if (errmsg != nullptr) {
		j["error"] = errmsg;
	}
	j["query"] = string(query_ptr,query_len);
	j["starttime_timestamp_us"] = start_time;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(start_time%1000000));
		j["starttime"] = buffer2;
	}
	j["endtime_timestamp_us"] = end_time;
	{
		time_t timer=end_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(end_time%1000000));
		j["endtime"] = buffer2;
	}
	j["duration_us"] = end_time-start_time;
	char digest_hex[20];
	sprintf(digest_hex,"0x%016llX", (long long unsigned int)query_digest);
	j["digest"] = digest_hex;

	if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
		j["client_stmt_id"] = client_stmt_id;
	}
	if (et == PROXYSQL_COM_STMT_EXECUTE) {
		if (session != nullptr) {
			if (mysql_thread___eventslog_stmt_parameters != 0) {
				extractStmtExecuteMetadataToJson(j);
			}
		}
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloMyLogger->wrlock();
		//move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
	return total_bytes; // always 0
}

void MySQL_Event::extractStmtExecuteMetadataToJson(json &j) {
	if (session == nullptr) {
		return;
	}
	if (et != PROXYSQL_COM_STMT_EXECUTE) {
		return;
	}
	if (session->CurrentQuery.stmt_info == nullptr) {
		return;
	}
	if (session->CurrentQuery.stmt_meta == nullptr) {
		return;
	}

	stmt_execute_metadata_t *meta = session->CurrentQuery.stmt_meta;

	// Create a JSON vector of objects each with "type" and "value"
	json jparams = json::array();
	for (uint16_t i = 0; i < meta->num_params; i++) {
		json jparam;
		// Check if parameter is NULL
		if (meta->is_nulls && meta->is_nulls[i]) {
			jparam["type"] = "NULL";
			jparam["value"] = nullptr;
		} else {
			// Extract the MYSQL_BIND for this parameter.
			MYSQL_BIND *bind = meta->binds ? &meta->binds[i] : nullptr;
			if (bind && bind->buffer) {
				// Use the length in meta->lengths[i] if available.
				unsigned long len = meta->lengths ? meta->lengths[i] : 0;
				auto[valType, convertedValue] = getValueForBind(bind, len);
				jparam["type"] = valType;
				jparam["value"] = convertedValue;
			} else {
				jparam["type"] = "unknown";
				jparam["value"] = nullptr;
			}
		}
		jparams.push_back(jparam);
	}
	j["parameters"] = jparams;

}
extern MySQL_Query_Processor* GloMyQPro;

//MySQL_Logger::MySQL_Logger() : metrics{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} {
MySQL_Logger::MySQL_Logger() : metrics{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} {
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
	events.max_log_file_size=100*1024*1024;
	audit.logfile=NULL;
	audit.log_file_id=0;
	audit.max_log_file_size=100*1024*1024;
	MyLogCB = new MySQL_Logger_CircularBuffer(0);

	// Initialize prometheus metrics
	init_prometheus_counter_array<ml_metrics_map_idx, p_ml_counter>(
		ml_metrics_map, this->prom_metrics.p_counter_array
	);
	init_prometheus_gauge_array<ml_metrics_map_idx, p_ml_gauge>(
		ml_metrics_map, this->prom_metrics.p_gauge_array
	);
};

MySQL_Logger::~MySQL_Logger() {
	if (events.datadir) {
		free(events.datadir);
	}
	free(events.base_filename);
	if (audit.datadir) {
		free(audit.datadir);
	}
	free(audit.base_filename);
	delete MyLogCB;
};

void MySQL_Logger::wrlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_lock(&wmutex);
#else
	spin_wrlock(&rwlock);
#endif
};

void MySQL_Logger::wrunlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_unlock(&wmutex);
#else
	spin_wrunlock(&rwlock);
#endif
};

void MySQL_Logger::flush_log() {
	if (audit.enabled==false && events.enabled==false) return;
	wrlock();
	events_flush_log_unlocked();
	audit_flush_log_unlocked();
	wrunlock();
}


void MySQL_Logger::events_close_log_unlocked() {
	if (events.logfile) {
		events.logfile->flush();
		events.logfile->close();
		delete events.logfile;
		events.logfile=NULL;
	}
}

void MySQL_Logger::audit_close_log_unlocked() {
	if (audit.logfile) {
		audit.logfile->flush();
		audit.logfile->close();
		delete audit.logfile;
		audit.logfile=NULL;
	}
}

void MySQL_Logger::events_flush_log_unlocked() {
	if (events.enabled==false) return;
	events_close_log_unlocked();
	events_open_log_unlocked();
}

void MySQL_Logger::audit_flush_log_unlocked() {
	if (audit.enabled==false) return;
	audit_close_log_unlocked();
	audit_open_log_unlocked();
}

void MySQL_Logger::events_open_log_unlocked() {
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
		proxy_info("Starting new mysql event log file %s\n", filen);
		if (mysql_thread___eventslog_format == 1) {
			// create a new event, type PROXYSQL_METADATA, that writes the ProxySQL version as part of the payload
			json j = {};
			j["version"] = string(PROXYSQL_VERSION);
			string msg = j.dump();
			MySQL_Event metaEvent(
				PROXYSQL_METADATA,    // event type for metadata
				0,                    // thread_id (0 for metadata events)
				(char*)msg.c_str(),   // using "metadata" as the username
				(char*)"",            // empty schemaname
				0,                    // start_time (current time)
				0,                    // end_time (current time)
				0,                    // query_digest not used for metadata
				(char *)"",           // client field holds the version string
				0,                    // length of version string
				nullptr               // no session associated
			);
			metaEvent.set_query((char *)"",0);
			metaEvent.write(events.logfile, nullptr);
		}
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new mysql event log file %s\n", filen);
		delete events.logfile;
		events.logfile=NULL;
	}
	free(filen);
};

void MySQL_Logger::audit_open_log_unlocked() {
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
		proxy_info("Starting new audit log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new audit log file %s\n", filen);
		delete audit.logfile;
		audit.logfile=NULL;
	}
	free(filen);
};

void MySQL_Logger::events_set_base_filename() {
	// if filename is the same, return
	wrlock();
	events.max_log_file_size=mysql_thread___eventslog_filesize;
	if (strcmp(events.base_filename,mysql_thread___eventslog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	events_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	events.log_file_id=0;
	free(events.base_filename);
	events.base_filename=strdup(mysql_thread___eventslog_filename);
	if (strlen(events.base_filename)) {
		events.enabled=true;
		events_open_log_unlocked();
	} else {
		events.enabled=false;
	}
	wrunlock();
}

void MySQL_Logger::events_set_datadir(char *s) {
	if (events.datadir)
		free(events.datadir);
	events.datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::audit_set_base_filename() {
	// if filename is the same, return
	wrlock();
	audit.max_log_file_size=mysql_thread___auditlog_filesize;
	if (strcmp(audit.base_filename,mysql_thread___auditlog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	audit_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	audit.log_file_id=0;
	free(audit.base_filename);
	audit.base_filename=strdup(mysql_thread___auditlog_filename);
	if (strlen(audit.base_filename)) {
		audit.enabled=true;
		audit_open_log_unlocked();
	} else {
		audit.enabled=false;
	}
	wrunlock();
}

void MySQL_Logger::audit_set_datadir(char *s) {
	if (audit.datadir)
		free(audit.datadir);
	audit.datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::log_request(MySQL_Session *sess, MySQL_Data_Stream *myds, const unsigned int myerrno, const char * errmsg) {
	int elmhs = mysql_thread___eventslog_buffer_history_size;
	if (elmhs == 0) {
		if (events.enabled==false) return;
		if (events.logfile==NULL) return;
	}
	// 'MySQL_Session::client_myds' could be NULL in case of 'RequestEnd' being called over a freshly created session
	// due to a failed 'CONNECTION_RESET'. Because this scenario isn't a client request, we just return.
	if (sess->client_myds==NULL || sess->client_myds->myconn== NULL) return;

	MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

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
	enum log_event_type let = PROXYSQL_COM_QUERY; // default
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			let = PROXYSQL_COM_STMT_EXECUTE;
			break;
		case PROCESSING_STMT_PREPARE:
			let = PROXYSQL_COM_STMT_PREPARE;
			break;
		case WAITING_CLIENT_DATA:
			{
				unsigned char c=*((unsigned char *)sess->pkt.ptr+sizeof(mysql_hdr));
				switch ((enum_mysql_command)c) {
					case _MYSQL_COM_STMT_PREPARE:
						// proxysql is responding to COM_STMT_PREPARE without
						// preparing on any backend
						let = PROXYSQL_COM_STMT_PREPARE;
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

	if (sess->status != PROCESSING_STMT_EXECUTE) {
		query_digest = GloMyQPro->get_digest(&sess->CurrentQuery.QueryParserArgs);
	} else {
		query_digest = sess->CurrentQuery.stmt_info->digest;
	}

	MySQL_Event me(let,
		sess->thread_session_id,ui->username,ui->schemaname,
		sess->CurrentQuery.start_time + curtime_real - curtime_mono,
		sess->CurrentQuery.end_time + curtime_real - curtime_mono,
		query_digest,
		ca, cl, sess
	);
	char *c = NULL;
	int ql = 0;
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			c = (char *)sess->CurrentQuery.stmt_info->query;
			ql = sess->CurrentQuery.stmt_info->query_length;
			me.set_client_stmt_id(sess->CurrentQuery.stmt_client_id);
			break;
		case PROCESSING_STMT_PREPARE:
		default:
			c = (char *)sess->CurrentQuery.QueryPointer;
			ql = sess->CurrentQuery.QueryLength;
			// NOTE: This needs to be located in the 'default' case because otherwise will miss state
			// 'WAITING_CLIENT_DATA'. This state is possible when the prepared statement is found in the
			// global cache and due to that we immediately reply to the client and session doesn't reach
			// 'PROCESSING_STMT_PREPARE' state. 'stmt_client_id' is expected to be '0' for anything that isn't
			// a prepared statement, still, logging should rely 'log_event_type' instead of this value.
			me.set_client_stmt_id(sess->CurrentQuery.stmt_client_id);
			break;
	}
	if (c) {
		me.set_query(c,ql);
	} else {
		me.set_query("",0);
	}

	if (sess->CurrentQuery.have_affected_rows) {
		me.set_affected_rows(sess->CurrentQuery.affected_rows, sess->CurrentQuery.last_insert_id);
	}
	me.set_rows_sent(sess->CurrentQuery.rows_sent);
	me.set_gtid(sess);

	if (myerrno != 0) {
		me.set_errmsg(myerrno, errmsg);
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
	

	if ((events.enabled == true) && (events.logfile != nullptr)) {
		//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
		GloMyLogger->wrlock();

		me.write(events.logfile, sess);


		unsigned long curpos=events.logfile->tellp();
		if (curpos > events.max_log_file_size) {
			events_flush_log_unlocked();
		}
		wrunlock();
	}
	if (MyLogCB->buffer_size != 0) {
		MySQL_Event *me2 = new MySQL_Event(me);
		MyLogCB->insert(me2);
#if 0
		for (int i=0; i<10000; i++) {
			MySQL_Event *me2 = new MySQL_Event(me);
			MyLogCB->insert(me2);
		}
#endif // 0
	}

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void MySQL_Logger::log_audit_entry(log_event_type _et, MySQL_Session *sess, MySQL_Data_Stream *myds, char *xi) {
	if (audit.enabled==false) return;
	if (audit.logfile==NULL) return;

	if (sess == NULL) return;
	if (sess->client_myds == NULL) return;

	MySQL_Connection_userinfo *ui= NULL;
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
			case PROXYSQL_MYSQL_AUTH_OK:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_OK;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_OK;
					default:
						break;
				}
				break;
			case PROXYSQL_MYSQL_AUTH_ERR:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_ERR;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_ERR;
					default:
						break;
				}
				break;
			case PROXYSQL_MYSQL_AUTH_QUIT:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_QUIT;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_QUIT;
					default:
						break;
				}
				break;
			case PROXYSQL_MYSQL_AUTH_CLOSE:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_CLOSE;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_CLOSE;
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
		if (ui->schemaname) {
			sn = ui->schemaname;
		}
	}
	MySQL_Event me(_et, sess->thread_session_id,
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

	//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
	GloMyLogger->wrlock();
	me.write(audit.logfile, sess);


	unsigned long curpos=audit.logfile->tellp();
	if (curpos > audit.max_log_file_size) {
		audit_flush_log_unlocked();
	}
	wrunlock();

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void MySQL_Logger::flush() {
	wrlock();
	if (events.logfile) {
		events.logfile->flush();
	}
	if (audit.logfile) {
		audit.logfile->flush();
	}
	wrunlock();
}

unsigned int MySQL_Logger::events_find_next_id() {
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

unsigned int MySQL_Logger::audit_find_next_id() {
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

void MySQL_Logger::print_version() {
	fprintf(stderr,"Standard ProxySQL MySQL Logger rev. %s -- %s -- %s\n", PROXYSQL_MYSQL_LOGGER_VERSION, __FILE__, __TIMESTAMP__);
};

MySQL_Logger_CircularBuffer::MySQL_Logger_CircularBuffer(size_t size) : event_buffer(size),
	eventsAddedCount(0), eventsDroppedCount(0),
	buffer_size(size) {}

MySQL_Logger_CircularBuffer::~MySQL_Logger_CircularBuffer() {
	std::lock_guard<std::mutex> lock(mutex);
	for (MySQL_Event* event : event_buffer) {
		delete event;
	}
}

void MySQL_Logger_CircularBuffer::insert(MySQL_Event* event) {
	std::lock_guard<std::mutex> lock(mutex);
	eventsAddedCount++;
	if (event_buffer.size() == buffer_size) {
		delete event_buffer.front();
		event_buffer.pop_front();
		eventsDroppedCount++;
	}
	event_buffer.push_back(event);
}


size_t MySQL_Logger_CircularBuffer::size() {
	std::lock_guard<std::mutex> lock(mutex);
	return event_buffer.size();
}

void MySQL_Logger_CircularBuffer::get_all_events(std::vector<MySQL_Event*>& events) {
	std::lock_guard<std::mutex> lock(mutex);
	events.reserve(event_buffer.size());
	events.insert(events.end(), event_buffer.begin(), event_buffer.end());
	event_buffer.clear();
}

size_t MySQL_Logger_CircularBuffer::getBufferSize() const {
	return buffer_size;
}

void MySQL_Logger_CircularBuffer::setBufferSize(size_t newSize) {
	std::lock_guard<std::mutex> lock(mutex);
	buffer_size = newSize;
}


void MySQL_Logger::insertMysqlEventsIntoDb(SQLite3DB * db, const std::string& tableName, size_t numEvents, std::vector<MySQL_Event*>::const_iterator begin){
	int rc = 0;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	char *query1=NULL;
	char *query32=NULL;
	const int numcols = 19;
	std::string query1s = "";
	std::string query32s = "";

	std::string coldefs = "(thread_id, username, schemaname, start_time, end_time, query_digest, query, server, client, event_type, hid, extra_info, affected_rows, last_insert_id, rows_sent, client_stmt_id, gtid, errno, error)";

	query1s  = "INSERT INTO " + tableName + coldefs + " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)";
	query32s = "INSERT INTO " + tableName + coldefs + " VALUES " + generate_multi_rows_query(32, numcols);
	query1  = (char *)query1s.c_str();
	query32 = (char *)query32s.c_str();
	rc = db->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	rc = db->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, db);

	char digest_hex_str[20]; // 2+sizeof(unsigned long long)*2+2

	db->execute("BEGIN");

	int row_idx=0;
	int max_bulk_row_idx=numEvents/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<MySQL_Event *>::const_iterator it = begin ; it != begin + numEvents; ++it) {
		MySQL_Event *event = *it;
		int idx=row_idx%32;

		if (row_idx<max_bulk_row_idx) { // bulk
			//Bind parameters. Handle potential errors in binding.
			rc = (*proxy_sqlite3_bind_int)(statement32, (idx*numcols)+1, event->thread_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+2, event->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+3, event->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+4, event->start_time); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+5, event->end_time); ASSERT_SQLITE_OK(rc, db);
			sprintf(digest_hex_str, "0x%016llX", (long long unsigned int)event->query_digest);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+6, digest_hex_str, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+7, event->query_ptr, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db); // MySQL_Events from circular-buffer are all null-terminated
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+8, event->server, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+9, event->client, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement32, (idx*numcols)+10, (int)event->et); ASSERT_SQLITE_OK(rc, db); // Assuming event_type is an enum mapped to integers
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+11, event->hid); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+12, event->extra_info, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+13, event->affected_rows); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+14, event->last_insert_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx*numcols)+15, event->rows_sent); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement32, (idx*numcols)+16, event->client_stmt_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+17, event->gtid, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement32, (idx*numcols)+18, event->myerrno); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx*numcols)+19, event->errmsg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, db);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, db);
			}
		} else { // single row
			//Bind parameters. Handle potential errors in binding.
			rc = (*proxy_sqlite3_bind_int)(statement1, 1, event->thread_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 2, event->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 3, event->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 4, event->start_time); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 5, event->end_time); ASSERT_SQLITE_OK(rc, db);
			sprintf(digest_hex_str, "0x%016llX", (long long unsigned int)event->query_digest);
			rc = (*proxy_sqlite3_bind_text)(statement1, 6, digest_hex_str, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 7, event->query_ptr, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db); // MySQL_Events from circular-buffer are all null-terminated
			rc = (*proxy_sqlite3_bind_text)(statement1, 8, event->server, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 9, event->client, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement1, 10, (int)event->et); ASSERT_SQLITE_OK(rc, db); // Assuming event_type is an enum mapped to integers
			rc = (*proxy_sqlite3_bind_int64)(statement1, 11, event->hid); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 12, event->extra_info, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 13, event->affected_rows); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 14, event->last_insert_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 15, event->rows_sent); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement1, 16, event->client_stmt_id); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 17, event->gtid, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_int)(statement1, 18, event->myerrno); ASSERT_SQLITE_OK(rc, db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 19, event->errmsg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	db->execute("COMMIT");
}


int MySQL_Logger::processEvents(SQLite3DB * statsdb , SQLite3DB * statsdb_disk) {
	unsigned long long startTimeMicros = monotonic_time();
	std::vector<MySQL_Event*> events = {};
	MyLogCB->get_all_events(events);

	metrics.getAllEventsCallsCount++;
	if (events.empty()) return 0;

	unsigned long long afterGetAllEventsTimeMicros = monotonic_time();
	metrics.getAllEventsEventsCount += events.size();
	metrics.totalGetAllEventsTimeMicros += (afterGetAllEventsTimeMicros-startTimeMicros);

	if (statsdb_disk != nullptr) {
		// Write to on-disk database first
		unsigned long long diskStartTimeMicros = monotonic_time();
		insertMysqlEventsIntoDb(statsdb_disk, "history_mysql_query_events", events.size(), events.begin());
		unsigned long long diskEndTimeMicros = monotonic_time();
		metrics.diskCopyCount++;
		metrics.totalDiskCopyTimeMicros += (diskEndTimeMicros - diskStartTimeMicros);
		metrics.totalEventsCopiedToDisk += events.size();
	}

	if (statsdb != nullptr) {
		unsigned long long memoryStartTimeMicros = monotonic_time();
		size_t maxInMemorySize = mysql_thread___eventslog_table_memory_size;
		size_t numEventsToInsert = std::min(events.size(), maxInMemorySize);

		if (events.size() >= maxInMemorySize) {
			// delete everything from stats_mysql_query_events
			statsdb->execute("DELETE FROM stats_mysql_query_events");
		} else {
			// make enough room in stats_mysql_query_events
			int current_rows = statsdb->return_one_int((char *)"SELECT COUNT(*) FROM stats_mysql_query_events");
			int rows_to_keep = maxInMemorySize - events.size();
			if (current_rows > rows_to_keep) {
				int rows_to_delete = (current_rows - rows_to_keep);
				string query = "SELECT MAX(id) FROM (SELECT id FROM stats_mysql_query_events ORDER BY id LIMIT " + to_string(rows_to_delete) + ")";
				int maxIdToDelete = statsdb->return_one_int(query.c_str());
				string delete_stmt = "DELETE FROM stats_mysql_query_events WHERE id <= " + to_string(maxIdToDelete);
				statsdb->execute(delete_stmt.c_str());
			}
		}

		// Pass iterators to avoid copying
		insertMysqlEventsIntoDb(statsdb, "stats_mysql_query_events", numEventsToInsert, events.begin());
		unsigned long long memoryEndTimeMicros = monotonic_time();
		metrics.memoryCopyCount++;
		metrics.totalMemoryCopyTimeMicros += (memoryEndTimeMicros - memoryStartTimeMicros);
		metrics.totalEventsCopiedToMemory += numEventsToInsert;
	}

	// cleanup of all events
	for (MySQL_Event* event : events) {
		delete event;
	}
	size_t ret = events.size();
#if 0
	std::cerr << "Circular:" << endl;
	std::cerr << "  EventsAddedCount:   " << MyLogCB->getEventsAddedCount() << endl;
	std::cerr << "  EventsDroppedCount: " << MyLogCB->getEventsDroppedCount() << endl;
	std::cerr << "  Size:               " << MyLogCB->size() << endl;
	std::cerr << "memoryCopy: Count: " << metrics.memoryCopyCount << " , TimeUs: " << metrics.totalMemoryCopyTimeMicros << endl;
	std::cerr << "diskCopy:   Count: " << metrics.diskCopyCount   << " , TimeUs: " << metrics.totalDiskCopyTimeMicros << endl;
#endif // 0
	return ret;
}


std::unordered_map<std::string, unsigned long long> MySQL_Logger::getAllMetrics() const {
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
    //allMetrics["eventsAddedToBufferCount"] = metrics.eventsAddedToBufferCount;
    //allMetrics["eventsDroppedFromBufferCount"] = metrics.eventsDroppedFromBufferCount;
    allMetrics["circularBufferEventsAddedCount"] = MyLogCB->getEventsAddedCount();
    allMetrics["circularBufferEventsDroppedCount"] = MyLogCB->getEventsDroppedCount();
    allMetrics["circularBufferEventsSize"] = MyLogCB->size();

    return allMetrics;
}

void MySQL_Logger::p_update_metrics() {
	using ml_c = p_ml_counter;
	const auto& counters { this->prom_metrics.p_counter_array };

	p_update_counter(counters[ml_c::memory_copy_count], metrics.memoryCopyCount);
	p_update_counter(counters[ml_c::disk_copy_count], metrics.diskCopyCount);
	p_update_counter(counters[ml_c::get_all_events_calls_count], metrics.getAllEventsCallsCount);
	p_update_counter(counters[ml_c::get_all_events_events_count], metrics.getAllEventsEventsCount);
	p_update_counter(counters[ml_c::total_memory_copy_time_us], metrics.totalMemoryCopyTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[ml_c::total_disk_copy_time_us], metrics.totalDiskCopyTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[ml_c::total_get_all_events_time_us], metrics.totalGetAllEventsTimeMicros / (1000.0 * 1000));
	p_update_counter(counters[ml_c::total_events_copied_to_memory], metrics.totalEventsCopiedToMemory);
	p_update_counter(counters[ml_c::total_events_copied_to_disk], metrics.totalEventsCopiedToDisk);

	p_update_counter(counters[ml_c::circular_buffer_events_added_count], MyLogCB->getEventsAddedCount());
	p_update_counter(counters[ml_c::circular_buffer_events_dropped_count], MyLogCB->getEventsDroppedCount());

	using ml_g = p_ml_gauge;
	const auto& gauges { this->prom_metrics.p_gauge_array };
	gauges[ml_g::circular_buffer_events_size]->Set(MyLogCB->size());
}
