#ifndef __CLASS_PGSQL_LOGGER_H
#define __CLASS_PGSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"

#define PROXYSQL_LOGGER_PTHREAD_MUTEX

enum class PGSQL_LOG_EVENT_TYPE {
	SIMPLE_QUERY,
	AUTH_OK,
	AUTH_ERR,
	AUTH_CLOSE,
	AUTH_QUIT,
	INITDB,
	ADMIN_AUTH_OK,
	ADMIN_AUTH_ERR,
	ADMIN_AUTH_CLOSE,
	ADMIN_AUTH_QUIT,
	SQLITE_AUTH_OK,
	SQLITE_AUTH_ERR,
	SQLITE_AUTH_CLOSE,
	SQLITE_AUTH_QUIT,
	STMT_EXECUTE,
	STMT_DESCRIBE,
	STMT_PREPARE
};

class PgSQL_Event {
	private:
	uint32_t thread_id;
	char *username;
	char *schemaname;
	size_t username_len;
	size_t schemaname_len;
	size_t client_stmt_name_len;
	uint64_t start_time;
	uint64_t end_time;
	uint64_t query_digest;
	char *query_ptr;
	size_t query_len;
	char *server;
	char *client;
	size_t server_len;
	size_t client_len;
	//uint64_t total_length;
	unsigned char buf[10];
	PGSQL_LOG_EVENT_TYPE et;
	uint64_t hid;
	char *extra_info;
	char *client_stmt_name;
	bool have_affected_rows;
	bool have_rows_sent;

	uint64_t affected_rows;
	uint64_t rows_sent;
	
	public:
	PgSQL_Event(PGSQL_LOG_EVENT_TYPE _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len);
	uint64_t write(std::fstream *f, PgSQL_Session *sess);
	uint64_t write_query_format_1(std::fstream *f);
	uint64_t write_query_format_2_json(std::fstream *f);
	void write_auth(std::fstream *f, PgSQL_Session *sess);
	void set_client_stmt_name(char* client_stmt_name);
	void set_query(const char *ptr, int len);
	void set_server(int _hid, const char *ptr, int len);
	void set_extra_info(char *);
	void set_affected_rows(uint64_t ar);
	void set_rows_sent(uint64_t rs);
};

class PgSQL_Logger {
	private:
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int max_log_file_size;
		std::fstream *logfile;
	} events;
	struct {
		bool enabled;
		char *base_filename;
		char *datadir;
		unsigned int log_file_id;
		unsigned int max_log_file_size;
		std::fstream *logfile;
	} audit;
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_t wmutex;
#else
	rwlock_t rwlock;
#endif
	void events_close_log_unlocked();
	void events_open_log_unlocked();
	void audit_close_log_unlocked();
	void audit_open_log_unlocked();
	unsigned int events_find_next_id();
	unsigned int audit_find_next_id();
	public:
	PgSQL_Logger();
	~PgSQL_Logger();
	void print_version();
	void flush_log();
	void events_flush_log_unlocked();
	void audit_flush_log_unlocked();
	void events_set_datadir(char *);
	void events_set_base_filename();
	void audit_set_datadir(char *);
	void audit_set_base_filename();
	void log_request(PgSQL_Session *, PgSQL_Data_Stream *);
	void log_audit_entry(PGSQL_LOG_EVENT_TYPE, PgSQL_Session *, PgSQL_Data_Stream *, char *e = NULL);
	void flush();
	void wrlock();
	void wrunlock();
};

#endif /* __CLASS_PGSQL_LOGGER_H */
