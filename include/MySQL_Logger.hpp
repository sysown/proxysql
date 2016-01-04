#ifndef __CLASS_MYSQL_LOGGER_H
#define __CLASS_MYSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"


class MySQL_Event {
	private:
	uint32_t thread_id;
	char *username;
	char *schemaname;
	size_t username_len;
	size_t schemaname_len;
	uint64_t start_time;
	uint64_t end_time;
	uint64_t query_digest;
	char *query_ptr;
	size_t query_len;
	char *server;
	char *client;
	size_t server_len;
	size_t client_len;
	uint64_t total_length;
	unsigned char buf[10];
	public:
	MySQL_Event(uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest);
	uint64_t write(std::fstream *f);
	void set_query(const char *ptr, int len);
};

class MySQL_Logger {
	private:
	bool enabled;
	char *base_filename;
	char *datadir;
	unsigned int log_file_id;
	unsigned int max_log_file_size;
	rwlock_t rwlock;
	void wrlock();
	void wrunlock();
	std::fstream *logfile;
	void close_log_unlocked();
	void open_log_unlocked();
	public:
	MySQL_Logger();
	~MySQL_Logger();
	void flush_log();
	void flush_log_unlocked();
	unsigned int find_next_id();
	void set_datadir(char *);
	void set_base_filename();
	void log_request(MySQL_Session *);
	void flush();
};


#endif /* __CLASS_MYSQL_LOGGER_H */
