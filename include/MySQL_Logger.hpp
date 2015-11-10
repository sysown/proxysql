#ifndef __CLASS_MYSQL_LOGGER_H
#define __CLASS_MYSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"

class MySQL_Logger {
	private:
	char *base_filename;
	char *datadir;
	unsigned int log_file_id;
	unsigned int max_log_file_size;
	rwlock_t rwlock;
	void wrlock();
	void wrunlock();
	std::fstream *logfile;
	public:
	MySQL_Logger();
	~MySQL_Logger();
	void flush_log();
	unsigned int find_next_id();
	void set_datadir(char *);
	void log_request(MySQL_Session *);
	void flush();
};


#endif /* __CLASS_MYSQL_LOGGER_H */
