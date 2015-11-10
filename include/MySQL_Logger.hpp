#ifndef __CLASS_MYSQL_LOGGER_H
#define __CLASS_MYSQL_LOGGER_H
#include "proxysql.h"
#include "cpp.h"

class MySQL_Logger {
	private:
	rwlock_t rwlock;
	void wrlock();
	void wrunlock();
	public:
	MySQL_Logger();
	~MySQL_Logger();
	void flush_log();
};


#endif /* __CLASS_MYSQL_LOGGER_H */
