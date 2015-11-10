#include "proxysql.h"
#include "cpp.h"

MySQL_Logger::MySQL_Logger() {
	spinlock_rwlock_init(&rwlock);
};

MySQL_Logger::~MySQL_Logger() {
};

void MySQL_Logger::wrlock() {
  spin_wrlock(&rwlock);
};

void MySQL_Logger::wrunlock() {
  spin_wrunlock(&rwlock);
};

void MySQL_Logger::flush_log() {
};
