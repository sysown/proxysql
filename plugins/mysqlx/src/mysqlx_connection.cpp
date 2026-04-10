#include "mysqlx_connection.h"
#include <unistd.h>

MysqlxConnection::MysqlxConnection()
	: state_(CREATED), fd_(-1), hostgroup_(-1), port_(0),
	  reusable_(false), in_transaction_(false),
	  has_prepared_stmt_(false), last_used_time_(0) {}

MysqlxConnection::~MysqlxConnection() {
	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
}

bool MysqlxConnection::is_reusable() const {
	if (in_transaction_) return false;
	if (has_prepared_stmt_) return false;
	return reusable_;
}

void MysqlxConnection::reset() {
	in_transaction_ = false;
	has_prepared_stmt_ = false;
	reusable_ = true;
}
