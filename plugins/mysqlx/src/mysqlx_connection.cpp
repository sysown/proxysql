#include "mysqlx_connection.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>

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

int MysqlxConnection::start_connect(const char* host, int port) {
	fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd_ < 0) { state_ = ERROR_STATE; return -1; }
	int flag = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &addr.sin_addr);
	int rc = ::connect(fd_, (struct sockaddr*)&addr, sizeof(addr));
	if (rc == 0) { state_ = AUTHENTICATING; return 0; }
	if (errno == EINPROGRESS) { state_ = CONNECTING; return 1; }
	state_ = ERROR_STATE; close(fd_); fd_ = -1; return -1;
}

int MysqlxConnection::check_connect() {
	int err = 0;
	socklen_t len = sizeof(err);
	getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err == 0) { state_ = AUTHENTICATING; return 0; }
	state_ = ERROR_STATE; return -1;
}
