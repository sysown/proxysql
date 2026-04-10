#ifndef __MYSQLX_CONNECTION_H
#define __MYSQLX_CONNECTION_H

#include <cstdint>
#include <cstring>
#include <string>

class MysqlxConnection {
public:
	enum State {
		CREATED = 0,
		CONNECTING,
		AUTHENTICATING,
		IDLE,
		IN_USE,
		ERROR_STATE,
		CLOSED
	};

	MysqlxConnection();
	~MysqlxConnection();

	State get_state() const { return state_; }
	void set_state(State s) { state_ = s; }

	int get_fd() const { return fd_; }
	void set_fd(int fd) { fd_ = fd; }

	int get_hostgroup() const { return hostgroup_; }
	void set_hostgroup(int hg) { hostgroup_ = hg; }

	const char* get_user() const { return user_.c_str(); }
	void set_user(const char* u) { user_ = u; }

	const char* get_schema() const { return schema_.c_str(); }
	void set_schema(const char* s) { schema_ = s; }

	const char* get_address() const { return address_.c_str(); }
	void set_address(const char* a) { address_ = a; }

	int get_port() const { return port_; }
	void set_port(int p) { port_ = p; }

	bool is_reusable() const;
	void set_reusable(bool r) { reusable_ = r; }
	void set_in_transaction(bool t) { in_transaction_ = t; }
	bool is_in_transaction() const { return in_transaction_; }
	void set_has_prepared_statement(bool p) { has_prepared_stmt_ = p; }
	bool has_prepared_statement() const { return has_prepared_stmt_; }

	uint64_t get_last_used_time() const { return last_used_time_; }
	void set_last_used_time(uint64_t t) { last_used_time_ = t; }

	void reset();

private:
	State state_;
	int fd_;
	int hostgroup_;
	std::string user_;
	std::string schema_;
	std::string address_;
	int port_;
	bool reusable_;
	bool in_transaction_;
	bool has_prepared_stmt_;
	uint64_t last_used_time_;
};

#endif
