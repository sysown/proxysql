#ifndef __MYSQLX_SESSION_H
#define __MYSQLX_SESSION_H

#include "mysqlx_data_stream.h"

#include <cstdint>
#include <string>
#include <vector>

class MysqlxSession {
public:
	enum Status {
		NONE = 0,
		CONNECTING_CLIENT,
		X_CAPABILITIES_GET,
		X_CAPABILITIES_SET,
		X_AUTH_START,
		X_AUTH_CHALLENGE_SENT,
		X_AUTH_OK_SENT,
		X_AUTH_FAILED,
		WAITING_CLIENT_XMSG,
		PROCESSING_X_QUERY,
		CONNECTING_SERVER,
		WAITING_SERVER_XMSG,
		X_FAST_FORWARD,
		X_SESSION_CLOSING,
		X_SESSION_CLOSED
	};

	MysqlxSession();
	~MysqlxSession();

	void init(int fd, void* thread_ptr);
	void reset();

	int handler();

	Status get_status() const { return status_; }
	void set_status(Status s) { status_ = s; }

	bool is_healthy() const { return healthy; }
	int get_fd() const { return client_ds_.get_fd(); }

	MysqlxDataStream& client_ds() { return client_ds_; }

	bool to_process;

private:
	void handler_connecting_client();
	void handler_capabilities_get();
	void handler_capabilities_set();
	void handler_auth_start();
	void handler_auth_challenge_response();
	void handler_waiting_client_msg();
	void handler_waiting_server_msg();
	void handler_fast_forward();
	void handler_session_closing();

	void send_error(int code, const char* msg);
	void send_ok(const char* msg = "");
	void send_auth_continue(const std::string& auth_data);
	void send_auth_ok();
	void send_capabilities();

	uint8_t extract_msg_type_from_frame(const MysqlxFrame& frame);

	MysqlxDataStream client_ds_;
	Status status_;
	bool healthy;
	std::string username_;
	std::string schema_;
	std::string auth_method_;
	std::vector<uint8_t> auth_challenge_;
};

#endif
