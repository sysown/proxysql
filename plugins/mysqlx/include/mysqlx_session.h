#ifndef __MYSQLX_SESSION_H
#define __MYSQLX_SESSION_H

#include "mysqlx_data_stream.h"
#include "mysqlx_connection.h"

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

class Mysqlx_Thread;

struct MysqlxCredentials {
	std::string password_hash;
	bool x_enabled;
	std::string allowed_auth;
};

typedef std::function<MysqlxCredentials(const std::string& username)> MysqlxCredentialLookup;

enum MysqlxResponseState {
	RESP_IDLE = 0,
	RESP_WAITING_STMT_EXECUTE,
	RESP_WAITING_CRUD,
	RESP_WAITING_PREPARE,
	RESP_WAITING_CURSOR,
	RESP_WAITING_EXPECT,
	RESP_WAITING_SESS_RESET
};

enum MysqlxTlsMode {
	TLS_OFF = 0,
	TLS_TERMINATE,
	TLS_PASSTHROUGH
};

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
		X_TLS_ACCEPT_INIT,
		X_TLS_ACCEPT_CONT,
		X_TLS_ACCEPT_DONE,
		X_TLS_CONNECT_INIT,
		X_TLS_CONNECT_CONT,
		X_TLS_CONNECT_DONE,
		X_SESSION_CLOSING,
		X_SESSION_CLOSED,
		X_SESSION_RESET_WAITING
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
	MysqlxDataStream& server_ds() { return server_ds_; }
	MysqlxConnection*& backend_conn() { return backend_conn_; }

	void set_credential_lookup(MysqlxCredentialLookup lookup) { credential_lookup_ = lookup; }
	void set_tls_mode(MysqlxTlsMode mode) { tls_mode_ = mode; }
	MysqlxTlsMode get_tls_mode() const { return tls_mode_; }
	uint64_t get_start_time() const { return start_time_; }
	uint64_t get_last_active_time() const { return last_active_time_; }
	void set_last_active_time(uint64_t t) { last_active_time_ = t; }

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
	void handler_connecting_server();
	void handler_session_reset_waiting();

	void handler_tls_accept_init();

	int dispatch_client_message(uint8_t msg_type);
	void forward_to_backend();
	void return_backend_to_pool();

	void send_error(int code, const char* msg, bool fatal = false);
	void send_ok(const char* msg = "");
	void send_auth_continue(const std::string& auth_data);
	void send_auth_ok();
	void send_capabilities();

	uint8_t extract_msg_type_from_frame(const MysqlxFrame& frame);
	bool is_terminal_for_state(uint8_t msg_type) const;

	MysqlxDataStream client_ds_;
	MysqlxDataStream server_ds_;
	MysqlxConnection* backend_conn_;
	void* thread_ptr_;
	Status status_;
	bool healthy;
	std::string username_;
	std::string schema_;
	std::string auth_method_;
	std::vector<uint8_t> auth_challenge_;
	int target_hostgroup_;
	std::string target_address_;
	int target_port_;
	MysqlxCredentialLookup credential_lookup_;
	uint64_t start_time_;
	uint64_t last_active_time_;
	MysqlxResponseState response_state_;
	MysqlxTlsMode tls_mode_;
};

#endif
