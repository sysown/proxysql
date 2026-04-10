#ifndef __MYSQLX_DATA_STREAM_H
#define __MYSQLX_DATA_STREAM_H

#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <vector>
#include <deque>
#include <optional>

typedef std::vector<uint8_t> MysqlxFrame;

enum mysqlx_data_stream_status {
	XDS_NOT_CONNECTED = 0,
	XDS_CONNECTING,
	XDS_CONNECTED,
	XDS_AUTHENTICATING,
	XDS_READY,
	XDS_CLOSING,
	XDS_CLOSED
};

enum mysqlx_ds_type {
	XDS_FRONTEND = 0,
	XDS_BACKEND,
	XDS_LISTENER
};

class MysqlxDataStream {
public:
	MysqlxDataStream();
	~MysqlxDataStream();

	void init(mysqlx_ds_type type, int fd);
	void set_nonblocking();

	int get_fd() const { return fd_; }
	mysqlx_ds_type get_type() const { return type_; }
	mysqlx_data_stream_status get_status() const { return status_; }
	void set_status(mysqlx_data_stream_status s) { status_ = s; }

	void feed_bytes(const uint8_t* data, size_t len);
	bool has_complete_frame() const;
	const MysqlxFrame& front_frame() const;
	void pop_frame();

	void enqueue_frame(uint8_t msg_type, const uint8_t* body, size_t body_len);
	size_t write_buffer_size() const { return write_buf_.size(); }
	const std::vector<uint8_t>& write_buffer_raw() const { return write_buf_; }

	ssize_t read_from_net();
	ssize_t write_to_net();

	ssize_t write_raw(const uint8_t* data, size_t len);
	std::optional<MysqlxFrame> try_read_one_frame();

	void set_poll_events(short events) { poll_events_ = events; }
	short get_poll_events() const { return poll_events_; }
	void set_revents(short revents) { revents_ = revents; }
	short get_revents() const { return revents_; }

	bool has_parse_error() const { return parse_error_; }

	void set_encrypted(bool e) { encrypted_ = e; }
	bool is_encrypted() const { return encrypted_; }

	int poll_fds_idx;

private:
	int fd_;
	mysqlx_ds_type type_;
	mysqlx_data_stream_status status_;
	short poll_events_;
	short revents_;

	std::vector<uint8_t> read_buf_;
	size_t read_offset_;

	std::vector<uint8_t> write_buf_;
	size_t write_offset_;

	std::deque<MysqlxFrame> complete_frames_;
	bool parse_error_;
	bool encrypted_;

	bool try_parse_frame();
	static constexpr size_t X_FRAME_HEADER_SIZE = 5;
	static constexpr size_t X_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;
};

#endif
