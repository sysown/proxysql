#include "mysqlx_data_stream.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <cerrno>
#include <cstring>
#include <algorithm>

MysqlxDataStream::MysqlxDataStream()
	: fd_(-1), type_(XDS_FRONTEND), status_(XDS_NOT_CONNECTED),
	  poll_events_(0), revents_(0), read_offset_(0), write_offset_(0),
	  parse_error_(false), encrypted_(false), poll_fds_idx(-1) {}

MysqlxDataStream::~MysqlxDataStream() {}

void MysqlxDataStream::init(mysqlx_ds_type type, int fd) {
	type_ = type;
	fd_ = fd;
	status_ = XDS_CONNECTED;
	read_buf_.clear();
	read_offset_ = 0;
	write_buf_.clear();
	write_offset_ = 0;
	parse_error_ = false;
	poll_fds_idx = -1;
	set_nonblocking();
}

void MysqlxDataStream::set_nonblocking() {
	if (fd_ >= 0) {
		int flags = fcntl(fd_, F_GETFL, 0);
		fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
	}
}

void MysqlxDataStream::feed_bytes(const uint8_t* data, size_t len) {
	read_buf_.insert(read_buf_.end(), data, data + len);
	while (try_parse_frame()) {}
}

bool MysqlxDataStream::try_parse_frame() {
	size_t available = read_buf_.size() - read_offset_;
	if (available < X_FRAME_HEADER_SIZE) return false;

	const uint8_t* hdr = read_buf_.data() + read_offset_;
	uint32_t payload_size = static_cast<uint32_t>(hdr[0]) |
			       (static_cast<uint32_t>(hdr[1]) << 8) |
			       (static_cast<uint32_t>(hdr[2]) << 16) |
			       (static_cast<uint32_t>(hdr[3]) << 24);

	if (payload_size < 1 || payload_size > X_MAX_PAYLOAD_SIZE) {
		parse_error_ = true;
		return false;
	}

	size_t frame_total = 4 + payload_size;
	if (available < frame_total) return false;

	MysqlxFrame frame(read_buf_.begin() + read_offset_, read_buf_.begin() + read_offset_ + frame_total);
	complete_frames_.push_back(std::move(frame));

	read_offset_ += frame_total;
	if (read_offset_ >= read_buf_.size()) {
		read_buf_.clear();
		read_offset_ = 0;
	} else if (read_offset_ > 4096) {
		read_buf_.erase(read_buf_.begin(), read_buf_.begin() + read_offset_);
		read_offset_ = 0;
	}
	return true;
}

bool MysqlxDataStream::has_complete_frame() const {
	return !complete_frames_.empty();
}

const MysqlxFrame& MysqlxDataStream::front_frame() const {
	return complete_frames_.front();
}

void MysqlxDataStream::pop_frame() {
	if (!complete_frames_.empty()) {
		complete_frames_.pop_front();
	}
}

void MysqlxDataStream::enqueue_frame(uint8_t msg_type, const uint8_t* body, size_t body_len) {
	if (body_len + 1 > X_MAX_PAYLOAD_SIZE) return;
	uint32_t payload_size = static_cast<uint32_t>(body_len) + 1;
	write_buf_.push_back(static_cast<uint8_t>(payload_size & 0xFF));
	write_buf_.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xFF));
	write_buf_.push_back(static_cast<uint8_t>((payload_size >> 16) & 0xFF));
	write_buf_.push_back(static_cast<uint8_t>((payload_size >> 24) & 0xFF));
	write_buf_.push_back(msg_type);
	if (body_len > 0 && body) {
		write_buf_.insert(write_buf_.end(), body, body + body_len);
	}
}

ssize_t MysqlxDataStream::read_from_net() {
	if (fd_ < 0) return -1;
	uint8_t buf[65536];
	ssize_t r = recv(fd_, buf, sizeof(buf), 0);
	if (r > 0) {
		feed_bytes(buf, static_cast<size_t>(r));
	}
	return r;
}

ssize_t MysqlxDataStream::write_to_net() {
	if (fd_ < 0) return -1;
	if (write_buf_.empty()) return 0;
	size_t available = write_buf_.size() - write_offset_;
	ssize_t r = send(fd_, write_buf_.data() + write_offset_, available, MSG_NOSIGNAL);
	if (r > 0) {
		write_offset_ += static_cast<size_t>(r);
		if (write_offset_ >= write_buf_.size()) {
			write_buf_.clear();
			write_offset_ = 0;
		}
	}
	return r;
}
