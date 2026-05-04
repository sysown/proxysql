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
	  parse_error_(false), encrypted_(false), poll_fds_idx(-1),
	  ssl_(nullptr), rbio_ssl_(nullptr), wbio_ssl_(nullptr),
	  ssl_write_offset_(0), ssl_handshake_done_(false), ssl_failed_(false) {}

MysqlxDataStream::~MysqlxDataStream() {
	if (ssl_) {
		SSL_set_quiet_shutdown(ssl_, 1);
		SSL_shutdown(ssl_);
		SSL_free(ssl_);
		ssl_ = nullptr;
		rbio_ssl_ = nullptr;
		wbio_ssl_ = nullptr;
	}
}

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

void MysqlxDataStream::close_and_reset() {
	if (ssl_) {
		SSL_set_quiet_shutdown(ssl_, 1);
		SSL_shutdown(ssl_);
		SSL_free(ssl_);
		ssl_ = nullptr;
		rbio_ssl_ = nullptr;
		wbio_ssl_ = nullptr;
	}
	ssl_write_buf_.clear();
	ssl_write_offset_ = 0;
	ssl_handshake_done_ = false;
	ssl_failed_ = false;
	encrypted_ = false;
	read_buf_.clear();
	read_offset_ = 0;
	write_buf_.clear();
	write_offset_ = 0;
	complete_frames_.clear();
	parse_error_ = false;
	poll_events_ = 0;
	revents_ = 0;
	poll_fds_idx = -1;
	fd_ = -1;
	status_ = XDS_NOT_CONNECTED;
	type_ = XDS_FRONTEND;
}

void MysqlxDataStream::clear_io_buffers() {
	read_buf_.clear();
	read_offset_ = 0;
	write_buf_.clear();
	write_offset_ = 0;
	complete_frames_.clear();
	parse_error_ = false;
	ssl_write_buf_.clear();
	ssl_write_offset_ = 0;
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
	if (body_len + 1 > X_MAX_PAYLOAD_SIZE) {
		// Server attempted to enqueue a frame larger than the X-Protocol
		// 16 MiB cap. Silently dropping the body would leave the client
		// expecting a frame that never arrives — usually a protocol
		// stall. Mark the parser as broken so the session loop tears
		// down cleanly instead of half-working. The caller (always a
		// server-side path: send_error, send_capabilities, compression
		// emit) is responsible for never feeding bodies anywhere near
		// this size; reaching here means an internal bug, not a
		// protocol-level event.
		parse_error_ = true;
		return;
	}
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

void MysqlxDataStream::init_ssl(SSL_CTX* ctx) {
	if (!ctx) return;
	ssl_ = SSL_new(ctx);
	rbio_ssl_ = BIO_new(BIO_s_mem());
	wbio_ssl_ = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl_, rbio_ssl_, wbio_ssl_);
	SSL_set_accept_state(ssl_);
	ssl_handshake_done_ = false;
	ssl_failed_ = false;
	encrypted_ = false;
}

void MysqlxDataStream::init_ssl_connect(SSL_CTX* ctx) {
	if (!ctx) return;
	ssl_ = SSL_new(ctx);
	rbio_ssl_ = BIO_new(BIO_s_mem());
	wbio_ssl_ = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl_, rbio_ssl_, wbio_ssl_);
	SSL_set_connect_state(ssl_);
	ssl_handshake_done_ = false;
	ssl_failed_ = false;
	encrypted_ = false;
}

mysqlx_ssl_status MysqlxDataStream::get_ssl_status(SSL* ssl, int n) {
	int err = SSL_get_error(ssl, n);
	ERR_clear_error();
	switch (err) {
		case SSL_ERROR_NONE:
			return MYSQLX_SSL_OK;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			return MYSQLX_SSL_WANT_IO;
		default:
			return MYSQLX_SSL_FAIL;
	}
}

void MysqlxDataStream::queue_encrypted_output() {
	char buf[16384];
	int n;
	while ((n = BIO_read(wbio_ssl_, buf, sizeof(buf))) > 0) {
		ssl_write_buf_.insert(ssl_write_buf_.end(), buf, buf + n);
	}
}

bool MysqlxDataStream::do_ssl_handshake() {
	if (!ssl_) return false;
	if (ssl_handshake_done_) return true;
	int n = SSL_do_handshake(ssl_);
	if (n == 1) {
		ssl_handshake_done_ = true;
		encrypted_ = true;
		queue_encrypted_output();
		// 64 KiB scratch buffer for the immediate post-handshake drain.
		// thread_local static avoids putting it on the worker stack —
		// some thread-stack budgets (e.g. ASan-instrumented builds, or
		// thread_pool_size >> default thread stack rlimit) would put a
		// stack-allocated 64 KiB local on the wrong side of the limit.
		// Each Mysqlx_Thread owns its own thread_local instance so the
		// buffer is not shared between threads.
		static thread_local uint8_t plain[65536];
		int dec;
		while ((dec = SSL_read(ssl_, plain, sizeof(plain))) > 0) {
			feed_bytes(plain, static_cast<size_t>(dec));
		}
		return true;
	}
	mysqlx_ssl_status status = get_ssl_status(ssl_, n);
	if (status == MYSQLX_SSL_WANT_IO) {
		queue_encrypted_output();
	} else {
		ssl_failed_ = true;
	}
	return false;
}

ssize_t MysqlxDataStream::flush_ssl_write_buf() {
	if (ssl_write_buf_.empty() || fd_ < 0) return 0;
	size_t avail = ssl_write_buf_.size() - ssl_write_offset_;
	ssize_t r;
	do {
		r = send(fd_, ssl_write_buf_.data() + ssl_write_offset_, avail, MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);
	if (r > 0) {
		ssl_write_offset_ += static_cast<size_t>(r);
		if (ssl_write_offset_ >= ssl_write_buf_.size()) {
			ssl_write_buf_.clear();
			ssl_write_offset_ = 0;
		}
	}
	return r;
}

bool MysqlxDataStream::has_ssl_pending_write() const {
	return !ssl_write_buf_.empty() ||
		(wbio_ssl_ && BIO_ctrl_pending(wbio_ssl_) > 0);
}

ssize_t MysqlxDataStream::read_from_net() {
	if (fd_ < 0) return -1;

	if (ssl_ && !ssl_handshake_done_) {
		uint8_t buf[65536];
		ssize_t r;
		do {
			r = recv(fd_, buf, sizeof(buf), 0);
		} while (r < 0 && errno == EINTR);
		if (r > 0) {
			BIO_write(rbio_ssl_, buf, static_cast<int>(r));
		}
		do_ssl_handshake();
		return r;
	}

	if (encrypted_ && ssl_) {
		uint8_t net_buf[65536];
		ssize_t r;
		do {
			r = recv(fd_, net_buf, sizeof(net_buf), 0);
		} while (r < 0 && errno == EINTR);
		if (r > 0) {
			BIO_write(rbio_ssl_, net_buf, static_cast<int>(r));
		} else {
			return r;
		}

		uint8_t plain_buf[65536];
		int decrypted = 0;
		while ((decrypted = SSL_read(ssl_, plain_buf, sizeof(plain_buf))) > 0) {
			feed_bytes(plain_buf, static_cast<size_t>(decrypted));
		}
		if (decrypted == 0) {
			// SSL_read returning 0 is a clean TLS shutdown (close_notify).
			// Surface it as a connection close, not as WANT_IO.
			return 0;
		}
		if (decrypted < 0) {
			mysqlx_ssl_status st = get_ssl_status(ssl_, decrypted);
			if (st == MYSQLX_SSL_WANT_IO) {
				queue_encrypted_output();
			} else if (st == MYSQLX_SSL_FAIL) {
				return -1;
			}
		}
		return r;
	}

	uint8_t buf[65536];
	ssize_t r;
	do {
		r = recv(fd_, buf, sizeof(buf), 0);
	} while (r < 0 && errno == EINTR);
	if (r > 0) {
		feed_bytes(buf, static_cast<size_t>(r));
	}
	return r;
}

ssize_t MysqlxDataStream::write_to_net() {
	if (fd_ < 0) return -1;

	if (ssl_ && !ssl_handshake_done_) {
		ssize_t r = flush_ssl_write_buf();
		if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return r;
		return 0;
	}

	if (encrypted_ && ssl_) {
		flush_ssl_write_buf();

		if (write_buf_.empty()) return 0;

		size_t available = write_buf_.size() - write_offset_;
		int n = SSL_write(ssl_, write_buf_.data() + write_offset_, static_cast<int>(available));
		if (n <= 0) {
			mysqlx_ssl_status st = get_ssl_status(ssl_, n);
			if (st == MYSQLX_SSL_FAIL) return -1;
			return 0;
		}
		write_offset_ += static_cast<size_t>(n);
		if (write_offset_ >= write_buf_.size()) {
			write_buf_.clear();
			write_offset_ = 0;
		}

		queue_encrypted_output();
		return flush_ssl_write_buf();
	}

	if (write_buf_.empty()) return 0;
	size_t available = write_buf_.size() - write_offset_;
	ssize_t r;
	do {
		r = send(fd_, write_buf_.data() + write_offset_, available, MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);
	if (r > 0) {
		write_offset_ += static_cast<size_t>(r);
		if (write_offset_ >= write_buf_.size()) {
			write_buf_.clear();
			write_offset_ = 0;
		}
	}
	return r;
}

ssize_t MysqlxDataStream::write_raw(const uint8_t* data, size_t len) {
	if (fd_ < 0) return -1;
	if (encrypted_ && ssl_) {
		int n = SSL_write(ssl_, data, static_cast<int>(len));
		if (n <= 0) return -1;
		queue_encrypted_output();
		return flush_ssl_write_buf();
	}
	return send(fd_, data, len, MSG_NOSIGNAL);
}

std::optional<MysqlxFrame> MysqlxDataStream::try_read_one_frame() {
	read_from_net();
	if (!has_complete_frame()) return std::nullopt;
	MysqlxFrame f = front_frame();
	pop_frame();
	return f;
}
