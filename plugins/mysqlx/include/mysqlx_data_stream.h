#ifndef __MYSQLX_DATA_STREAM_H
#define __MYSQLX_DATA_STREAM_H

#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <vector>
#include <deque>
#include <optional>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

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

enum mysqlx_ssl_status {
	MYSQLX_SSL_OK = 0,
	MYSQLX_SSL_WANT_IO,
	MYSQLX_SSL_FAIL
};

class MysqlxDataStream {
public:
	MysqlxDataStream();
	~MysqlxDataStream();

	void init(mysqlx_ds_type type, int fd);
	// Tear down owned SSL/BIO state and clear buffers without close()ing fd.
	// Used when the underlying fd is owned by another object (e.g. the pooled
	// MysqlxConnection) and must remain valid after the data stream is reset.
	void close_and_reset();
	// Scrub I/O buffers (read_buf_, write_buf_, ssl_write_buf_, complete_frames_,
	// parse_error_) and reset frame-parser offsets without touching the fd, the
	// SSL*/BIO context, or the encrypted_ flag. Called by MysqlxConnection::reset()
	// between session reuses on a pooled backend connection so any straggler
	// frame the prior session left in flight (e.g. a NOTICE arriving after the
	// terminal frame, or a partial parse that did not complete) cannot be served
	// to the next session as if it were a response to its first query. Preserving
	// the SSL state is critical: rebuilding the SSL* would force a TLS handshake
	// on every pool checkout and discard ALPN/cipher negotiation already done.
	void clear_io_buffers();
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

	void init_ssl(SSL_CTX* ctx);
	bool do_ssl_handshake();
	bool ssl_init_done() const { return ssl_ != nullptr; }
	bool ssl_handshake_complete() const { return ssl_handshake_done_; }
	bool ssl_handshake_failed() const { return ssl_failed_; }
	bool has_ssl_pending_write() const;
	ssize_t flush_ssl_write_buf();

	void init_ssl_connect(SSL_CTX* ctx);
	SSL* get_ssl() const { return ssl_; }
	BIO* get_rbio_ssl() const { return rbio_ssl_; }

	int poll_fds_idx;

private:
	mysqlx_ssl_status get_ssl_status(SSL* ssl, int n);
	void queue_encrypted_output();

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

	SSL *ssl_;
	BIO *rbio_ssl_;
	BIO *wbio_ssl_;
	std::vector<uint8_t> ssl_write_buf_;
	size_t ssl_write_offset_;
	bool ssl_handshake_done_;
	bool ssl_failed_;

	bool try_parse_frame();
	static constexpr size_t X_FRAME_HEADER_SIZE = 5;
	static constexpr size_t X_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;
};

#endif
