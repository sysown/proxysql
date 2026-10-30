#ifndef PROXYSQL_ADMIN_RESPONSE_DRAIN_H
#define PROXYSQL_ADMIN_RESPONSE_DRAIN_H

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <openssl/bio.h>
#include <poll.h>

/** @brief Includes TLS ciphertext and partially staged packets in pending Admin output. */
template<class Stream>
bool proxysql_admin_response_pending(Stream& stream) {
	return stream.available_data_out() || stream.queueOUT.partial ||
		(stream.encrypted && (stream.ssl_write_len ||
			(stream.wbio_ssl && BIO_ctrl_pending(stream.wbio_ssl))));
}

/**
 * @brief Flushes an Admin reply before its command initiates client teardown.
 * @param stream Live MySQL or PostgreSQL Admin stream, owned by the caller.
 * @param timeout_ms Maximum wait for a slow reader; shutdown must remain bounded.
 * @return true if all output drained, false on disconnect, I/O failure, or timeout.
 */
template<class Stream>
bool proxysql_drain_admin_response(Stream& stream, unsigned int timeout_ms) {
	using clock = std::chrono::steady_clock;
	const auto deadline = clock::now() + std::chrono::milliseconds(timeout_ms);
	for (;;) {
		stream.array2buffer_full();
		if (!proxysql_admin_response_pending(stream)) return true;
		if (!stream.active || stream.net_failure || clock::now() >= deadline) return false;
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now()).count();
		pollfd socket { stream.fd, POLLOUT, 0 };
		const int ready = poll(&socket, 1, static_cast<int>(std::max<long long>(1, std::min<long long>(remaining, 50))));
		if (ready < 0) {
			if (errno == EINTR) continue;
			return false;
		}
		if (socket.revents & (POLLERR | POLLHUP | POLLNVAL)) return false;
		if (ready > 0 && (socket.revents & POLLOUT)) stream.write_to_net();
	}
}
#endif
