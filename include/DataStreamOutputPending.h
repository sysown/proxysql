#ifndef PROXYSQL_DATA_STREAM_OUTPUT_PENDING_H
#define PROXYSQL_DATA_STREAM_OUTPUT_PENDING_H

#include <openssl/bio.h>

/**
 * @brief Whether a MySQL or PostgreSQL data stream still has output to send to its peer.
 * @details Besides the plaintext queues checked by 'available_data_out()', counts a packet
 *   partially staged in 'queueOUT' and, for TLS streams, ciphertext already produced but not yet
 *   written to the socket: bytes kept in 'ssl_write_buf' after a short write, and bytes still in
 *   the write BIO. After a short write to a full socket the plaintext queues can be empty while the
 *   end of a response is still waiting as ciphertext.
 */
template<class Stream>
bool proxysql_stream_output_pending(Stream& stream) {
	return stream.available_data_out() || stream.queueOUT.partial ||
		(stream.encrypted && (stream.ssl_write_len ||
			(stream.wbio_ssl && BIO_ctrl_pending(stream.wbio_ssl))));
}

#endif // PROXYSQL_DATA_STREAM_OUTPUT_PENDING_H
