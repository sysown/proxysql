#ifndef TRAFFIC_OBSERVER_HPP
#define TRAFFIC_OBSERVER_HPP

#include <cstddef>

/**
 * @class TrafficObserver
 * @brief Interface for protocol-aware traffic observation in ProxySQL.
 *
 * This interface allows for passive observation of client and server data streams,
 * enabling metadata extraction (like query digests and execution stats) without
 * interfering with the data being forwarded.
 */
class TrafficObserver {
public:
    virtual ~TrafficObserver() = default;

    /**
     * @brief Called when data is received from the client.
     * @param buf Pointer to the raw protocol data buffer.
     * @param len Length of the data in the buffer.
     */
    virtual void on_client_data(const char* buf, std::size_t len) = 0;

    /**
     * @brief Called when data is received from the server.
     * @param buf Pointer to the raw protocol data buffer.
     * @param len Length of the data in the buffer.
     */
    virtual void on_server_data(const char* buf, std::size_t len) = 0;

    /**
     * @brief Called when the session is closing.
     * Ensures all pending metrics are finalized and resources are cleaned up.
     */
    virtual void on_close() = 0;

    /**
     * @brief Returns the total amount of data currently buffered by the observer.
     * @return Number of bytes currently in reassembly buffers.
     */
    virtual std::size_t get_buffered_size() const = 0;
};

#endif // TRAFFIC_OBSERVER_HPP
