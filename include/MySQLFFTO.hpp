#ifndef MYSQL_FFTO_HPP
#define MYSQL_FFTO_HPP

#include "TrafficObserver.hpp"
#include "MySQLResultsetFramer.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <stdint.h>

class MySQL_Session;

/**
 * @class MySQLFFTO
 * @brief Observer class for MySQL traffic when Fast-Forward mode is active.
 *
 * This class implements a state machine to track MySQL protocol interactions (text and binary)
 * to extract query metrics (affected_rows, rows_sent) and record them in ProxySQL's query digests.
 * It is used specifically in Fast-Forward mode where ProxySQL would otherwise bypass statistics gathering.
 */
class MySQLFFTO : public TrafficObserver {
public:
    /**
     * @brief Constructor for MySQLFFTO.
     * @param session The associated MySQL session.
     */
    explicit MySQLFFTO(MySQL_Session* session);

    /**
     * @brief Destructor for MySQLFFTO. Ensures cleanup and reports any pending query stats.
     */
    ~MySQLFFTO() override;

    /**
     * @brief Entry point for data received from the client.
     * @param buf Pointer to the raw data buffer.
     * @param len Length of the data in bytes.
     */
    void on_client_data(const char* buf, std::size_t len) override;

    /**
     * @brief Entry point for data received from the MySQL server.
     * @param buf Pointer to the raw data buffer.
     * @param len Length of the data in bytes.
     */
    void on_server_data(const char* buf, std::size_t len) override;

    /**
     * @brief Called when the session is closing. Ensures the final query's metrics are reported.
     */
    void on_close() override;

    /**
     * @brief Returns the total amount of data currently buffered by the observer.
     * @return Number of bytes currently in reassembly buffers.
     */
    std::size_t get_buffered_size() const override;

private:
    /**
     * @enum State
     * @brief Represents the internal state of the MySQL protocol parser.
     */
    enum State {
        IDLE,                 ///< No query is currently active.
        AWAITING_PREPARE_OK,  ///< A COM_STMT_PREPARE has been sent; waiting for the server's response.
        AWAITING_RESPONSE     ///< A query has been sent; framer owns resultset sub-states.
    };

    MySQL_Session* m_session; ///< Pointer to the session being observed.
    State m_state;            ///< Current state of the protocol parser.
    MySQLResultsetFramer m_rs; ///< Resultset framer for COM_QUERY / EXECUTE / FETCH responses.
    std::vector<char> m_client_buffer; ///< Temporary buffer for client-side packet reassembly.
    std::vector<char> m_server_buffer; ///< Temporary buffer for server-side packet reassembly.
    std::size_t m_client_offset {0};   ///< Current read offset in m_client_buffer.
    std::size_t m_server_offset {0};   ///< Current read offset in m_server_buffer.

    std::string m_current_query;          ///< The query currently being tracked.
    std::string m_pending_prepare_query;  ///< The SQL text of a pending prepare statement.
    unsigned long long m_query_start_time; ///< Start timestamp of the current query in microseconds.
    uint64_t m_affected_rows;             ///< Number of rows affected by the current DML query.
    uint64_t m_rows_sent;                 ///< Number of rows returned by the current SELECT query.
    uint64_t m_framer_rs_rows {0};        ///< In-progress framer row count (partial RS on close).

    /// Per-statement metadata captured from the COM_STMT_PREPARE_OK response.
    struct PreparedStatement {
        std::string query;
        uint64_t column_count { 0 };
    };
    std::unordered_map<uint32_t, PreparedStatement> m_statements;

    /**
     * @brief Processes individual MySQL packets from the client.
     * @param data Pointer to the packet payload.
     * @param len Length of the packet payload.
     */
    void process_client_packet(const unsigned char* data, size_t len);

    /**
     * @brief Processes individual MySQL packets from the server.
     * @param data Pointer to the packet payload.
     * @param len Length of the packet payload.
     */
    void process_server_packet(const unsigned char* data, size_t len);

    bool is_in_flight_query_state() const;
    void clear_active_query();
    bool client_deprecate_eof() const;
    void finalize_in_flight_best_effort();
    void begin_tracked_query(const std::string& query, bool binary_protocol);

    /**
     * @brief Computes and records query metrics into the ProxySQL query digests.
     * @param query The SQL query text.
     * @param duration_us Query execution duration in microseconds.
     * @param affected_rows Number of rows affected.
     * @param rows_sent Number of rows returned.
     */
    void report_query_stats(const std::string& query, unsigned long long duration_us, uint64_t affected_rows = 0, uint64_t rows_sent = 0);

    /**
     * @brief Records an error from a MySQL ERR packet into stats_mysql_errors.
     * @param data Pointer to the ERR packet payload (starting with 0xFF).
     * @param len Length of the payload.
     */
    void report_error(const unsigned char* data, size_t len);
};

#endif // MYSQL_FFTO_HPP
