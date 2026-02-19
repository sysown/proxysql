#ifndef PGSQL_FFTO_HPP
#define PGSQL_FFTO_HPP

#include "TrafficObserver.hpp"
#include <vector>
#include <string>
#include <unordered_map>

class PgSQL_Session;

/**
 * @class PgSQLFFTO
 * @brief Observer class for PostgreSQL traffic in Fast-Forward mode.
 *
 * Implements a PostgreSQL protocol observer to track query metrics (affected_rows, rows_sent)
 * during Fast-Forward mode. It handles Simple Query and Extended Query protocols (Parse, Bind, Execute)
 * to ensure query statistics remain accurate even when full session processing is bypassed.
 */
class PgSQLFFTO : public TrafficObserver {
public:
    /**
     * @brief Constructor for PgSQLFFTO.
     * @param session The associated PostgreSQL session.
     */
    explicit PgSQLFFTO(PgSQL_Session* session);

    /**
     * @brief Destructor for PgSQLFFTO. Ensures cleanup and metrics reporting.
     */
    ~PgSQLFFTO() override;

    /**
     * @brief Entry point for data received from the PostgreSQL client.
     * @param buf Pointer to the raw data buffer.
     * @param len Length of the data in bytes.
     */
    void on_client_data(const char* buf, std::size_t len) override;

    /**
     * @brief Entry point for data received from the PostgreSQL server.
     * @param buf Pointer to the raw data buffer.
     * @param len Length of the data in bytes.
     */
    void on_server_data(const char* buf, std::size_t len) override;

    /**
     * @brief Called when the PostgreSQL session is closing. Ensures final stats are reported.
     */
    void on_close() override;

private:
    /**
     * @enum State
     * @brief Represents the internal state of the PostgreSQL protocol observer.
     */
    enum State {
        IDLE,                 ///< No query is currently active.
        AWAITING_RESPONSE     ///< A query has been sent; waiting for the server's CommandComplete or ReadyForQuery.
    };

    PgSQL_Session* m_session; ///< Pointer to the session being observed.
    State m_state;            ///< Current state of the protocol observer.
    std::vector<char> m_client_buffer; ///< Temporary buffer for client message reassembly.
    std::vector<char> m_server_buffer; ///< Temporary buffer for server message reassembly.
    std::size_t m_client_offset {0};   ///< Current read offset in m_client_buffer.
    std::size_t m_server_offset {0};   ///< Current read offset in m_server_buffer.

    std::string m_current_query;           ///< The SQL query currently being tracked.
    unsigned long long m_query_start_time;  ///< Start timestamp of the current query in microseconds.
    uint64_t m_affected_rows {0};          ///< Accumulated affected rows for the current query.
    uint64_t m_rows_sent {0};              ///< Accumulated rows sent for the current query.

    // Binary Protocol Tracking (PostgreSQL Extended Query)
    std::unordered_map<std::string, std::string> m_statements; ///< Map of statement names to original SQL text.
    std::unordered_map<std::string, std::string> m_portals;   ///< Map of portal names to statement names.

    /**
     * @brief Processes individual PostgreSQL protocol messages from the client.
     * @param type Message type character (e.g., 'Q', 'P', 'B', 'E').
     * @param payload Pointer to the message payload.
     * @param len Length of the message payload.
     */
    void process_client_message(char type, const unsigned char* payload, size_t len);

    /**
     * @brief Processes individual PostgreSQL protocol messages from the server.
     * @param type Message type character (e.g., 'C', 'Z', 'E').
     * @param payload Pointer to the message payload.
     * @param len Length of the message payload.
     */
    void process_server_message(char type, const unsigned char* payload, size_t len);

    /**
     * @brief Computes and records query metrics into the ProxySQL query digests.
     * @param query The SQL query text.
     * @param duration_us Query execution duration in microseconds.
     * @param affected_rows Number of rows affected.
     * @param rows_sent Number of rows returned.
     */
    void report_query_stats(const std::string& query, unsigned long long duration_us, uint64_t affected_rows = 0, uint64_t rows_sent = 0);
};

#endif // PGSQL_FFTO_HPP
