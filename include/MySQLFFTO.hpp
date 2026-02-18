#ifndef MYSQL_FFTO_HPP
#define MYSQL_FFTO_HPP

#include "TrafficObserver.hpp"
#include <vector>
#include <string>

class MySQL_Session;

/**
 * @class MySQLFFTO
 * @brief MySQL-specific implementation of TrafficObserver.
 */
class MySQLFFTO : public TrafficObserver {
public:
    explicit MySQLFFTO(MySQL_Session* session);
    virtual ~MySQLFFTO();

    void on_client_data(const char* buf, size_t len) override;
    void on_server_data(const char* buf, size_t len) override;
    void on_close() override;

private:
    enum State {
        IDLE,
        AWAITING_RESULTSET,
        READING_RESULTSET,
        AWAITING_OK_ERR
    };

    MySQL_Session* m_session;
    State m_state;
    std::vector<char> m_client_buffer;
    std::vector<char> m_server_buffer;
    
    std::string m_current_query;
    unsigned long long m_query_start_time;

    void process_client_packet(const unsigned char* data, size_t len);
    void process_server_packet(const unsigned char* data, size_t len);
    void report_query_stats(const std::string& query, unsigned long long duration_us);
};

#endif // MYSQL_FFTO_HPP
