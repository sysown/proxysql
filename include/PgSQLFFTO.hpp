#ifndef PGSQL_FFTO_HPP
#define PGSQL_FFTO_HPP

#include "TrafficObserver.hpp"
#include <vector>
#include <string>

class PgSQL_Session;

/**
 * @class PgSQLFFTO
 * @brief PostgreSQL-specific implementation of TrafficObserver.
 */
class PgSQLFFTO : public TrafficObserver {
public:
    explicit PgSQLFFTO(PgSQL_Session* session);
    virtual ~PgSQLFFTO();

    void on_client_data(const char* buf, size_t len) override;
    void on_server_data(const char* buf, size_t len) override;
    void on_close() override;

private:
    enum State {
        IDLE,
        AWAITING_RESPONSE
    };

    PgSQL_Session* m_session;
    State m_state;
    std::vector<char> m_client_buffer;
    std::vector<char> m_server_buffer;

    std::string m_current_query;
    unsigned long long m_query_start_time;

    void process_client_message(char type, const unsigned char* payload, size_t len);
    void process_server_message(char type, const unsigned char* payload, size_t len);
    void report_query_stats(const std::string& query, unsigned long long duration_us);
};

#endif // PGSQL_FFTO_HPP
