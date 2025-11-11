#ifndef PG_LITE_CLIENT_HPP
#define PG_LITE_CLIENT_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <memory>
#include <variant>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <functional>

class PgException : public std::runtime_error {
public:
    explicit PgException(const std::string& msg) 
        : std::runtime_error(msg) {}
};

class PgResult {
public:
    using Value = std::variant<std::monostate, std::string, std::vector<uint8_t>>;
    
    PgResult() = default;
    
    void addRow(const std::vector<Value>& row);
    void setColumns(const std::vector<std::string>& cols);
    void setColumnFormats(const std::vector<int16_t>& fmts);
    
    int rowCount() const;
    int columnCount() const;
    Value getValue(int row, int col) const;
    std::string columnName(int col) const;
    int16_t columnFormat(int col) const;
    bool isNull(int row, int col) const;

private:
    std::vector<std::string> columns_;
    std::vector<int16_t> columnFormats_;
    std::vector<std::vector<Value>> rows_;
};

class BufferReader {
public:
    BufferReader(const uint8_t* data, size_t size)
        : data_(data), size_(size), pos_(0) {
    }

    BufferReader(const std::vector<uint8_t>& buffer)
        : data_(buffer.data()), size_(buffer.size()), pos_(0) {
    }

    uint8_t readByte() {
        if (pos_ >= size_) throw PgException("Buffer underrun");
        return data_[pos_++];
    }

    int16_t readInt16() {
        if (pos_ + 2 > size_) throw PgException("Buffer underrun");
        int16_t value;
        memcpy(&value, data_ + pos_, 2);
        pos_ += 2;
        return ntohs(value);
    }

    int32_t readInt32() {
        if (pos_ + 4 > size_) throw PgException("Buffer underrun");
        int32_t value;
        memcpy(&value, data_ + pos_, 4);
        pos_ += 4;
        return ntohl(value);
    }

    std::string readString() {
        const char* start = reinterpret_cast<const char*>(data_ + pos_);
        size_t len = 0;
        while (pos_ + len < size_ && data_[pos_ + len] != '\0') {
            len++;
        }
        if (pos_ + len >= size_) throw PgException("String missing null terminator");
        std::string str(start, len);
        pos_ += len + 1; // skip null terminator
        return str;
    }

    std::vector<uint8_t> readBytes(size_t count) {
        if (pos_ + count > size_) throw PgException("Buffer underrun");
        std::vector<uint8_t> bytes(data_ + pos_, data_ + pos_ + count);
        pos_ += count;
        return bytes;
    }

    size_t remaining() const { return size_ - pos_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_;
};


class PgConnection {
public:
    // Protocol constants
    static const int PROTOCOL_VERSION = 196608; // 3.0
    static const char SSL_REQUEST = 'N';
    static const char AUTH_TYPE = 'R';
    static const char PARAMETER_STATUS = 'S';
    static const char READY_FOR_QUERY = 'Z';
    static const char ROW_DESCRIPTION = 'T';
    static const char PARAMETER_DESCRIPTION = 't';
    static const char DATA_ROW = 'D';
    static const char COMMAND_COMPLETE = 'C';
    static const char PARSE_COMPLETE = '1';
    static const char BIND_COMPLETE = '2';
    static const char NO_DATA = 'n';
    static const char ERROR_RESPONSE = 'E';
    static const char CLOSE_COMPLETE = '3';
    static const char EMPTY_QUERY_RESPONSE = 'I';
    static const char PORTAL_SUSPENDED = 's';
    static const char NOTICE_RESPONSE = 'N';

    struct Param {
        std::variant<std::monostate, int32_t, std::string, std::vector<uint8_t>> value;
        int16_t format; // 0 = text, 1 = binary
    };
    
    PgConnection(int timeout_ms = 0);
    ~PgConnection();
    
    void connect(
        const std::string& host, 
        int port,
        const std::string& dbname,
        const std::string& user,
        const std::string& password
    );
    
    void disconnect();
    bool isConnected() const;
    inline int getSocket() const { return sock_; }

    void execute(const std::string& query);
    void executeParams(
        const std::string& stmtName,
        const std::string& query,
        const std::vector<Param>& params,
        const std::vector<int16_t>& resultFormats = {}
    );
    
    // Prepared statement interface
    void prepareStatement(const std::string& stmtName, const std::string& query, bool send_sync,const std::vector<uint32_t>& paramType = {});
    void describeStatement(const std::string& stmtName, bool send_sync);
    void describePortal(const std::string& stmtName, bool send_sync);
    void bindStatement(
        const std::string& stmtName,
        const std::string& portalName,
        const std::vector<Param>& params,
        const std::vector<int16_t>& resultFormats = {},
		bool sync = false
    );
    void executePortal(
        const std::string& portalName,
        int maxRows = 0,  // 0 = all rows
		bool send_sync = true
    );
    void executeStatement(
        int maxRows = 0,
        bool send_sync = true
    );
    void closePortal(const std::string& portalName, bool send_sync);
    void closeStatement(const std::string& stmtName, bool send_sync);
    void sendSync();
    void waitForMessage(char expectedType, const std::string& errorContext, bool wait_for_ready);
    void consumeInputUntilReady();
    void readMessage(char& type, std::vector<uint8_t>& buffer);
    void sendMessage(char type, const std::vector<uint8_t>& data);
    void sendQuery(const std::string& query);
    void waitForReady();
	std::shared_ptr<PgResult> readResult(); // NOT TESTED YET

private:
    int sock_ = -1;
	int timeout_ms_ = 0;
    std::string user_;
    std::string dbname_;
    
    void sendStartupPacket();
    void handleAuthentication(const std::string& password);
    void sendPassword(const std::string& password);
    
    
    void sendParse(const std::string& query, const std::string& stmtName, const std::vector<uint32_t>& paramType);
    void sendDescribeStatement(const std::string& stmtName);
    void sendDescribePortal(const std::string& portalName);
    void sendBind(
        const std::vector<Param>& params,
        const std::string& stmtName,
        const std::vector<int16_t>& resultFormats
    );
    void sendExecute(const std::string& portalName, int maxRows);
    
    void sendClose(const std::string& name, char type, bool send_sync);
    
    std::vector<uint8_t> readBytes(size_t count);
    void writeBytes(const uint8_t* data, size_t count);
    
    std::string readString();
    void writeString(const std::string& str);
    
    int32_t readInt32();
    void writeInt32(int32_t value);
    int16_t readInt16();
    void writeInt16(int16_t value);
};

#endif // PG_CLIENT_HPP