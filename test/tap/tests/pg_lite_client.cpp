// NOSONAR - TAP test files do not need to follow the same rules as production code
/* This is a minimal PostgreSQL client intended >>only for testing or experimentation<<
 * >> Do not use in production <<
 * This library provides basic functionality to connect to a PostgreSQL database and execute simple queries.
*/
#include "pg_lite_client.h"
#include <fcntl.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <variant>
#include <thread>
#include <chrono>

// Buffer writing helpers
static void writeInt32ToBuffer(std::vector<uint8_t>& buffer, int32_t value) {
    value = htonl(value);
    uint8_t bytes[4];
    memcpy(bytes, &value, sizeof(value));
    buffer.insert(buffer.end(), bytes, bytes + 4);
}

static void writeInt16ToBuffer(std::vector<uint8_t>& buffer, int16_t value) {
    value = htons(value);
    uint8_t bytes[2];
    memcpy(bytes, &value, sizeof(value));
    buffer.insert(buffer.end(), bytes, bytes + 2);
}

static void writeStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str) {
    buffer.insert(buffer.end(), str.begin(), str.end());
    buffer.push_back(0);  // Null terminator
}

// ===== Connection Implementation =====

// Message helpers
void PgConnection::writeBytes(const uint8_t* data, size_t count) {
    if (sock_ < 0) throw PgException("Not connected");
    
    ssize_t sent = 0;
    while (sent < static_cast<ssize_t>(count)) {
        ssize_t n = send(sock_, data + sent, count - sent, 0);
        if (n <= 0) throw PgException("Write failed");
        sent += n;
    }
}

void PgConnection::writeString(const std::string& str) {
    writeBytes(reinterpret_cast<const uint8_t*>(str.c_str()), str.size() + 1);
}

void PgConnection::writeInt32(int32_t value) {
    value = htonl(value);
    writeBytes(reinterpret_cast<const uint8_t*>(&value), 4);
}

void PgConnection::writeInt16(int16_t value) {
    value = htons(value);
    writeBytes(reinterpret_cast<const uint8_t*>(&value), 2);
}

std::vector<uint8_t> PgConnection::readBytes(size_t count) {
    std::vector<uint8_t> buffer(count);
    ssize_t received = 0;
    
    while (received < static_cast<ssize_t>(count)) {

        if (timeout_ms_ > 0) {
            // Wait for the socket to become readable
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock_, &readfds);

            struct timeval tv;
            tv.tv_sec = timeout_ms_ / 1000;
            tv.tv_usec = (timeout_ms_ % 1000) * 1000;

            int result = select(sock_ + 1, &readfds, nullptr, nullptr, &tv);
            if (result == 0) {
                throw PgException("Read timed out");
            } else if (result < 0) {
                throw PgException("select() failed while reading");
            }
        }

        ssize_t n = recv(sock_, buffer.data() + received, count - received, 0);
        if (n < 0) {
            throw PgException("Socket read failed");
        } else if (n == 0) {
            throw PgException("Connection closed by peer");
        }
        received += n;
    }
    return buffer;
}

std::string PgConnection::readString() {
    std::string str;
    char c;
    while (true) {

        if (timeout_ms_ > 0) {
            // Wait for the socket to become readable
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock_, &readfds);

            struct timeval tv;
            tv.tv_sec = timeout_ms_ / 1000;
            tv.tv_usec = (timeout_ms_ % 1000) * 1000;

            int result = select(sock_ + 1, &readfds, nullptr, nullptr, &tv);
            if (result == 0) {
                throw PgException("Read timed out");
            }
            else if (result < 0) {
                throw PgException("select() failed while reading");
            }
        }

        ssize_t n = recv(sock_, &c, 1, 0);
        if (n < 0) {
            throw PgException("Socket read failed while reading string");
        } else if (n == 0) {
            throw PgException("Connection closed by peer while reading string");
        }
        if (c == '\0') break;
        str += c;
    }
    return str;
}

int32_t PgConnection::readInt32() {
    auto data = readBytes(4);
    int32_t value;
    memcpy(&value, data.data(), 4);
    return ntohl(value);
}

int16_t PgConnection::readInt16() {
    auto data = readBytes(2);
    int16_t value;
    memcpy(&value, data.data(), 2);
    return ntohs(value);
}

void PgConnection::sendMessage(char type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> buffer;
    buffer.reserve(5 + data.size());
    
    // Message type
    buffer.push_back(type);
    
    // Message length (including self)
    int32_t len = data.size() + 4;
    len = htonl(len);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&len), 
                 reinterpret_cast<const uint8_t*>(&len) + 4);
    
    // Message body
    buffer.insert(buffer.end(), data.begin(), data.end());
    
    writeBytes(buffer.data(), buffer.size());
}

void PgConnection::readMessage(char& type, std::vector<uint8_t>& buffer) {
    type = readBytes(1)[0];
    int32_t len = readInt32() - 4;  // Exclude length itself
    if (len < 0) throw PgException("Invalid message length");
    buffer = readBytes(len);
}

// Connection management
PgConnection::PgConnection(int timeout_ms) {
	timeout_ms_ = timeout_ms;
}

PgConnection::~PgConnection() {
    disconnect();
}

void PgConnection::connect(const std::string& host, int port,
                          const std::string& dbname,
                          const std::string& user,
                          const std::string& password) {
    // Create socket
    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) {
        throw PgException("Socket creation failed");
    }
    
    // Connect to server
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock_);
        throw PgException("Invalid address: " + host);
    }
    
    if (::connect(sock_, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock_);
        sock_ = -1;
        throw PgException("Connection failed to " + host + ":" + std::to_string(port));
    }
    
    // Save credentials
    user_ = user;
    dbname_ = dbname;
    
    // SSL negotiation (not supported)
   /* writeInt32(8);  // Length
    writeInt32(80877103); // SSL request code
    char response = readBytes(1)[0];
    if (response != 'N') {
        close(sock_);
        sock_ = -1;
        throw PgException("SSL required but not implemented");
    }*/
    
    // Send startup packet
    sendStartupPacket();
    
    // Handle authentication
    handleAuthentication(password);
    
    // Wait for ready
    waitForReady();
}

void PgConnection::disconnect() {
   /* if (sock_ >= 0) {
        // Send termination
        writeBytes(reinterpret_cast<const uint8_t*>("X"), 1);
        writeInt32(4);  // Length only
        
        close(sock_);
        sock_ = -1;
    }*/
    if (sock_ >= 0) {
        // Set socket to non-blocking mode
        int flags = fcntl(sock_, F_GETFL, 0);
        if (flags != -1) {
            fcntl(sock_, F_SETFL, flags | O_NONBLOCK);
        }

        // Attempt to send termination message without blocking
        const uint8_t term[] = { 'X', 0, 0, 0, 4 };  // Termination message
        ssize_t sent = send(sock_, term, sizeof(term), MSG_NOSIGNAL);

        // Restore original socket flags
        if (flags != -1) {
            fcntl(sock_, F_SETFL, flags);
        }

        // Close socket regardless of send success
        close(sock_);
        sock_ = -1;
    }
}

bool PgConnection::isConnected() const {
    return sock_ >= 0;
}

// Startup sequence
void PgConnection::sendStartupPacket() {
    std::vector<uint8_t> packet;

    // Add protocol version
    writeInt32ToBuffer(packet, PROTOCOL_VERSION);

    // Add parameters
    writeStringToBuffer(packet, "user");
    writeStringToBuffer(packet, user_);
    writeStringToBuffer(packet, "database");
    writeStringToBuffer(packet, dbname_);

    // Final null terminator
    packet.push_back(0);

    // Prepend length (including the length field itself)
    int32_t len = packet.size() + 4;
    std::vector<uint8_t> fullPacket;
    writeInt32ToBuffer(fullPacket, len);
    fullPacket.insert(fullPacket.end(), packet.begin(), packet.end());

    writeBytes(fullPacket.data(), fullPacket.size());
}

void PgConnection::handleAuthentication(const std::string& password) {
    char type;
    std::vector<uint8_t> buffer;

    while (true) {
        readMessage(type, buffer);

        if (type == AUTH_TYPE) {
            if (buffer.size() < 4) throw PgException("Invalid authentication message");
            int32_t authType = ntohl(*reinterpret_cast<int32_t*>(buffer.data()));
            if (authType == 0) {  // AuthenticationOK
                return;
            }
            else if (authType == 3) {  // Cleartext password
                sendPassword(password);
                // After sending password, we need to wait for auth result
                readMessage(type, buffer);
                if (type == AUTH_TYPE) {
                    authType = ntohl(*reinterpret_cast<int32_t*>(buffer.data()));
                    if (authType == 0) return;
                }
            }
            else {
                throw PgException("Unsupported authentication method: " + std::to_string(authType));
            }
        }
        else if (type == ERROR_RESPONSE) {
            // Extract error message (field type 'M' is the message)
            const char* ptr = reinterpret_cast<const char*>(buffer.data());
            while (*ptr) ptr++;  // Skip severity
            ptr++;
            if (*ptr) {
                std::string errorMsg(ptr);
                throw PgException("Authentication error: " + errorMsg);
            }
            else {
                throw PgException("Authentication error");
            }
        }
    }
}

// Password message
void PgConnection::sendPassword(const std::string& password) {
    std::vector<uint8_t> packet;
    writeStringToBuffer(packet, password);
    sendMessage('p', packet);
}

void PgConnection::waitForReady() {
    char type;
    std::vector<uint8_t> buffer;
    
    while (true) {
        readMessage(type, buffer);
        if (type == READY_FOR_QUERY) {
            return;  // Ready to proceed
        } else if (type == ERROR_RESPONSE) {
            size_t pos = 0;
            while (pos < buffer.size() && buffer[pos] != 0) pos++;
            if (++pos < buffer.size()) {
                std::string errorMsg(reinterpret_cast<char*>(buffer.data() + pos));
                throw PgException("Startup error: " + errorMsg);
            } else {
                throw PgException("Startup error");
            }
        }
    }
}

// Query execution
void PgConnection::execute(const std::string& query) {
    sendQuery(query);
}

void PgConnection::executeParams(
    const std::string& stmtName,
    const std::string& query,
    const std::vector<Param>& params,
    const std::vector<int16_t>& resultFormats
) {
    // Extended query protocol
    //sendParse(query, stmtName);
    //waitForMessage(PARSE_COMPLETE, "parse", false);
    sendBind(params, stmtName, resultFormats);
    waitForMessage(BIND_COMPLETE, "bind", false);
    sendExecute("", 0); // Unnamed portal, all rows
    sendSync();
}

// Query message
void PgConnection::sendQuery(const std::string& query) {
    std::vector<uint8_t> packet;
    writeStringToBuffer(packet, query);
    sendMessage('Q', packet);
}

// Parse message
void PgConnection::sendParse(const std::string& query, const std::string& stmtName, const std::vector<uint32_t>& paramType) {
    std::vector<uint8_t> packet;
    writeStringToBuffer(packet, stmtName);
    writeStringToBuffer(packet, query);
    if (paramType.empty())
        writeInt16ToBuffer(packet, 0);  // No parameter types
    else {
        writeInt16ToBuffer(packet, paramType.size());
        for (uint32_t type : paramType) {
            writeInt32ToBuffer(packet, type);  // Write each parameter type
        }
	}
    sendMessage('P', packet);
}

// Describe Statement message
void PgConnection::sendDescribeStatement(const std::string& stmtName) {
    std::vector<uint8_t> packet;
    packet.push_back('S');  // 'S' for prepared statement
    writeStringToBuffer(packet, stmtName);
    sendMessage('D', packet);
}

void PgConnection::sendDescribePortal(const std::string& portalName) {
    std::vector<uint8_t> packet;
    packet.push_back('P');  // 'P' for portal
    writeStringToBuffer(packet, portalName);
	sendMessage('D', packet);
}

// Bind message
void PgConnection::sendBind(
    const std::vector<Param>& params,
    const std::string& stmtName,
    const std::vector<int16_t>& resultFormats
) {
    std::vector<uint8_t> packet;

    // Portal name (empty for unnamed)
    writeStringToBuffer(packet, "");
    // Statement name
    writeStringToBuffer(packet, stmtName);

    // Parameter formats
    writeInt16ToBuffer(packet, params.size());
    for (const auto& param : params) {
        writeInt16ToBuffer(packet, param.format);
    }

    // Parameters
    writeInt16ToBuffer(packet, params.size());
    for (const auto& param : params) {
        if (std::holds_alternative<std::monostate>(param.value)) {
            writeInt32ToBuffer(packet, -1); // NULL
        }
        else if (std::holds_alternative<std::string>(param.value)) {
            const std::string& s = std::get<std::string>(param.value);
            writeInt32ToBuffer(packet, s.size());
            packet.insert(packet.end(), s.begin(), s.end());
        }
        else if (std::holds_alternative<std::vector<uint8_t>>(param.value)) {
            const std::vector<uint8_t>& v = std::get<std::vector<uint8_t>>(param.value);
            writeInt32ToBuffer(packet, v.size());
            packet.insert(packet.end(), v.begin(), v.end());
        }
    }

    // Result formats
    writeInt16ToBuffer(packet, resultFormats.size());
    for (int16_t fmt : resultFormats) {
        writeInt16ToBuffer(packet, fmt);
    }

    sendMessage('B', packet);
}

void PgConnection::sendExecute(const std::string& portalName, int maxRows) {
    std::vector<uint8_t> packet;
    writeStringToBuffer(packet, portalName);  // Portal name
    writeInt32ToBuffer(packet, maxRows);      // Max rows
    sendMessage('E', packet);
}

void PgConnection::sendSync() {
    sendMessage('S', std::vector<uint8_t>());
}

void PgConnection::waitForMessage(char expectedType, const std::string& errorContext, bool wait_for_ready) {
    char type;
    std::vector<uint8_t> buffer;
    readMessage(type, buffer);

    if (type == expectedType) {
        if (wait_for_ready) {
            // After successful operation, read until READY_FOR_QUERY
            while (type != READY_FOR_QUERY) {
                readMessage(type, buffer);
            }
        }
        return;
    }

    if (type == ERROR_RESPONSE) {
        BufferReader reader(buffer);
        std::string errorMsg;
        char fieldType;

        while (reader.remaining() > 0 && (fieldType = reader.readByte()) != 0) {
            if (fieldType == 'M') {
                errorMsg = reader.readString();
            }
            else {
                reader.readString();
            }
        }
        throw PgException(errorContext + " error: " + errorMsg);
    }

    std::stringstream ss;
    ss << "Unexpected response during " << errorContext
        << ": expected '" << expectedType << "', received '" << type << "'";
    throw PgException(ss.str());
}

void PgConnection::consumeInputUntilReady() {
    char type;
    std::vector<uint8_t> buffer;
    bool got_ready = false;

    while (!got_ready) {
        readMessage(type, buffer);
        if (type == PgConnection::READY_FOR_QUERY) {
            got_ready = true;
        }
    }
}

// ===== Prepared Statement Interface =====
void PgConnection::prepareStatement(const std::string& stmtName, const std::string& query, bool send_sync, const std::vector<uint32_t>& paramType) {
    sendParse(query, stmtName, paramType);
    if (send_sync) {
        sendSync();
        waitForMessage(PARSE_COMPLETE, "prepare", send_sync);
    }
}

void PgConnection::describeStatement(const std::string& stmtName, bool send_sync) {
	sendDescribeStatement(stmtName);
    if (send_sync) {
        sendSync();
    }
}

void PgConnection::describePortal(const std::string& stmtName, bool send_sync) {
    sendDescribePortal(stmtName);
    if (send_sync) {
        sendSync();
    }
}

void PgConnection::bindStatement(
    const std::string& stmtName,
    const std::string& portalName,
    const std::vector<Param>& params,
    const std::vector<int16_t>& resultFormats,
    bool sync
) {
    std::vector<uint8_t> packet;  // Create a buffer for the packet

    // Portal name
    writeStringToBuffer(packet, portalName);
    // Statement name
    writeStringToBuffer(packet, stmtName);

    // Parameter formats
    bool any_binary_format = false;

    for (const auto& param : params) {
        if (param.format == 1) {
			any_binary_format = true;
			break;  // At least one binary format
       }
    }

    if (any_binary_format) {
        writeInt16ToBuffer(packet, params.size());
        for (const auto& param : params) {
            writeInt16ToBuffer(packet, param.format);
        }
    } else {
        writeInt16ToBuffer(packet, 0); // Default: all text
	}

  
    // Parameters
    writeInt16ToBuffer(packet, params.size());
    for (const auto& param : params) {
        if (std::holds_alternative<std::monostate>(param.value)) {
            writeInt32ToBuffer(packet, -1); // NULL
        }
        else if (std::holds_alternative<std::string>(param.value)) {
            const std::string& s = std::get<std::string>(param.value);
            writeInt32ToBuffer(packet, s.size());
            packet.insert(packet.end(), s.begin(), s.end());
        }
        else if (std::holds_alternative<std::vector<uint8_t>>(param.value)) {
            const std::vector<uint8_t>& v = std::get<std::vector<uint8_t>>(param.value);
            writeInt32ToBuffer(packet, v.size());
            packet.insert(packet.end(), v.begin(), v.end());
        } else if (std::holds_alternative<int32_t>(param.value)) {
            const int32_t& v = std::get<int32_t>(param.value);
            writeInt32ToBuffer(packet, sizeof(int32_t));
            packet.push_back((v >> 24) & 0xFF);
            packet.push_back((v >> 16) & 0xFF);
            packet.push_back((v >> 8) & 0xFF);
            packet.push_back(v & 0xFF);
        }
        
    }

    // Result formats
    if (resultFormats.empty()) {
        writeInt16ToBuffer(packet, 0); // Default: all text
    }
    else {
        writeInt16ToBuffer(packet, resultFormats.size());
        for (int16_t fmt : resultFormats) {
            writeInt16ToBuffer(packet, fmt);
        }
    }

    sendMessage('B', packet);
    if (sync) {
        sendSync();
		waitForMessage(BIND_COMPLETE, "bind", sync);
    }
}

void PgConnection::executePortal(
    const std::string& portalName,
    int maxRows,
	bool send_sync
) {
    sendExecute(portalName, maxRows);

    if (send_sync) {
        sendSync();
    }
}

void PgConnection::executeStatement(
    int maxRows,
    bool send_sync
) {
    executePortal("", maxRows, send_sync);
}

void PgConnection::sendClose(const std::string& name, char type, bool send_sync) {
    std::vector<uint8_t> packet;
    packet.push_back(type);  // 'S' for prepared statement
    writeStringToBuffer(packet, name);  
    sendMessage('C', packet);

    if (send_sync) {
        sendSync();
        waitForMessage(CLOSE_COMPLETE, "close_" + type, send_sync);
    }
}

void PgConnection::closePortal(const std::string& portalName, bool send_sync) {
    sendClose(portalName, 'P', send_sync);  // 'P' for Close portal
}

void PgConnection::closeStatement(const std::string& stmtName, bool send_sync) {
    sendClose(stmtName, 'S', send_sync);  // 'S' for Close statement
}

// Result parsing
std::shared_ptr<PgResult> PgConnection::readResult() {
    auto result = std::make_shared<PgResult>();
    char type;
    std::vector<uint8_t> buffer;
    bool resultSetStarted = false;

    while (true) {
        readMessage(type, buffer);
        BufferReader reader(buffer);

        switch (type) {
        case ROW_DESCRIPTION: {
            resultSetStarted = true;
            std::vector<std::string> columns;
            std::vector<int16_t> columnFormats;
            int16_t numCols = reader.readInt16();
            for (int i = 0; i < numCols; i++) {
                std::string colName = reader.readString();
                reader.readInt32();   // Table OID
                reader.readInt16();   // Column attr num
                reader.readInt32();   // Type OID
                reader.readInt16();   // Type size
                reader.readInt32();   // Type modifier
                int16_t format = reader.readInt16();
                columnFormats.push_back(format);
                columns.push_back(colName);
            }
            result->setColumns(columns);
            result->setColumnFormats(columnFormats);
            break;
        }

        case DATA_ROW: {
            if (!resultSetStarted) throw PgException("Data row without description");
            std::vector<PgResult::Value> row;
            int16_t numCols = reader.readInt16();
            for (int i = 0; i < numCols; i++) {
                int32_t len = reader.readInt32();
                if (len == -1) {
                    row.emplace_back(std::monostate{});
                }
                else {
                    auto data = reader.readBytes(len);
                    if (i >= result->columnCount()) {
                        throw PgException("Column index out of range in data row");
                    }
                    int16_t colFormat = result->columnFormat(i);
                    if (colFormat == 0) {
                        // Text format
                        row.emplace_back(std::string(data.begin(), data.end()));
                    }
                    else if (colFormat == 1) {
                        // Binary format
                        row.emplace_back(data);
                    }
                    else {
                        throw PgException("Unknown column format: " + std::to_string(colFormat));
                    }
                }
            }
            result->addRow(row);
            break;
        }

        case COMMAND_COMPLETE: {
            // Command finished (OK)
            break;
        }

        case READY_FOR_QUERY: {
            // End of query cycle
            return result;
        }

        case PARSE_COMPLETE: {
            // Prepared statement parsed successfully
            break;
        }

        case BIND_COMPLETE: {
            // Parameters bound successfully
            break;
        }

        case CLOSE_COMPLETE: {
            // Statement or portal closed
            break;
        }

        case NO_DATA: {
            // Statement returns no data
            break;
        }

        case EMPTY_QUERY_RESPONSE: {
            // Empty query was submitted
           break;
        }

        case PORTAL_SUSPENDED: {
            // Portal suspended (partial results)
            break;
        }

        case PARAMETER_STATUS: {
            // Server parameter change notification
            std::string name = reader.readString();
            std::string value = reader.readString();
            break;
        }

        case NOTICE_RESPONSE: {
            // Server notice message
            std::string message;
            char field;
            while ((field = reader.readByte()) != 0) {
                if (field == 'M') message = reader.readString();
                else reader.readString();  // Skip other fields
            }
            break;
        }

        case ERROR_RESPONSE: {
            std::string errorMsg;
            char field;
            while ((field = reader.readByte()) != 0) {
                if (field == 'M') errorMsg = reader.readString();
                else reader.readString();  // Skip other fields
            }
            throw PgException("Query error: " + errorMsg);
        }

        default: {
            std::stringstream ss;
            ss << "Unexpected message type: " << type;
            throw PgException(ss.str());
        }
        }
    }
}


// ===== PgResult Implementation =====
void PgResult::addRow(const std::vector<Value>& row) {
    rows_.push_back(row);
}

void PgResult::setColumns(const std::vector<std::string>& cols) {
    columns_ = cols;
}

void PgResult::setColumnFormats(const std::vector<int16_t>& fmts) {
    columnFormats_ = fmts;
}

int PgResult::rowCount() const {
    return rows_.size();
}

int PgResult::columnCount() const {
    return columns_.size();
}

PgResult::Value PgResult::getValue(int row, int col) const {
    if (row < 0 || row >= rowCount() || col < 0 || col >= columnCount()) {
        throw PgException("Result index out of range");
    }
    return rows_[row][col];
}

std::string PgResult::columnName(int col) const {
    if (col < 0 || col >= columnCount()) {
        throw PgException("Column index out of range");
    }
    return columns_[col];
}

int16_t PgResult::columnFormat(int col) const {
    if (col < 0 || col >= columnCount()) {
        throw PgException("Column index out of range");
    }
    return columnFormats_[col];
}

bool PgResult::isNull(int row, int col) const {
    return std::holds_alternative<std::monostate>(getValue(row, col));
}

#if 0
#include <iostream>
#include <thread>
#include <libpq-fe.h>

void exit_on_error(PGconn* conn, PGresult* res) {
    fprintf(stderr, "Error: %s\n", PQerrorMessage(conn));
    if (res) PQclear(res);
    PQfinish(conn);
    exit(1);
}

bool test_descibe() {
    PGconn* conn = PQconnectdb("host=localhost dbname=postgres user=postgres password=postgres sslmode='disable'");

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    PGresult* res;
    // 1. CREATE TABLE IF NOT EXISTS
    const char* createSQL =
        "CREATE TABLE IF NOT EXISTS test_users ("
        "id SERIAL PRIMARY KEY, "
        "name TEXT NOT NULL, "
        "age INT NOT NULL);";

    res = PQexec(conn, createSQL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "CREATE TABLE failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    PQclear(res);

    // 2. INSERT SAMPLE DATA
    const char* insertSQL =
        "INSERT INTO test_users (name, age) VALUES "
        "('Alice', 30), ('Bob', 22), ('Carol', 35) "
        "ON CONFLICT DO NOTHING;";  // For idempotency

    res = PQexec(conn, insertSQL);
    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "CREATE TABLE failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    PQclear(res);

    // Prepare a statement with a parameter
    Oid types[1] = { 20 };
    res = PQprepare(conn, "my_stmt", "INSERT INTO test_users (name, age) VALUES ('Alice1', $1)", 0, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Prepare failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    PQclear(res);

    res = PQdescribePrepared(conn, "my_stmt");

    if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Describe failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    // Bind value to the prepared statement and create a portal
    const char* paramValues[1] = { "25" };
    res = PQexecPrepared(conn, "my_stmt", 1, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Execution failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    // Describe the result (RowDescription is part of the PGresult)
    int nfields = PQnfields(res);
    printf("Query returns %d columns:\n", nfields);
    for (int i = 0; i < nfields; i++) {
        printf("  Column %d: %s (%s)\n", i + 1, PQfname(res, i), PQftype(res, i) == 23 ? "integer" :
            PQftype(res, i) == 25 ? "text" : "other");
    }

    PQclear(res);
    PQfinish(conn);
    return 0;
}

bool test_parse_diff_types() {
    PGconn* conn = PQconnectdb("host=localhost port=5432 dbname=postgres user=postgres password=postgres");
    if (PQstatus(conn) != CONNECTION_OK)
        exit_on_error(conn, NULL);

    // Drop and create table
    PGresult* res = PQexec(conn, "DROP TABLE IF EXISTS test_table");
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);

    res = PQexec(conn, "CREATE TABLE test_table (val TEXT)");
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);

    // Prepare the statement
    Oid types[1] = { 23 };
    res = PQprepare(conn, "insert_stmt", "INSERT INTO test_table(val) VALUES ($1)", 1, types);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);
    
    Oid types[1] = {23};
	res = PQprepare(conn, "insert_stmt", "SELECT val FROM test_table WHERE 1=1 OR val = $1", 1, types);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Prepare failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    PQclear(res);
    
    fprintf(stderr, ">>>> here");
    */
    // Insert integer
    const char* param1 = "12345678901";
    res = PQexecPrepared(conn, "insert_stmt", 1, &param1, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);
    /*
    // Describe the prepared statement (retrieve metadata)
    res = PQdescribePrepared(conn, "insert_stmt");

    if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Describe failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    // Print metadata
    int nfields = PQnfields(res);
    printf("Prepared statement returns %d column(s):\n", nfields);
    for (int i = 0; i < nfields; i++) {
        printf("  Column %d: name=%s, type_oid=%u\n",
            i + 1,
            PQfname(res, i),
            PQftype(res, i));
    }
    PQclear(res);
    */

    // Insert float
    const char* param2 = "45.67";
    res = PQexecPrepared(conn, "insert_stmt", 1, &param2, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);

    // Insert text
    const char* param3 = "hello world";
    res = PQexecPrepared(conn, "insert_stmt", 1, &param3, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        exit_on_error(conn, res);
    PQclear(res);

    // Query to verify
    res = PQexec(conn, "SELECT val FROM test_table");
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
        exit_on_error(conn, res);

    printf("Inserted rows:\n");
    int rows = PQntuples(res);
    for (int i = 0; i < rows; ++i)
        printf("Row %d: %s\n", i + 1, PQgetvalue(res, i, 0));

    PQclear(res);
    PQfinish(conn);
    return 0;
}

bool test_parse(PgConnection* conn) {
	try {
		// Prepare a statement
		const std::string stmtName = "user_query";
		conn->prepareStatement(stmtName,
			"SELECT id, name, age FROM test_prepare_statement_users WHERE country = $1 AND age > $2",
			true);
		// Bind to different portals with different parameters
		const std::string portalUSA = "us_portal";
		std::vector<PgConnection::Param> usParams = {
			{"USA", 0},     // Text format
			{"25", 0}       // Text format (string)
		};
		conn->bindStatement(stmtName, portalUSA, usParams, {}, true);
		// Execute the prepared statement
		auto results = conn->executePortal(portalUSA);
		std::cout << "Results (" << results->rowCount() << " rows):\n";
		for (int i = 0; i < results->rowCount(); i++) {
			std::cout << " - ID: " << std::get<std::string>(results->getValue(i, 0))
				<< ", Name: " << std::get<std::string>(results->getValue(i, 1))
				<< ", Age: " << std::get<std::string>(results->getValue(i, 2))
				<< "\n";
		}
		// Clean up
		conn->closePortal(portalUSA);
		conn->closeStatement(stmtName);
	}
	catch (const PgException& e) {
		std::cerr << "Error: " << e.what() << "\n";
		return false;
	}
	return true;
}

int main() {

    try {
		test_descibe();
		return 0;

		test_parse_diff_types();
        return 0;

        PgConnection conn;
        conn.connect("127.0.0.1", 6133, "postgres", "postgres", "postgres");

        conn.execute("DROP TABLE IF EXISTS test_prepare_statement_users");
        conn.execute("CREATE TABLE IF NOT EXISTS test_prepare_statement_users ("
            "id SERIAL PRIMARY KEY, "
            "name TEXT NOT NULL, "
            "age INT NOT NULL, "
            "country TEXT NOT NULL)");

        // Insert some test data
        conn.execute("INSERT INTO test_prepare_statement_users (name, age, country) VALUES "
            "('Alice', 30, 'USA'), "
            "('Bob', 35, 'USA'), "
            "('Charlie', 35, 'Canada'), "
            "('David', 28, 'Canada'), "
            "('Eve', 22, 'USA'), "
            "('Frank', 40, 'Canada')");

		test_parse(&conn);
		return 0;

        char* conninfo = (char*)"host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres sslmode=disable";
        PGconn* conn1 = PQconnectdb(conninfo);

        if (PQstatus(conn1) != CONNECTION_OK) {
            fprintf(stderr, "Connection failed: %s\n", PQerrorMessage(conn1));
            PQfinish(conn1);
            exit(1);
        }
        // Prepare the statement
        const char* query = "SELECT id, name, age FROM users WHERE age > $1";
        const char* statement_name = "my_prepared_statement";

        const unsigned int paramTypes[1] = { 23 };

        PGresult* prepare_result = PQprepare(conn1, statement_name, query, 1, paramTypes);

        if (PQresultStatus(prepare_result) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Prepare failed: %s\n", PQresultErrorMessage(prepare_result));
            PQclear(prepare_result);
            PQfinish(conn1);
            exit(1);
        }

        // Execute the prepared statement
      /*  const char* params[2] = {
            { "USA" },     // Text format
            { "25" }
	    }; // Text format (string)
        PGresult* exec_result = PQexecPrepared(conn1, statement_name, 2, params, NULL, NULL, 0);

        if (PQresultStatus(exec_result) != PGRES_TUPLES_OK) {
            fprintf(stderr, "Execution failed: %s\n", PQresultErrorMessage(exec_result));
            PQclear(exec_result);
            PQclear(prepare_result);
            PQfinish(conn1);
            exit(1);
        }
        */
        // 1. Prepare a statement
        const std::string stmtName = "user_query";
        conn.prepareStatement(stmtName,
            "SELECT id, name, age FROM users123 WHERE country = $1 AND age > $2",
            true);

        // 2. Bind to different portals with different parameters
        const std::string portalUSA = "us_portal";
        std::vector<PgConnection::Param> usParams = {
            {"USA", 0},     // Text format
            {"25", 0}       // Text format (string)
        };
        conn.bindStatement(stmtName, portalUSA, usParams, {}, true);

      /*  const std::string portalCanada = "ca_portal";
        std::vector<PgConnection::Param> caParams = {
            {"Canada", 0}, // Text format
            {"30", 0}        // Text format
        };
        conn.bindStatement(stmtName, portalCanada, caParams, {}, false);
        */
        // 3. Execute portals at different times
        std::cout << "Executing US portal after 2 seconds...\n";
       // std::this_thread::sleep_for(std::chrono::seconds(2));

        // Execute first portal
        auto usResults = conn.executePortal(portalUSA);
        std::cout << "US Results (" << usResults->rowCount() << " rows):\n";
        for (int i = 0; i < usResults->rowCount(); i++) {
            std::cout << " - ID: " << std::get<std::string>(usResults->getValue(i, 0))
                << ", Name: " << std::get<std::string>(usResults->getValue(i, 1))
                << ", Age: " << std::get<std::string>(usResults->getValue(i, 2))
                << "\n";
        }

    /* std::cout << "\nExecuting Canada portal after 3 seconds...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));

       // Execute second portal
        auto caResults = conn.executePortal(portalCanada);
        std::cout << "Canada Results (" << caResults->rowCount() << " rows):\n";
        for (int i = 0; i < caResults->rowCount(); i++) {
            std::cout << " - ID: " << std::get<std::string>(caResults->getValue(i, 0))
                << ", Name: " << std::get<std::string>(caResults->getValue(i, 1))
                << ", Age: " << std::get<std::string>(caResults->getValue(i, 2))
                << "\n";
        }*/
        

        // 4. Clean up
        conn.closePortal(portalUSA);
        //conn.closePortal(portalCanada);
        conn.closeStatement(stmtName);

        conn.disconnect();
    }
    catch (const PgException& e) {
        std::cerr << "PostgreSQL error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
#endif
