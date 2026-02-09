#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include "json.hpp" // Requires nlohmann/json.hpp

using json = nlohmann::json;


// this is copied from proxysql_structs.h
enum log_event_type {
	PROXYSQL_COM_QUERY,
	PROXYSQL_MYSQL_AUTH_OK,
	PROXYSQL_MYSQL_AUTH_ERR,
	PROXYSQL_MYSQL_AUTH_CLOSE,
	PROXYSQL_MYSQL_AUTH_QUIT,
	PROXYSQL_MYSQL_CHANGE_USER_OK,
	PROXYSQL_MYSQL_CHANGE_USER_ERR,
	PROXYSQL_MYSQL_INITDB,
	PROXYSQL_ADMIN_AUTH_OK,
	PROXYSQL_ADMIN_AUTH_ERR,
	PROXYSQL_ADMIN_AUTH_CLOSE,
	PROXYSQL_ADMIN_AUTH_QUIT,
	PROXYSQL_SQLITE_AUTH_OK,
	PROXYSQL_SQLITE_AUTH_ERR,
	PROXYSQL_SQLITE_AUTH_CLOSE,
	PROXYSQL_SQLITE_AUTH_QUIT,
	PROXYSQL_COM_STMT_EXECUTE,
	PROXYSQL_COM_STMT_PREPARE,
	PROXYSQL_METADATA
};


// Decodes a MySQL length-encoded integer from the stream.
// Returns true if decoding was successful.
bool decodeInt(std::istream &in, uint64_t &val) {
	unsigned char first;
	if (!in.read(reinterpret_cast<char*>(&first), 1))
		return false;
	if (first < 251) {
		val = first;
		return true;
	} else if (first == 0xfc) {
		uint16_t tmp;
		if (!in.read(reinterpret_cast<char*>(&tmp), sizeof(tmp)))
			return false;
		val = tmp;
		return true;
	} else if (first == 0xfd) {
		uint32_t tmp = 0;
		char buf[3] = {0};
		if (!in.read(buf, 3))
			return false;
		tmp = (unsigned char)buf[0] | 
			  ((unsigned char)buf[1] << 8) | 
			  ((unsigned char)buf[2] << 16);
		val = tmp;
		return true;
	} else if (first == 0xfe) {
		uint64_t tmp;
		if (!in.read(reinterpret_cast<char*>(&tmp), sizeof(tmp)))
			return false;
		val = tmp;
		return true;
	}
	return false;
}

// Reads a fixed-size value from the stream.
template <typename T>
bool readValue(std::istream &in, T &value) {
	in.read(reinterpret_cast<char*>(&value), sizeof(T));
	return in.good();
}

// Reads raw bytes into a string.
std::string readString(std::istream &in, uint64_t length) {
	std::vector<char> buf(length);
	if (!in.read(buf.data(), length))
		return "";
	return std::string(buf.begin(), buf.end());
}

json parseEvent(std::istream &in, bool verbose = true) {

	json j;
	// Read total_bytes (first 8 bytes)
	uint64_t total_bytes = 0;
	if (!readValue(in, total_bytes))
		throw std::runtime_error("Cannot read total_bytes");
	// j["total_bytes"] = total_bytes; // optional
	if (verbose == true) {
		std::cout << "total_bytes: " << total_bytes << std::endl;
	}

	// Read event type (1 byte)
	char etb;
	enum log_event_type et;
	std::string et_name = "";

	if (!readValue(in, etb))
		throw std::runtime_error("Cannot read event type");
	et = static_cast<log_event_type>(etb);
		switch (et) {
		case PROXYSQL_COM_STMT_EXECUTE:
			et_name="COM_STMT_EXECUTE";
			break;
		case PROXYSQL_COM_STMT_PREPARE:
			et_name="COM_STMT_PREPARE";
			break;
		case PROXYSQL_METADATA:
			et_name="METADATA";
			break;
		default:
			et_name="COM_QUERY";
			break;
	}

	j["event_type"] = et_name;
	if (verbose == true) {
		std::cout << "event_type: " << static_cast<int>(et) << std::endl;
	}

	// Read thread_id
	uint64_t thread_id = 0;
	if (!decodeInt(in, thread_id))
		throw std::runtime_error("Error decoding thread_id");
	if (et != PROXYSQL_METADATA) {
		j["thread_id"] = thread_id;
		if (verbose == true) {
			std::cout << "thread_id: " << thread_id << std::endl;
		}
	}

	// Username: first read its length then the raw string.
	uint64_t username_len = 0;
	if (!decodeInt(in, username_len))
		throw std::runtime_error("Error decoding username length");
	std::string username = readString(in, username_len);
	if (et != PROXYSQL_METADATA) {
		j["username"] = username;
		if (verbose == true) {
			std::cout << "username: " << username << std::endl;
		}
	} else {
		json metadata = json::parse(username);
		j["metadata"] = metadata;
	}

	// Schemaname
	uint64_t schemaname_len = 0;
	if (!decodeInt(in, schemaname_len))
		throw std::runtime_error("Error decoding schemaname length");
	std::string schemaname = readString(in, schemaname_len);
	if (et != PROXYSQL_METADATA) {
		j["schemaname"] = schemaname;
		if (verbose == true) {
			std::cout << "schemaname: " << schemaname << std::endl;
		}
	}
	// Client string
	uint64_t client_len = 0;
	if (!decodeInt(in, client_len))
		throw std::runtime_error("Error decoding client length");
	std::string client = readString(in, client_len);
	if (et != PROXYSQL_METADATA) {
		j["client"] = client;
		if (verbose == true) {
			std::cout << "client: " << client << std::endl;
		}
	}
	// Host id (hid)
	uint64_t hid = 0;
	if (!decodeInt(in, hid))
		throw std::runtime_error("Error decoding hid");
	if (et != PROXYSQL_METADATA) {
		j["hid"] = hid;
		if (verbose == true) {
			std::cout << "hid: " << hid << std::endl;
		}
	}
	// If hid != UINT64_MAX then read server string.
	if (hid != UINT64_MAX) {
		uint64_t server_len = 0;
		if (!decodeInt(in, server_len))
			throw std::runtime_error("Error decoding server length");
		std::string server = readString(in, server_len);
		j["server"] = server;
		if (verbose == true) {
			std::cout << "server: " << server << std::endl;
		}
	}

	// Start time and End time
	uint64_t start_time = 0, end_time = 0;
	if (!decodeInt(in, start_time))
		throw std::runtime_error("Error decoding start_time");
	if (!decodeInt(in, end_time))
		throw std::runtime_error("Error decoding end_time");
	if (et != PROXYSQL_METADATA) {
		j["start_time"] = start_time;
		j["end_time"] = end_time;
		if (verbose == true) {
			std::cout << "start_time: " << start_time << ", end_time: " << end_time << std::endl;
		}
	}
	// Client statement id (only for COM_STMT_PREPARE/EXECUTE events)
	uint64_t client_stmt_id = 0;
	if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
		if (!decodeInt(in, client_stmt_id))
			throw std::runtime_error("Error decoding client_stmt_id");
		j["client_stmt_id"] = client_stmt_id;
		if (verbose == true) {
			std::cout << "client_stmt_id: " << client_stmt_id << std::endl;
		}
	}

	// affected_rows, last_insert_id, rows_sent, query_digest
	uint64_t affected_rows, last_insert_id, rows_sent, query_digest;
	if (!decodeInt(in, affected_rows))
		throw std::runtime_error("Error decoding affected_rows");
	if (!decodeInt(in, last_insert_id))
		throw std::runtime_error("Error decoding last_insert_id");
	if (!decodeInt(in, rows_sent))
		throw std::runtime_error("Error decoding rows_sent");
	if (!decodeInt(in, query_digest))
		throw std::runtime_error("Error decoding query_digest");
	if (et != PROXYSQL_METADATA) {
		j["affected_rows"] = affected_rows;
		j["last_insert_id"] = last_insert_id;
		j["rows_sent"] = rows_sent;
		j["query_digest"] = query_digest;
		if (verbose == true) {
			std::cout << "affected_rows: " << affected_rows
					  << ", last_insert_id: " << last_insert_id
					  << ", rows_sent: " << rows_sent
					  << ", query_digest: " << query_digest << std::endl;
		}
	}
	// Query: first read its length then raw query bytes.
	uint64_t query_len = 0;
	if (!decodeInt(in, query_len))
		throw std::runtime_error("Error decoding query length");
	std::string query = readString(in, query_len);
	if (et != PROXYSQL_METADATA) {
		j["query"] = query;
		if (verbose == true) {
			std::cout << "query: " << query << std::endl;
		}
	}
	// If the event is COM_STMT_EXECUTE then read parameter block.
	if (et == PROXYSQL_COM_STMT_EXECUTE) {
		// Read parameters count
		uint64_t num_params;
		if (!decodeInt(in, num_params))
			throw std::runtime_error("Error decoding parameter count");
		if (verbose == true) {
			std::cout << "num_params: " << num_params << std::endl;
		}

		json jparams = json::array();
		// Calculate null bitmap size
		size_t bitmap_size = (num_params + 7) / 8;
		std::vector<unsigned char> null_bitmap(bitmap_size);
		if (!in.read(reinterpret_cast<char*>(null_bitmap.data()), bitmap_size))
			throw std::runtime_error("Error reading null bitmap");
		if (verbose == true) {
			std::cout << "null_bitmap size: " << bitmap_size << std::endl;
		}

		for (uint16_t i = 0; i < num_params; i++) {
			json jparam;
			// Read parameter type (2 bytes)
			uint16_t param_type;
			if (!readValue(in, param_type))
				throw std::runtime_error("Error reading parameter type");
			jparam["type"] = param_type;
			if (verbose == true) {
				std::cout << "param[" << i << "] type: " << param_type << std::endl;
			}
			// Check if parameter is NULL using null bitmap.
			bool isNull = false;
			if (i < num_params) {
				isNull = (null_bitmap[i / 8] & (1 << (i % 8))) != 0;
			}
			if (isNull) {
				jparam["value"] = nullptr;
				if (verbose == true) {
					std::cout << "param[" << i << "] is NULL" << std::endl;
				}
			} else {
				// Read encoded length of parameter value
				uint64_t param_value_len;
				if (!decodeInt(in, param_value_len))
					throw std::runtime_error("Error decoding param value length");
				if (verbose == true) {
					std::cout << "param[" << i << "] value length: " << param_value_len << std::endl;
				}
				// Read raw parameter value bytes.
				std::string param_value = readString(in, param_value_len);
				jparam["value"] = param_value;
				if (verbose == true) {
					std::cout << "param[" << i << "] value: " << param_value << std::endl;
				}
			}
			jparams.push_back(jparam);
		}
		j["parameters"] = jparams;
	}
	return j;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <binary_log_file>" << std::endl;
		return 1;
	}
	std::ifstream infile(argv[1], std::ios::binary);
	if (!infile.is_open()) {
		std::cerr << "Failed to open file: " << argv[1] << std::endl;
		return 1;
	}

	//const bool verbose = true;
	const bool verbose = false;
	json jEvents = json::array();
	// Read events until end-of-file.
	while (infile.peek() != EOF) {
		try {
			json jEvent = parseEvent(infile, verbose);
			jEvents.push_back(jEvent);
		} catch (const std::exception &ex) {
			// Break on error or end of file.
			break;
		}
	}
	std::cout << jEvents.dump(4) << std::endl;
	return 0;
}
