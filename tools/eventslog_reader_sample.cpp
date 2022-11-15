#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif /* __STDC_LIMIT_MACROS */
#include <stdint.h>
#include <string.h>
#include <assert.h>
using namespace std;

#define CPY1(x) *((uint8_t *)x)

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
	PROXYSQL_COM_STMT_PREPARE
};

typedef union _4bytes_t {
	unsigned char data[4];
	uint32_t i;
} _4bytes_t;

unsigned int CPY3(unsigned char *ptr) {
	_4bytes_t buf;
	buf.i=*(uint32_t *)ptr;
	buf.data[3]=0;
	return buf.i;
}


uint8_t mysql_decode_length(unsigned char *ptr, uint64_t *len) {
	if (*ptr <= 0xfb) { if (len) { *len = CPY1(ptr); };  return 1; }
	//if (*ptr == 0xfc) { if (len) { *len = CPY2(ptr+1); }; return 3; }
	if (*ptr == 0xfc) {
		if (len) {
			memcpy((void *)len,(void *)(ptr+1),2);
		};
		return 3;
	}
	if (*ptr == 0xfd) { if (len) { *len = CPY3(ptr+1); };  return 4; }
	//if (*ptr == 0xfe) { if (len) { *len = CPY8(ptr+1); };  return 9; }
	if (*ptr == 0xfe) {
		if (len) {
			memcpy((void *)len,(void *)(ptr+1),8);
		};
		return 9;
	}
	return 0; // never reaches here
}


void read_encoded_length(uint64_t *ptr, std::fstream *f) {
	unsigned char buf[9];
	memset(buf,0,sizeof(uint64_t));
	uint8_t len;
	*ptr=0;
	f->read((char *)buf,1);
	len=mysql_decode_length(buf,NULL);
	if (len) {
		f->read((char *)buf+1,len-1);
		mysql_decode_length(buf,ptr);
	}
}

char * read_string(std::fstream *f, size_t len) {
	char *str=(char *)malloc(len+1);
	str[len]=0;
	if (len) {
		f->read(str,len);
	}
	return str;
}

class MySQL_Event {
	private:
	uint32_t thread_id;
	char *username;
	char *schemaname;
	size_t username_len;
	size_t schemaname_len;
	uint64_t start_time;
	uint64_t end_time;
	uint64_t query_digest;
	char *query_ptr;
	size_t query_len;
	char *server = NULL;
	char *client = NULL;
	size_t server_len;
	size_t client_len;
	uint64_t client_stmt_id;
	uint64_t total_length;
	uint64_t hid;
	uint64_t affected_rows;
	uint64_t rows_sent;
	log_event_type et;
	public:
	MySQL_Event() {
		query_len=0;
		client_stmt_id=0;
	}
	void read(std::fstream *f) {
		f->read((char *)&et,1);
		switch (et) {
			case PROXYSQL_COM_QUERY:
			case PROXYSQL_COM_STMT_EXECUTE:
			case PROXYSQL_COM_STMT_PREPARE:
				read_query(f);
				break;
			default:
				break;
		}
	}
	void read_query(std::fstream *f) {

		read_encoded_length((uint64_t *)&thread_id,f);
		read_encoded_length((uint64_t *)&username_len,f);
		username=read_string(f,username_len);
		read_encoded_length((uint64_t *)&schemaname_len,f);
		schemaname=read_string(f,schemaname_len);
		read_encoded_length((uint64_t *)&client_len,f);
		client=read_string(f,client_len);
		cout << "ProxySQL LOG ";
		switch (et) {
			case PROXYSQL_COM_STMT_EXECUTE:
				cout << "COM_STMT_EXECUTE";
				break;
			case PROXYSQL_COM_STMT_PREPARE:
				cout << "COM_STMT_PREPARE";
				break;
			case PROXYSQL_COM_QUERY:
				cout << "COM_QUERY";
				break;
			default:
				assert(0); // not supported
				break;
		}
		cout << ": thread_id=\"" << thread_id << "\" username=\"" << username << "\" schemaname=\"" << schemaname << "\" client=\"" << client << "\"";
		read_encoded_length((uint64_t *)&hid,f);
		if (hid==UINT64_MAX) {
			cout << " HID=NULL ";
		} else {
			read_encoded_length((uint64_t *)&server_len,f);
			server=read_string(f,server_len);
			cout << " HID=" << hid << " server=\"" << server << "\"";
		}
		read_encoded_length((uint64_t *)&start_time,f);
		read_encoded_length((uint64_t *)&end_time,f);
		if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
			read_encoded_length((uint64_t *)&client_stmt_id,f);
		}
		read_encoded_length((uint64_t *)&affected_rows,f);
		read_encoded_length((uint64_t *)&rows_sent,f);
		read_encoded_length((uint64_t *)&query_digest,f);
		char digest_hex[20];
		sprintf(digest_hex,"0x%016llX", (long long unsigned int)query_digest);
		read_encoded_length((uint64_t *)&query_len,f);
		query_ptr=read_string(f,query_len);
		char buffer[26];
		char buffer2[10];
		struct tm* tm_info;
		time_t timer;
		timer=start_time/1000/1000;
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%06u", (unsigned)(start_time%1000000));
		cout << " starttime=\"" << buffer << "." << buffer2 << "\"";
		timer=end_time/1000/1000;
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%06u", (unsigned)(end_time%1000000));
		cout << " endtime=\"" << buffer << "." << buffer2 << "\"";
		cout << " duration=" << (end_time-start_time) << "us";
		if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
			cout << " client_stmt_id=" << client_stmt_id;
		}
		cout << " rows_affected=" << affected_rows;
		cout << " rows_sent=" << rows_sent;
		cout << " digest=\"" << digest_hex << "\"" << endl << query_ptr << endl;
	}
	~MySQL_Event() {
		free(username);
		free(schemaname);
		free(query_ptr);
		if(client){
		   free(client);
		}
                if(server){
                    free(server);
		}
	}
};

int main(int argc, char **argv) {
	fstream input;
	char buf[10241];
	input.rdbuf()->pubsetbuf(buf, sizeof buf);

	if (argc != 2) {
		cout << "Invalid number of arguments. Please supply path to target log file.";
		return EXIT_FAILURE;
	}

	try {
		input.open(argv[1], ios::in | ios::binary);
		input.exceptions (std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
	} catch (std::exception& e) {
		cout << "Opening log file '" << argv[1] << "' failed with exception '" << e.what() << "'";
		return EXIT_FAILURE;
	}

	bool more_data=true;
	uint64_t msg_len=0;

	while (more_data) {
		try {
			input.read((char *)&msg_len,sizeof(uint64_t));
			//cout << msg_len << endl;
			MySQL_Event me;
			me.read(&input);
			
//			unsigned long curpos=input.tellg();
//			curpos+=msg_len;
//			input.seekg(curpos);
			
		} catch(...) {
			more_data=false;
		}
	}

	return EXIT_SUCCESS;
}
