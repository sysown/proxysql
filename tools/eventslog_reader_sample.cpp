#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdint.h>

using namespace std;

#define CPY1(x) *((uint8_t *)x)
#define CPY2(x) *((uint16_t *)x)
#define CPY8(x) *((uint64_t *)x)

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
	if (*ptr == 0xfc) { if (len) { *len = CPY2(ptr+1); }; return 3; }
	if (*ptr == 0xfd) { if (len) { *len = CPY3(ptr+1); };  return 4; }
	if (*ptr == 0xfe) { if (len) { *len = CPY8(ptr+1); };  return 9; }
	return 0; // never reaches here
}


void read_encoded_length(uint64_t *ptr, std::fstream *f) {
	unsigned char buf[10];
	uint8_t len;
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
	char *server;
	char *client;
	size_t server_len;
	size_t client_len;
	uint64_t total_length;
	public:
	MySQL_Event() {
		query_len=0;
	}
	void read(std::fstream *f) {
		read_encoded_length((uint64_t *)&thread_id,f);
		read_encoded_length((uint64_t *)&username_len,f);
		username=read_string(f,username_len);
		read_encoded_length((uint64_t *)&schemaname_len,f);
		schemaname=read_string(f,schemaname_len);
		cout << username_len << " " << username << " " << schemaname_len << " " << schemaname << endl;
		read_encoded_length((uint64_t *)&start_time,f);
		read_encoded_length((uint64_t *)&end_time,f);
		read_encoded_length((uint64_t *)&query_digest,f);
		read_encoded_length((uint64_t *)&query_len,f);
		query_ptr=read_string(f,query_len);
		cout << start_time << " " << end_time << endl;
		cout << query_len << " " << query_ptr << endl;
	}
	~MySQL_Event() {
		free(username);
		free(schemaname);
		free(query_ptr);
	}
};

int main(int argc, char **argv) {
	fstream input;
	char buf[10241];
	input.rdbuf()->pubsetbuf(buf, sizeof buf);
	input.open(argv[1], ios::in | ios::binary);
	bool more_data=true;
	uint64_t msg_len=0;
	input.exceptions ( std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit );
	while (more_data) {
		try {
			input.read((char *)&msg_len,sizeof(uint64_t));
			cout << msg_len << endl;
			MySQL_Event me;
			me.read(&input);
			
//			unsigned long curpos=input.tellg();
//			curpos+=msg_len;
//			input.seekg(curpos);
			
		}
		catch(...) {
			more_data=false;
		}
	}
}
