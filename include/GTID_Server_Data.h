#ifndef CLASS_GTID_Server_Data_H
#define CLASS_GTID_Server_Data_H

#include <cstddef>
#include <cstdint>
#include <pthread.h>
#include <proxysql_gtid.h>

class GTID_Server_Data {
	public:
	char *address;
	uint16_t port;
	uint16_t mysql_port;
	char *data;
	size_t len;
	size_t size;
	size_t pos;
	struct ev_io *w;
	char uuid_server[64];
	unsigned long long events_read;
	GTID_Set gtid_executed;
	bool active;
	GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port);
	void resize(size_t _s);
	~GTID_Server_Data();
	bool readall();
	bool writeout();
	bool read_next_gtid();
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid);
	void read_all_gtids();
	void dump();

	private:
	pthread_rwlock_t executed_rwlock;

	public:
	bool add_gtid_from_ok(const char* gtid);
	std::string gtid_executed_to_string();
};

#endif // CLASS_GTID_Server_Data_H
