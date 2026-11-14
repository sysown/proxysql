#ifndef CLASS_GTID_Server_Data_H
#define CLASS_GTID_Server_Data_H

#include <cstddef>
#include <cstdint>
#include <pthread.h>
#include <proxysql_gtid.h>
#include <string>

struct GTID_Executed_Snapshot {
	std::string gtid_executed;
	unsigned long long events_read;
};

// Flavor of the id field carried by the binlog reader wire messages. A single
// endpoint speaks exactly one flavor: a 32 hex digit MySQL UUID or a decimal
// MariaDB domain id. Anything else, and any change across messages, is a
// protocol violation.
enum GTID_Id_Flavor {
	GTID_ID_FLAVOR_UNKNOWN = 0,
	GTID_ID_FLAVOR_UUID = 1,
	GTID_ID_FLAVOR_DOMAIN = 2
};

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
	int gtid_flavor;
	GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port);
	void resize(size_t _s);
	~GTID_Server_Data();
	bool readall();
	bool writeout();
	bool read_next_gtid();
	// Forgets the state tied to one reader connection (id flavor, last id,
	// unread bytes, executed GTID set) so a new connection starts from its
	// own bootstrap, which re-sends the executed set.
	void reset_reader_stream();
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid);
	void read_all_gtids();
	void dump();

	private:
	pthread_rwlock_t executed_rwlock;

	public:
	bool add_gtid_from_ok(const char* gtid);
	GTID_Executed_Snapshot get_gtid_executed_snapshot();
	std::string gtid_executed_to_string();
};

#endif // CLASS_GTID_Server_Data_H
