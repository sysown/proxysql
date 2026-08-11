/**
 * @file gtid_server_data_unit-t.cpp
 * @brief Unit tests for GTID_Server_Data wire protocol parsing.
 *
 * Tests read_next_gtid() by stuffing messages directly into the internal
 * buffer, bypassing the network layer. Covers:
 *   - ST= bootstrap messages (single trxid and ranges)
 *   - I1/I2 single trxid incremental messages
 *   - I3/I4 range-based incremental messages
 *   - Unknown message type triggers disconnect (active = false)
 *   - events_read counter accuracy
 */

#include "tap.h"

#include "GTID_Server_Data.h"
#include "MySQL_HostGroups_Manager.h"

#include <dirent.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

extern struct ev_io * new_connect_watcher(char *address, uint16_t gtid_port, uint16_t mysql_port);

static const char *UUID_A = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa";
static char UUID_A_STRIPPED[] = "aaaaaaaa000011112222aaaaaaaaaaaa";
static const char *UUID_B = "bbbbbbbb-3333-4444-5555-bbbbbbbbbbbb";
static char UUID_B_STRIPPED[] = "bbbbbbbb333344445555bbbbbbbbbbbb";
static char LOOPBACK_ADDRESS[] = "127.0.0.1";
static char EMPTY_COMMENT[] = "";

/**
 * @brief Helper: stuff a message string into sd's buffer and reset pos.
 *
 * Replaces the entire buffer content. The caller can stuff multiple
 * newline-delimited messages in a single call.
 */
static void stuff_buffer(GTID_Server_Data &sd, const std::string &msg) {
	size_t needed = msg.size();
	if (needed > sd.size) {
		sd.resize(needed);
	}
	memcpy(sd.data, msg.c_str(), needed);
	sd.len = needed;
	sd.pos = 0;
}

/**
 * @brief ST= bootstrap with single trxids.
 */
static void test_bootstrap_single() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("ST=") + UUID_A + ":100," + UUID_B + ":200\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == true, "ST= bootstrap: returns true");
	ok(sd.active == true, "ST= bootstrap: active remains true");
	ok(sd.events_read == 1, "ST= bootstrap: events_read incremented");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 100) == true, "ST= bootstrap: UUID_A trxid 100 exists");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 200) == true, "ST= bootstrap: UUID_B trxid 200 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 101) == false, "ST= bootstrap: UUID_A trxid 101 does not exist");
}

/**
 * @brief ST= bootstrap with trxid ranges.
 */
static void test_bootstrap_range() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("ST=") + UUID_A + ":1-100," + UUID_B + ":50-200\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == true, "ST= range: returns true");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 1) == true, "ST= range: UUID_A trxid 1 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 50) == true, "ST= range: UUID_A trxid 50 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 100) == true, "ST= range: UUID_A trxid 100 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 101) == false, "ST= range: UUID_A trxid 101 does not exist");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 49) == false, "ST= range: UUID_B trxid 49 does not exist");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 50) == true, "ST= range: UUID_B trxid 50 exists");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 200) == true, "ST= range: UUID_B trxid 200 exists");
}

/**
 * @brief I1= single trxid with UUID.
 */
static void test_i1_single_trxid() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("I1=") + UUID_A_STRIPPED + ":42\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == true, "I1: returns true");
	ok(sd.active == true, "I1: active remains true");
	ok(sd.events_read == 1, "I1: events_read incremented");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 42) == true, "I1: trxid 42 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 43) == false, "I1: trxid 43 does not exist");
}

/**
 * @brief I1= must parse only a single trxid, not a range.
 */
static void test_i1_ignores_range() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// If someone sends a range via I1, atoll() parses only the first number
	std::string msg = std::string("I1=") + UUID_A_STRIPPED + ":10-20\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == true, "I1 range: returns true");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 10) == true, "I1 range: trxid 10 exists (atoll parses first number)");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 15) == false, "I1 range: trxid 15 does not exist (range not parsed)");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 20) == false, "I1 range: trxid 20 does not exist (range not parsed)");
}

/**
 * @brief I2= single trxid, reusing UUID from previous I1.
 */
static void test_i2_reuse_uuid() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// First set uuid_server via I1
	std::string msg1 = std::string("I1=") + UUID_A_STRIPPED + ":10\n";
	stuff_buffer(sd, msg1);
	sd.read_next_gtid();

	// Now I2 reuses uuid_server
	std::string msg2 = "I2=20\n";
	stuff_buffer(sd, msg2);

	ok(sd.read_next_gtid() == true, "I2: returns true");
	ok(sd.active == true, "I2: active remains true");
	ok(sd.events_read == 2, "I2: events_read incremented to 2");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 20) == true, "I2: trxid 20 exists under UUID_A");
}

/**
 * @brief I3= trxid range with UUID.
 */
static void test_i3_range() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("I3=") + UUID_A_STRIPPED + ":100-200\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == true, "I3: returns true");
	ok(sd.active == true, "I3: active remains true");
	ok(sd.events_read == 1, "I3: events_read incremented");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 99) == false, "I3: trxid 99 does not exist");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 100) == true, "I3: trxid 100 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 150) == true, "I3: trxid 150 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 200) == true, "I3: trxid 200 exists");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 201) == false, "I3: trxid 201 does not exist");
}

/**
 * @brief I4= trxid range, reusing UUID from previous I3.
 */
static void test_i4_range_reuse_uuid() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// Set uuid_server via I3
	std::string msg1 = std::string("I3=") + UUID_B_STRIPPED + ":10-20\n";
	stuff_buffer(sd, msg1);
	sd.read_next_gtid();

	// I4 reuses uuid_server
	std::string msg2 = "I4=30-40\n";
	stuff_buffer(sd, msg2);

	ok(sd.read_next_gtid() == true, "I4: returns true");
	ok(sd.active == true, "I4: active remains true");
	ok(sd.events_read == 2, "I4: events_read incremented to 2");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 30) == true, "I4: trxid 30 exists under UUID_B");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 35) == true, "I4: trxid 35 exists under UUID_B");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 40) == true, "I4: trxid 40 exists under UUID_B");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 41) == false, "I4: trxid 41 does not exist");
}

/**
 * @brief Unknown message type sets active=false and returns false.
 */
static void test_unknown_message_disconnects() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// First, send a valid message to confirm baseline
	std::string msg1 = std::string("I1=") + UUID_A_STRIPPED + ":10\n";
	stuff_buffer(sd, msg1);
	sd.read_next_gtid();
	ok(sd.active == true, "unknown: baseline active is true");
	ok(sd.events_read == 1, "unknown: baseline events_read is 1");

	// Now send an unknown message type I9
	std::string msg2 = "I9=garbage\n";
	stuff_buffer(sd, msg2);

	ok(sd.read_next_gtid() == false, "unknown: returns false");
	ok(sd.active == false, "unknown: active set to false (disconnect)");
	ok(sd.events_read == 1, "unknown: events_read NOT incremented");
}

/**
 * @brief Malformed bootstrap trxid ranges disconnect without counting an event.
 */
static void test_malformed_bootstrap_disconnects() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("ST=") + UUID_A + ":abc\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == false, "malformed ST: returns false");
	ok(sd.active == false, "malformed ST: active set to false");
	ok(sd.events_read == 0, "malformed ST: events_read NOT incremented");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 0) == false, "malformed ST: trxid 0 was not added");
}

/**
 * @brief Malformed I3 trxid ranges disconnect without counting an event.
 */
static void test_malformed_i3_disconnects() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("I3=") + UUID_A_STRIPPED + ":10-abc\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == false, "malformed I3: returns false");
	ok(sd.active == false, "malformed I3: active set to false");
	ok(sd.events_read == 0, "malformed I3: events_read NOT incremented");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 0) == false, "malformed I3: trxid 0 was not added");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 10) == false, "malformed I3: trxid 10 was not added");
}

/**
 * @brief Malformed I4 trxid ranges disconnect and preserve earlier event count.
 */
static void test_malformed_i4_disconnects() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg1 = std::string("I3=") + UUID_B_STRIPPED + ":10-20\n";
	stuff_buffer(sd, msg1);
	sd.read_next_gtid();

	std::string msg2 = "I4=30-40x\n";
	stuff_buffer(sd, msg2);

	ok(sd.read_next_gtid() == false, "malformed I4: returns false");
	ok(sd.active == false, "malformed I4: active set to false");
	ok(sd.events_read == 1, "malformed I4: events_read NOT incremented");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 30) == false, "malformed I4: trxid 30 was not added");
}

/**
 * @brief Multiple messages in sequence: ST bootstrap, then I1, I3, I2, I4.
 */
static void test_mixed_sequence() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// Bootstrap
	std::string boot = std::string("ST=") + UUID_A + ":1-5\n";
	stuff_buffer(sd, boot);
	sd.read_next_gtid();
	ok(sd.events_read == 1, "mixed: bootstrap events_read=1");

	// I1: single trxid, sets UUID to A
	std::string m1 = std::string("I1=") + UUID_A_STRIPPED + ":6\n";
	stuff_buffer(sd, m1);
	sd.read_next_gtid();
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 6) == true, "mixed: I1 trxid 6 exists");

	// I2: single trxid, reuses UUID A
	std::string m2 = "I2=7\n";
	stuff_buffer(sd, m2);
	sd.read_next_gtid();
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 7) == true, "mixed: I2 trxid 7 exists");

	// I3: range, sets UUID to B
	std::string m3 = std::string("I3=") + UUID_B_STRIPPED + ":100-110\n";
	stuff_buffer(sd, m3);
	sd.read_next_gtid();
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 105) == true, "mixed: I3 trxid 105 exists");

	// I4: range, reuses UUID B
	std::string m4 = "I4=111-120\n";
	stuff_buffer(sd, m4);
	sd.read_next_gtid();
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 115) == true, "mixed: I4 trxid 115 exists");

	ok(sd.events_read == 5, "mixed: events_read=5 after all messages");
	ok(sd.active == true, "mixed: still active after valid sequence");

	// Verify the full GTID state
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 1) == true, "mixed: UUID_A range start from bootstrap");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 5) == true, "mixed: UUID_A range end from bootstrap");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 100) == true, "mixed: UUID_B range start from I3");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 120) == true, "mixed: UUID_B range end from I4");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 99) == false, "mixed: UUID_B before range");
	ok(sd.gtid_exists((char *)UUID_B_STRIPPED, 121) == false, "mixed: UUID_B after range");
}

/**
 * @brief read_all_gtids() stops on unknown message; earlier messages are processed.
 */
static void test_read_all_stops_on_unknown() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	// Three messages: two valid, one unknown
	std::string msgs = std::string("I1=") + UUID_A_STRIPPED + ":10\n"
					 + "I2=11\n"
					 + "I9=bad\n";
	stuff_buffer(sd, msgs);

	sd.read_all_gtids();

	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 10) == true, "read_all: first message processed");
	ok(sd.gtid_exists((char *)UUID_A_STRIPPED, 11) == true, "read_all: second message processed");
	ok(sd.active == false, "read_all: active=false after unknown message");
	ok(sd.events_read == 2, "read_all: events_read=2 (unknown not counted)");
}

/**
 * @brief Empty buffer returns false, active stays true.
 */
static void test_empty_buffer() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	ok(sd.read_next_gtid() == false, "empty: returns false");
	ok(sd.active == true, "empty: active remains true");
	ok(sd.events_read == 0, "empty: events_read stays 0");
}

/**
 * @brief Incomplete message (no newline) returns false, active stays true.
 */
static void test_incomplete_message() {
	GTID_Server_Data sd(nullptr, (char *)"127.0.0.1", 0, 3306);

	std::string msg = std::string("I1=") + UUID_A_STRIPPED + ":42";  // no newline
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid() == false, "incomplete: returns false (no newline)");
	ok(sd.active == true, "incomplete: active remains true");
	ok(sd.events_read == 0, "incomplete: events_read stays 0");
}

static void test_ok_gtid_survives_inactive_reader() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	sd.active = false;

	ok(sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42"),
		"OK GTID: first observation updates the set");
	ok(sd.gtid_exists(UUID_A_STRIPPED, 42),
		"OK GTID: direct evidence is valid while reader is inactive");
	ok(!sd.gtid_exists(UUID_A_STRIPPED, 43),
		"OK GTID: an unobserved transaction remains absent");
	ok(sd.gtid_executed_to_string().find(":42") != std::string::npos,
		"OK GTID: union is visible in stats rendering");
	ok(sd.events_read == 0,
		"OK GTID: binlog event counter is unchanged");
	ok(!sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42"),
		"OK GTID: duplicate observation is not counted as an update");
}

static void test_known_gtid_survives_inactive_reader() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	std::string msg = std::string("I1=") + UUID_A_STRIPPED + ":55\n";
	stuff_buffer(sd, msg);

	ok(sd.read_next_gtid(), "known GTID: binlog message is parsed");
	ok(sd.gtid_exists(UUID_A_STRIPPED, 55),
		"known GTID: active endpoint record contains the transaction");
	sd.active = false;
	ok(sd.gtid_exists(UUID_A_STRIPPED, 55),
		"known GTID: inactive reader does not hide endpoint state");
}

static void test_ok_gtid_validation() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);

	ok(!sd.add_gtid_from_ok(nullptr), "OK GTID: null is rejected");
	ok(!sd.add_gtid_from_ok("missing-separator"), "OK GTID: missing separator is rejected");
	ok(!sd.add_gtid_from_ok("zzzzzzzz-0000-1111-2222-aaaaaaaaaaaa:1"),
		"OK GTID: nonhexadecimal UUID is rejected");
	ok(!sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:not-a-number"),
		"OK GTID: nonnumeric transaction ID is rejected");
	ok(!sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:0"),
		"OK GTID: transaction zero is rejected");
	ok(sd.gtid_executed_to_string().empty(),
		"OK GTID: invalid input does not mutate the endpoint set");
}

static void test_ok_and_binlog_merge() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	std::string msg = std::string("I1=") + UUID_A_STRIPPED + ":60\n";
	stuff_buffer(sd, msg);
	sd.read_next_gtid();

	ok(sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:61"),
		"mixed observations: direct GTID is added");
	ok(sd.gtid_exists(UUID_A_STRIPPED, 60),
		"mixed observations: binlog GTID is eligible");
	sd.active = false;
	ok(sd.gtid_exists(UUID_A_STRIPPED, 60),
		"mixed observations: known binlog GTID remains eligible when inactive");
	ok(sd.gtid_exists(UUID_A_STRIPPED, 61),
		"mixed observations: known OK GTID remains eligible when inactive");
}

static void test_manager_gtid_lookup_survives_inactive_reader() {
	MySQL_HostGroups_Manager manager;
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	MySrvC server(LOOPBACK_ADDRESS, 3306, 0, 1, MYSQL_SERVER_STATUS_ONLINE,
		0, 100, 0, 0, 0, EMPTY_COMMENT);

	sd.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:70");
	manager.gtid_map.emplace("127.0.0.1:3306", &sd);
	sd.active = false;

	ok(manager.gtid_exists(&server, UUID_A_STRIPPED, 70),
		"manager GTID lookup: known endpoint state remains eligible when inactive");
}

static int count_open_file_descriptors() {
	DIR* directory = opendir("/proc/self/fd");
	if (directory == nullptr) {
		directory = opendir("/dev/fd");
	}
	if (directory == nullptr) {
		return -1;
	}

	int count = 0;
	while (dirent* entry = readdir(directory)) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
			++count;
		}
	}
	closedir(directory);
	return count;
}

static void test_connect_watcher_closes_socket_on_resolution_failure() {
	const int before = count_open_file_descriptors();
	if (before < 0) {
		skip(3, "open file descriptors cannot be enumerated on this platform");
		return;
	}

	bool all_failed = true;
	char invalid_address[] = "invalid host name";

	for (int i = 0; i < 32; ++i) {
		ev_io* watcher = new_connect_watcher(invalid_address, 3307, 3306);
		if (watcher != nullptr) {
			all_failed = false;
			close(watcher->fd);
			free(watcher);
		}
	}

	const int after = count_open_file_descriptors();
	ok(true, "connect watcher: open descriptors can be counted");
	ok(all_failed, "connect watcher: invalid address fails every connection attempt");
	ok(after == before,
		"connect watcher: resolution failures do not leak sockets (%d before, %d after)", before, after);
}

static unsigned long long snapshot_last_trxid(const std::string& gtid_executed) {
	if (gtid_executed.empty()) {
		return 0;
	}

	const std::string::size_type separator = gtid_executed.find_last_of(":-");
	return separator == std::string::npos
		? 0
		: strtoull(gtid_executed.c_str() + separator + 1, nullptr, 10);
}

/**
 * @brief Stats snapshots stay coherent while binlog records are applied.
 *
 * For this single-UUID sequential stream, the highest GTID must always equal
 * the number of binlog events. A snapshot assembled across two lock sections,
 * or with an unlocked events_read access, can expose different generations.
 */
static void test_gtid_snapshot_is_coherent_during_binlog_updates() {
	GTID_Server_Data sd(nullptr, LOOPBACK_ADDRESS, 0, 3306);
	constexpr unsigned long long event_count = 4000;
	std::string messages;
	messages.reserve(event_count * 16);
	messages.append("I1=").append(UUID_A_STRIPPED).append(":1\n");
	for (unsigned long long trxid = 2; trxid <= event_count; ++trxid) {
		messages.append("I2=").append(std::to_string(trxid)).append("\n");
	}
	stuff_buffer(sd, messages);

	std::atomic<bool> start { false };
	std::atomic<bool> writer_done { false };
	std::atomic<bool> coherent { true };
	std::atomic<unsigned long long> snapshots { 0 };

	std::thread writer([&start, &sd, &writer_done]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		while (sd.read_next_gtid()) {
			std::this_thread::yield();
		}
		writer_done.store(true);
	});

	auto capture_snapshot = [&sd, &coherent, &snapshots]() {
		const GTID_Executed_Snapshot snapshot = sd.get_gtid_executed_snapshot();
		if (snapshot_last_trxid(snapshot.gtid_executed) != snapshot.events_read) {
			coherent.store(false);
		}
		snapshots.fetch_add(1);
	};

	std::thread reader([&start, &writer_done, &capture_snapshot]() {
		capture_snapshot();
		start.store(true);
		do {
			capture_snapshot();
		} while (!writer_done.load());
	});

	writer.join();
	reader.join();

	const GTID_Executed_Snapshot final_snapshot = sd.get_gtid_executed_snapshot();
	ok(snapshots.load() > 1,
		"GTID snapshot: reader sampled while binlog updates were running");
	ok(coherent.load(),
		"GTID snapshot: text and binlog event count always describe one generation");
	ok(final_snapshot.events_read == event_count &&
			snapshot_last_trxid(final_snapshot.gtid_executed) == event_count,
		"GTID snapshot: final state contains all %llu binlog events", event_count);
}

int main() {
	plan(109);

	test_bootstrap_single();            //  6 assertions
	test_bootstrap_range();             //  8 assertions
	test_i1_single_trxid();             //  5 assertions
	test_i1_ignores_range();            //  4 assertions
	test_i2_reuse_uuid();               //  4 assertions
	test_i3_range();                    //  8 assertions
	test_i4_range_reuse_uuid();         //  7 assertions
	test_unknown_message_disconnects(); //  5 assertions
	test_malformed_bootstrap_disconnects(); // 4 assertions
	test_malformed_i3_disconnects();    //  5 assertions
	test_malformed_i4_disconnects();    //  4 assertions
	test_mixed_sequence();              // 14 assertions
	test_read_all_stops_on_unknown();   //  4 assertions
	test_empty_buffer();                //  3 assertions
	test_incomplete_message();          //  3 assertions
	test_ok_gtid_survives_inactive_reader();
	test_known_gtid_survives_inactive_reader();
	test_ok_gtid_validation();
	test_ok_and_binlog_merge();
	test_manager_gtid_lookup_survives_inactive_reader();
	test_connect_watcher_closes_socket_on_resolution_failure();
	test_gtid_snapshot_is_coherent_during_binlog_updates();

	return exit_status();
}
