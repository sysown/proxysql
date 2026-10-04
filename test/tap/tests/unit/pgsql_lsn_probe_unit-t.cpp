#include "tap.h"
#include "PgSQL_LSN_Probe.h"
using namespace pgsql_lsn;

static ProbeRows identity(const char* sysid = "12345", const char* timeline = "1") {
	return {{{sysid}, {timeline}, {"FFFFFFFF/FFFFFFFF"}, {"postgres"}}};
}
static ProbeRows sample(const char* role = "f", const char* lsn = "0/123", const char* start = "1000") {
	return {{{start}, {role}, lsn ? std::optional<std::string>(lsn) : std::nullopt}};
}
static PgSQL_LSN_Probe writer(std::optional<Incarnation> expected = {}, std::optional<History> previous = {}) {
	return {1, {"writer", 5432}, expected ? std::optional<ServerToken>{{1, {"writer",5432}, *expected, Role::Writer}} : std::nullopt, 7, 100, previous};
}
int main() {
	plan(NO_PLAN);
	std::string error;
	auto probe = writer();
	ok(!probe.finish(), "new connection is uncertified");
	ok(probe.next_command() == "IDENTIFY_SYSTEM", "new connection requires initial identity");
	ok(!probe.next_command(), "command cannot be sent twice while awaiting result");
	ok(probe.consume_result(identity(), error), "valid initial identity accepted");
	ok(!probe.finish(), "identity alone cannot certify progress");
	auto sql = probe.next_command();
	ok(sql && sql->find("pg_current_wal_insert_lsn()") != std::string::npos, "writer samples insertion position");
	ok(probe.consume_result(sample(), error), "writer sample accepted provisionally");
	ok(!probe.finish(), "sample without following identity is not publishable");
	ok(probe.next_command() == "IDENTIFY_SYSTEM", "sample is followed by identity check");
	ok(probe.consume_result(identity(), error), "matching final identity accepted");
	auto published = probe.finish();
	ok(published && published->valid && published->insert_lsn == 0x123, "published position comes from SQL sample");
	ok(published && published->server.incarnation.history.system_id == 12345
		&& published->server.incarnation.postmaster_start_us == 1000 && published->connection_generation == 7,
		"publication includes complete incarnation and connection generation");
	ok(!probe.next_command(), "finished probe sends no more commands");

	auto repeat = writer(Incarnation{{12345, 1}, 1000}, History{12345, 1});
	sql = repeat.next_command();
	ok(sql && sql->find("SELECT") == 0, "continuous connection reuses preceding identity");
	ok(repeat.consume_result(sample(), error), "subsequent sample accepted");
	repeat.next_command();
	ok(!repeat.consume_result(identity("12345", "2"), error), "timeline change across sample rejected");
	ok(!repeat.finish() && repeat.failure_reason() == Reason::HistoryChanged, "history mismatch cannot publish");

	for (const auto& bad : {identity("other"), identity("18446744073709551616"), identity("12345", "0"),
		identity("12345", "4294967296"), ProbeRows{}, ProbeRows{{{"12345"}}}}) {
		auto p = writer(); p.next_command();
		ok(!p.consume_result(bad, error) && !p.finish(), "malformed identity rejected");
	}
	for (const auto& bad : {sample("t"), sample("unknown"), sample("f", nullptr), sample("f", "0/G"),
		sample("f", "0/1", "1001"), sample("f", "0/1", "9223372036854775808"), ProbeRows{},
		ProbeRows{sample()[0], sample()[0]}}) {
		auto p = writer(Incarnation{{12345, 1}, 1000}, History{12345, 1}); p.next_command();
		ok(!p.consume_result(bad, error) && !p.finish(), "invalid role/position/incarnation/shape rejected");
	}
	auto wrong_system = writer();
	wrong_system.next_command(); wrong_system.consume_result(identity(), error);
	wrong_system.next_command(); wrong_system.consume_result(sample(), error);
	wrong_system.next_command();
	ok(!wrong_system.consume_result(identity("54321"), error) && !wrong_system.finish(), "different system cannot qualify");
	auto reconnected = writer(Incarnation{{12345, 1}, 1000});
	ok(reconnected.next_command() == "IDENTIFY_SYSTEM", "reconnect cannot reuse prior connection identity");
	auto demoted = writer(Incarnation{{12345, 1}, 1000}, History{12345, 1});
	demoted.next_command();
	demoted.consume_result(sample("t", nullptr), error);
	ok(demoted.failure_reason() == Reason::HistoryChanged, "writer becoming standby is detected even with NULL insertion position");
	PgSQL_LSN_Probe replica(1, {"reader", 5432}, {}, 8, 100);
	replica.next_command(); replica.consume_result(identity(), error);
	sql = replica.next_command();
	ok(sql && sql->find("pg_last_wal_replay_lsn()") != std::string::npos, "replica samples replay position");
	ok(replica.consume_result(sample("t", "0/42", "2000"), error), "replica sample accepted");
	replica.next_command(); replica.consume_result(identity(), error);
	auto r = replica.finish();
	ok(r && r->replay_lsn == 0x42 && !r->insert_lsn, "flush position in identity does not replace replay");
	auto denied = writer(); denied.next_command(); denied.fail("permission denied", Reason::NoSafeBackend);
	ok(!denied.finish() && !denied.next_command(), "failed command cannot publish or continue");

	ProbeCadence cadence;
	ok(cadence.due(1000, 10000, true), "new demand is immediately due");
	cadence.started(1000);
	ok(!cadence.due(10999, 10000, true), "minimum interval between starts enforced");
	ok(!cadence.due(500000, 10000, true), "active probe prevents duplicate dispatch");
	cadence.finished();
	ok(cadence.due(500000, 10000, true), "one delayed probe can start after completion");
	cadence.started(500000); cadence.finished();
	ok(!cadence.due(500001, 10000, true), "missed intervals do not form a backlog");
	ok(cadence.due(501000, 1000, true), "interval reduction affects future probes");
	ok(!cadence.due(1000000, 1000, false), "no SQL sampling without demand");
	return exit_status();
}
