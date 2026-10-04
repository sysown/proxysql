#include "PgSQL_LSN_Probe.h"
#include "tap.h"
using namespace pgsql_lsn;
static ProbeRows identity(const char *sysid = "12345", const char *timeline = "1") {
	return {{{sysid}, {timeline}, {"FFFFFFFF/FFFFFFFF"}, {"postgres"}}};
}
static ProbeRows sample(const char *role = "f", const char *lsn = "0/123",
						const char *start = "1000") {
	return {{{start}, {role}, lsn ? std::optional<std::string>{lsn} : std::nullopt}};
}
static ProbeRows layout(const char *alignment = "8", const char *block = "8192",
						const char *segment = "16777216", const char *version = "170000") {
	return {{{alignment}, {block}, {segment}, {version}}};
}
static void metadata(PgSQL_LSN_Probe &probe, const ProbeRows &row = layout()) {
	std::string error;
	probe.next_command(25);
	probe.consume_result(row, error);
}
int main() {
	plan(NO_PLAN);
	std::string error;
	PgSQL_LSN_Probe p({"host", 5432});
	ok(!p.finish(), "new probe cannot publish identity-less progress");
	ok(p.next_command(10) == "IDENTIFY_SYSTEM", "initial background identity query required");
	ok(!p.next_command(20), "at most one command outstanding");
	ok(p.consume_result(identity(), error), "initial identity accepted");
	auto metadata_sql = p.next_command(50);
	ok(metadata_sql && metadata_sql->find("pg_control_init()") != std::string::npos &&
		   metadata_sql->find("max_data_alignment") != std::string::npos &&
		   metadata_sql->find("wal_block_size") != std::string::npos &&
		   metadata_sql->find("bytes_per_wal_segment") != std::string::npos,
	   "connection obtains actual WAL layout before sampling");
	ok(p.consume_result(layout(), error), "valid server WAL layout accepted");
	auto sql = p.next_command(100);
	ok(sql && sql->find("pg_current_wal_insert_lsn()") != std::string::npos &&
		   sql->find("pg_last_wal_replay_lsn()") != std::string::npos,
	   "sample chooses insertion or replay position using recovery status");
	ok(sql && sql->find("pg_current_wal_flush_lsn") == std::string::npos &&
		   sql->find("pg_current_wal_lsn()") == std::string::npos &&
		   sql->find("pg_control_init") == std::string::npos,
	   "regular sample uses insertion, never write/flush or repeated "
	   "control-file reads");
	ok(p.consume_result(sample(), error) && !p.finish(),
	   "position waits for final identity validation");
	ok(p.next_command(200) == "IDENTIFY_SYSTEM" && p.consume_result(identity(), error),
	   "final identity validates entire sample response");
	auto result = p.finish();
	ok(result && result->valid && result->sample.lsn == 0x123 && result->sample.started_at == 100,
	   "publication keeps exact sample-send time despite delayed final identity");
	ok(result && result->history == History{12345, 1} && result->postmaster_start_us == 1000,
	   "publication holds complete background identity metadata");
	ok(!p.next_command(300), "completed probe sends no additional commands");
	PgSQL_LSN_Probe repeat({"host", 5432}, History{12345, 1}, p.layout());
	auto repeat_sql = repeat.next_command(400);
	ok(repeat_sql && repeat_sql->find("pg_current_wal_insert_lsn()") != std::string::npos &&
		   repeat_sql->find("pg_control_init") == std::string::npos,
	   "same connection reuses validated identity and layout without repeating "
	   "metadata SQL");
	repeat.consume_result(sample("t", "0/42", "2000"), error);
	repeat.next_command(500);
	ok(!repeat.consume_result(identity("12345", "2"), error) && !repeat.finish(),
	   "identity change across sample never publishes partial progress");
	for (const auto &bad :
		 {identity("other"), identity("18446744073709551616"), identity("12345", "0"),
		  identity("12345", "4294967296"), ProbeRows{}, ProbeRows{{{"12345"}}}}) {
		PgSQL_LSN_Probe q({"host", 5432});
		q.next_command(10);
		ok(!q.consume_result(bad, error) && !q.finish(), "malformed identity rejected");
	}
	for (const auto &bad : {sample("unknown"), sample("f", nullptr), sample("f", "0/G"),
							sample("f", "0/1", "9223372036854775808"), ProbeRows{},
							ProbeRows{sample()[0], sample()[0]}}) {
		PgSQL_LSN_Probe q({"host", 5432}, History{12345, 1});
		metadata(q);
		q.next_command(30);
		ok(!q.consume_result(bad, error) && !q.finish(), "malformed sample rejected");
	}
	for (const auto &bad :
		 {layout("0"), layout("8", "7"), layout("8", "8192", "7"),
		  layout("8", "8192", "1073741825"), layout("8", "131072"),
		  layout("8", "8192", "16777216", "bad"), ProbeRows{}, ProbeRows{{{"8"}}}}) {
		PgSQL_LSN_Probe q({"host", 5432}, History{12345, 1});
		q.next_command(10);
		ok(!q.consume_result(bad, error) && !q.finish(), "malformed WAL layout rejected");
	}
	struct Boundary {
		const char *input;
		Lsn expected;
		const char *role;
		const char *alignment;
		const char *block;
		const char *segment;
		const char *version;
	};
	for (const auto &b :
		 {Boundary{"0/4000028", 0x4000000, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4002018", 0x4002000, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000020", 0x4000020, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000030", 0x4000030, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4002020", 0x4002020, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4004028", 0x4004028, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000028", 0x4000028, "t", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000028", 0x4000028, "f", "8", "8192", "16777216", "190000"},
		  Boundary{"0/4000018", 0x4000018, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000000", 0x4000000, "f", "8", "8192", "16777216", "170000"},
		  Boundary{"0/4000028", 0x4000028, "f", "8", "8192", "16777216", "130000"},
		  Boundary{"0/4000028", 0x4000028, "f", "16", "8192", "16777216", "170000"},
		  Boundary{"0/4001018", 0x4001000, "f", "8", "4096", "1048576", "140000"},
		  Boundary{"0/4100028", 0x4100000, "f", "8", "4096", "1048576", "180000"},
		  Boundary{"0/4000024", 0x4000000, "f", "4", "8192", "16777216", "170000"},
		  Boundary{"0/4002014", 0x4002000, "f", "4", "8192", "16777216", "170000"},
		  Boundary{"0/4000028", 0x4000028, "f", "4", "8192", "16777216", "170000"}}) {
		PgSQL_LSN_Probe q({"host", 5432}, History{12345, 1});
		metadata(q, layout(b.alignment, b.block, b.segment, b.version));
		q.next_command(30);
		const bool accepted = q.consume_result(sample(b.role, b.input), error);
		q.next_command(40);
		q.consume_result(identity(), error);
		ok(accepted && q.finish() && q.finish()->sample.lsn == b.expected,
		   "%s recovery=%s alignment=%s version=%s changes only exact supported "
		   "insertion boundaries",
		   b.input, b.role, b.alignment, b.version);
	}
	PgSQL_LSN_Probe replica({"reader", 5432});
	replica.next_command(10);
	replica.consume_result(identity(), error);
	metadata(replica);
	replica.next_command(20);
	replica.consume_result(sample("t", "0/42", "2000"), error);
	replica.next_command(30);
	replica.consume_result(identity(), error);
	ok(replica.finish() && replica.finish()->sample.lsn == 0x42,
	   "identity flush location cannot replace actual replay location");
	PgSQL_LSN_Probe denied({"host", 5432});
	denied.next_command(10);
	denied.fail("denied");
	ok(!denied.finish() && !denied.next_command(20), "failed command cannot continue or publish");
	ProbeCadence cadence;
	ok(cadence.due(1000, 10000), "configured endpoint starts without frontend demand");
	cadence.started(1000);
	ok(!cadence.due(500000, 10000), "outstanding probe coalesces missed ticks");
	cadence.finished();
	ok(!cadence.due(10999, 10000) && cadence.due(11000, 10000), "interval bounds sample starts");
	cadence.started(500000);
	cadence.finished();
	ok(!cadence.due(500001, 10000) && cadence.due(501000, 1000),
	   "runtime interval reduction takes effect without backlog");
	return exit_status();
}
