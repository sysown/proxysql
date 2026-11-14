# Investigating the SELECT 1 throughput ranking reversal

The earlier cross-protocol ranking was setup-sensitive. A controlled follow-up did not reproduce the reversal: PostgreSQL was faster both directly and through native TCP. This investigation found no query-counting error or product correctness failure. It does not identify the exact cause of the historical ranking.

## Controlled results

Same immutable client, ProxySQL host and TCP plugin binaries, exact `SELECT 1`, verified result `1`, four synchronous clients, 100 warmups per client, five-second persistent-query phases, three globally rotated rounds. Each native trial used a fresh daemon with both SQL worker groups set to two, two TCP workers, Admin active and monitors disabled. The database, proxy and clients used separate physical CPU core sets.

| Backend protocol | Direct QPS | Via MySQL HGM QPS | Via PostgreSQL HGM QPS |
|---|---:|---:|---:|
| MySQL | 111,385 | 69,624 | 65,992 |
| PostgreSQL | 123,820 | 75,086 | 75,752 |

All values are medians of three observations. Direct and native PostgreSQL results now exceed their corresponding MySQL results. For each database, changing the mapping selected a different hostgroup manager while retaining the same actual database endpoint, database protocol and client library. Native TCP handles the traffic as bytes, so this cross-mapping is a useful diagnostic control with SQL monitors disabled.

MySQL traffic was faster through the MySQL manager than through the PostgreSQL manager (69,623.6 versus 65,991.5 QPS). PostgreSQL traffic changed little across the two managers (75,085.8 versus 75,751.9 QPS). The data therefore does not support a MySQL-manager-specific penalty as the explanation of the original cross-protocol gap. It also does not establish that hostgroup-manager costs are identical: the observed namespace differences were about 5.2% for MySQL traffic and 0.9% for PostgreSQL traffic, with only three observations per arm.

## What changed from the earlier test

The earlier [SELECT 1 comparison](2026-11-11-tcp-select1-fast-forward.html) correctly recorded completed verified queries and elapsed time. It left CPU placement to the scheduler and ran all MySQL rounds before PostgreSQL rounds. The new diagnostic pins the database to CPUs 0–3, proxy to 4–5, clients to 8–11 and orchestration to 12–15, without sharing SMT sibling cores between these groups. It interleaves protocol arms globally and enables both SQL worker groups identically in every native arm. Monitoring and process-wait orchestration also differ. These controls changed together; the improvement cannot be attributed solely to CPU affinity.

| Run | MySQL direct QPS | PostgreSQL direct QPS | MySQL native QPS | PostgreSQL native QPS |
|---|---:|---:|---:|---:|
| Earlier SELECT 1 test | 108,923 | 90,269 | 46,606 | 57,360 |
| Controlled diagnostic | 111,385 | 123,820 | 69,624 | 75,752 |

The native entries use each protocol's corresponding hostgroup manager. The substantial movement shows why the earlier numbers should be treated as observations of that setup, rather than stable protocol-specific proxy costs. This diagnostic did not rerun fast-forward, so its native figures must not be compared directly with the old fast-forward figures to claim a new speedup.

MySQL uses MariaDB Connector/C and PostgreSQL uses libpq, with different wire-protocol and client I/O behavior. Consequently the two database paths do not constitute an experiment with identical client/server implementations. A rank change alone cannot distinguish a relay defect from scheduling, protocol, client or server interactions. The precise historical cause remains unisolated.

## CPU and routing evidence

Under these controls, median proxy CPU time per verified query was 21.63 microseconds for MySQL through MySQL HGM and 21.19 microseconds for PostgreSQL through PostgreSQL HGM. The cross-mapped arms were also approximately 21–23 microseconds per query. These values come from true per-thread task statistics summed across the daemon; the interval includes client startup, warmups and close, so they are diagnostic CPU costs rather than isolated relay instruction costs. Two proxy threads dominated the CPU usage, consistent with the two active relay workers.

Each native arm held a successfully queried connection open and proved: the requested runtime mapping was active; the selected manager had a Used connection; the other manager had none; plugin accepted/active and bidirectional byte counters advanced; neither SQL frontend processlist contained that client socket; result verification succeeded. Each trial then completed without connection errors and drained its Used/Free counts.

Per-thread client affinity was observed while all five threads were live, rather than inferred after process exit. A separate busy/idle thread oracle checked that per-thread CPU counters were not accidentally duplicated process totals. Early development errors in this new diagnostic's CPU and affinity evidence were corrected before the timed run; they did not affect the historical QPS calculations.

PostgreSQL query-backend CPU remains unavailable in this diagnostic: exited query processes are missed by the endpoint snapshots, and the recorded database CPU is explicitly a lower bound. Hardware performance counters were unavailable (`perf_event_paranoid=4`); no kernel settings were changed and no traces ran during the timing phases. CPU affinity is not exclusive CPU reservation, and unrelated host load or frequency scaling can still matter.

## Per-arm variation

| Arm | Median QPS | Minimum QPS | Maximum QPS |
|---|---:|---:|---:|
| mysql_direct | 111,385.0 | 111,187.0 | 112,144.0 |
| mysql_via_MYSQL_HGM | 69,623.6 | 66,826.3 | 70,553.0 |
| mysql_via_PGSQL_HGM | 65,991.5 | 60,274.3 | 66,358.2 |
| pgsql_direct | 123,820.0 | 114,801.0 | 125,648.0 |
| pgsql_via_MYSQL_HGM | 75,085.8 | 73,148.8 | 75,223.4 |
| pgsql_via_PGSQL_HGM | 75,751.9 | 74,965.3 | 75,893.7 |

## Verification and provenance

One controlled run completed: 18 trials, twelve positive held-routing proofs, verified SQL/result and rate arithmetic, observed client/proxy affinities, successful shutdown of twelve daemons and both task-owned database fixtures, and independent confirmation that all fourteen owned PIDs were gone. Root recomputed the raw query-count/elapsed-time rates and all median/range summaries; a separate reviewer approved the evidence and the limited interpretation. No production or benchmark-tool source in either repository changed.

The [raw diagnostic JSON](2026-11-12-tcp-ranking-diagnostic.json) contains all trials, configuration, counters, process statistics, proofs, order and input hashes. The temporary reproducibility bundle is `/tmp/tcp-ranking-diagnostic/final/`; its delivery manifest and standalone harness are retained there. The standalone harness was delegated through OpenCode using `opencode-go/deepseek-v4.1-flash`, with root review and verification.

| Input | SHA-256 |
|---|---|
| ProxySQL | `81c4f518f15e05af5de94a14ac445570ffbd0845e9f7bd4a2e9a85b281800d02` |
| TCP plugin | `f4111f8949276645977d9ee917eed9784c574017d3a00709050b614ca527b9c4` |
| Native client | `87092ec5d5a95b73acc8e9278f686e97ad12641e7bb202c2f7ac1f52384c572b` |
| Diagnostic harness | `d6230232e4d7e298fcac294b215e4b9f38acd674a2f5db9743535fc0c601a187` |
