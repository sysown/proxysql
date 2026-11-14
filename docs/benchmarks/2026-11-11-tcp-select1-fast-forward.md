# SELECT 1 native mapped TCP vs permanent SQL fast-forward

Status: **MEASURED**

Generated: `2026-11-11T22:15:40.662899+00:00`

Workload: `select1`; exact SQL `SELECT 1`; expected result `1`.

Tiny smoke: no

## Interpretation and verification

This comparison sends exact SQL `SELECT 1` and validates one row, one field and the value `1`. The same synchronous native C++ client runs against the same task-owned real database through direct connections, native mapped TCP, and permanent SQL fast-forward. Each client has one outstanding query; there is no pipelining or prepared-statement workload. Transport is plaintext, compression and GSS encryption are disabled, and TCP_NODELAY is observed enabled. Both proxy paths have two relevant SQL workers and two TCP workers configured, with four concurrent clients targeting the selected path.

Medians of three rotated rounds:

| Protocol | Path | Query RTT p50 (microseconds) | Established queries/second | Fresh connection cycles/second |
|---|---|---:|---:|---:|
| MySQL | Direct database | 46.1 | 108923 | 14500 |
| MySQL | Native TCP | 69.8 | 46606 | 8097 |
| MySQL | Fast-forward | 78.1 | 47273 | 3449 |
| PostgreSQL | Direct database | 52.3 | 90269 | 1671 |
| PostgreSQL | Native TCP | 54.3 | 57360 | 1539 |
| PostgreSQL | Fast-forward | 80.7 | 48078 | 1388 |

MySQL established-session throughput is similar: the native median is 1.4% below fast-forward, with overlapping observed ranges (40419–49002 versus 42662–47618 QPS). Native TCP achieved 2.35 times the fresh MySQL connection-cycle rate. Its median query RTT is lower in this run, with overlapping ranges between modes.

PostgreSQL native TCP achieved 19.3% higher median query throughput and 32.7% lower median query RTT than fast-forward. Its median fresh connection-cycle rate was 10.9% higher. These are observations from the listed local workload; three short rounds do not establish statistical significance, maximum capacity, higher-concurrency scaling or the cause of performance differences.

RTT uses 1000 timed samples per client after 100 warmups. Each established-session throughput and connection-cycle phase requests five seconds, using actual observed elapsed time through final completion and cleanup as its rate denominator. A fresh connection cycle includes connect, authentication, the first verified `SELECT 1`, and close. Query throughput uses established authenticated connections and reports completed verified queries only. The earlier [payload comparison](2026-11-11-tcp-fast-forward-comparison.html) measures a different workload and remains unchanged.

Independent root verification recomputed all 72,000 latency samples and percentiles, 54 phase rates/counts and three-round summaries. All 18 trials succeeded with zero reported connection errors, drained hostgroup connections and successful task-owned process cleanup. Live held probes confirmed permanent fast-forward and native TCP routing through the shared hostgroup managers. The [raw JSON](2026-11-11-tcp-select1-fast-forward.json) preserves configuration, proofs, counters, resources, samples and hashes; the [reproduction guide](../../plugins/tcp_proxy/tests/README.fast-forward.md) documents the workload option. No production proxy code changed for this benchmark.

## Workload geometry

- Rounds: 3; clients: 4; warmups/client: 100; SELECT 1 RTT samples/client: 1000.
- Requested phase duration: 5.0 s; phases: `['rtt_select1', 'connections', 'select1_qps']`; timeout: 2000 ms.
- Order rotation: `[['direct', 'native', 'ff'], ['native', 'ff', 'direct'], ['ff', 'direct', 'native']]`.

## Provenance

- host: `/tmp/tcp-four-table/core-final/proxysql` sha256 `81c4f518f15e05af5de94a14ac445570ffbd0845e9f7bd4a2e9a85b281800d02`
- plugin: `/tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so` sha256 `f4111f8949276645977d9ee917eed9784c574017d3a00709050b614ca527b9c4`
- client: `/tmp/tcp-select1-benchmark/fast_forward_bench_client` sha256 `87092ec5d5a95b73acc8e9278f686e97ad12641e7bb202c2f7ac1f52384c572b`

- Build flags: `-std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread`; include flags: `-I/mnt/data/rene/proxysql5/proxysql/deps/mariadb-client-library/mariadb_client/include -I/mnt/data/rene/proxysql5/proxysql/deps/postgresql/postgresql/src/interfaces/libpq -I/mnt/data/rene/proxysql5/proxysql/deps/postgresql/postgres-REL_16_10/src/include`
- Link inputs: `/mnt/data/rene/proxysql5/proxysql/deps/mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a /lib/x86_64-linux-gnu/libpq.so.5 -lssl -lcrypto -lz -ldl -lm -lresolv -pthread`
- Client library versions: `{'mariadb_connector_c': '3.3.8', 'libpq': '160015'}`
- Host: `{'node': 'dev128', 'system': 'Linux', 'release': '6.8.0-85-generic', 'machine': 'x86_64', 'processor': 'x86_64', 'cpu_model': 'AMD Ryzen 9 5950X 16-Core Processor', 'cpu_count': 32, 'mem_total_kb': 131804344, 'uid': 1000, 'python': '3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]'}`

## Per-round exact SELECT 1 results

| Proto | Round | Path | RTT p50/p95/p99 (us) | Connections/s | SELECT1 QPS | requested/actual s |
|---|---:|---|---|---:|---:|---|
| mysql | 1 | direct | 46.1/74.2/79.7 | 14588.6 | 96946.1 | 5.00/5.00 |
| mysql | 1 | native | 66.5/73.1/81.7 | 7999.9 | 40419.2 | 5.00/5.00 |
| mysql | 1 | ff | 84.4/109.4/122.8 | 3449.1 | 42661.5 | 5.00/5.00 |
| mysql | 2 | direct | 43.7/59.4/69.3 | 14490.4 | 116032.0 | 5.00/5.00 |
| mysql | 2 | native | 71.7/81.9/88.3 | 8208.1 | 49002.4 | 5.00/5.00 |
| mysql | 2 | ff | 69.8/79.0/100.3 | 3818.7 | 47272.9 | 5.00/5.00 |
| mysql | 3 | direct | 52.5/63.6/74.9 | 14499.9 | 108923.0 | 5.00/5.00 |
| mysql | 3 | native | 69.8/115.9/127.5 | 8097.0 | 46605.7 | 5.00/5.00 |
| mysql | 3 | ff | 78.1/115.3/125.9 | 3434.2 | 47618.3 | 5.00/5.00 |
| pgsql | 1 | direct | 52.3/60.3/72.6 | 1665.7 | 89524.0 | 5.00/5.00 |
| pgsql | 1 | native | 52.1/64.9/73.2 | 1474.6 | 64281.2 | 5.00/5.00 |
| pgsql | 1 | ff | 67.1/86.8/94.1 | 1423.4 | 49179.9 | 5.00/5.00 |
| pgsql | 2 | direct | 48.3/56.1/64.1 | 1678.2 | 90566.7 | 5.00/5.00 |
| pgsql | 2 | native | 59.6/73.9/82.9 | 1569.7 | 56954.7 | 5.00/5.00 |
| pgsql | 2 | ff | 80.7/115.2/130.8 | 1378.8 | 48077.5 | 5.00/5.00 |
| pgsql | 3 | direct | 54.5/70.0/87.7 | 1670.9 | 90268.9 | 5.00/5.00 |
| pgsql | 3 | native | 54.3/63.1/69.6 | 1539.0 | 57360.0 | 5.00/5.00 |
| pgsql | 3 | ff | 82.3/137.0/160.4 | 1387.6 | 44010.4 | 5.00/5.00 |

## Median and range across rounds

| Proto | Path | RTT p50 us | RTT p95 us | RTT p99 us | Connections/s | SELECT1 QPS |
|---|---|---:|---:|---:|---:|---:|
| mysql | direct | 46.1 [43.7-52.5] | 63.6 [59.4-74.2] | 74.9 [69.3-79.7] | 14499.9 [14490.4-14588.6] | 108923.0 [96946.1-116032.0] |
| mysql | native | 69.8 [66.5-71.7] | 81.9 [73.1-115.9] | 88.3 [81.7-127.5] | 8097.0 [7999.9-8208.1] | 46605.7 [40419.2-49002.4] |
| mysql | ff | 78.1 [69.8-84.4] | 109.4 [79.0-115.3] | 122.8 [100.3-125.9] | 3449.1 [3434.2-3818.7] | 47272.9 [42661.5-47618.3] |
| pgsql | direct | 52.3 [48.3-54.5] | 60.3 [56.1-70.0] | 72.6 [64.1-87.7] | 1670.9 [1665.7-1678.2] | 90268.9 [89524.0-90566.7] |
| pgsql | native | 54.3 [52.1-59.6] | 64.9 [63.1-73.9] | 73.2 [69.6-82.9] | 1539.0 [1474.6-1569.7] | 57360.0 [56954.7-64281.2] |
| pgsql | ff | 80.7 [67.1-82.3] | 115.2 [86.8-137.0] | 130.8 [94.1-160.4] | 1387.6 [1378.8-1423.4] | 48077.5 [44010.4-49179.9] |

## Configuration/auth/TLS evidence

- mysql fixture: `real-mysql` /usr/sbin/mysqld  Ver 8.0.46-0ubuntu0.24.04.4 for Linux on x86_64 ((Ubuntu)) auth=`mysql_native_password`.
- mysql round 1 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- mysql round 1 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- mysql round 2 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- mysql round 2 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- mysql round 3 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- mysql round 3 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql fixture: `real-postgresql` postgres (PostgreSQL) 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) auth=`md5`.
- pgsql round 1 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql round 1 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql round 2 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql round 2 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql round 3 native: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.
- pgsql round 3 ff: exact_sql=`SELECT 1` expected=`1` sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` tls=`False` gss=`False` tcp_nodelay=`1`.

## Application result and wire counters

The result value is one byte; SQL text is eight bytes per query. The legacy application_request_bytes counter counts the one-byte constant value and is not the SQL request size. HGM/TCP counters include framing/auth.

| Proto | Round | Path | Phase | Queries/cycles | App response bytes | HGM sent/recv | TCP wire c2s/s2c |
|---|---:|---|---|---:|---:|---|---|
| mysql | 1 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| mysql | 1 | direct | connections | 72947 | 72947 | None/None | None/None |
| mysql | 1 | direct | select1_qps | 484739 | 484739 | None/None | None/None |
| mysql | 1 | native | rtt_select1 | 4000 | 4000 | 58184/247064 | 58184/247064 |
| mysql | 1 | native | connections | 40003 | 40003 | 10360777/8880666 | 10360777/8880666 |
| mysql | 1 | native | select1_qps | 202102 | 202102 | 2633510/11340776 | 2633510/11340776 |
| mysql | 1 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| mysql | 1 | ff | connections | 17247 | 17247 | 0/0 | None/None |
| mysql | 1 | ff | select1_qps | 213326 | 213326 | 0/0 | None/None |
| mysql | 2 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| mysql | 2 | direct | connections | 72455 | 72455 | None/None | None/None |
| mysql | 2 | direct | select1_qps | 580170 | 580170 | None/None | None/None |
| mysql | 2 | native | rtt_select1 | 4000 | 4000 | 58184/247064 | 58184/247064 |
| mysql | 2 | native | connections | 41043 | 41043 | 10630137/9111546 | 10630137/9111546 |
| mysql | 2 | native | select1_qps | 245020 | 245020 | 3191444/13744184 | 3191444/13744184 |
| mysql | 2 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| mysql | 2 | ff | connections | 19097 | 19097 | 0/0 | None/None |
| mysql | 2 | ff | select1_qps | 236371 | 236371 | 0/0 | None/None |
| mysql | 3 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| mysql | 3 | direct | connections | 72503 | 72503 | None/None | None/None |
| mysql | 3 | direct | select1_qps | 544625 | 544625 | None/None | None/None |
| mysql | 3 | native | rtt_select1 | 4000 | 4000 | 58184/247064 | 58184/247064 |
| mysql | 3 | native | connections | 40488 | 40488 | 10486392/8988336 | 10486392/8988336 |
| mysql | 3 | native | select1_qps | 233037 | 233037 | 3035665/13073136 | 3035665/13073136 |
| mysql | 3 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| mysql | 3 | ff | connections | 17174 | 17174 | 0/0 | None/None |
| mysql | 3 | ff | select1_qps | 238105 | 238105 | 0/0 | None/None |
| pgsql | 1 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| pgsql | 1 | direct | connections | 8332 | 8332 | None/None | None/None |
| pgsql | 1 | direct | select1_qps | 447629 | 447629 | None/None | None/None |
| pgsql | 1 | native | rtt_select1 | 4000 | 4000 | 62060/292300 | 62060/292300 |
| pgsql | 1 | native | connections | 7376 | 7376 | 951504/3990416 | 951504/3990416 |
| pgsql | 1 | native | select1_qps | 321412 | 321412 | 4505828/21241492 | 4505828/21241492 |
| pgsql | 1 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| pgsql | 1 | ff | connections | 7120 | 7120 | 0/0 | None/None |
| pgsql | 1 | ff | select1_qps | 245911 | 245911 | 0/0 | None/None |
| pgsql | 2 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| pgsql | 2 | direct | connections | 8395 | 8395 | None/None | None/None |
| pgsql | 2 | direct | select1_qps | 452845 | 452845 | None/None | None/None |
| pgsql | 2 | native | rtt_select1 | 4000 | 4000 | 62060/292300 | 62060/292300 |
| pgsql | 2 | native | connections | 7852 | 7852 | 1012908/4247932 | 1012908/4247932 |
| pgsql | 2 | native | select1_qps | 284783 | 284783 | 3993022/18823978 | 3993022/18823978 |
| pgsql | 2 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| pgsql | 2 | ff | connections | 6897 | 6897 | 0/0 | None/None |
| pgsql | 2 | ff | select1_qps | 240400 | 240400 | 0/0 | None/None |
| pgsql | 3 | direct | rtt_select1 | 4000 | 4000 | None/None | None/None |
| pgsql | 3 | direct | connections | 8358 | 8358 | None/None | None/None |
| pgsql | 3 | direct | select1_qps | 451355 | 451355 | None/None | None/None |
| pgsql | 3 | native | rtt_select1 | 4000 | 4000 | 62060/292300 | 62060/292300 |
| pgsql | 3 | native | connections | 7699 | 7699 | 993171/4165159 | 993171/4165159 |
| pgsql | 3 | native | select1_qps | 286805 | 286805 | 4021330/18957430 | 4021330/18957430 |
| pgsql | 3 | ff | rtt_select1 | 4000 | 4000 | 0/0 | None/None |
| pgsql | 3 | ff | connections | 6942 | 6942 | 0/0 | None/None |
| pgsql | 3 | ff | select1_qps | 220058 | 220058 | 0/0 | None/None |

## Active proof

- mysql round 1 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-000/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `36040`; runtime active/fast_forward `1/1`; status `22`.
- mysql round 1 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-000/native/proof/mysql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- mysql round 2 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-001/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `33208`; runtime active/fast_forward `1/1`; status `22`.
- mysql round 2 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-001/native/proof/mysql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- mysql round 3 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-002/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `42674`; runtime active/fast_forward `1/1`; status `22`.
- mysql round 3 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/mysql/round-002/native/proof/mysql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 1 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-000/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `36844`; runtime active/fast_forward `1/1`; status `22`.
- pgsql round 1 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-000/native/proof/pgsql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 2 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-001/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `59784`; runtime active/fast_forward `1/1`; status `22`.
- pgsql round 2 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-001/native/proof/pgsql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 3 FF: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-002/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `60866`; runtime active/fast_forward `1/1`; status `22`.
- pgsql round 3 native: `/tmp/tcp-select1-benchmark/measure-20261111-221540-3592982/pgsql/round-002/native/proof/pgsql-native-proof.json`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.

## Resource scopes and limitations

- Proxy CPU/RSS/fds/threads cover the whole daemon PID; database CPU is the whole mysqld PID or PostgreSQL postmaster PID only (forked backend CPU excluded).
- Client CPU is a live-sampled estimate and can miss startup/exit ticks.
- PostgreSQL fast-forward HGM byte counters are zero on this host; raw application results and native plugin wire counters remain separate.
- No wire relay capacity, general SQL capacity or causal claim is made.
