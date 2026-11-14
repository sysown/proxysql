# Native mapped TCP vs permanent SQL fast-forward

Status: **MEASURED**

Generated: `2026-11-11T20:09:10.499185+00:00`

Profile: `measure`

This report is generated from real task-owned MySQL and PostgreSQL servers and immutable benchmarked binaries. The smoke profile is not a measurement and must not be interpreted as benchmark results.

## Interpretation and verification

The following comparisons use the median of three rotated rounds, with four clients and two workers per proxy path. Both proxy paths used the same backend, SQL text, client binary, plaintext transport and user configuration. Direct database results are included as a baseline below.

| Protocol | Metric | Native TCP | Fast-forward |
|---|---|---:|---:|
| MySQL | 64-byte query RTT p50 (microseconds) | 71.6 | 77.4 |
| MySQL | Fresh authenticated connection cycles/second | 8172 | 3791 |
| MySQL | 64 KiB payload throughput (MiB/s per direction) | 285.2 | 340.8 |
| MySQL | 1 MiB payload throughput (MiB/s per direction) | 319.5 | 349.0 |
| PostgreSQL | 64-byte query RTT p50 (microseconds) | 59.3 | 130.9 |
| PostgreSQL | Fresh authenticated connection cycles/second | 1553 | 1402 |
| PostgreSQL | 64 KiB payload throughput (MiB/s per direction) | 408.4 | 328.2 |
| PostgreSQL | 1 MiB payload throughput (MiB/s per direction) | 567.7 | 410.1 |

Native TCP achieved 2.16 times the MySQL connection-cycle rate. MySQL fast-forward had higher median sustained payload throughput: 19.5% for 64 KiB and 9.2% for 1 MiB. PostgreSQL native TCP had 54.7% lower median query RTT and higher median throughput: 24.4% for 64 KiB and 38.4% for 1 MiB.

These are local SQL workload observations. Each connection-rate and throughput phase lasted about two seconds; RTT used 1000 samples per client. Several metrics varied substantially between rounds; the ranges and all trial values below show that variation. The workload includes database SQL parsing/execution and client result validation. It does not establish maximum relay capacity, statistical significance, scaling at higher concurrency, encrypted transport performance, or the cause of the throughput differences. The results support a connection-setup benefit and a PostgreSQL benefit in this workload; they do not establish a universal performance advantage for native TCP.

A connection cycle includes connect, authentication, the first verified query and close. Throughput sends a SQL literal and returns the same payload; each reported direction has the stated application throughput, with protocol framing recorded separately. The native TCP relay used its configured 16 KiB buffer. No production code was changed for this comparison.

Root verification independently recomputed all 72 phase results, 72,000 raw RTT samples and percentiles, elapsed-time rates, exact payload byte totals, and round summaries. All trials had successful result validation, zero reported HGM connection errors and zero remaining Used/Free connections; all task-owned daemons and databases exited successfully. Live probes confirmed permanent SQL fast-forward and native TCP hostgroup accounting. The [raw JSON report](2026-11-11-tcp-fast-forward-comparison.json) contains the samples, proofs, configuration, counters and artifact hashes. The [reproduction guide](../../plugins/tcp_proxy/tests/README.fast-forward.md) describes the harness.

## Workload

- Rounds: 3; clients: 4; warmups/client: 20; RTT samples/client: 1000.
- Requested phase duration: 2.0 s; throughput payloads: [65536, 1048576] bytes.
- Order rotation: `[['direct', 'native', 'ff'], ['native', 'ff', 'direct'], ['ff', 'direct', 'native']]`.
- Smoke label: none (measured profile).

## Provenance

- host: `/tmp/tcp-four-table/core-final/proxysql` sha256 `81c4f518f15e05af5de94a14ac445570ffbd0845e9f7bd4a2e9a85b281800d02`
- plugin: `/tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so` sha256 `f4111f8949276645977d9ee917eed9784c574017d3a00709050b614ca527b9c4`
- client: `/tmp/tcp-ff-benchmark/fast_forward_bench_client` sha256 `c216b7f446ceaad45c3dc18400084b72198bf781623f3474a285093d6fe2d1cf`

Build/library evidence:

- Compiler: `/usr/bin/g++` ['g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0', 'Copyright (C) 2023 Free Software Foundation, Inc.']
- Flags: `-std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread`
- Include flags: `-I/mnt/data/rene/proxysql5/proxysql/deps/mariadb-client-library/mariadb_client/include -I/mnt/data/rene/proxysql5/proxysql/deps/postgresql/postgresql/src/interfaces/libpq -I/mnt/data/rene/proxysql5/proxysql/deps/postgresql/postgres-REL_16_10/src/include`
- Link inputs: `/mnt/data/rene/proxysql5/proxysql/deps/mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a /lib/x86_64-linux-gnu/libpq.so.5 -lssl -lcrypto -lz -ldl -lm -lresolv -pthread`
- Linked client library versions: `{'mariadb_connector_c': '3.3.8', 'libpq': '160015'}`
- Host: `{'node': 'dev128', 'system': 'Linux', 'release': '6.8.0-85-generic', 'machine': 'x86_64', 'processor': 'x86_64', 'cpu_model': 'AMD Ryzen 9 5950X 16-Core Processor', 'cpu_count': 32, 'mem_total_kb': 131804344, 'uid': 1000, 'python': '3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]'}`

Source/host provenance references:

- `/tmp/tcp-ff-benchmark/benchmark-design.md` sha256 `a5420021fa3bd51da09c47b8e64cb1ad6772ea8a1d00733d2ef41763f75062bc`
- `/tmp/tcp-ff-benchmark/ff-mode-evidence.md` sha256 `4e3682f91155460478b8c24897eb9f4e95caae5ec39e5c71fe1e4b48202a6c04`
- `/tmp/tcp-four-table/core-final/all-core-source-hashes.json` sha256 `cb62c4b1eb0d85ec5c3440548d37a6c165b0d4a221125259af0942cffd3fd1a6`
- `/tmp/tcp-four-table/core-final/manifest.json` sha256 `05c62af6935bf59cf0902d9ad8b8637a967e782a582a9d58d5e459dc9ff3110c`
- `/tmp/tcp-four-table/plugin-final/SHA256SUMS` sha256 `ecad4969fed2ef6dd833688cfdd0024cbbb634dc9b4199273c7663bae222b30b`
- `/tmp/tcp-four-table/plugin-final/manifest.json` sha256 `d8a14d467d97dcb0b7f66f5dfef5eefbbddabd764db257331d84d335e7fccbb0`

## Per-trial values (all rounds)

| Proto | Round | Path | RTT p50/p95/p99 (us) | Conn/s | 64K q/s | 64K MiB/s | 1M q/s | 1M MiB/s | requested/actual s |
|---|---:|---|---|---:|---:|---:|---:|---:|---|
| mysql | 1 | direct | 37.4/43.3/49.9 | 14899.5 | 10695.2 | 668.451 | 386.7 | 386.726 | 2.00/2.00 |
| mysql | 1 | native | 71.6/92.5/101.0 | 7966.6 | 4931.4 | 308.209 | 364.1 | 364.085 | 2.00/2.00 |
| mysql | 1 | ff | 74.7/94.8/107.7 | 3791.1 | 5152.3 | 322.021 | 349.0 | 348.952 | 2.00/2.00 |
| mysql | 2 | direct | 36.3/48.4/57.4 | 14908.1 | 8780.8 | 548.800 | 660.3 | 660.338 | 2.00/2.00 |
| mysql | 2 | native | 129.6/151.8/169.1 | 8172.5 | 4444.5 | 277.779 | 319.5 | 319.471 | 2.00/2.00 |
| mysql | 2 | ff | 86.3/112.3/125.5 | 3693.0 | 5453.1 | 340.818 | 246.6 | 246.604 | 2.00/2.00 |
| mysql | 3 | direct | 62.3/73.2/86.1 | 14854.8 | 9773.4 | 610.839 | 372.1 | 372.148 | 2.00/2.00 |
| mysql | 3 | native | 68.1/77.6/87.0 | 8281.1 | 4563.9 | 285.247 | 297.8 | 297.753 | 2.00/2.00 |
| mysql | 3 | ff | 77.4/88.5/98.4 | 3791.7 | 5958.6 | 372.410 | 360.1 | 360.097 | 2.00/2.00 |
| pgsql | 1 | direct | 54.1/61.4/69.0 | 1671.8 | 11696.3 | 731.021 | 854.7 | 854.705 | 2.00/2.00 |
| pgsql | 1 | native | 53.6/66.1/74.0 | 1552.7 | 8081.1 | 505.068 | 567.7 | 567.665 | 2.00/2.00 |
| pgsql | 1 | ff | 130.9/164.8/186.9 | 1426.7 | 3251.6 | 203.228 | 421.4 | 421.387 | 2.00/2.00 |
| pgsql | 2 | direct | 32.4/41.5/55.3 | 1647.3 | 11636.8 | 727.300 | 850.1 | 850.146 | 2.00/2.00 |
| pgsql | 2 | native | 61.0/69.7/75.9 | 1542.8 | 5999.3 | 374.954 | 567.9 | 567.863 | 2.00/2.00 |
| pgsql | 2 | ff | 79.5/98.6/112.6 | 1401.9 | 5251.8 | 328.236 | 401.3 | 401.284 | 2.00/2.00 |
| pgsql | 3 | direct | 45.0/60.4/72.2 | 1646.3 | 11698.5 | 731.156 | 850.0 | 850.046 | 2.00/2.00 |
| pgsql | 3 | native | 59.3/67.5/73.5 | 1565.9 | 6535.1 | 408.442 | 491.9 | 491.905 | 2.00/2.00 |
| pgsql | 3 | ff | 135.9/171.9/199.0 | 1364.1 | 5921.6 | 370.098 | 410.1 | 410.079 | 2.00/2.00 |

## Median and range across rounds

| Proto | Path | RTT p50 us | RTT p95 us | RTT p99 us | Conn/s | 64K q/s | 64K MiB/s | 1M q/s | 1M MiB/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mysql | direct | 37.4 [36.3-62.3] | 48.4 [43.3-73.2] | 57.4 [49.9-86.1] | 14899.5 [14854.8-14908.1] | 9773.4 [8780.8-10695.2] | 610.8 [548.8-668.5] | 386.7 [372.1-660.3] | 386.7 [372.1-660.3] |
| mysql | native | 71.6 [68.1-129.6] | 92.5 [77.6-151.8] | 101.0 [87.0-169.1] | 8172.5 [7966.6-8281.1] | 4563.9 [4444.5-4931.4] | 285.2 [277.8-308.2] | 319.5 [297.8-364.1] | 319.5 [297.8-364.1] |
| mysql | ff | 77.4 [74.7-86.3] | 94.8 [88.5-112.3] | 107.7 [98.4-125.5] | 3791.1 [3693.0-3791.7] | 5453.1 [5152.3-5958.6] | 340.8 [322.0-372.4] | 349.0 [246.6-360.1] | 349.0 [246.6-360.1] |
| pgsql | direct | 45.0 [32.4-54.1] | 60.4 [41.5-61.4] | 69.0 [55.3-72.2] | 1647.3 [1646.3-1671.8] | 11696.3 [11636.8-11698.5] | 731.0 [727.3-731.2] | 850.1 [850.0-854.7] | 850.1 [850.0-854.7] |
| pgsql | native | 59.3 [53.6-61.0] | 67.5 [66.1-69.7] | 74.0 [73.5-75.9] | 1552.7 [1542.8-1565.9] | 6535.1 [5999.3-8081.1] | 408.4 [375.0-505.1] | 567.7 [491.9-567.9] | 567.7 [491.9-567.9] |
| pgsql | ff | 130.9 [79.5-135.9] | 164.8 [98.6-171.9] | 186.9 [112.6-199.0] | 1401.9 [1364.1-1426.7] | 5251.8 [3251.6-5921.6] | 328.2 [203.2-370.1] | 410.1 [401.3-421.4] | 410.1 [401.3-421.4] |

## Configuration/auth/TLS evidence

- mysql fixture: `real-mysql` /usr/sbin/mysqld  Ver 8.0.46-0ubuntu0.24.04.4 for Linux on x86_64 ((Ubuntu)) auth=`mysql_native_password`.
- mysql round 1 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- mysql round 1 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- mysql round 2 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- mysql round 2 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- mysql round 3 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- mysql round 3 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	101	1	1	0	1	1000` source=`101	127.0.0.1	42025	ONLINE	1	0	1000	0	0` pgsql_auth=`None` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql fixture: `real-postgresql` postgres (PostgreSQL) 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) auth=`md5`.
- pgsql round 1 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql round 1 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql round 2 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql round 2 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql round 3 native: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.
- pgsql round 3 ff: sql_threads=`2` tcp_workers=`2	10000	16384	5000	30000` user=`ffbench	1	0	201	1	1	0	1	1000` source=`201	127.0.0.1	37425	ONLINE	1	0	1000	0	0` pgsql_auth=`2` tls=`False` ssl_cipher=`` gss=`False` tcp_nodelay=`1`.

## Wire counters versus application payload

Application bytes below come from verified native-client queries. HGM/TCP wire counters include authentication, SQL text and protocol framing and are never expected to equal payload bytes. Native paths expose plugin TCP and HGM counters; this immutable host exposes zero HGM byte counters for fast-forward sessions, so those zeros are recorded rather than substituted.

| Proto | Round | Path | Phase | App response bytes | HGM sent/recv delta | TCP wire c2s/s2c delta |
|---|---:|---|---|---:|---|---|
| mysql | 1 | direct | rtt64 | 256000 | None/None | None/None |
| mysql | 1 | direct | connections | 1907392 | None/None | None/None |
| mysql | 1 | direct | throughput64k | 1402077184 | None/None | None/None |
| mysql | 1 | direct | throughput1m | 814743552 | None/None | None/None |
| mysql | 1 | native | rtt64 | 256000 | 417144/563704 | 417144/563704 |
| mysql | 1 | native | connections | 1019904 | 5545728/4844544 | 5545728/4844544 |
| mysql | 1 | native | throughput64k | 646512640 | 652134414/652521949 | 652134414/652521949 |
| mysql | 1 | native | throughput1m | 768606208 | 852524166/852555553 | 852524166/852555553 |
| mysql | 1 | ff | rtt64 | 256000 | 0/0 | None/None |
| mysql | 1 | ff | connections | 485440 | 0/0 | None/None |
| mysql | 1 | ff | throughput64k | 675479552 | 0/0 | None/None |
| mysql | 1 | ff | throughput1m | 735051776 | 0/0 | None/None |
| mysql | 2 | direct | rtt64 | 256000 | None/None | None/None |
| mysql | 2 | direct | connections | 1908480 | None/None | None/None |
| mysql | 2 | direct | throughput64k | 1151074304 | None/None | None/None |
| mysql | 2 | direct | throughput1m | 1388314624 | None/None | None/None |
| mysql | 2 | native | rtt64 | 256000 | 417144/563704 | 417144/563704 |
| mysql | 2 | native | connections | 1046272 | 5689104/4969792 | 5689104/4969792 |
| mysql | 2 | native | throughput64k | 582746112 | 588330912/588680500 | 588330912/588680500 |
| mysql | 2 | native | throughput1m | 672137216 | 756051678/756079477 | 756051678/756079477 |
| mysql | 2 | ff | rtt64 | 256000 | 0/0 | None/None |
| mysql | 2 | ff | connections | 472960 | 0/0 | None/None |
| mysql | 2 | ff | throughput64k | 715063296 | 0/0 | None/None |
| mysql | 2 | ff | throughput1m | 522190848 | 0/0 | None/None |
| mysql | 3 | direct | rtt64 | 256000 | None/None | None/None |
| mysql | 3 | direct | connections | 1901632 | None/None | None/None |
| mysql | 3 | direct | throughput64k | 1281228800 | None/None | None/None |
| mysql | 3 | direct | throughput1m | 784334848 | None/None | None/None |
| mysql | 3 | native | rtt64 | 256000 | 417144/563704 | 417144/563704 |
| mysql | 3 | native | connections | 1060224 | 5764968/5036064 | 5764968/5036064 |
| mysql | 3 | native | throughput64k | 598540288 | 604134246/604493233 | 604134246/604493233 |
| mysql | 3 | native | throughput1m | 628097024 | 712009890/712036051 | 712009890/712036051 |
| mysql | 3 | ff | rtt64 | 256000 | 0/0 | None/None |
| mysql | 3 | ff | connections | 485504 | 0/0 | None/None |
| mysql | 3 | ff | throughput64k | 781320192 | 0/0 | None/None |
| mysql | 3 | ff | throughput1m | 759169024 | 0/0 | None/None |
| pgsql | 1 | direct | rtt64 | 256000 | None/None | None/None |
| pgsql | 1 | direct | connections | 214272 | None/None | None/None |
| pgsql | 1 | direct | throughput64k | 1533411328 | None/None | None/None |
| pgsql | 1 | direct | throughput1m | 1795162112 | None/None | None/None |
| pgsql | 1 | native | rtt64 | 256000 | 420700/577180 | 420700/577180 |
| pgsql | 1 | native | connections | 198976 | 677762/1915144 | 677762/1915144 |
| pgsql | 1 | native | throughput64k | 1059454976 | 1065331910/1065950698 | 1065331910/1065950698 |
| pgsql | 1 | native | throughput1m | 1193279488 | 1277213530/1277261254 | 1277213530/1277261254 |
| pgsql | 1 | ff | rtt64 | 256000 | 0/0 | None/None |
| pgsql | 1 | ff | connections | 182848 | 0/0 | None/None |
| pgsql | 1 | ff | throughput64k | 426377216 | 0/0 | None/None |
| pgsql | 1 | ff | throughput1m | 888143872 | 0/0 | None/None |
| pgsql | 2 | direct | rtt64 | 256000 | None/None | None/None |
| pgsql | 2 | direct | connections | 211072 | None/None | None/None |
| pgsql | 2 | direct | throughput64k | 1525612544 | None/None | None/None |
| pgsql | 2 | direct | throughput1m | 1786773504 | None/None | None/None |
| pgsql | 2 | native | rtt64 | 256000 | 420700/577180 | 420700/577180 |
| pgsql | 2 | native | connections | 197568 | 672966/1901592 | 672966/1901592 |
| pgsql | 2 | native | throughput64k | 786563072 | 792277610/792738166 | 792277610/792738166 |
| pgsql | 2 | native | throughput1m | 1193279488 | 1277213530/1277261254 | 1277213530/1277261254 |
| pgsql | 2 | ff | rtt64 | 256000 | 0/0 | None/None |
| pgsql | 2 | ff | connections | 179648 | 0/0 | None/None |
| pgsql | 2 | ff | throughput64k | 688652288 | 0/0 | None/None |
| pgsql | 2 | ff | throughput1m | 846200832 | 0/0 | None/None |
| pgsql | 3 | direct | rtt64 | 256000 | None/None | None/None |
| pgsql | 3 | direct | connections | 210944 | None/None | None/None |
| pgsql | 3 | direct | throughput64k | 1533673472 | None/None | None/None |
| pgsql | 3 | direct | throughput1m | 1785724928 | None/None | None/None |
| pgsql | 3 | native | rtt64 | 256000 | 420700/577180 | 420700/577180 |
| pgsql | 3 | native | connections | 200640 | 683430/1931160 | 683430/1931160 |
| pgsql | 3 | native | throughput64k | 856817664 | 862574010/863075302 | 862574010/863075302 |
| pgsql | 3 | native | throughput1m | 1034944512 | 1118872665/1118914651 | 1118872665/1118914651 |
| pgsql | 3 | ff | rtt64 | 256000 | 0/0 | None/None |
| pgsql | 3 | ff | connections | 174784 | 0/0 | None/None |
| pgsql | 3 | ff | throughput64k | 776339456 | 0/0 | None/None |
| pgsql | 3 | ff | throughput1m | 862978048 | 0/0 | None/None |

## Active proof

- mysql round 1 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-000/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `59202`; runtime fast_forward `1`; status `22`.
- mysql round 1 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-000/native/proof/mysql-native-proof.json`; held cli_port `50932`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- mysql round 2 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-001/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `47716`; runtime fast_forward `1`; status `22`.
- mysql round 2 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-001/native/proof/mysql-native-proof.json`; held cli_port `51818`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- mysql round 3 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-002/ff/proof/mysql-ff-proof.json`; command `Fast forward`; cli_port `50340`; runtime fast_forward `1`; status `22`.
- mysql round 3 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/mysql/round-002/native/proof/mysql-native-proof.json`; held cli_port `45664`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 1 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-000/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `52972`; runtime fast_forward `1`; status `22`.
- pgsql round 1 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-000/native/proof/pgsql-native-proof.json`; held cli_port `57424`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 2 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-001/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `60930`; runtime fast_forward `1`; status `22`.
- pgsql round 2 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-001/native/proof/pgsql-native-proof.json`; held cli_port `38206`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.
- pgsql round 3 FF: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-002/ff/proof/pgsql-ff-proof.json`; command `Fast forward`; cli_port `37060`; runtime fast_forward `1`; status `22`.
- pgsql round 3 native: `/tmp/tcp-ff-benchmark/measure-20261111-200910-3493133/pgsql/round-002/native/proof/pgsql-native-proof.json`; held cli_port `58380`; SQL processlist matches `0`; plugin active `1`; HGM ConnUsed `1`.

## Resource summary

| Proto | Round | Path | Proxy CPU% | Proxy RSS KB | Proxy fd/thread | DB CPU% | DB RSS KB | Client CPU% | Client RSS KB |
|---|---:|---|---:|---:|---|---:|---:|---:|---:|
| mysql | 1 | direct |  | -1 | -1/-1 | 306.0 | 415140 | 106.0 | 22436 |
| mysql | 1 | native | 98.7 | 37364 | 29/11 | 216.1 | 424612 | 88.7 | 23092 |
| mysql | 1 | ff | 98.2 | 38980 | 29/11 | 162.5 | 424612 | 73.7 | 20532 |
| mysql | 2 | direct |  | -1 | -1/-1 | 297.6 | 429732 | 121.0 | 25344 |
| mysql | 2 | native | 99.0 | 37008 | 29/11 | 206.7 | 424612 | 98.3 | 22164 |
| mysql | 2 | ff | 95.6 | 41084 | 29/11 | 140.9 | 424612 | 69.8 | 19924 |
| mysql | 3 | direct |  | -1 | -1/-1 | 303.5 | 435108 | 111.3 | 23484 |
| mysql | 3 | native | 98.6 | 37080 | 29/11 | 207.2 | 435364 | 82.7 | 21260 |
| mysql | 3 | ff | 98.5 | 40496 | 29/11 | 162.4 | 429732 | 73.5 | 20580 |
| pgsql | 1 | direct |  | -1 | -1/-1 | 0.0 | 37120 | 98.8 | 29572 |
| pgsql | 1 | native | 94.2 | 35412 | 33/12 | 0.0 | 37120 | 65.7 | 29836 |
| pgsql | 1 | ff | 103.8 | 41840 | 27/11 | 0.0 | 37120 | 40.0 | 29560 |
| pgsql | 2 | direct |  | -1 | -1/-1 | 0.2 | 37120 | 100.8 | 29828 |
| pgsql | 2 | native | 90.2 | 36604 | 31/11 | 0.0 | 37120 | 63.1 | 29572 |
| pgsql | 2 | ff | 106.9 | 42804 | 27/11 | 0.0 | 37120 | 43.2 | 29824 |
| pgsql | 3 | direct |  | -1 | -1/-1 | 0.2 | 37120 | 97.0 | 29572 |
| pgsql | 3 | native | 91.2 | 36032 | 33/11 | 0.0 | 37120 | 61.1 | 30084 |
| pgsql | 3 | ff | 87.7 | 42152 | 27/11 | 0.2 | 37120 | 40.6 | 29824 |

## Resource scopes and limitations

- Proxy resources cover the whole ProxySQL daemon PID; database resources cover the whole mysqld PID or PostgreSQL postmaster PID only, so PostgreSQL forked backend CPU is not included.
- Client CPU is a bounded live-sampled estimate (50 ms) and can miss startup/exit ticks. RSS/fd/thread endpoint maxima are named explicitly.
- Byte equality to application payload is not required or used for HGM/TCP wire counters.
- No winner or production-capacity claim is made from these workloads.
