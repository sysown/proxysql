#!/bin/bash
# capture.bash - Regenerate test/tsdb-lab/fixtures/seed-10min.csv.gz from a
# real 3-node ProxySQL cluster under load.
#
# This is a HUMAN-RUN script, not part of CI. It:
#   1. Brings up a MySQL backend via the standard test infra harness.
#   2. Spawns 3 ProxySQL instances (src/proxysql) directly on the host,
#      wired into a leader-election cluster.
#   3. Configures them to route to the backend across two hostgroups.
#   4. Drives variable-rate load (sysbench, or a mysql-client fallback)
#      through the leader for DURATION_S seconds.
#   5. Dumps the leader's stats_history.tsdb_metrics window to CSV, gzips
#      it, and writes fixtures/seed-10min.csv.gz + a provenance README.
#   6. Shuts the 3 ProxySQL instances down and leaves the backend infra
#      running (the harness owns its lifecycle).
#
# Usage:
#   bash test/tsdb-lab/capture.bash
#   DURATION_S=120 bash test/tsdb-lab/capture.bash   # quick smoke run
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WORKSPACE="${WORKSPACE:-$(git rev-parse --show-toplevel)}"
DURATION_S="${DURATION_S:-600}"
INFRA_ID="tsdb-lab"
TAP_GROUP="legacy-g5"

LAB_DIR="${WORKSPACE}/test/tsdb-lab"
CAPTURE_DIR="${LAB_DIR}/.capture"
FIXTURES_DIR="${LAB_DIR}/fixtures"
FIXTURE_CSV_GZ="${FIXTURES_DIR}/seed-10min.csv.gz"
FIXTURE_README="${FIXTURES_DIR}/seed-10min.README"
PROXYSQL_BIN="${WORKSPACE}/src/proxysql"

# 3-node cluster: admin ports 16362/16372/16382, mysql = admin+1.
# Weights descend so node1 deterministically wins leader election, mirroring
# test/tap/tests/test_cluster_leader_election-t.cpp.
NODE_IDX=(1 2 3)
ADMIN_PORT=(16362 16372 16382)
MYSQL_PORT=(16363 16373 16383)
WEIGHT=(300 200 100)

CLUSTER_USER="cluster1"
CLUSTER_PASS="secret1pass"
BACKEND_USER="testuser"
BACKEND_PASS="testuser"
SYSBENCH_DB="sysbench"

MAX_FIXTURE_BYTES=$((2 * 1024 * 1024))

PIDS=()
LEADER_IDX=0  # 0-based index into the arrays above; refined after convergence

log() { echo ">>> [capture.bash] $*"; }
err() { echo "ERROR: $*" >&2; }

admin_sql() {
    # admin_sql <admin_port> <sql>
    mysql --connect-timeout=5 -h127.0.0.1 -P"$1" -uadmin -padmin -N -B -e "$2"
}

admin_sql_ok() {
    mysql --connect-timeout=5 -h127.0.0.1 -P"$1" -uadmin -padmin -e "$2" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Teardown: always attempt to stop the 3 nodes we spawned, whatever else
# happened. The backend infra is intentionally left running (harness-owned).
# ---------------------------------------------------------------------------
cleanup() {
    local rc=$?
    log "Tearing down capture cluster..."
    for i in "${!NODE_IDX[@]}"; do
        admin_sql_ok "${ADMIN_PORT[$i]}" "PROXYSQL SHUTDOWN" || true
    done
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid:-}" ] || continue
        if kill -0 "$pid" 2>/dev/null; then
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.5
            done
            kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    local leftover=0
    for p in "${ADMIN_PORT[@]}"; do
        if ss -ltn 2>/dev/null | grep -q ":${p}\b"; then
            err "listener still present on admin port ${p} after shutdown"
            leftover=1
        fi
    done
    [ "$leftover" -eq 0 ] && log "confirmed no listeners remain on capture admin ports"
    exit "$rc"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 0: sanity checks
# ---------------------------------------------------------------------------
if [ ! -x "${PROXYSQL_BIN}" ]; then
    err "${PROXYSQL_BIN} not found or not executable."
    err "Build it first: PROXYSQL31=1 make debug -j\$(nproc)"
    exit 1
fi

for p in "${ADMIN_PORT[@]}" "${MYSQL_PORT[@]}"; do
    if ss -ltn 2>/dev/null | grep -q ":${p}\b"; then
        err "port ${p} is already in use; refusing to start (check for another capture.bash run or a stale node)"
        exit 1
    fi
done

if ! command -v mysql >/dev/null 2>&1; then
    err "mysql client not found in PATH; required to configure/query ProxySQL admin"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: bring up the MySQL backend via the standard harness.
# COMPOSE_PROJECT=placeholder works around a known ensure-infras.bash bug
# when the backend for this INFRA_ID is already running.
# ---------------------------------------------------------------------------
log "Ensuring backend infra (INFRA_ID=${INFRA_ID}, TAP_GROUP=${TAP_GROUP})..."
export COMPOSE_PROJECT=placeholder
WORKSPACE="${WORKSPACE}" INFRA_ID="${INFRA_ID}" TAP_GROUP="${TAP_GROUP}" \
    "${WORKSPACE}/test/infra/control/ensure-infras.bash"

BACKEND_CONTAINER="infra-dbdeployer-mysql57-${INFRA_ID}-dbdeployer1-1"
BACKEND_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${BACKEND_CONTAINER}" 2>/dev/null || true)"
if [ -z "${BACKEND_IP}" ]; then
    err "could not resolve IP for backend container ${BACKEND_CONTAINER}"
    exit 1
fi
log "Backend container ${BACKEND_CONTAINER} at ${BACKEND_IP}:3306 (used for both hostgroup 0 and hostgroup 1)"

if ! timeout 5 bash -c "cat < /dev/null > /dev/tcp/${BACKEND_IP}/3306" 2>/dev/null; then
    err "backend ${BACKEND_IP}:3306 not reachable from host"
    exit 1
fi

# Prime the backend's reverse-DNS cache: a host-native process connecting to
# a container IP (rather than another container on the same docker network)
# triggers mysqld's client-host reverse lookup, which can take several
# seconds on the very first connection from a given source address (no PTR
# record; the embedded docker resolver has to time out) before the negative
# result gets cached. Absorb that delay here, once, up front, with a
# generous timeout — otherwise ProxySQL's own connect_timeout_server (set
# below, but still finite) can race it during real traffic and report
# spurious "Max connect timeout reached" errors.
log "Priming backend reverse-DNS cache (first connect can be slow)..."
if ! timeout 20 mysql --connect-timeout=15 -h"${BACKEND_IP}" -P3306 -u"${BACKEND_USER}" -p"${BACKEND_PASS}" -e "SELECT 1" >/dev/null 2>&1; then
    err "could not prime connection to backend ${BACKEND_IP}:3306 as ${BACKEND_USER}"
    exit 1
fi
log "Backend reverse-DNS cache primed."

# ---------------------------------------------------------------------------
# Step 2: spawn 3 ProxySQL instances directly on the host.
# ---------------------------------------------------------------------------
log "Preparing datadirs under ${CAPTURE_DIR}..."
rm -rf "${CAPTURE_DIR}"
mkdir -p "${CAPTURE_DIR}"

write_node_config() {
    local i="$1" cnf="$2" datadir="$3"
    {
        printf 'datadir="%s"\n' "${datadir}"
        printf 'admin_variables=\n{\n'
        printf '\tadmin_credentials="admin:admin;%s:%s"\n' "${CLUSTER_USER}" "${CLUSTER_PASS}"
        printf '\tmysql_ifaces="0.0.0.0:%d"\n' "${ADMIN_PORT[$i]}"
        printf '\tcluster_username="%s"\n' "${CLUSTER_USER}"
        printf '\tcluster_password="%s"\n' "${CLUSTER_PASS}"
        printf '\tcluster_check_interval_ms=200\n'
        printf '\tcluster_leader_election="true"\n'
        printf '\tcluster_leader_node_timeout_ms=1000\n'
        printf '\tcluster_leader_grace_ms=500\n'
        printf '}\n'
        printf 'mysql_variables=\n{\n'
        printf '\tthreads=2\n'
        printf '\tinterfaces="0.0.0.0:%d"\n' "${MYSQL_PORT[$i]}"
        printf '}\n'
        printf 'proxysql_servers=\n(\n'
        for j in "${!NODE_IDX[@]}"; do
            local sep=","
            [ "$j" -eq $((${#NODE_IDX[@]} - 1)) ] && sep=""
            printf '\t{ hostname="127.0.0.1"; port=%d; weight=%d; comment="node%d"; }%s\n' \
                "${ADMIN_PORT[$j]}" "${WEIGHT[$j]}" "${NODE_IDX[$j]}" "${sep}"
        done
        printf ')\n'
    } > "${cnf}"
}

for i in "${!NODE_IDX[@]}"; do
    n="${NODE_IDX[$i]}"
    datadir="${CAPTURE_DIR}/node${n}"
    mkdir -p "${datadir}"
    cnf="${datadir}/node.cnf"
    write_node_config "$i" "${cnf}" "${datadir}"

    # 'exec' is load-bearing: without it, /bin/sh forks proxysql and the pid
    # captured via $! is the shell wrapper, not proxysql itself, so teardown
    # (kill "$pid") would miss the real process. See
    # test/tap/tests/test_cluster_leader_election-t.cpp for the same pattern.
    cmd="exec ${PROXYSQL_BIN} -f -M -c ${cnf} -D ${datadir} --initial >> ${datadir}/stderr.log 2>&1"
    sh -c "${cmd}" &
    PIDS[$i]=$!
    log "spawned node${n} (pid ${PIDS[$i]}, admin=${ADMIN_PORT[$i]}, mysql=${MYSQL_PORT[$i]})"
done

log "Waiting for admin ports to come up..."
for i in "${!NODE_IDX[@]}"; do
    ok=0
    for _ in $(seq 1 30); do
        if admin_sql_ok "${ADMIN_PORT[$i]}" "SELECT 1"; then ok=1; break; fi
        sleep 0.5
    done
    if [ "$ok" -ne 1 ]; then
        err "node${NODE_IDX[$i]} admin port ${ADMIN_PORT[$i]} never came up; see ${CAPTURE_DIR}/node${NODE_IDX[$i]}/stderr.log"
        exit 1
    fi
done
log "All 3 admin ports are up."

# ---------------------------------------------------------------------------
# Step 3: configure each node while still PROXYSQL READWRITE (forced), then
# hand control back to leader election.
# ---------------------------------------------------------------------------
log "Configuring hostgroups/users/TSDB on each node (forced READWRITE)..."
CONFIG_SQL="
PROXYSQL READWRITE;
DELETE FROM mysql_servers;
-- Same backend (host:port) in both hostgroups on purpose: the brief calls
-- for one backend registered in two hostgroups (label/series diversity
-- for the TSDB fixture), not an actual writer/replica routing split. Do
-- not point hostgroup 1 at the dbdeployer :3307 replica -- that's a
-- separate mysqld and turns this into a two-backend setup instead.
INSERT INTO mysql_servers (hostgroup_id,hostname,port,comment) VALUES (0,'${BACKEND_IP}',3306,'tsdb-lab-writer');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,comment) VALUES (1,'${BACKEND_IP}',3306,'tsdb-lab-reader');
DELETE FROM mysql_users WHERE username='${BACKEND_USER}';
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('${BACKEND_USER}','${BACKEND_PASS}',1,0,'tsdb-lab');
LOAD MYSQL SERVERS TO RUNTIME;
LOAD MYSQL USERS TO RUNTIME;
SET mysql-connect_timeout_server=12000;
SET mysql-connect_timeout_server_max=20000;
SET mysql-monitor_connect_timeout=8000;
LOAD MYSQL VARIABLES TO RUNTIME;
SET tsdb-enabled='1';
LOAD TSDB VARIABLES TO RUNTIME;
"
for i in "${!NODE_IDX[@]}"; do
    if ! admin_sql_ok "${ADMIN_PORT[$i]}" "${CONFIG_SQL}"; then
        err "failed to configure node${NODE_IDX[$i]} (admin port ${ADMIN_PORT[$i]})"
        exit 1
    fi
    log "node${NODE_IDX[$i]} configured (2 hostgroups, ${BACKEND_USER} user, tsdb-enabled)"
done

for i in "${!NODE_IDX[@]}"; do
    admin_sql_ok "${ADMIN_PORT[$i]}" "PROXYSQL READONLY AUTO" || {
        err "failed to release node${NODE_IDX[$i]} back to READONLY AUTO"
        exit 1
    }
done

log "Waiting for leader election to converge..."
converged=0
for _ in $(seq 1 30); do
    leader_port="$(admin_sql "${ADMIN_PORT[0]}" \
        "SELECT port FROM stats_proxysql_servers_status WHERE master='YES'" 2>/dev/null | head -1 || true)"
    if [ -n "${leader_port:-}" ]; then converged=1; break; fi
    sleep 0.5
done
if [ "$converged" -ne 1 ]; then
    err "cluster never converged on a leader"
    exit 1
fi
for i in "${!NODE_IDX[@]}"; do
    if [ "${ADMIN_PORT[$i]}" = "${leader_port}" ]; then LEADER_IDX="$i"; fi
done
log "Leader converged: node${NODE_IDX[$LEADER_IDX]} (admin port ${leader_port})"

# ---------------------------------------------------------------------------
# Step 4: drive variable-rate load through node1's mysql port for DURATION_S.
# ---------------------------------------------------------------------------
CAPTURE_START_TS="$(date +%s)"
log "Load window starts at ${CAPTURE_START_TS}; running for ${DURATION_S}s"

RATES=(20 200 60)

run_sysbench_load() {
    local script=/usr/share/sysbench/oltp_read_write.lua
    local common=(
        --db-driver=mysql
        --mysql-host=127.0.0.1
        --mysql-port="${MYSQL_PORT[0]}"
        --mysql-user="${BACKEND_USER}"
        --mysql-password="${BACKEND_PASS}"
        --mysql-db="${SYSBENCH_DB}"
        --tables=4
        --table-size=2000
        --threads=4
    )
    log "sysbench found; using ${script}"
    sysbench "${script}" "${common[@]}" cleanup >/dev/null 2>&1 || true
    sysbench "${script}" "${common[@]}" prepare
    local elapsed=0 idx=0
    while [ "${elapsed}" -lt "${DURATION_S}" ]; do
        local remaining=$((DURATION_S - elapsed))
        local slice=60
        [ "${remaining}" -lt 60 ] && slice="${remaining}"
        local rate="${RATES[$((idx % ${#RATES[@]}))]}"
        log "sysbench run: ${slice}s @ rate=${rate}"
        sysbench "${script}" "${common[@]}" --time="${slice}" --rate="${rate}" run || true
        elapsed=$((elapsed + slice))
        idx=$((idx + 1))
    done
    sysbench "${script}" "${common[@]}" cleanup >/dev/null 2>&1 || true
}

run_fallback_load() {
    log "sysbench NOT installed; falling back to a mysql-client mixed SELECT/INSERT loop"
    mysql --connect-timeout=5 -h127.0.0.1 -P"${MYSQL_PORT[0]}" -u"${BACKEND_USER}" -p"${BACKEND_PASS}" "${SYSBENCH_DB}" -e \
        "CREATE TABLE IF NOT EXISTS tsdb_lab_fallback (id INT PRIMARY KEY AUTO_INCREMENT, val INT, ts INT)" \
        || { err "fallback: could not prepare tsdb_lab_fallback table"; exit 1; }
    local elapsed=0 idx=0
    while [ "${elapsed}" -lt "${DURATION_S}" ]; do
        local remaining=$((DURATION_S - elapsed))
        local slice=60
        [ "${remaining}" -lt 60 ] && slice="${remaining}"
        local rate="${RATES[$((idx % ${#RATES[@]}))]}"
        local sleep_s
        sleep_s="$(awk -v r="${rate}" 'BEGIN{printf "%.4f", 1.0/r}')"
        log "fallback loop: ${slice}s @ ~${rate} statements/sec"
        local slice_end=$(( $(date +%s) + slice ))
        while [ "$(date +%s)" -lt "${slice_end}" ]; do
            mysql --connect-timeout=5 -h127.0.0.1 -P"${MYSQL_PORT[0]}" -u"${BACKEND_USER}" -p"${BACKEND_PASS}" "${SYSBENCH_DB}" -e \
                "INSERT INTO tsdb_lab_fallback (val, ts) VALUES (${RANDOM}, UNIX_TIMESTAMP()); \
                 SELECT * FROM tsdb_lab_fallback WHERE id = (SELECT MAX(id) FROM tsdb_lab_fallback);" \
                >/dev/null 2>&1 || true
            sleep "${sleep_s}"
        done
        elapsed=$((elapsed + slice))
        idx=$((idx + 1))
    done
}

if command -v sysbench >/dev/null 2>&1; then
    LOAD_GENERATOR="sysbench"
    run_sysbench_load
else
    LOAD_GENERATOR="mysql-client fallback loop"
    run_fallback_load
fi

CAPTURE_END_TS="$(date +%s)"
log "Load window ended at ${CAPTURE_END_TS} (load generator: ${LOAD_GENERATOR})"

# ---------------------------------------------------------------------------
# Step 5: dump the leader's tsdb_metrics window to CSV, gzip it.
# ---------------------------------------------------------------------------
leader_admin_port="${ADMIN_PORT[$LEADER_IDX]}"
log "Dumping stats_history.tsdb_metrics from leader (admin port ${leader_admin_port})..."

RAW_TSV="$(mktemp "${CAPTURE_DIR}/tsdb_metrics.XXXXXX.tsv")"
mysql --connect-timeout=5 -h127.0.0.1 -P"${leader_admin_port}" -uadmin -padmin -N -B -e \
    "SELECT timestamp, metric_name, labels, value FROM stats_history.tsdb_metrics WHERE timestamp >= ${CAPTURE_START_TS} ORDER BY timestamp" \
    > "${RAW_TSV}"

ROW_COUNT="$(wc -l < "${RAW_TSV}" | tr -d ' ')"
if [ "${ROW_COUNT}" -eq 0 ]; then
    err "leader returned zero tsdb_metrics rows for the capture window; aborting"
    exit 1
fi
log "Fetched ${ROW_COUNT} raw rows from the leader"

mkdir -p "${FIXTURES_DIR}"
TMP_CSV="$(mktemp "${CAPTURE_DIR}/seed.XXXXXX.csv")"

# mysql's default batch mode backslash-escapes embedded \t \n \\ \0 within
# field values; undo that here and let csv.writer add proper quoting (labels
# is a JSON blob that routinely contains commas/braces/quotes).
python3 - "${RAW_TSV}" "${TMP_CSV}" <<'PYEOF'
import csv
import sys

raw_path, out_path = sys.argv[1], sys.argv[2]


def unescape(field):
    out = []
    i = 0
    n = len(field)
    while i < n:
        c = field[i]
        if c == "\\" and i + 1 < n:
            nc = field[i + 1]
            if nc == "t":
                out.append("\t")
            elif nc == "n":
                out.append("\n")
            elif nc == "0":
                out.append("\0")
            elif nc == "\\":
                out.append("\\")
            else:
                out.append(nc)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


with open(raw_path, "r", encoding="utf-8") as inf, \
     open(out_path, "w", encoding="utf-8", newline="") as outf:
    w = csv.writer(outf)
    w.writerow(["timestamp", "metric_name", "labels", "value"])
    n = 0
    for line in inf:
        line = line.rstrip("\n")
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        w.writerow([unescape(f) for f in fields])
        n += 1
    print("converted %d rows" % n)
PYEOF

gzip -c "${TMP_CSV}" > "${FIXTURE_CSV_GZ}.tmp"
FIXTURE_BYTES="$(stat -c%s "${FIXTURE_CSV_GZ}.tmp")"
log "Compressed fixture size: ${FIXTURE_BYTES} bytes"

if [ "${FIXTURE_BYTES}" -gt "${MAX_FIXTURE_BYTES}" ]; then
    err "fixture is ${FIXTURE_BYTES} bytes, over the ${MAX_FIXTURE_BYTES}-byte (2 MB) abort limit."
    err "NOT committing it. Inspect ${TMP_CSV} / reduce DURATION_S / series count, then re-run."
    rm -f "${FIXTURE_CSV_GZ}.tmp"
    exit 1
fi

mv "${FIXTURE_CSV_GZ}.tmp" "${FIXTURE_CSV_GZ}"
rm -f "${TMP_CSV}" "${RAW_TSV}"
log "Wrote ${FIXTURE_CSV_GZ} (${FIXTURE_BYTES} bytes)"

# ---------------------------------------------------------------------------
# Step 6: provenance
# ---------------------------------------------------------------------------
PROXYSQL_VERSION="$("${PROXYSQL_BIN}" --version 2>&1 | grep -m1 '^ProxySQL version' || true)"
SERIES_COUNT="$(python3 -c "
import gzip, csv
with gzip.open('${FIXTURE_CSV_GZ}', 'rt') as f:
    rows = list(csv.DictReader(f))
print(len({(r['metric_name'], r['labels']) for r in rows}))
")"
FIXTURE_ROWS="$(python3 -c "
import gzip, csv
with gzip.open('${FIXTURE_CSV_GZ}', 'rt') as f:
    print(sum(1 for _ in csv.DictReader(f)))
")"

cat > "${FIXTURE_README}" <<EOF
# seed-10min.csv.gz provenance

Captured by: test/tsdb-lab/capture.bash
Capture date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
ProxySQL version: ${PROXYSQL_VERSION}
Build tier: PROXYSQL31 debug (src/proxysql)

## Cluster

- Nodes: 3 (leader election enabled, weights 300/200/100)
- Leader during capture: node$((LEADER_IDX + 1)) (admin port ${leader_admin_port})
- Backend: ${BACKEND_CONTAINER} (dbdeployer MySQL 5.7, GTID replication),
  same host:port registered in both hostgroups (two hostgroups over one
  backend, not a writer/replica routing split)
  - hostgroup 0: ${BACKEND_IP}:3306
  - hostgroup 1: ${BACKEND_IP}:3306
- Load generator: ${LOAD_GENERATOR}
- Requested duration: ${DURATION_S}s (rates cycled 20/200/60 events-per-sec every 60s)

## Fixture

- Rows: ${FIXTURE_ROWS}
- Distinct series (metric_name, labels): ${SERIES_COUNT}
- Compressed size: ${FIXTURE_BYTES} bytes
- Capture window: [${CAPTURE_START_TS}, ${CAPTURE_END_TS}) unix epoch seconds
- Source query: SELECT timestamp, metric_name, labels, value FROM stats_history.tsdb_metrics WHERE timestamp >= ${CAPTURE_START_TS} ORDER BY timestamp

## Structural fidelity

Real metric names, real label sets, real cardinality and volume, sampled at
the default tsdb-sample_interval (5s) from a live 3-node cluster under
sysbench oltp_read_write load. See test/tsdb-lab/README.md for how
expand.py tiles this block forward for storage/replication/query sizing.
EOF

log "Wrote provenance: ${FIXTURE_README}"
log "Rows=${FIXTURE_ROWS} Series=${SERIES_COUNT} CompressedBytes=${FIXTURE_BYTES}"
log "Done."
