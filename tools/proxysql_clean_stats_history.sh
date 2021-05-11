#!/bin/

# proxysql-stats-history-cleaner.sh
# This is a script to delete historical mysql query digests over a certain amount of days, with the
# option to reclaim the disk space using SQLite VACUUM.

# It is intended to be used with ProxySQL Scheduler.

# Example commandline executions:
# cleans stats over 30 days old, in chunks of 1 day. Does not vacuum
# ./tools/proxysql_clean_stats_history.sh ~/.my_proxysql.cnf 30 1440
#
# cleans stats over 60 days old, in a single chunk. Vacuums the stats.db afterward
# ./tools/proxysql_clean_stats_history.sh ~/.my_proxysql.cnf 60 0 1
#
# cleans stats over 60 days old in chunks of 1 day (1440 minutes). Does not vacuum, and logs to 'stats_cleaner.log' file
# ./tools/proxysql_clean_stats_history.sh ~/.my_proxysql.cnf 60 0 1 /var/lib/proxysql/stats_cleaner.log

function usage() {
  echo "Usage"
  cat << EOF

Usage: $0 <keep_days> <chunk_interval> [should_vacuum] [log_file]
- DEFAULTS_FILE (required) ".my.cnf" The location of the defaults_file to handle connectivity to the ProxySQL ADMIN interface. This is done to avoid modifying credentials in the script.
- KEEP_DAYS   (required)  (0..)   The number of days of stats to keep. Anything older than this value will be deleted.
- CHUNK_INTERVAL   (required)  (0..)   The number of minutes to use in each chunk. Adjust this value to control the amount of stats deleted. The lower this value, the less load is expected. However, it also is expected that the cleaning operation will run longer with low values.
Providing 0 for the CHUNK_INTERVAL will assume a chunk of 1, and delete everything past KEEP_DAYS in 1 chunk.
- SHOULD_VACUUM (optional) 0|1 Whether the script executes a vacuum at the end of its run. Vacuuming in SQLite is the ability to clean up space after rows are deleted. This can cause some contention on very large files that need to be vacuumed. Defaults to false.
- LOG_FILE (optional)  File in which to log messages. Defaults to /var/lib/proxysql/stats_cleaner.log

IMPORTANT:
  This script requires connectivity to ProxySQL admin interface with rights to delete from the stats_history db. We recommend using a defaults file with the connectivity setting to avoid modifying the script.
EOF
}

# These are passed in as arguments
DEFAULTS_FILE="${1:-/var/lib/proxysql/proxysql-admin.cnf}"
KEEP_DAYS="$2" # in days. Assumption is most users will want to delete past 30 or 60 days
CHUNK_INTERVAL="$3" # in minutes. If zero, will delete in 1 chunk
SHOULD_VACUUM="${4:-0}" # Whether to vacuum after deleting. Can be a blocking operation if large amount of space to reclaim.
LOG_FILE="${5:-/var/lib/proxysql/stats_cleaner.log}"

function log_message() {
  echo "`date` [${1}] - ${2}" >> $LOG_FILE
}

function log_info {
  log_message "INFO" "$1"
}

function log_error {
  log_message "ERROR" "$1"
  exit 1
}

function is_int() {
  test "$1" -eq "$1" 2>/dev/null
}
# Validate variables
function validate_variables() {
  if ! test -f "$DEFAULTS_FILE"; then
    log_error "The defaults file '$DEFAULTS_FILE' does not exist."
  fi
  if [[ -z "$KEEP_DAYS" ]]; then
    log_error "The first argument KEEP_DAYS is required, but was not provided."
  fi

  if ! is_int "$KEEP_DAYS"; then
    log_error "KEEP_DAYS must be an integer."
  fi

  if [[ -z "$CHUNK_INTERVAL" ]]; then
    log_error "The second argument CHUNK_INTERVAL is required, but was not provided."
  fi

  if ! is_int "$CHUNK_INTERVAL"; then
    log_error "CHUNK_INTERVAL must be an integer."
  fi

  if ! test -f "$LOG_FILE"; then
    log_info "The log file '$LOG_FILE' does not exist. Creating it"
    touch $LOG_FILE
    if [ $? -ne 0 ]; then
      log_error "There was an error creating the $LOG_FILE. Ensure proper permissions."
    fi
  fi
}

## DO NOT CHANGE
PROXYSQL_CMDLINE="mysql --defaults-file=$DEFAULTS_FILE --protocol=tcp -Nse"

# Ensure connectivity to ProxySQL Admin works before proceeding.
validate_connection() {
  $PROXYSQL_CMDLINE "\s" &> /dev/null
  if [ $? != 0 ]
  then
    log_error "Cannot connect to MySQL. Trying: $PROXYSQL_CMDLINE"
  fi
}

# Retrieve the earliest save timestamp, which helps determine the number of chunks.
function get_earliest_save() {
  earliestSaveTS=$($PROXYSQL_CMDLINE "SELECT MIN(dump_time) FROM stats_history.history_mysql_query_digest;")

  if [[ "$earliestSaveTS" -eq "NULL" ]]; then
    log_info "There are no historical stats to purge. Ensure 'admin-stats_mysql_query_digest_to_disk' is set correctly."
    exit 0
  fi
}

# Calculate the number of chunks required to delete based on the arguments provided.
function get_num_chunks() {
  get_earliest_save

  purgeBeforeTS=$(date +%s -d "$KEEP_DAYS days ago")

  if [ $CHUNK_INTERVAL -eq 0 ]; then
    # If deleting in one chunk, then the earliestSaveTS is not relevant for deleting.
    # Set it to be the purgeBeforeTS
    totalChunks=1
    earliestSaveTS=$purgeBeforeTS
  else
    totalPurgeMinutes=$(echo "($purgeBeforeTS - $earliestSaveTS)/60" | bc )

    # This conditional exists for the edge-case that CHUNK_INTERVAL is significantly larger than
    # totalPurgeMinutes.
    if [ $totalPurgeMinutes -lt $CHUNK_INTERVAL ]; then
      totalChunks=1
    else
      # Attempts to round up to the nearest chunk. Significant proportion edge-cases may fail.
      # Eg; if CHUNK_INTERVAL is significantly larger than the minutes to purge, it won't work.
      totalChunks=$(echo "scale=2;$totalPurgeMinutes / $CHUNK_INTERVAL" | bc | awk '{print ($0-int($0))<0.001?int($0):int($0)+1}')
    fi
  fi

  log_info "Purge before date: $(date -d @$purgeBeforeTS)"
  log_info "Earliest save date: $(date -d @$earliestSaveTS)"
  log_info "Total chunks: $totalChunks"
}

# Delete entries from stats_history.history_mysql_query_digest.
function delete_stats_history() {
  get_num_chunks

  if [[ $totalChunks -le 0 ]]
  then
    log_info "No stats to delete. Exiting."
    exit 0
  fi

  i="0"
  currentSaveTS=$earliestSaveTS
  while [ $i -lt $totalChunks ]
  do
    currentSaveTS=$(date +%s -d "$(date -d @$currentSaveTS) $CHUNK_INTERVAL minutes")
    log_info "Deleting stats before $(date -d @$currentSaveTS)"

    $PROXYSQL_CMDLINE "DELETE FROM stats_history.history_mysql_query_digest WHERE dump_time<$currentSaveTS;"
    i=$[$i+1]
  done
}

# Reclaim space by running vacuum. This can be a blocking operation depending on how much
# space is needed to reclaim.
vacuum_stats_history() {
  log_info "Vacuuming stats history table"
  $PROXYSQL_CMDLINE "VACUUM stats"
}

# prevent execution if another script is already running.
BASENAME=`basename "$0"`
pidof -x -o %PPID ${BASENAME}
ANOTHER_PROCESS_IS_RUNNING=$?
if [ ${ANOTHER_PROCESS_IS_RUNNING} -eq 0 ]; then
  log_info "Another stats cleaner process is already running. Abort!"
  exit 0
fi

# Ensure variables are acceptable.
validate_variables

# Ensure proxysql admin connectivity
validate_connection

# Delete the stats
delete_stats_history

# Vacuum if requested
if [[ $SHOULD_VACUUM -eq 1 ]]
then
  vacuum_stats_history
else
  log_info "Skipping vacuuming the stats_history table."
fi
