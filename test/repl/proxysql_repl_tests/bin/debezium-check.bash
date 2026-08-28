#!/usr/bin/bash


res=0

. constants


#-------------------------------------------------------------------------------
# function for test output
fn_echo_test() {
  echo "================================================================================"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
  if [[ $1 == "0" ]]; then
    echo "DEBEZIUM TEST PASSED: Max GTID processed by Debezium ($2) matches max GTID from MySQL ($3)"
  else
    echo "DEBEZIUM TEST FAILED: Max GTID processed by Debezium ($2) doesn't match max GTID from MySQL ($3)"
  fi
  echo "================================================================================"
}

# get the list of all sysbench.sbtest* topics from Kafka processed by Debezium
topics_list=$(docker-compose exec -T kafka /kafka/bin/kafka-get-offsets.sh --bootstrap-server kafka:9092 --topic dbserver1.sysbench.sbtest.*)

max_gtid="0"

# process each line of topics_list in a loop
for line in $(echo ${topics_list})
do

  if [[ "$line" == "" || $(grep -o ":" <<< "$line" | wc -l) -lt 2 ]]; then
    echo "Error: kafka topic string must contain at least two ':' characters"
    res=1
    fn_echo_test $res
    exit $res
  fi

  line=$(echo "$line" | tr -d '\r\n')

  IFS=':' read -ra values <<< "$line"

  topic="${values[0]}"
  ((values[1] > 0)) && partition="${values[1]}" || partition="0"
  ((values[2] > 0)) && offset="$((values[2]-1))" || offset="0"


  # find last gtid for each topic, partition and offset
  gtid=$(docker-compose exec -T kafka /kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9092 --max-messages 1 --partition $partition --offset $offset --topic $topic | grep -oE '"gtid":"[^"]*' | sed -e 's/"gtid":"\(.*\)/\1/')


  # print the result
  echo "topic: $topic, partition: $partition, offset: $offset, gtid: $gtid"

  # extract the last number from gtid and update max_gtid if necessary
  gtid_num=$(echo "$gtid" | cut -d':' -f2)
  if (( gtid_num > ${max_gtid#*:} )); then
    max_gtid="$gtid"
  fi

done

# extract the last number from gtid_executed
gtid_executed=$(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -s -N -e "SHOW GLOBAL VARIABLES LIKE 'gtid_executed';" 2>/dev/null | cut -d ':' -f 2- | cut -d '-' -f 2)
gtid_uuid=$(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -s -N -e "SHOW GLOBAL VARIABLES LIKE 'server_uuid';" 2>/dev/null | cut -f 2-)

# compare the last number from max_gtid with the last number from gtid_executed
if (( ${max_gtid#*:} == $gtid_executed )); then
  fn_echo_test $res ${max_gtid#*:} $gtid_executed
else
  res=1
  fn_echo_test $res ${max_gtid#*:} $gtid_executed
fi

exit $res
