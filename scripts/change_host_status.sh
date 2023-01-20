#!/bin/sh

# Change a particular host status:
#
# - Optional params (with default values): '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin" }'
# - Mandatory params: '{ "hostgroup_id": N, "hostname": "N.N.N.N", "port": N, "status": "ONLINE|OFFLINE_HARD" }'

if [ ! "$1" ]; then
    echo { \"err\": \"Missing required argument specifying hostgroup_id/hostname/port/status\" }
	exit 0
fi

# Script mandatory parameters
hostgroup_id=$(echo $1 | jq '.hostgroup_id')
hostname=$(echo $1 | jq '.hostname')
port=$(echo $1 | jq '.port')
status=$(echo $1 | jq '.status')

# Script optional parameters
admin_host=$(echo $1 | jq -r '.admin_host')
admin_port=$(echo $1 | jq -r '.admin_port')
admin_user=$(echo $1 | jq -r '.admin_user')
admin_pass=$(echo $1 | jq -r '.admin_pass')

if [ $hostgroup_id == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument \'hostgroup_id\'\" }
    exit 0
fi
if [ $hostname == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument \'hostname\'\" }
    exit 0
fi
if [ $port == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument \'port\'\" }
    exit 0
fi
if [ $status == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument \'status\'\" }
    exit 0
fi

# Optional parameters
if [ $admin_host == "null" ]; then
    admin_host="127.0.0.1"
fi
if [ $admin_port == "null" ]; then
    admin_port=6032
fi
if [ $admin_user == "null" ]; then
    admin_user="radmin"
fi
if [ $admin_pass == "null" ]; then
    admin_pass="radmin"
fi

cmd_output=$(mysql -h$admin_host -P$admin_port -u$admin_user -p$admin_pass -e \
    "UPDATE mysql_servers SET status=$status WHERE hostgroup_id=$hostgroup_id AND hostname=$hostname AND port=$port" 2> $(pwd)/change_host_st_err.log)

if [ $? -eq 0 ]; then
    echo { \"err_code\": 0, \"res\": \"$cmd_output\" }
else
    echo { \"err_code\": 1, \"res\": \"$(cat $(pwd)/change_host_st_err.log)\" }
fi

rm $(pwd)/change_host_st_err.log
