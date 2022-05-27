#!/usr/bin/sh

# Flush Query cache from a ProxySQL instance:
#
# - Optional params (with default values): '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin" }'

if [ ! "$1" ]; then
    j_arg="{}"
else
    j_arg=$1
fi

# Script optional parameters
admin_host=$(echo $j_arg | jq -r '.admin_host')
admin_port=$(echo $j_arg | jq -r '.admin_port')
admin_user=$(echo $j_arg | jq -r '.admin_user')
admin_pass=$(echo $j_arg | jq -r '.admin_pass')

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
    "PROXYSQL FLUSH QUERY CACHE" 2> $(pwd)/flush_cache_err.log)

if [ $? -eq 0 ]; then
    echo { \"err_code\": 0, \"res\": \"$cmd_output\" }
else
    echo { \"err_code\": 1, \"res\": \"$(cat $(pwd)/flush_cache_err.log)\" }
fi

rm $(pwd)/flush_cache_err.log
