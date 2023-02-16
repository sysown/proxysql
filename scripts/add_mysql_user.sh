#!/bin/sh

# Add a MySQL user:
#
# - Optional params (with default values): '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin" }'
# - Mandatory params: '{ "user": "username", "pass": "password" }'

if [ ! "$1" ]; then
    echo { \"err\": \"Missing required argument specifying username/password\" }
	exit 0
fi

# Script mandatory parameters
user=$(echo $1 | jq '.user')
pass=$(echo $1 | jq '.pass')

# Script optional parameters
admin_host=$(echo $1 | jq -r '.admin_host')
admin_port=$(echo $1 | jq -r '.admin_port')
admin_user=$(echo $1 | jq -r '.admin_user')
admin_pass=$(echo $1 | jq -r '.admin_pass')
to_runtime=$(echo $1 | jq -r '.to_runtime')

if [ $user == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument username\" }
    exit 0
fi
if [ $pass == "null" ]; then
    echo { \"err_code\": 1, \"res\": \"Missing required argument password\" }
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
if [ $to_runtime == "null" ]; then
    to_runtime=0
fi

cmd_output=$(mysql -h$admin_host -P$admin_port -u$admin_user -p$admin_pass -e \
    "INSERT OR REPLACE INTO mysql_users (username,password) VALUES ($user, $pass)" 2> $(pwd)/add_mysql_err.log)

if [ $? -eq 0 ]; then
    if [ $to_runtime -eq 1 ]; then
        cmd_output=$(mysql -h$admin_host -P$admin_port -u$admin_user -p$admin_pass -e \
            "LOAD MYSQL USERS TO RUNTIME" 2> $(pwd)/add_mysql_err.log)
    fi

    if [ $? -eq 0 ]; then
        echo { \"err_code\": 0, \"res\": \"$cmd_output\" }
    else
        echo { \"err_code\": 1, \"res\": \"$(cat $(pwd)/add_mysql_err.log)\" }
    fi
else
    echo { \"err_code\": 1, \"res\": \"$(cat $(pwd)/add_mysql_err.log)\" }
fi

rm $(pwd)/add_mysql_err.log
