#!/usr/bin/env python
"""
Kills all ProxySQL idle backend connections from a particular instance.

- Optional params (with default values): '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin" }'
- Mandatory params: '{ "timeout": N }'
"""

import json
import jsonschema
import sys
import time

import pymysql.cursors

schema = {
    "type": "object",
    "properties": {
        "admin_host": {"type": "string"},
        "admin_port": {"type": "number"},
        "admin_user": {"type": "string"},
        "admin_pass": {"type": "string"},
        "timeout": {"type": "number"}
    },
    "required": ["timeout"]
}

def validate_params():
    """Validates the JSON encoded received parameters."""
    res = {}

    if len(sys.argv) != 2:
        res = {"err_code": 1, "res": "Invalid number of parameters"}
    else:
        try:
           j_arg = json.loads(sys.argv[1])
           jsonschema.validate(instance=j_arg, schema=schema)

           res = {"err_code": 0, "res": ""}
        except jsonschema.exceptions.ValidationError as err:
           res = {"err_code": 1, "res": "Params validation failed: `" + str(err) + "`"}
        except json.decoder.JSONDecodeError as err:
           res = {"err_code": 1, "res": "Invalid supplied JSON: `" + str(err) + "`"}

    return res

if __name__ == "__main__":
    p_res = validate_params()

    if p_res["err_code"] != 0:
        print(json.dumps(p_res))
        exit(0)

    params = json.loads(sys.argv[1])

    if params.get('admin_host') is None:
        params['admin_host'] = "127.0.0.1"
    if params.get('admin_port') is None:
        params['admin_port'] = 6032
    if params.get('admin_user') is None:
        params['admin_user'] = "radmin"
    if params.get('admin_pass') is None:
        params['admin_pass'] = "radmin"

    try:
        proxy_admin_conn = pymysql.connect(
            host=params['admin_host'],
            user=params['admin_user'],
            password=params['admin_pass'],
            port=int(params['admin_port']),
            cursorclass=pymysql.cursors.DictCursor,
            defer_connect=True
        )

        proxy_admin_conn.client_flag |= pymysql.constants.CLIENT.MULTI_STATEMENTS
        proxy_admin_conn.connect()
        proxy_admin_conn.autocommit(True)
    except Exception as err:
        print(json.dumps({"err_code": 1, "res": "Connection attempt failed: `" + str(err) + "`"}))
        exit(0)

    with proxy_admin_conn:
        with proxy_admin_conn.cursor() as cursor:
            # Backup the current 'free_connections_pct'
            prev_free_conns_pct = ""

            s_var_query = "SELECT variable_value FROM global_variables WHERE variable_name='mysql-free_connections_pct'"
            cursor.execute(s_var_query)
            my_varval = cursor.fetchall()

            if len(my_varval) != 1:
                print(json.dumps({"err_code": 1, "res": "Invalid resulset received for query `" + s_var_query + "`"}))
                exit(0)
            else:
                prev_free_conns_pct = my_varval[0]['variable_value']

            # Set the 'free_connections_pct' to '0', to performa purge of the idle backend connections
            update_query = "UPDATE global_variables SET variable_value=%s WHERE variable_name='mysql-free_connections_pct'"
            cursor.execute(update_query, "0")
            cursor.execute("LOAD MYSQL VARIABLES TO RUNTIME")

            # Loop with a timeout until ProxySQL has cleaned all the backend connections
            free_conns = -1
            waited = 0
            timeout = int(params['timeout'])

            while free_conns != 0 and waited < timeout:
                s_free_query = "SELECT SUM(ConnFree) FROM stats.stats_mysql_connection_pool"

                cursor.execute(s_free_query)
                my_rows = cursor.fetchall()

                if len(my_rows) != 1:
                    print(json.dumps({"err_code": 1, "res": "Invalid resulset received for query `" + s_free_query + "`"}))
                    exit(0)
                else:
                    conn_free_field = my_rows[0]['SUM(ConnFree)']

                    if conn_free_field is not None:
                        free_conns = int(conn_free_field)
                    else:
                        free_conns = 0

                time.sleep(1)

            # Recover previous 'mysql-free_connections_pct'
            cursor.execute(update_query, prev_free_conns_pct)
            cursor.execute("LOAD MYSQL VARIABLES TO RUNTIME")

            if waited >= timeout:
                print(json.dumps({"err_code": 1, "res": "Operation timedout"}))
            else:
                print(json.dumps({"err_code": 0, "res": "Success!"}))
