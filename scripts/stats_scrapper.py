#!/usr/bin/env python

"""
Retuns the content of a particular table from Admin 'stats' schema.

- Optional params (with default values): '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin" }'
- Mandatory params: '{ "table": "tablename" }'
"""

import json
import jsonschema
import sys

import pymysql.cursors

schema = {
    "type": "object",
    "properties": {
        "admin_host": {"type": "string"},
        "admin_port": {"type": "number"},
        "admin_user": {"type": "string"},
        "admin_pass": {"type": "string"},
        "table": {"type": "string"},
    },
    "required": ["table"]
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

    s_query = "SELECT * FROM stats.%s"

    with proxy_admin_conn:
        with proxy_admin_conn.cursor() as cursor:
            cursor.execute(s_query, params['table'])
            rows = cursor.fetchall()

            print(json.dumps({"err_code": 0, "res": rows}))
