#!/usr/bin/env python

import base64
import json
import os
import requests
import sys

import MySQLdb

USAGE = """
proxysql-consul put config config_type
"""

CFG_PATH = '/etc/proxysql-consul.cfg'
CFG_CONSUL_IFACE = 'consul_iface'
CFG_CONSUL_PORT = 'consul_port'
CFG_PROXY_IFACE = 'proxysql_admin_iface'
CFG_PROXY_PORT = 'proxysql_admin_port'
CFG_PROXY_USERNAME = 'proxysql_admin_username'
CFG_PROXY_PASSWORD = 'proxysql_admin_password'

# Proxysql config types to Consul key mapping
TABLE_TO_KEY = {
        'mysql_servers': 'proxysql/mysql_servers',
        'global_variables': 'proxysql/global_variables'
        }

config = {}


def read_config():
    global config
    with open(CFG_PATH) as config_file:
        config_data = config_file.read()
    config = json.loads(config_data)

    # TODO validate config


def fetch_proxysql_config(table):
    admin_connection = MySQLdb.connect(config[CFG_PROXY_IFACE],
            config[CFG_PROXY_USERNAME],
            config[CFG_PROXY_PASSWORD],
            port=config[CFG_PROXY_PORT],
            db='main')
    cursor = admin_connection.cursor()
    cursor.execute('SELECT * FROM %s' % table)
    rows = cursor.fetchall()
    cursor.close()
    admin_connection.close()
    return rows 


def put_config(table):
    if table not in TABLE_TO_KEY:
        print 'Unknown config table. Exiting.'
        exit(1)

    rows = fetch_proxysql_config(table)
    rows_json = json.dumps(rows)

    key = TABLE_TO_KEY[table]
    consul_iface = config[CFG_CONSUL_IFACE]
    consul_port = config[CFG_CONSUL_PORT]

    url = 'http://%s:%s/v1/kv/%s' % (consul_iface, consul_port, key)
    r = requests.put(url, data=rows_json)
    print r.status_code


def update_config():
    """
    Reads all input from stdin that is passed by Consul and extracts the config
    that was modified.

    Consul is configured to watch all proxysql keys and returns all their values
    when one key is modified. To determine the value that was actually modified
    we use the CONSUL_INDEX env var written by Consul. This should match the
    'ModifyIndex' field of the value that triggered the watch.

    Values are returned as a JSON array. The actual value content is stored in
    the 'Value' field, base64 encoded.
    """
    if 'CONSUL_INDEX' not in os.environ:
        print 'Missing consul index on update request'
        exit(1)
    consul_index = int(os.environ['CONSUL_INDEX'])
    consul_data = sys.stdin.read()

    updated_value = None
    values = json.loads(consul_data)
    for value in values:
        if 'ModifyIndex' in value and value['ModifyIndex'] == consul_index:
           updated_value = value
           break
    if not updated_value:
        print 'Failed to determine updated config from Consul data'
        exit(1)

    proxysql_config = base64.b64decode(updated_value['Value'])
    print proxysql_config

if __name__ == '__main__':
    read_config()

    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == 'put' and len(sys.argv) > 2:
            table = sys.argv[2]
            put_config(table)
            exit(0)
        elif mode == 'update':
            update_config()
            exit(0)

    print USAGE
    exit(1)
