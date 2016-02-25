#!/usr/bin/env python

import base64
import json
import os
import requests
import sys

import MySQLdb

USAGE = """
proxysql-consul put tablename
proxysql update < config
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
        'mysql_query_rules': 'proxysql/mysql_query_rules'
        }

SAVE_QUERY_BY_TABLE = {
        'mysql_servers': 'SAVE MYSQL SERVERS TO MEMORY',
        'mysql_query_rules': 'SAVE MYSQL QUERY RULES TO MEMORY'
        }

LOAD_QUERY_BY_TABLE = {
        'mysql_servers': 'LOAD MYSQL SERVERS FROM MEMORY',
        'mysql_query_rules': 'LOAD MYSQL QUERY RULES FROM MEMORY'
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

    # save runtime config to memory so we can read them
    cursor = admin_connection.cursor()
    save_query = SAVE_QUERY_BY_TABLE[table]
    cursor.execute(save_query)
    cursor.close()

    # read runtime config from memory
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
    consul_data = {}
    consul_data['table'] = table
    consul_data['rows'] = rows
    consul_data_json = json.dumps(consul_data)

    key = TABLE_TO_KEY[table]
    consul_iface = config[CFG_CONSUL_IFACE]
    consul_port = config[CFG_CONSUL_PORT]

    url = 'http://%s:%s/v1/kv/%s' % (consul_iface, consul_port, key)
    r = requests.put(url, data=consul_data_json)


def build_multivalue_insert(table, rows):
    # add quotes arround all values to make them strings in the sql query
    quoted_values = [['"' + x + '"' for x in row] for row in rows]
    # join each row in a values() group
    row_join = [','.join(x) for x in quoted_values]
    query = 'INSERT INTO %s VALUES(%s)' % (table, '),('.join(row_join))
    return query

def update_proxysql_config(table, rows):
    admin_connection = MySQLdb.connect(config[CFG_PROXY_IFACE],
            config[CFG_PROXY_USERNAME],
            config[CFG_PROXY_PASSWORD],
            port=config[CFG_PROXY_PORT],
            db='main')
    
    # clear table
    cursor = admin_connection.cursor()
    cursor.execute('DELETE FROM %s' % table)
    cursor.close()
    
    # insert values from Consul
    insert_query = build_multivalue_insert(table, rows)
    cursor = admin_connection.cursor()
    cursor.execute(insert_query)
    cursor.close()

    # commit changes to runtine
    load_query = LOAD_QUERY_BY_TABLE[table]
    cursor = admin_connection.cursor()
    cursor.execute(load_query)
    cursor.close()

    admin_connection.close()


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

    proxysql_config_json = base64.b64decode(updated_value['Value'])
    proxysql_config = json.loads(proxysql_config_json)
    table = proxysql_config['table']
    rows = proxysql_config['rows']
    if not rows:
        print 'Empty config set for table: %s.' % table
        return
    update_proxysql_config(table, rows)

if __name__ == '__main__':
    read_config()

    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == 'put' and len(sys.argv) > 2:
            table = sys.argv[2]
            put_config(table)
            print 'Configs pushed successfully.'
            exit(0)
        elif mode == 'update':
            update_config()
            print 'Configs updated successfully.'
            exit(0)

    print USAGE
    exit(1)
