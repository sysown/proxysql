#!/usr/bin/env python

import base64
import json
import os
import requests
import sys


USAGE = """
proxysql-consul put config config_type
"""

CFG_PATH = '/etc/proxysql-consul.cfg'
CFG_CONSUL_IFACE = 'consul_iface'
CFG_CONSUL_PORT = 'consul_port'

# Proxysql config types to Consul key mapping
TYPE_TO_KEY = {
        'mysql_servers': 'proxysql/mysql_serverss'
        }

config = {}


def read_config():
    global config
    with open(CFG_PATH) as config_file:
        config_data = config_file.read()
    config = json.loads(config_data)

    # TODO validate config


def write_data(proxysql_cfg, proxysql_cfg_type):
    if proxysql_cfg_type not in TYPE_TO_KEY:
        print 'Unknown config type. Exiting.'
        exit(1)
    key = TYPE_TO_KEY[proxysql_cfg_type]

    consul_iface = config[CFG_CONSUL_IFACE]
    consul_port = config[CFG_CONSUL_PORT]

    url = 'http://%s:%s/v1/kv/%s' % (consul_iface, consul_port, key)
    r = requests.put(url, data=proxysql_cfg)
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
        if mode == 'put' and len(sys.argv) > 3:
            key = sys.argv[2]
            value = sys.argv[3]
            write_data(key, value)
            exit(0)
        elif mode == 'update':
            update_config()
            exit(0)

    print USAGE
    exit(1)
