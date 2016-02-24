#!/usr/bin/env python

import json
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
        'mysql_servers': 'proxysql/mysql_servers'
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

if __name__ == '__main__':
    read_config()

    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == 'put' and len(sys.argv) > 3:
            key = sys.argv[2]
            value = sys.argv[3]
            write_data(key, value)
            exit(0)
    print USAGE
    exit(1)
