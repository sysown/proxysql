#!/usr/bin/env python3

""" A library with common utilities for test scripts """

import os
import yaml
import pymysql
import subprocess
import sys
import re

def check_output(*popenargs, **kwargs):

    """ Adding to support Python 2.6 in RHEL / CentOS 6.7
    """

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise subprocess.CalledProcessError(retcode, cmd)
    return output

def sorted_nicely( l , reverse=False):
    """ Sorts the given iterable in the way that is expected.

    Required arguments:
    l -- The iterable to be sorted.

    """
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
    return sorted(l, key = alphanum_key, reverse = reverse)

def init_config(cfg_filename):
    # Initialise config file
    try:
        dir = os.path.dirname(__file__)
        cfg_path = os.path.join(dir, '../etc/%s' % cfg_filename)
        with open(cfg_path) as cfg_file:
            cfg_file_contents = cfg_file.read()
            all_data = yaml.safe_load(cfg_file_contents)
        return all_data
    except Exception:
        return False

def run_command(command, host, ssh_key='~/.ssh/id_rsa', ssh_user='root', output=None, message=None, check_output=False):
    if host not in ['localhost','127.0.0.1','::1']:
        ssh_connection = 'ssh %s -i %s -l %s -o StrictHostKeyChecking=no -- ' \
                         % (host, ssh_key, ssh_user)
        command = '{0} "{1}"'.format(ssh_connection, command)

    if check_output is False:
        try:
           with open(output, 'a') as job_log:
               cmd_pipe = subprocess.Popen(command, stdout=job_log, stderr=subprocess.STDOUT, shell=True)
               cmd_pipe.communicate()
           if cmd_pipe.returncode != 0:
               return False
           else:
               return True
        except Exception as e:
            return False
    else:
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
            return 0, output
        except subprocess.CalledProcessError as e:
            return e.returncode, e.output

def open_mysql_conn(host, port=3306, user=None, passwd=None, timeout=60):

    conn = None

    try:
        if user is None and passwd is None:
            conn = pymysql.connect(host=host,
                                   port=port,
                                   read_default_group='client',
                                   connect_timeout=timeout,
                                   cursorclass=pymysql.cursors.DictCursor,
                                   defer_connect=True)
        else:
            conn = pymysql.connect(host=host,
                                   port=port,
                                   user=user,
                                   passwd=passwd,
                                   connect_timeout=timeout,
                                   cursorclass=pymysql.cursors.DictCursor,
                                   defer_connect=True)
        conn.client_flag |= pymysql.constants.CLIENT.MULTI_STATEMENTS
        conn.connect()
        conn.autocommit(True)
    except Exception as e:
        print(e)
        raise

    return conn


