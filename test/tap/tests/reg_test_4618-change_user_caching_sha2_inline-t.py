#!/usr/bin/env python3
"""
Regression test for #4618: COM_CHANGE_USER carrying an inline 'caching_sha2_password'
auth response.

Oracle's libmysqlclient sends COM_CHANGE_USER with an empty auth response (covered by
'reg_test_4618-change_user_caching_sha2_libmysql-t'). Other connectors -- Connector/J,
Connector/Python, Rust mysql_async, ... -- compute the 32-byte SHA-256 scramble from the
nonce of the initial handshake and send it inline in COM_CHANGE_USER. Before the fix
ProxySQL rejected every such request with 'Access denied', whatever the stored password.

This test uses mysql-connector-python (pure-Python implementation, which builds the
COM_CHANGE_USER packet with the inline scramble) and checks, for target users whose
password is stored as clear text, as a 'mysql_native_password' hash and as a
'caching_sha2_password' hash, that 'cmd_change_user()':
  - succeeds with the correct password (and the session belongs to the target user),
  - fails with 1045 with a wrong password.
"""

import json
import os
import sys

import mysql.connector
from mysql.connector import errorcode

ADMIN = {
    'host': os.environ.get('TAP_ADMINHOST', '127.0.0.1'),
    'port': int(os.environ.get('TAP_ADMINPORT', '6032')),
    'user': os.environ.get('TAP_ADMINUSERNAME', 'radmin'),
    'password': os.environ.get('TAP_ADMINPASSWORD', 'radmin'),
}
PROXY_HOST = os.environ.get('TAP_HOST', '127.0.0.1')
PROXY_PORT = int(os.environ.get('TAP_PORT', '6033'))

# Per-run names: the test never touches a pre-existing account.
SRC_USER = 'cu4618i_{}_src'.format(os.getpid() % 100000)
SRC_PASS = 'cu4618i_src_pass'
TG_PASS = 'cu4618i-Secret'
WRONG_PASS = 'cu4618i-Wrong'

test_num = 0
failures = 0


def ok(cond, msg):
    global test_num, failures
    test_num += 1
    if not cond:
        failures += 1
    print('{} {} - {}'.format('ok' if cond else 'not ok', test_num, msg), flush=True)


def diag(msg):
    for line in str(msg).splitlines():
        print('# ' + line, flush=True)


def admin_exec(admin, query):
    cur = admin.cursor()
    cur.execute(query)
    rows = cur.fetchall() if cur.with_rows else []
    cur.close()
    return rows


def stored_value(admin, fmt, password):
    if fmt == 'clear_text':
        return password
    if fmt == 'native_hash':
        return admin_exec(admin, "SELECT MYSQL_NATIVE_PASSWORD('{}')".format(password))[0][0]
    if fmt == 'sha2_hash':
        return admin_exec(
            admin, "SELECT CACHING_SHA2_PASSWORD('{}','46181618461816184618')".format(password)
        )[0][0]
    raise ValueError(fmt)


def create_user(admin, user, stored):
    # A fresh runtime entry carries no cached clear-text password.
    admin_exec(admin, "DELETE FROM mysql_users WHERE username='{}'".format(user))
    admin_exec(admin, "LOAD MYSQL USERS TO RUNTIME")
    admin_exec(
        admin,
        "INSERT INTO mysql_users (username,password,active,default_hostgroup) "
        "VALUES ('{}','{}',1,0)".format(user, stored)
    )
    admin_exec(admin, "LOAD MYSQL USERS TO RUNTIME")


def set_variable(admin, name, value):
    admin_exec(admin, "SET {}='{}'".format(name, value))
    admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME")


def set_default_plugin(admin, plugin):
    set_variable(admin, 'mysql-default_authentication_plugin', plugin)


def snapshot_variable(admin, name):
    """Return (memory value, runtime value) of a global variable."""
    mem = admin_exec(
        admin, "SELECT variable_value FROM global_variables WHERE variable_name='{}'".format(name)
    )[0][0]
    rt = admin_exec(
        admin,
        "SELECT variable_value FROM runtime_global_variables WHERE variable_name='{}'".format(name)
    )[0][0]
    return mem, rt


def restore_variable(admin, name, snapshot):
    """Restore runtime first, then memory, so an unsaved runtime value survives."""
    mem, rt = snapshot
    set_variable(admin, name, rt)
    admin_exec(admin, "SET {}='{}'".format(name, mem))


def connect_src(use_tls):
    kwargs = dict(
        host=PROXY_HOST, port=PROXY_PORT, user=SRC_USER, password=SRC_PASS,
        auth_plugin='caching_sha2_password', use_pure=True,
    )
    if use_tls:
        kwargs['ssl_disabled'] = False
        kwargs['ssl_verify_cert'] = False
    else:
        kwargs['ssl_disabled'] = True
    return mysql.connector.connect(**kwargs)


def session_username(conn):
    cur = conn.cursor()
    cur.execute('PROXYSQL INTERNAL SESSION')
    row = cur.fetchone()
    cur.close()
    return json.loads(row[0])['client']['userinfo']['username']


user_seq = 0


def next_user():
    global user_seq
    user_seq += 1
    return 'cu4618i_{}_{}'.format(os.getpid() % 100000, user_seq)


def run_case(admin, def_plugin, fmt, use_tls):
    desc = 'def_plugin={} stored={} transport={}'.format(
        def_plugin, fmt, 'TLS' if use_tls else 'plain'
    )
    set_default_plugin(admin, def_plugin)

    # Correct password
    tg_user = next_user()
    conn = None
    try:
        create_user(admin, tg_user, stored_value(admin, fmt, TG_PASS))
        conn = connect_src(use_tls)
        conn.cmd_change_user(username=tg_user, password=TG_PASS)
        sess_user = session_username(conn)
        ok(sess_user == tg_user,
           'COM_CHANGE_USER (inline scramble) with the correct password should succeed   '
           '{} session_user={} exp_user={}'.format(desc, sess_user, tg_user))
    except Exception as ex:  # noqa: BLE001 - report any failure as a TAP failure
        ok(False, 'COM_CHANGE_USER (inline scramble) with the correct password should '
                  'succeed   {} err={!r}'.format(desc, ex))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    # Wrong password. Only an error raised by cmd_change_user() itself counts: a 1045
    # from the fixture or from the source connection is a test failure.
    tg_user = next_user()
    conn = None
    try:
        create_user(admin, tg_user, stored_value(admin, fmt, TG_PASS))
        conn = connect_src(use_tls)
    except Exception as ex:  # noqa: BLE001
        ok(False, 'COM_CHANGE_USER (inline scramble) with a wrong password should fail '
                  'with 1045   {} setup failed: err={!r}'.format(desc, ex))
        if conn is not None:
            conn.close()
        return
    try:
        try:
            conn.cmd_change_user(username=tg_user, password=WRONG_PASS)
            ok(False, 'COM_CHANGE_USER (inline scramble) with a wrong password should fail '
                      'with 1045   {} (it succeeded)'.format(desc))
        except mysql.connector.Error as ex:
            ok(ex.errno == errorcode.ER_ACCESS_DENIED_ERROR,
               'COM_CHANGE_USER (inline scramble) with a wrong password should fail with 1045   '
               '{} errno={} err={!r}'.format(desc, ex.errno, ex))
        except Exception as ex:  # noqa: BLE001
            ok(False, 'COM_CHANGE_USER (inline scramble) with a wrong password should fail '
                      'with 1045   {} err={!r}'.format(desc, ex))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def main():
    cases = []
    # Hashed passwords need full authentication; Connector/Python only performs it over TLS.
    for fmt in ('clear_text', 'native_hash', 'sha2_hash'):
        cases.append(('caching_sha2_password', fmt, True))
    cases.append(('caching_sha2_password', 'clear_text', False))
    # ProxySQL advertising 'mysql_native_password'.
    cases.append(('mysql_native_password', 'clear_text', True))
    cases.append(('mysql_native_password', 'native_hash', True))

    print('1..{}'.format(len(cases) * 2), flush=True)

    admin = mysql.connector.connect(use_pure=True, ssl_disabled=True, **ADMIN)
    admin.autocommit = True
    variables = ('mysql-default_authentication_plugin', 'mysql-have_ssl')
    snapshots = {name: snapshot_variable(admin, name) for name in variables}
    diag('mysql-connector-python version: {}'.format(mysql.connector.__version__))

    try:
        # The TLS cases must not depend on the state left by earlier tests.
        set_variable(admin, 'mysql-have_ssl', 'true')
        create_user(admin, SRC_USER, SRC_PASS)
        for def_plugin, fmt, use_tls in cases:
            run_case(admin, def_plugin, fmt, use_tls)
    finally:
        # Every step is attempted even if an earlier one fails. Only users with this
        # run's prefix are removed: they were all created by this test.
        cleanup = [
            lambda: admin_exec(
                admin,
                "DELETE FROM mysql_users WHERE username LIKE 'cu4618i\\_{}\\_%' ESCAPE '\\'"
                .format(os.getpid() % 100000)
            ),
            lambda: admin_exec(admin, "LOAD MYSQL USERS TO RUNTIME"),
        ] + [
            (lambda name=name: restore_variable(admin, name, snapshots[name]))
            for name in variables
        ]
        for step in cleanup:
            try:
                step()
            except Exception as ex:  # noqa: BLE001
                diag('cleanup step failed: {!r}'.format(ex))
        admin.close()

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
