# coding=utf-8

import diamond.collector
from diamond.collector import str_to_bool
import re
import time

try:
    import MySQLdb
    from MySQLdb import MySQLError
except ImportError:
    MySQLdb = None
    MySQLError = ValueError


class ProxySQLCollector(diamond.collector.Collector):

    _GAUGE_KEYS = [
        'Active_Transactions',
        'Client_Connections_connected',
        'ConnPool_memory_bytes',
        'MySQL_Monitor_Workers',
        'MySQL_Thread_Workers',
        'Query_Cache_Entries',
        'Query_Cache_Memory_bytes',
        'SQLite3_memory_bytes',
        'Server_Connections_connected',
        'mysql_backend_buffers_bytes',
        'mysql_frontend_buffers_bytes',
        'mysql_session_internal_bytes',
        ]

    def __init__(self, *args, **kwargs):
        super(ProxySQLCollector, self).__init__(*args, **kwargs)

    def process_config(self):
        super(ProxySQLCollector, self).process_config()
        if self.config['hosts'].__class__.__name__ != 'list':
            self.config['hosts'] = [self.config['hosts']]

        # Move legacy config format to new format
        if 'host' in self.config:
            hoststr = "%s:%s@%s:%s/%s" % (
                self.config['user'],
                self.config['passwd'],
                self.config['host'],
                self.config['port'],
                self.config['db'],
            )
            self.config['hosts'].append(hoststr)

        self.db = None

    def get_default_config_help(self):
        config_help = super(ProxySQLCollector, self).get_default_config_help()
        config_help.update({
            'publish':
                "Which rows of 'SHOW MYSQL STATUS' you would " +
                "like to publish. Leave unset to publish all",
            'hosts': 'List of hosts to collect from. Format is ' +
            'yourusername:yourpassword@host:port/db[/nickname]' +
            'use db "None" to avoid connecting to a particular db'
        })
        return config_help

    def get_default_config(self):
        """
        Returns the default collector settings
        """
        config = super(ProxySQLCollector, self).get_default_config()
        config.update({
            'path':     'proxysql',
            # Connection settings
            'hosts':    [],

        })
        return config

    def get_db_stats(self, query):
        cursor = self.db.cursor(cursorclass=MySQLdb.cursors.DictCursor)

        try:
            cursor.execute(query)
            return cursor.fetchall()
        except MySQLError, e:
            self.log.error('ProxySQLCollector could not get db stats', e)
            return ()

    def connect(self, params):
        try:
            self.db = MySQLdb.connect(**params)
            self.log.debug('ProxySQLCollector: Connected to database.')
        except MySQLError, e:
            self.log.error('ProxySQLCollector couldnt connect to database %s', e)
            return False
        return True

    def disconnect(self):
        self.db.close()

    def get_db_global_status(self):
        return self.get_db_stats('SHOW MYSQL STATUS')

    def get_stats(self, params):
        metrics = {'status': {}}

        if not self.connect(params):
            return metrics

        rows = self.get_db_global_status()
        for row in rows:
            try:
                metrics['status'][row['Variable_name']] = float(row['Value'])
            except:
                pass

        self.disconnect()

        return metrics

    def _publish_stats(self, nickname, metrics):

        for key in metrics:
            for metric_name in metrics[key]:
                metric_value = metrics[key][metric_name]

                if type(metric_value) is not float:
                    continue

                if metric_name not in self._GAUGE_KEYS:
                    metric_value = self.derivative(nickname + metric_name,
                                                   metric_value)
                if key == 'status':
                    if (('publish' not in self.config or
                         metric_name in self.config['publish'])):
                        self.publish(nickname + metric_name, metric_value)
                else:
                    self.publish(nickname + metric_name, metric_value)

    def collect(self):

        if MySQLdb is None:
            self.log.error('Unable to import MySQLdb')
            return False

        for host in self.config['hosts']:
            matches = re.search(
                '^([^:]*):([^@]*)@([^:]*):?([^/]*)/([^/]*)/?(.*)', host)

            if not matches:
                self.log.error(
                    'Connection string not in required format, skipping: %s',
                    host)
                continue

            params = {}

            params['host'] = matches.group(3)
            try:
                params['port'] = int(matches.group(4))
            except ValueError:
                params['port'] = 3306
            params['db'] = matches.group(5)
            params['user'] = matches.group(1)
            params['passwd'] = matches.group(2)

            nickname = matches.group(6)
            if len(nickname):
                nickname += '.'

            if params['db'] == 'None':
                del params['db']

            try:
                metrics = self.get_stats(params=params)
            except Exception, e:
                try:
                    self.disconnect()
                except MySQLdb.ProgrammingError:
                    pass
                self.log.error('Collection failed for %s %s', nickname, e)
                continue

            # Warn if publish contains an unknown variable
            if 'publish' in self.config and metrics['status']:
                for k in self.config['publish'].split():
                    if k not in metrics['status']:
                        self.log.error("No such key '%s' available, issue " +
                                       "'show global status' for a full " +
                                       "list", k)
            self._publish_stats(nickname, metrics)
