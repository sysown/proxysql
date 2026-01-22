import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Configuration System',
      items: [
        'configuration_file/configuration_file',
        'startup_options/startup_options',
        'bootstrap_mode/bootstrap-mode',
        'proxysql_internal_session/proxysql_internal_session',
        'disk/disk_disk',
      ],
    },
    {
      type: 'category',
      label: 'ProxySQL Admin',
      items: [
        'the_admin_schemas/the_admin_schemas',
        'main_runtime/main_runtime_tables',
      ],
    },
    {
      type: 'category',
      label: 'Backend Configuration',
      items: [
        'backend_monitoring/mysql_monitoring',
        'backend_monitoring/postgresql_monitoring',
        'galera_configuration/Galera_Configuration',
        'group_replication_configuration/group-replication-configuration',
        'aurora_configuration/aws-aurora-configuration',
        'proxysql_configuration_postgres/proxysql_configuration_postgres',
        'dns_cache/dns_cache',
        'proxy_protocol/proxy-protocol',
      ],
    },
    {
      type: 'category',
      label: 'Security',
      items: [
        'authentication/authentication_methods',
        'authentication/password_management',
        'ssl_support/ssl_support',
      ],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        'proxysql_cluster/proxysql-cluster',
        {
          type: 'category',
          label: 'Query Logging',
          items: [
            'query_logging/query_logging',
            'query_logging/advanced_logging',
          ],
        },
        'query_annotations/query_annotations',
        'prepared_statements/prepared_statements',
        'mysql_binlog_reader/mysql-binlog-reader',
        'coredumper_support/coredumper_support',
        'jemalloc/jemalloc',
      ],
    },
    {
      type: 'category',
      label: 'Monitoring & Stats',
      items: [
        'prometheus_metrics/prometheus_metrics',
        'stats_statistics/stats_statistics',
        'stats_history/stats_history',
        'error_log/error_log',
      ],
    },
    {
      type: 'category',
      label: 'Reference (Global Variables)',
      items: [
        'global_variables/quick-reference',
        'global_variables/global_variables',
        'global_variables/admin_variables',
        'global_variables/mysql_variables',
        'global_variables/mysql_monitor_variables',
        'global_variables/pgsql_variables',
        'global_variables/pgsql_monitor_variables',
      ],
    },
    {
      type: 'category',
      label: 'FAQ',
      items: [
        'faq/frequently_asked_questions',
        'faq/detailed_answers_on_faq',
      ],
    },
  ],
};

export default sidebars;