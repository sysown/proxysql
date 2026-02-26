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
    'architecture/architecture',
    {
      type: 'category',
      label: 'Guides',
      items: [
        {
          type: 'doc',
          id: 'guides/proxysql_configuration',
          label: 'Initial Configuration',
        },
      ],
    },
    {
      type: 'category',
      label: 'Configuration System',
      items: [
        'main_runtime/multi_layer_configuration',
        'configuration_file/configuration_file',
        'startup_options/startup_options',
        'bootstrap_mode/bootstrap-mode',
        'proxysql_internal_session/proxysql_internal_session',
        'disk/disk_disk',
      ],
    },
    {
      type: 'category',
      label: 'MySQL',
      items: [
        'main_runtime/mysql_tables',
        'references/mysql_variables',
        'references/mysql_monitor_variables',
        'backend_monitoring/mysql_monitoring',
        'users_management/mysql_users_management',
        'users_management/mysql_password_management',
        'users_management/mysql_authentication',
        {
          type: 'doc',
          id: 'galera_configuration/Galera_Configuration',
          label: 'Galera',
        },
        {
          type: 'doc',
          id: 'group_replication_configuration/group-replication-configuration',
          label: 'Group Replication',
        },
        {
          type: 'doc',
          id: 'aurora_configuration/aws-aurora-configuration',
          label: 'AWS Aurora',
        },
      ],
    },
    {
      type: 'category',
      label: 'PostgreSQL',
      items: [
        {
          type: 'doc',
          id: 'proxysql_configuration_postgres/proxysql_configuration_postgres',
          label: 'PostgreSQL Configuration',
        },
        'main_runtime/postgresql_tables',
        'references/pgsql_variables',
        'references/pgsql_monitor_variables',
        'backend_monitoring/postgresql_monitoring',
        'users_management/postgresql_users_management',
        'users_management/postgresql_authentication',
        {
          type: 'category',
          label: 'Extended Query Protocol',
          items: [
            'postgresql/extended_query_protocol',
            'postgresql/applying_query_rules_in_extended_query_protocol',
            'postgresql/prepared_statement_cache',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Generative AI',
      items: [
        'genai/mcp_server',
        'genai/mcp_integration',
        'genai/mcp_endpoints',
        'genai/mcp_autodiscovery',
        'genai/nl2sql',
        {
          type: 'category',
          label: 'RAG',
          items: [
            {
              type: 'doc',
              id: 'genai/rag_overview',
              label: 'Overview',
            },
            {
              type: 'doc',
              id: 'genai/rag_ingest',
              label: 'Ingest CLI',
            },
            {
              type: 'doc',
              id: 'genai/mcp_fts',
              label: 'Full-Text Search (FTS)',
            },
          ],
        },
        {
          type: 'category',
          label: 'MCP Tools',
          items: [
            'genai/mcp_tools_query',
            'genai/mcp_tools_rag',
            'genai/mcp_tools_upcoming',
          ],
        },
        'genai/mcp_catalog',
        'genai/mcp_stats',
        'references/mcp_variables',
        'main_runtime/mcp_tables',
      ],
    },
    {
      type: 'category',
      label: 'ProxySQL Admin',
      items: [
        'the_admin_schemas/the_admin_schemas',
        'the_admin_schemas/admin_commands',
        'main_runtime/configuration_tables',
        'main_runtime/mysql_tables',
        'main_runtime/postgresql_tables',
        'main_runtime/mcp_tables',
      ],
    },
    {
      type: 'category',
      label: 'Backend Configuration',
      items: [
        'backend_monitoring/mysql_monitoring',
        'backend_monitoring/postgresql_monitoring',
        {
          type: 'doc',
          id: 'galera_configuration/Galera_Configuration',
          label: 'Galera',
        },
        {
          type: 'doc',
          id: 'group_replication_configuration/group-replication-configuration',
          label: 'Group Replication',
        },
        {
          type: 'doc',
          id: 'aurora_configuration/aws-aurora-configuration',
          label: 'AWS Aurora',
        },
        {
          type: 'doc',
          id: 'proxysql_configuration_postgres/proxysql_configuration_postgres',
          label: 'PostgreSQL Configuration',
        },
        {
          type: 'doc',
          id: 'dns_cache/dns_cache',
          label: 'DNS Cache',
        },
      ],
    },
    {
      type: 'category',
      label: 'Users Management',
      items: [
        'users_management/mysql_users_management',
        'users_management/mysql_password_management',
        'users_management/mysql_authentication',
        'users_management/postgresql_users_management',
        'users_management/postgresql_authentication',
      ],
    },
    {
      type: 'category',
      label: 'Security',
      items: [
        'ssl_support/ssl_support',
      ],
    },
    {
      type: 'category',
      label: 'ProxySQL Cluster',
      items: [
        {
          type: 'doc',
          id: 'proxysql_cluster/proxysql-cluster',
          label: 'Cluster Overview',
        },
        {
          type: 'doc',
          id: 'proxysql_cluster/cluster_commands',
          label: 'Cluster Commands',
        },
        {
          type: 'doc',
          id: 'proxysql_cluster/cluster_variables',
          label: 'Cluster Variables',
        },
      ],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
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
        'features/scheduler',
        'features/http_web_server',
        'features/rest_api',
        'features/sqlite3_server',
        'coredumper_support/coredumper_support',
        'jemalloc/jemalloc',
        {
          type: 'doc',
          id: 'dns_cache/dns_cache',
          label: 'DNS Cache',
        },
        {
          type: 'doc',
          id: 'proxy_protocol/proxy-protocol',
          label: 'PROXY Protocol',
        },
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
      label: 'References',
      items: [
        'references/global_variables',
        {
          type: 'doc',
          id: 'references/admin_variables',
          label: 'Admin Variables',
        },
        {
          type: 'doc',
          id: 'references/mysql_variables',
          label: 'MySQL Variables',
        },
        {
          type: 'doc',
          id: 'references/mysql_monitor_variables',
          label: 'MySQL Monitor Variables',
        },
        {
          type: 'doc',
          id: 'references/pgsql_variables',
          label: 'PostgreSQL Variables',
        },
        {
          type: 'doc',
          id: 'references/pgsql_monitor_variables',
          label: 'PostgreSQL Monitor Variables',
        },
        {
          type: 'doc',
          id: 'references/mcp_variables',
          label: 'MCP Variables',
        },
        {
          type: 'doc',
          id: 'references/sqliteserver_variables',
          label: 'SQLite3 Server Variables',
        },
        'references/prometheus_metrics',
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