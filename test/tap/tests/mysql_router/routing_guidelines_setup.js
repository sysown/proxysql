// Runs through rg-shell.sh (unmodified MySQL Shell 9.x) after
// innodb_cluster_setup.js: `session` and `cluster` are pre-bound.
//
// Creates, but does NOT activate, two Routing Guidelines with the public
// AdminAPI and tags one instance. The TAP test activates / modifies them.
var clientNetwork = os.getenv('MYSQL_ROUTER_RG_CLIENT_NETWORK') || '10.0.0.0';
var clientMask = parseInt(os.getenv('MYSQL_ROUTER_RG_CLIENT_MASK') || '8', 10);
var host = os.getenv('MYSQL_ROUTER_IC_HOST');
var taggedEndpoint = host + ':3307';

function sqlRows(sql, args) {
    return session.runSql(sql, args || []).fetchAll().map(function(row) {
        var values = [];
        for (var i = 0; i < row.length; ++i) values.push(row[i]);
        return values;
    });
}

// Application accounts used by the guideline routes (replicated by GR).
session.runSql('CREATE DATABASE IF NOT EXISTS router_e2e');
['rg_reporting', 'rg_batch'].forEach(function(user) {
    session.runSql("CREATE USER IF NOT EXISTS '" + user + "'@'%' IDENTIFIED BY 'router-app-password'");
    session.runSql("ALTER USER '" + user + "'@'%' IDENTIFIED BY 'router-app-password'");
    session.runSql("GRANT ALL PRIVILEGES ON router_e2e.* TO '" + user + "'@'%'");
});

// Instance tag stored in v2_instances.attributes->'$.tags'.
cluster.setInstanceOption('root:' + encodeURIComponent(os.getenv('MYSQL_ROUTER_IC_PASSWORD')) +
    '@' + taggedEndpoint, 'tag:region', 'eu');

// Re-runs replace earlier fixture guidelines (they are never active here).
function createGuideline(name) {
    var exists = true;
    try {
        cluster.getRoutingGuideline(name);
    } catch (error) {
        exists = false;
    }
    if (exists) cluster.removeRoutingGuideline(name);
    return cluster.createRoutingGuideline(name);
}

// 1. Shell default guideline for an InnoDB Cluster (no JSON argument).
var rgDefault = createGuideline('rg_default');

// 2. Custom guideline built incrementally with the AdminAPI.
var rgCustom = createGuideline('rg_custom');
rgCustom.addDestination('EUServers', "$.server.tags.region = 'eu'");
rgCustom.addRoute('eu_reporting', "$.session.user = 'rg_reporting'",
    ['first-available(EUServers)', 'round-robin(Secondary)'], {order: 0});
rgCustom.addRoute('batch_program', "$.session.connectAttrs.program_name = 'rg_batch'",
    ['round-robin(ReadReplica)', 'round-robin(Secondary)'], {order: 1});
rgCustom.addRoute('backend_network_readers',
    "$.session.user = 'app_reader' AND NETWORK($.session.sourceIP, " + clientMask +
    ") = '" + clientNetwork + "'",
    ['round-robin(Secondary, ReadReplica)', 'first-available(Primary)'], {order: 2});

var guidelineRows = sqlRows(
    'SELECT guideline_id, name, CAST(guideline AS CHAR) FROM ' +
    'mysql_innodb_cluster_metadata.routing_guidelines ORDER BY name');
var schemaVersion = sqlRows(
    'SELECT major, minor, patch FROM mysql_innodb_cluster_metadata.schema_version')[0];
var taggedRows = sqlRows(
    "SELECT mysql_server_uuid, address, CAST(attributes->'$.tags' AS CHAR) FROM " +
    "mysql_innodb_cluster_metadata.v2_instances WHERE attributes->'$.tags.region' IS NOT NULL");

println('MYSQL_ROUTER_RG_FIXTURE=' + JSON.stringify({
    mysqlsh_version: shell.version,
    metadata_schema_version: schemaVersion.join('.'),
    client_network: clientNetwork + '/' + clientMask,
    tagged_instances: taggedRows.map(function(row) {
        return {server_uuid: row[0], address: row[1], tags: JSON.parse(row[2])};
    }),
    guidelines: {
        rg_default: rgDefault.asJson(),
        rg_custom: rgCustom.asJson()
    },
    metadata_rows: guidelineRows.map(function(row) {
        return {guideline_id: row[0], name: row[1], guideline: JSON.parse(row[2])};
    }),
    router_options: cluster.routerOptions()
}));
