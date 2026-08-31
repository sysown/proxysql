var host = os.getenv('MYSQL_ROUTER_IC_HOST');
var password = os.getenv('MYSQL_ROUTER_IC_PASSWORD');
var clusterName = 'proxysql_e2e';

function uri(port) {
    return 'root:' + encodeURIComponent(password) + '@' + host + ':' + port;
}

function waitForInstance(port) {
    var lastError = '';
    for (var attempt = 0; attempt < 60; ++attempt) {
        try {
            var probe = mysql.getSession(uri(port));
            probe.close();
            return;
        } catch (error) {
            lastError = error.message;
            os.sleep(1);
        }
    }
    throw new Error('MySQL instance ' + port + ' did not restart: ' + lastError);
}

for (var port = 3306; port <= 3309; ++port) {
    try {
        dba.configureInstance(uri(port), {restart: true});
    } catch (error) {
        print('configureInstance(' + port + '): ' + error.message);
    }
}

for (var readyPort = 3306; readyPort <= 3309; ++readyPort) {
    waitForInstance(readyPort);
}

shell.connect(uri(3306));
var cluster;
try {
    cluster = dba.getCluster(clusterName);
} catch (error) {
    cluster = dba.createCluster(clusterName, {
        gtidSetIsComplete: true,
        communicationStack: 'MYSQL'
    });
}

function topologyContains(port) {
    var topology = cluster.status({extended: 1}).defaultReplicaSet.topology;
    return Object.keys(topology).some(function(key) {
        return key.endsWith(':' + port);
    });
}

for (var memberPort = 3307; memberPort <= 3308; ++memberPort) {
    if (!topologyContains(memberPort)) {
        cluster.addInstance(uri(memberPort), {recoveryMethod: 'clone'});
    }
}

var readReplicaAdded = false;
try {
    if (!topologyContains(3309)) {
        cluster.addReplicaInstance(uri(3309), {
            recoveryMethod: 'clone',
            label: 'read-replica'
        });
    }
    readReplicaAdded = true;
} catch (error) {
    println('READ_REPLICA_UNAVAILABLE=' + error.message);
}

var session = mysql.getSession(uri(3306));
session.runSql('CREATE DATABASE IF NOT EXISTS router_e2e');
session.runSql("CREATE USER IF NOT EXISTS 'app_writer'@'%' IDENTIFIED BY 'router-app-password'");
session.runSql("ALTER USER 'app_writer'@'%' IDENTIFIED BY 'router-app-password'");
session.runSql("GRANT ALL PRIVILEGES ON router_e2e.* TO 'app_writer'@'%'");
session.runSql("CREATE USER IF NOT EXISTS 'app_reader'@'%' IDENTIFIED BY 'router-app-password'");
session.runSql("ALTER USER 'app_reader'@'%' IDENTIFIED BY 'router-app-password'");
session.runSql("GRANT SELECT ON router_e2e.* TO 'app_reader'@'%'");
session.runSql("CREATE USER IF NOT EXISTS 'operator_user'@'%' IDENTIFIED BY 'operator-password'");
session.runSql("ALTER USER 'operator_user'@'%' IDENTIFIED BY 'operator-password'");
session.runSql("GRANT ALL PRIVILEGES ON router_e2e.* TO 'operator_user'@'%'");

var topologyUuid = session.runSql(
    "SELECT cluster_id FROM mysql_innodb_cluster_metadata.v2_gr_clusters WHERE cluster_name=?",
    [clusterName]).fetchOne()[0];
var primaryUuid = session.runSql(
    "SELECT MEMBER_ID FROM performance_schema.replication_group_members " +
    "WHERE MEMBER_ROLE='PRIMARY' AND MEMBER_STATE='ONLINE'").fetchOne()[0];
var instances = session.runSql(
    "SELECT mysql_server_uuid,address,instance_type FROM mysql_innodb_cluster_metadata.v2_instances " +
    "WHERE cluster_id=? ORDER BY address", [topologyUuid]).fetchAll();
readReplicaAdded = instances.some(function(row) { return row[2] == 'read-replica'; });

var fixture = {
    mysqlsh_version: shell.version,
    cluster_name: clusterName,
    topology_uuid: topologyUuid,
    primary_uuid: primaryUuid,
    read_replica_added: readReplicaAdded,
    instances: instances.map(function(row) {
        return {server_uuid: row[0], endpoint: row[1], instance_type: row[2]};
    })
};
println('MYSQL_ROUTER_FIXTURE=' + JSON.stringify(fixture));
