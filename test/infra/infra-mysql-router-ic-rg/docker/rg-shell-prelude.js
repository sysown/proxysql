// Prepended by rg-shell.sh to every script. Connects the unmodified MySQL
// Shell to a reachable InnoDB Cluster member and binds `session` and
// `cluster` for the caller's script.
var __rgHost = os.getenv('MYSQL_ROUTER_IC_HOST');
var __rgPassword = os.getenv('MYSQL_ROUTER_IC_PASSWORD');
var __rgClusterName = os.getenv('MYSQL_ROUTER_IC_CLUSTER') || 'proxysql_e2e';
if (!__rgHost || !__rgPassword) {
    throw new Error('MYSQL_ROUTER_IC_HOST and MYSQL_ROUTER_IC_PASSWORD must be set');
}
function rgMemberUri(port) {
    return 'root:' + encodeURIComponent(__rgPassword) + '@' + __rgHost + ':' + port;
}
var __rgLastError = '';
var __rgConnected = false;
for (var __rgPort = 3306; __rgPort <= 3308 && !__rgConnected; ++__rgPort) {
    try {
        shell.connect(rgMemberUri(__rgPort));
        __rgConnected = true;
    } catch (error) {
        __rgLastError = error.message;
    }
}
if (!__rgConnected) {
    throw new Error('no reachable InnoDB Cluster member: ' + __rgLastError);
}
var cluster = dba.getCluster(__rgClusterName);
