var host = os.getenv('MYSQL_ROUTER_IC_HOST');
var password = os.getenv('MYSQL_ROUTER_IC_PASSWORD');
var router = os.getenv('MYSQL_ROUTER_SHELL_ROUTER');
var session = mysql.getSession('root:' + encodeURIComponent(password) + '@' + host + ':3306');
shell.setSession(session);
var cluster = dba.getCluster('proxysql_e2e');

var before = cluster.listRouters();
var options = cluster.routerOptions({router: router});
var routing = cluster.routingOptions(router);
cluster.setRoutingOption(router, 'read_only_targets', 'all');
cluster.setupRouterAccount('shell_router_app', {
    password: 'shell-router-password'
});
var after = cluster.listRouters();
var routingAfter = cluster.routingOptions(router);
var accountCount = session.runSql(
    "SELECT COUNT(*) FROM mysql.user WHERE user='shell_router_app'").fetchOne()[0];
var accountGrants = session.runSql(
    "SHOW GRANTS FOR 'shell_router_app'@'%'").fetchAll().map(function(row) { return row[0]; });

println('MYSQL_ROUTER_SHELL_CONTRACT=' + JSON.stringify({
    router: router,
    list_before: before,
    router_options: options,
    routing_options: routing,
    list_after: after,
    routing_options_after: routingAfter,
    account_count: accountCount,
    account_grants: accountGrants
}));
