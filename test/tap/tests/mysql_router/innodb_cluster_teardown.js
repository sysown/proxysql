var host = os.getenv('MYSQL_ROUTER_IC_HOST');
var port = os.getenv('MYSQL_ROUTER_IC_PORT') || '3306';
var password = os.getenv('MYSQL_ROUTER_IC_PASSWORD');
try {
    shell.connect('root:' + encodeURIComponent(password) + '@' + host + ':' + port);
    var cluster = dba.getCluster('proxysql_e2e');
    try {
        cluster.removeRouterMetadata(os.getenv('MYSQL_ROUTER_SHELL_ROUTER'));
    } catch (error) {
        print('removeRouterMetadata: ' + error.message);
    }
    cluster.dissolve({force: true});
} catch (error) {
    print('teardown: ' + error.message);
}
