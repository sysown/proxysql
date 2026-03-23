#include <mutex>
#include <vector>
#include "tap.h"
#include "PgSQL_HostGroup_Routing.h"

// TAP noise tool stubs
extern "C" int get_noise_tools_count() { return 0; }
extern "C" void stop_noise_tools() {}
std::mutex noise_failure_mutex;
std::vector<std::string> noise_failures;

void test_basic_routing() {
    PgSQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 10;
    sess.default_hostgroup = 10;
    sess.locked_on_hostgroup = -1;
    sess.transaction_persistent_hostgroup = -1;
    
    PgSQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 20;
    qpo.lock_hostgroup = false;
    
    PgSQL_Routing_Result res = resolve_pgsql_hostgroup_routing(sess, qpo, 1);
    
    ok(res.new_current_hostgroup == 20, "Basic: current_hostgroup should be destination_hostgroup from QPO");
    ok(res.error == false, "Basic: no error expected");
}

void test_locking_success() {
    PgSQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 10;
    sess.default_hostgroup = 10;
    sess.locked_on_hostgroup = -1;
    sess.transaction_persistent_hostgroup = -1;
    
    PgSQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 20;
    qpo.lock_hostgroup = true;
    
    // Test initial locking
    PgSQL_Routing_Result res = resolve_pgsql_hostgroup_routing(sess, qpo, 1);
    ok(res.new_current_hostgroup == 20, "Locking: current_hostgroup updated to destination");
    ok(res.lock_hostgroup == true, "Locking: lock_hostgroup flag set");
    ok(res.new_locked_on_hostgroup == 20, "Locking: new_locked_on_hostgroup set to 20");
    ok(res.error == false, "Locking: no error expected");
}

void test_locking_error() {
    PgSQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 20;
    sess.default_hostgroup = 10;
    sess.locked_on_hostgroup = 20;
    sess.transaction_persistent_hostgroup = -1;
    
    PgSQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 30; // Trying to reach a different hostgroup
    qpo.lock_hostgroup = false;
    
    PgSQL_Routing_Result res = resolve_pgsql_hostgroup_routing(sess, qpo, 1);
    ok(res.error == true, "Locked Error: error set when trying to reach different hostgroup");
    ok(res.error_msg.find("locked to hostgroup 20") != std::string::npos, "Locked Error: error message contains correct hostgroup");
}

void test_legacy_behavior() {
    PgSQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 10;
    sess.default_hostgroup = 5;
    sess.locked_on_hostgroup = -1;
    sess.transaction_persistent_hostgroup = -1;
    
    PgSQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = -1; // No rule match
    qpo.lock_hostgroup = false;
    
    PgSQL_Routing_Result res = resolve_pgsql_hostgroup_routing(sess, qpo, 0); // Legacy mode
    ok(res.new_current_hostgroup == 5, "Legacy: falls back to default_hostgroup when no QPO destination");
    
    sess.transaction_persistent_hostgroup = 10;
    res = resolve_pgsql_hostgroup_routing(sess, qpo, 0);
    ok(res.new_current_hostgroup == 10, "Legacy: remains on transaction_persistent_hostgroup");
}

int main() {
    plan(10);
    
    test_basic_routing();
    test_locking_success();
    test_locking_error();
    test_legacy_behavior();
    
    return exit_status();
}
