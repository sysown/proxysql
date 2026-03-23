#include <mutex>
#include <vector>
#include "tap.h"
#include "MySQL_HostGroup_Routing.h"

// TAP noise tool stubs
extern "C" int get_noise_tools_count() { return 0; }
extern "C" void stop_noise_tools() {}
std::mutex noise_failure_mutex;
std::vector<std::string> noise_failures;

void test_mirroring() {
    MySQL_Routing_Session_State sess = {0};
    sess.mirror = true;
    sess.current_hostgroup = 10;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 20;
    
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 1);
    
    ok(res.new_current_hostgroup == 20, "Mirroring: current_hostgroup should be destination_hostgroup from QPO");
    ok(res.error == false, "Mirroring: no error expected");
}

void test_show_warnings() {
    MySQL_Routing_Session_State sess = {0};
    sess.warning_in_hg = 15;
    sess.current_hostgroup = 10;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.is_show_warnings = true;
    
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 1);
    
    ok(res.new_current_hostgroup == 15, "SHOW WARNINGS: current_hostgroup should be warning_in_hg");
    
    sess.warning_in_hg = -1;
    res = resolve_hostgroup_routing(sess, qpo, 1);
    ok(res.new_current_hostgroup == 10, "SHOW WARNINGS: current_hostgroup should remain unchanged if warning_in_hg is -1");
}

void test_last_insert_id() {
    MySQL_Routing_Session_State sess = {0};
    sess.last_HG_affected_rows = 25;
    sess.current_hostgroup = 10;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.is_last_insert_id = true;
    
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 1);
    
    ok(res.new_current_hostgroup == 25, "LAST_INSERT_ID: current_hostgroup should be last_HG_affected_rows");
}

void test_locking_success() {
    MySQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 10;
    sess.default_hostgroup = 10;
    sess.locked_on_hostgroup = -1;
    sess.transaction_persistent_hostgroup = -1;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 20;
    qpo.is_set_statement = true;
    
    // Test initial locking
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 1);
    ok(res.new_current_hostgroup == 20, "Locking: current_hostgroup updated to destination (expected 20, got %d)", res.new_current_hostgroup);
    ok(res.lock_hostgroup == true, "Locking: lock_hostgroup flag set");
    ok(res.new_locked_on_hostgroup == 20, "Locking: new_locked_on_hostgroup set to 20 (got %d)", res.new_locked_on_hostgroup);
    ok(res.error == false, "Locking: no error expected");
    
    // Test subsequent query on same hostgroup
    sess.current_hostgroup = 20;
    sess.locked_on_hostgroup = 20;
    qpo.is_set_statement = false;
    qpo.destination_hostgroup = 20;
    res = resolve_hostgroup_routing(sess, qpo, 1);
    ok(res.new_current_hostgroup == 20, "Locked: current_hostgroup remains 20");
    ok(res.error == false, "Locked: no error when hostgroup matches");
}

void test_locking_error() {
    MySQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 20;
    sess.locked_on_hostgroup = 20;
    sess.transaction_persistent_hostgroup = -1;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = 30; // Trying to reach a different hostgroup
    
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 1);
    ok(res.error == true, "Locked Error: error set when trying to reach different hostgroup");
    ok(res.error_msg.find("locked to hostgroup 20") != std::string::npos, "Locked Error: error message contains correct hostgroup");
}

void test_legacy_behavior() {
    MySQL_Routing_Session_State sess = {0};
    sess.current_hostgroup = 10;
    sess.default_hostgroup = 5;
    sess.transaction_persistent_hostgroup = -1;
    
    MySQL_Routing_QPO_State qpo = {0};
    qpo.destination_hostgroup = -1; // No rule match
    
    MySQL_Routing_Result res = resolve_hostgroup_routing(sess, qpo, 0); // Legacy mode
    ok(res.new_current_hostgroup == 5, "Legacy: falls back to default_hostgroup when no QPO destination");
    
    sess.transaction_persistent_hostgroup = 10;
    res = resolve_hostgroup_routing(sess, qpo, 0);
    ok(res.new_current_hostgroup == 10, "Legacy: remains on transaction_persistent_hostgroup");
}

int main() {
    plan(15);
    
    test_mirroring();
    test_show_warnings();
    test_last_insert_id();
    test_locking_success();
    test_locking_error();
    test_legacy_behavior();
    
    return exit_status();
}
