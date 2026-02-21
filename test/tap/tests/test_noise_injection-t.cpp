#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <sys/types.h>
#include <signal.h>
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "noise_utils.h"

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get environment variables");
        return 1;
    }

    if (!cl.use_noise) {
        skip_all("TAP_USE_NOISE is not enabled. Skip noise injection test.");
    }

    plan(5);

    // --- External Noise Test ---
    std::string pid_file = "/tmp/proxysql_noise_test.pid";
    std::string cmd = "echo $$ > " + pid_file + " && exec sleep 100";
    spawn_noise(cl, "/bin/bash", {"-c", cmd});

    sleep(1); // Give it time to start

    ok(access(pid_file.c_str(), F_OK) == 0, "External noise process started and created PID file");

    FILE* f = fopen(pid_file.c_str(), "r");
    pid_t pid = 0;
    if (f) {
        if (fscanf(f, "%d", &pid) != 1) pid = 0;
        fclose(f);
    }
    diag("External noise process PID: %d", pid);

    ok(pid > 0 && kill(pid, 0) == 0, "External noise process is alive");

    // --- Internal Noise Test ---
    spawn_internal_noise(cl, internal_noise_admin_pinger);
    spawn_internal_noise(cl, internal_noise_prometheus_poller);
    spawn_internal_noise(cl, internal_noise_mysql_traffic);
    spawn_internal_noise(cl, internal_noise_pgsql_traffic);
    
    ok(1, "Internal noise threads spawned without crash");

    // --- Cleanup Verification ---
    stop_noise_tools();
    sleep(1); // Give it time to be killed
    
    ok(pid > 0 && kill(pid, 0) != 0, "External noise process was killed");
    ok(1, "Internal noise tools stopped (implied by join finishing)");

    if (access(pid_file.c_str(), F_OK) == 0) {
        unlink(pid_file.c_str());
    }

    return exit_status();
}
