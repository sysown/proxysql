#include "AlertRouter.h"
#include "OpsGenieConnector.h"
#include "proxysql.h"
#include "cpp.h"

extern ProxySQL_Admin *GloAdmin;

// TODO(iprunache) Push alerts in separate threads to prevent blocking the threads that generated the alerts.


AlertRouter::AlertRouter() {
    // Set last push time to the minimum allow interval between pushes in the past to allow alert push immediately.
    lastPushTime = time(NULL) - GloAdmin->get_min_time_between_alerts_sec() - 1;
}

void AlertRouter::pushAlertToOpsGenie(const char * message) {
    if (!GloAdmin->get_ops_genie_api_key() || !GloAdmin->get_ops_genie_recipients()) {
        proxy_error("You need to set both ops_genie_api_key and ops_genie_recipients to enable integration with OpsGenei");
        return;
    }

    OpsGenieConnector opsGenieConnector(GloAdmin->get_ops_genie_api_key(), GloAdmin->get_ops_genie_recipients());
    opsGenieConnector.pushAlert(message);
}

// Checks which alert service integrations are enabled and sends the given message as an alert
// to all enabled services.
void AlertRouter::pushAlert(const char *message) {
    // Drop the alert if it is to soon since the last alert was pushed.
    time_t now = time(NULL);
    int min_time_between_alerts_sec = GloAdmin->get_min_time_between_alerts_sec();
    if ((int) difftime(now, lastPushTime) < min_time_between_alerts_sec) {
        proxy_info("Dropping alert raised sooner than %d seconds since previously pushed alert. Message: %s",
                   min_time_between_alerts_sec, message);
        return;
    }

    if (GloAdmin->get_enable_ops_genie_integration()) {
        pushAlertToOpsGenie(message);
    }
    lastPushTime = time(NULL);
}


