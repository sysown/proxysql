#include "AlertRouter.h"
#include "proxysql_admin.h"
#include "OpsGenieConnector.h"

extern ProxySQL_Admin *GloAdmin;

// TODO(iprunache) Push alerts in separate threads to prevent blocking the threads that generated the alerts.

// Checks which alert service integrations are enabled and sends the given message as an alert
// to all enabled services.
void AlertRouter::pushAlert(const char *message) {
    if (GloAdmin->get_enable_ops_genie_integration()) {
        if (!GloAdmin->get_ops_genie_key() || !GloAdmin->get_ops_genie_recipient()) {
            proxy_error("You need to set both ops_genie_key and ops_genie_recipient to enable integration with OpsGenei");
        }

        OpsGenieConnector opsGenieConnector(GloAdmin->get_ops_genie_key(), GloAdmin->get_ops_genie_recipient());
        int ret = opsGenieConnector.pushAlert(message);
        if (!ret) {
            proxy_error("Failed to send alert to OpsGenie. Alert message: %s", message);
        }
    }
}
