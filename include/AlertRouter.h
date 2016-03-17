#ifndef PROXYSQL_ALERTROUTER_H
#define PROXYSQL_ALERTROUTER_H

#include <atomic>

// Acts as a gateway between ProxySQL core and integrations with alerting services.
// All alerts that need to be pushed to an external service should pass through it.
// It detects which integrations are enabled and passes the alert to all active
// integrations.
//
// It uses the AlertServiceConnector interface to interact with the various external
// services connector. Since it mostly forwards alerts to the connectors, AlertRouter
// mostly shares the same interface with AlertServiceConnector.
class AlertRouter {
private:
    std::atomic_ullong lastPushTime;
    static void *pushAlertToOpsGenie(void *message);
    static void *pushAlertToPagerduty(void *message);
    void pushAlertInDetachedThread(void *(*pushMethod)(void *), char *message);
public:
    AlertRouter();
    AlertRouter(unsigned long long lastPushTime);
    void pushAlert(char *message);
};

#endif //PROXYSQL_ALERTROUTER_H
