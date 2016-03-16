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


AlertRouter::AlertRouter(time_t lastPushTime) {
    this->lastPushTime = lastPushTime;
}


// Forwards the given message to OpsGenieConnector so it can be pushed to OpsGenie.
//
// It assumes that it can be run in a different thread than the one that allocated message so it will free message
// before returning.
void *AlertRouter::pushAlertToOpsGenie(void *message) {
    if (!GloAdmin->get_ops_genie_api_key()) {
        proxy_error("You need to set ops_genie_api_key to enable integration with OpsGenie");
        free(message);
        return NULL;
    }

    OpsGenieConnector opsGenieConnector(GloAdmin->get_ops_genie_api_key());
    opsGenieConnector.pushAlert((char *)message);
    free(message);
    return NULL;
}


// Creates a detached thread to run the pushMethod with the given message as argument.
//
// Clones message so the thread can safely use it even if parent thread frees it before the new thread runs.
void AlertRouter::pushAlertInDetachedThread(void *(*pushMethod)(void *), char *message) {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // The thread we spawn should free this buffer. We need to duplicate otherwise the parent thread may get to free
    // message before the child thread gets to access it. The child thread will be responsible of cleaning it up.
    char *arg = strdup(message);
    int rc = pthread_create(&thread, &attr, pushMethod, arg);
    if (rc) {
        proxy_error("Failed to create detached thread for pushing alert with message: %s.\n Return code is %d\n",
                    arg, rc);
    }
    pthread_attr_destroy(&attr);
}

// Checks which alert service integrations are enabled and sends the given message as an alert
// to all enabled services.
//
// This method spawns new treads to do push the requests so it doesn't block the thread creating the alert. It creates
// a copy of message so you can free message at will.
void AlertRouter::pushAlert(char *message) {
    // Drop the alert if it is to soon since the last alert was pushed.
    time_t now = time(NULL);
    int min_time_between_alerts_sec = GloAdmin->get_min_time_between_alerts_sec();
    if ((int) difftime(now, lastPushTime) < min_time_between_alerts_sec) {
        proxy_info("Dropping alert raised sooner than %d seconds since previously pushed alert. Message: %s",
                   min_time_between_alerts_sec, message);
        return;
    }

    if (GloAdmin->get_enable_ops_genie_integration()) {
        pushAlertInDetachedThread(AlertRouter::pushAlertToOpsGenie, message);
    }
    lastPushTime = time(NULL);
}


