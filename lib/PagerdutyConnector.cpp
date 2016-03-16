#include "proxysql.h"
#include "http_client.h"
#include "PagerdutyConnector.h"

const char *PagerdutyConnector::apiUrl = "https://events.pagerduty.com/generic/2010-04-15/create_event.json";

PagerdutyConnector::PagerdutyConnector(const char *serviceKey) {
    this->serviceKey = serviceKey;
}

int PagerdutyConnector::pushAlert(const char *message) {
    char json[1000];
    json_emit(json, 1000, "{s:s, s:s, s:s, s:s}", "service_key", this->serviceKey, "event_type", "trigger",
              "description", message, "client", "ProxySQL");
    http_response *response = http_post(this->apiUrl, "Content-Type: application/json\r\n", json);

    if (!response) {
        proxy_error("Failed to do http post to pagerduty for message: '%s'.\n", message);
        return 0;
    }

    int r_val = response->status_code == 200;
    if (!r_val && response->body) {
        proxy_error("Failed to push alert with message '%s' to pagerduty\n. Response: %s\n", message, response->body);
    }
    free(response);
    return r_val;
}
