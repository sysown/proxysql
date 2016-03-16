#include "proxysql.h"
#include "http_client.h"
#include "PagerdutyConnector.h"

const char *PagerdutyConnector::apiUrl = "https://api.opsgenie.com/v1/json/alert";

PagerdutyConnector::PagerdutyConnector(const char *apiKey) {
    this->apiKey = apiKey;
}

int PagerdutyConnector::pushAlert(const char *message) {
    char json[1000];
    json_emit(json, 1000, "{s:s, s:s}", "message", message, "apiKey", apiKey);
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
