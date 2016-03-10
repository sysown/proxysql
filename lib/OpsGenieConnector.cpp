#include "proxysql.h"
#include "http_client.h"
#include "OpsGenieConnector.h"

const char *OpsGenieConnector::apiUrl = "https://api.opsgenie.com/v1/json/alert";

OpsGenieConnector::OpsGenieConnector(const char *apiKey, const char *recipient) {
    this->apiKey = apiKey;
    this->recipient = recipient;
}

int OpsGenieConnector::pushAlert(const char *message) {
    char json[1000];
    json_emit(json, 1000, "{s:s, s:s, s:[s]}", "message", message, "apiKey", apiKey, "recipients", recipient);
    http_response *response = http_post(this->apiUrl, "Content-Type: application/json\r\n", json);

    if (!response) {
        proxy_error("Failed to do http post to OpsGenie for message: '%s'.\n", message);
        return 0;
    }

    int r_val = response->status_code == 200;
    if (!r_val && response->body) {
        proxy_error("Failed to push alert with message '%s' to OpsGenie\n. Response: %s\n", message, response->body);
    }
    free(response);
    return r_val;
}
