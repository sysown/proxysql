#include "http_client.h"
#include "OpsGenieConnector.h"

const char *OpsGenieConnector::apiUrl = "https://api.opsgenie.com/v1/json/alert";

OpsGenieConnector::OpsGenieConnector(const char *apiKey, const char *recipient) {
    this->apiKey = apiKey;
    this->recipient = recipient;
}

int OpsGenieConnector::createAlert(const char *message) {
    const char *json_format = "{\"message\":\"%s\", \"apiKey\": \"%s\", \"recipients\": [\"%s\"]}";
    char *json = (char *) malloc(strlen(json_format)
                                 + strlen(message)
                                 + strlen(this->apiKey)
                                 + strlen(this->recipient)
                                 + 1);
    sprintf(json, json_format, message, this->apiKey, this->recipient);
    http_response *response = http_post(this->apiUrl, "Content-Type: application/json\r\n", json);
    free(json);

    if (response) {
        int r_val = response->status_code == 200;
        free(response);
        return r_val;
    }
    return 0;
}
