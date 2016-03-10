#include "http_client.h"

int main(int argc, char *argv[]) {
    http_response *hr = http_post((char *) "http://httpbin.org/post", "Content-Type: application/x-www-form-urlencoded\r\n", (char *) "urls=asdasdsad");
    if (hr) {
        printf("Status code: %d\n", hr->status_code);
        if (hr->body) printf("Response body: %s\n", hr->body);
        free_response(hr);
    } else {
        printf("Failed to do HTTP post.\n");
    }
    return 0;
}