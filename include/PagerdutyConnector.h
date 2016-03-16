#ifndef PROXYSQL_PAGERDUTYCONNECTOR_H
#define PROXYSQL_PAGERDUTYCONNECTOR_H


#include "AlertServiceConnector.h"

class PagerdutyConnector : public AlertServiceConnector {
private:
    static const char *apiUrl;
    const char *apiKey;
public:
    PagerdutyConnector(const char *apiKey);
    int pushAlert(const char *message);
};


#endif //PROXYSQL_PAGERDUTYCONNECTOR_H
