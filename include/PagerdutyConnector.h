#ifndef PROXYSQL_PAGERDUTYCONNECTOR_H
#define PROXYSQL_PAGERDUTYCONNECTOR_H


#include "AlertServiceConnector.h"

class PagerdutyConnector : public AlertServiceConnector {
private:
    static const char *apiUrl;
    const char *serviceKey;
public:
    PagerdutyConnector(const char *serviceKey);
    int pushAlert(const char *message);
};


#endif //PROXYSQL_PAGERDUTYCONNECTOR_H
