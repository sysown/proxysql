#ifndef PROXYSQL_OPSGENIECONNECTOR_H
#define PROXYSQL_OPSGENIECONNECTOR_H


#include "AlertServiceConnector.h"

class OpsGenieConnector : public AlertServiceConnector {
private:
    static const char *apiUrl;
    const char *apiKey;
    const char *recipient;
public:
    OpsGenieConnector(const char *apiKey, const char *recipient);
    int createAlert(const char *);
};


#endif //PROXYSQL_OPSGENIECONNECTOR_H
