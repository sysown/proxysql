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
    int pushAlert(const char *message);
};


#endif //PROXYSQL_OPSGENIECONNECTOR_H
