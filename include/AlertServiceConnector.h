#ifndef PROXYSQL_ALERTSERVICECONNECTOR_H
#define PROXYSQL_ALERTSERVICECONNECTOR_H

// Interface for all connectors to alert services.
class AlertServiceConnector {
public:
    virtual int createAlert(const char *message) = 0;
};

#endif //PROXYSQL_ALERTSERVICECONNECTOR_H
