#ifndef MANAGED_CONFIGURATION_API_HELPER_H
#define MANAGED_CONFIGURATION_API_HELPER_H

#include "tap.h"
#include "json.hpp"
#include "curl/curl.h"
#include "mysql.h"
#include "libpq-fe.h"
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace managed_api_test {
using json = nlohmann::json;

inline size_t receive(char* data, size_t size, size_t count, void* context) {
    auto& body = *static_cast<std::string*>(context);
    if (size && count > (4*1024*1024-body.size())/size) return 0;
    body.append(data, size*count);
    return size*count;
}

inline json request(const json& fixture, const char* method, const json* document=nullptr) {
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) throw std::runtime_error("curl initialization failed");
    const std::string url=fixture.at("api_url"), ca=fixture.at("ca_path");
    if (url.rfind("https://",0)!=0) throw std::runtime_error("managed API test requires HTTPS");
    const std::string identity=fixture.at("access_key_id").get<std::string>()+":"+
        fixture.at("secret_access_key").get<std::string>();
    const std::string scope="aws:amz:"+fixture.at("region").get<std::string>()+":rds";
    const std::string payload=document ? document->dump() : "";
    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl.get(), CURLOPT_AWS_SIGV4, scope.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_USERPWD, identity.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl.get(), CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, receive);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    if (document) {
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, payload.data());
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(payload.size()));
    }
    const auto result=curl_easy_perform(curl.get());
    long status=0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    // Never print signed credentials, write-only secrets, or response bodies.
    if (result!=CURLE_OK) throw std::runtime_error(std::string("HTTPS request failed: ")+curl_easy_strerror(result));
    if (status!=200) throw std::runtime_error("managed API returned HTTP "+std::to_string(status));
    return json::parse(response);
}

inline int run(bool mysql_engine) {
    plan(7);
    try {
        const char* override_path=getenv("MANAGED_INTEGRATION_FIXTURE");
        const char* workspace=getenv("WORKSPACE");
        const char* infra=getenv("INFRA_ID");
        if (!override_path && (!workspace || !infra)) throw std::runtime_error("required managed integration fixture is unavailable");
        const std::string path=override_path ? override_path : std::string(workspace)+"/ci_infra_logs/"+infra+
            "/aws-managed/"+(mysql_engine?"MYSQL.json":"POSTGRESQL.json");
        std::ifstream input(path);
        if (!input) throw std::runtime_error("required managed integration fixture cannot be opened");
        json fixture; input>>fixture;
        if (curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) throw std::runtime_error("curl global initialization failed");
        auto before=request(fixture,"GET");
        ok(before.value("outcome","")=="ok", "signed native configuration read succeeds");
        auto envelope=fixture.at("envelope");
        envelope["expected_revision"]=before.at("desired_revision");
        envelope["idempotency_key"]="tap-"+std::to_string(getpid())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        auto after=request(fixture,"PUT",&envelope);
        ok(after.value("outcome","")=="ok", "complete configuration applied through signed API without Admin LOAD/SAVE");
        ok(after.at("desired_revision")==after.at("applied_revision") &&
            after.at("desired_revision").get<uint64_t>()>before.at("desired_revision").get<uint64_t>(),
            "successful response records the new desired revision as applied");
        auto readback=request(fixture,"GET");
        bool redacted=!readback.contains("secrets") && !readback.contains("credentials");
        const auto& tables=readback.at("configuration").at("tables");
        const char* user_table=mysql_engine?"mysql_users":"pgsql_users";
        for (const auto& user:tables.at(user_table)) redacted=redacted && !user.contains("password");
        ok(redacted, "readback contains references instead of write-only user passwords");
        const auto& proxy=fixture.at("proxy");
        const std::string host=proxy.at("host"), user=proxy.at("user"), password=proxy.at("password"),
            database=proxy.at("database"), ca=proxy.at("ca_path");
        const std::string query=fixture.at("check").at("query"), expected=fixture.at("check").at("expected");
        std::string value;
        if (mysql_engine) {
            std::unique_ptr<MYSQL, decltype(&mysql_close)> connection(mysql_init(nullptr),mysql_close);
            if (!connection) throw std::runtime_error("MySQL client initialization failed");
            unsigned int timeout=15; bool enabled=true;
            if (mysql_options(connection.get(),MYSQL_OPT_CONNECT_TIMEOUT,&timeout) ||
                mysql_options(connection.get(),MYSQL_OPT_SSL_ENFORCE,&enabled) ||
                mysql_options(connection.get(),MYSQL_OPT_SSL_VERIFY_SERVER_CERT,&enabled) ||
                mysql_ssl_set(connection.get(),nullptr,nullptr,ca.c_str(),nullptr,nullptr))
                throw std::runtime_error("MySQL client could not require verified TLS");
            const bool connected=mysql_real_connect(connection.get(),host.c_str(),user.c_str(),password.c_str(),
                database.c_str(),proxy.at("port").get<unsigned int>(),nullptr,0)!=nullptr;
            ok(connected && mysql_get_ssl_cipher(connection.get())!=nullptr,
                "API-configured MySQL credentials establish a verified TLS connection");
            if (!connected) throw std::runtime_error("MySQL connection failed");
            const bool queried=mysql_query(connection.get(),query.c_str())==0;
            std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> rows(queried?mysql_store_result(connection.get()):nullptr,mysql_free_result);
            ok(queried && rows && mysql_num_rows(rows.get())==1,"MySQL query routes to the configured backend");
            if (rows) { auto row=mysql_fetch_row(rows.get()); if(row && row[0]) value=row[0]; }
        } else {
            const std::string port=std::to_string(proxy.at("port").get<unsigned int>());
            const char* keys[]={"host","port","user","password","dbname","sslmode","sslrootcert","connect_timeout",nullptr};
            const char* values[]={host.c_str(),port.c_str(),user.c_str(),password.c_str(),database.c_str(),"verify-full",ca.c_str(),"15",nullptr};
            std::unique_ptr<PGconn,decltype(&PQfinish)> connection(PQconnectdbParams(keys,values,0),PQfinish);
            const bool connected=connection && PQstatus(connection.get())==CONNECTION_OK;
            ok(connected && PQsslInUse(connection.get()),"API-configured PostgreSQL credentials establish a verified TLS connection");
            if (!connected) throw std::runtime_error("PostgreSQL connection failed");
            std::unique_ptr<PGresult,decltype(&PQclear)> rows(PQexec(connection.get(),query.c_str()),PQclear);
            ok(rows && PQresultStatus(rows.get())==PGRES_TUPLES_OK && PQntuples(rows.get())==1,
                "PostgreSQL query routes to the configured backend");
            if (rows && PQntuples(rows.get())==1 && PQnfields(rows.get())>0 && !PQgetisnull(rows.get(),0,0)) value=PQgetvalue(rows.get(),0,0);
        }
        ok(value==expected,"existing per-hostgroup init_connect produces the configured session value");
        curl_global_cleanup();
    } catch (const json::exception&) {
        diag("managed integration fixture or API response has invalid JSON/schema");
        return EXIT_FAILURE;
    } catch (const std::exception& error) {
        // Exception messages originate here or from structural JSON validation;
        // no response bodies, configuration documents or credentials are printed.
        diag("managed integration failed: %s",error.what());
        return EXIT_FAILURE;
    }
    return exit_status();
}
} // namespace managed_api_test
#endif
