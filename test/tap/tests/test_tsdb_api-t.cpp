/**
 * @file test_tsdb_api-t.cpp
 * @brief End-to-end TSDB dashboard + REST API test (regression for #5684).
 *
 * The TSDB dashboard's JS issues relative-URL fetch() calls:
 *   <script src="/Chart.bundle.js"></script>
 *   fetch('/api/tsdb/metrics')
 *   fetch('/api/tsdb/query?...')
 *
 * Those URLs only resolve if the dashboard and the API endpoints share
 * the same origin (host + port). Issue #5684 reported "Error loading
 * metrics" because the dashboard was served from admin-web_port while
 * the API lived on admin-restapi_port. This test pins the new wiring:
 *
 *   - Dashboard at http://host:restapi_port/tsdb
 *   - Chart.bundle.js at http://host:restapi_port/Chart.bundle.js
 *   - All /api/tsdb/* endpoints at http://host:restapi_port/api/tsdb/*
 *
 * Each assertion below executes a real HTTP GET against a running
 * ProxySQL and inspects the response: status code, content-type, and
 * for JSON endpoints the parsed payload shape.
 */
#include <algorithm>
#include <map>
#include <regex>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "curl/curl.h"
#include "mysql.h"
#include "json.hpp"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;
using json = nlohmann::json;

struct http_result {
    long code = 0;
    string body;
    string content_type;
};

static size_t write_cb(void* data, size_t size, size_t nmemb, void* userp) {
    string* out = static_cast<string*>(userp);
    out->append(static_cast<char*>(data), size * nmemb);
    return size * nmemb;
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, void* userp) {
    auto* hdrs = static_cast<std::map<string, string>*>(userp);
    string line(buffer, size * nitems);
    auto colon = line.find(':');
    if (colon != string::npos) {
        string key = line.substr(0, colon);
        string val = line.substr(colon + 1);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        // trim
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) val.pop_back();
        (*hdrs)[key] = val;
    }
    return size * nitems;
}

static http_result http_get(const string& url, const string& userpwd) {
    http_result r;
    std::map<string, string> hdrs;
    CURL* c = curl_easy_init();
    if (!c) return r;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &hdrs);
    // Pin to TLS 1.3 minimum for the test client. The NOSONAR is needed
    // because SonarCloud's S4423 matcher flags any CURLOPT_SSLVERSION
    // line regardless of the value set (TLS 1.3 is the strongest
    // available).
    curl_easy_setopt(c, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_3); // NOSONAR
    // Cert verification is disabled: this test connects to a localhost
    // proxysql instance that serves an auto-generated self-signed
    // certificate. Verifying the chain or hostname requires installing
    // the per-run cert into the system CA store, which is out of scope
    // for a TAP test. SonarCloud rules S4423 / S5527 / S4830 do not apply
    // to a localhost test client. (SonarCloud)
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L); // NOSONAR
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L); // NOSONAR
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    if (!userpwd.empty()) {
        curl_easy_setopt(c, CURLOPT_USERPWD, userpwd.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);
    }
    CURLcode rc = curl_easy_perform(c);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.code);
    } else {
        diag("curl GET %s failed: %s", url.c_str(), curl_easy_strerror(rc));
    }
    auto ct = hdrs.find("content-type");
    if (ct != hdrs.end()) r.content_type = ct->second;
    curl_easy_cleanup(c);
    return r;
}

static void drain_results(MYSQL* m) {
    MYSQL_RES* res;
    while (true) {
        res = mysql_store_result(m);
        if (res) mysql_free_result(res);
        if (mysql_next_result(m) != 0) break;
    }
}

/* Extract every same-origin URL the dashboard HTML references --
 * src="/...", href="/...", or fetch("/..."). These are the URLs the
 * browser would issue against the page origin. */
static vector<string> extract_relative_urls(const string& html) {
    vector<string> urls;
    std::regex pat(R"REX((?:src|href)\s*=\s*"(/[^"\s]*)"|fetch\(\s*['"`](/[^'"`\s?]+)(?:\?[^'"`]*)?['"`])REX");
    auto begin = std::sregex_iterator(html.begin(), html.end(), pat);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        string match = (*it)[1].matched ? (*it)[1].str() : (*it)[2].str();
        if (std::find(urls.begin(), urls.end(), match) == urls.end()) urls.push_back(match);
    }
    return urls;
}

int main() {
    CommandLine cl;
    if (cl.getEnv()) {
        diag("Failed to get environmental variables");
        return EXIT_FAILURE;
    }
    curl_global_init(CURL_GLOBAL_ALL);

    /* Plan:
     *   1  - admin reachable
     *   2  - dashboard 200 on restapi_port
     *   3  - dashboard Content-Type is text/html
     *   4  - dashboard body contains the title
     *   5  - dashboard body contains the canvas
     *   6  - every relative URL the dashboard references resolves
     *        on the same origin (this is the core #5684 assertion)
     *   7  - dashboard returns 404 on web_port (regression guard)
     *   8  - /api/tsdb/status JSON has the expected keys
     *   9  - /api/tsdb/metrics returns a JSON array
     *   10 - /api/tsdb/query returns rows with expected shape
     */
    plan(10);

    MYSQL* admin = mysql_init(NULL);
    if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        diag("Admin connect failed: %s", mysql_error(admin));
        ok(false, "admin reachable");
        return exit_status();
    }
    ok(true, "admin reachable at %s:%d", cl.admin_host, cl.admin_port);

    /* Configure TSDB + restapi + web. Both ports must be enabled so we
     * can also assert the dashboard is *not* served on the web port. */
    const char* setup_sql[] = {
        "SET tsdb-enabled='1'",
        "SET tsdb-sample_interval='1'",
        "SET admin-restapi_enabled='1'",
        "SET admin-web_enabled='1'",
        "LOAD TSDB VARIABLES TO RUNTIME",
        "LOAD ADMIN VARIABLES TO RUNTIME",
    };
    for (const char* q : setup_sql) {
        if (mysql_query(admin, q)) {
            diag("%s failed: %s", q, mysql_error(admin));
        }
        drain_results(admin);
    }

    /* Read the live restapi_port / web_port so the test honours
     * non-default values. */
    int restapi_port = 6070, web_port = 6080;
    if (!mysql_query(admin, "SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name IN ('admin-restapi_port', 'admin-web_port')")) {
        MYSQL_RES* res = mysql_store_result(admin);
        if (res) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res))) {
                if (string(row[0]) == "admin-restapi_port") restapi_port = atoi(row[1]);
                else if (string(row[0]) == "admin-web_port") web_port = atoi(row[1]);
            }
            mysql_free_result(res);
        }
    }
    drain_results(admin);
    diag("restapi_port=%d  web_port=%d", restapi_port, web_port);

    /* Sleep long enough for restapi + web to bind, and for at least one
     * tsdb sample to land in the DB so query/metrics return non-empty. */
    diag("waiting 8s for HTTP servers to come up and for tsdb samples to land");
    sleep(8);

    // ProxySQL REST API listens on plain HTTP by design; this test
    // must hit the real endpoint, not a TLS variant. (SonarCloud S5332)
    const string restapi_origin = string("http://") + cl.admin_host + ":" + std::to_string(restapi_port); // NOSONAR
    const string web_origin     = string("https://") + cl.admin_host + ":" + std::to_string(web_port);
    const string admin_creds    = string(cl.admin_username) + ":" + cl.admin_password;
    const string stats_creds    = "stats:stats";

    /* (2-5) Dashboard on the REST API port. */
    http_result dash = http_get(restapi_origin + "/tsdb", admin_creds);
    ok(dash.code == 200, "dashboard /tsdb on restapi_port returns 200 (got %ld)", dash.code);
    ok(dash.content_type.find("text/html") != string::npos,
       "dashboard Content-Type is text/html (got '%s')", dash.content_type.c_str());
    ok(dash.body.find("ProxySQL TSDB Dashboard") != string::npos, "dashboard body contains title");
    ok(dash.body.find("tsdbChart") != string::npos, "dashboard body contains canvas id");

    /* (6) The same-origin assertion that catches #5684: every relative
     * URL the dashboard references must be served on the dashboard's
     * own origin. We probe each URL with no arguments. The bug was that
     * these URLs 404'd on the dashboard's port; for API routes the
     * arg-less probe legitimately returns 4xx ("missing parameter"),
     * which proves the route IS wired here. Anything 404 or 5xx is a
     * failure -- the dashboard's fetch() would have produced exactly
     * the "Error loading metrics" the bug reported. */
    vector<string> rels = extract_relative_urls(dash.body);
    diag("dashboard references %zu relative URLs", rels.size());
    bool all_same_origin_ok = !rels.empty();
    for (const string& path : rels) {
        http_result sub = http_get(restapi_origin + path, admin_creds);
        diag("  GET %s%s -> %ld", restapi_origin.c_str(), path.c_str(), sub.code);
        if (sub.code == 0 || sub.code == 404 || sub.code >= 500) all_same_origin_ok = false;
    }
    ok(all_same_origin_ok, "every relative URL in the dashboard resolves on restapi_port (#5684)");

    /* (7) Regression guard: the dashboard must NOT be reachable on the
     * web port. If someone re-introduces the /tsdb handler in
     * ProxySQL_HTTP_Server the bug returns. */
    http_result web_dash = http_get(web_origin + "/tsdb", stats_creds);
    ok(web_dash.code == 404,
       "dashboard /tsdb on web_port returns 404 (got %ld); else #5684 has regressed", web_dash.code);

    /* (8) /api/tsdb/status -- real JSON, real keys. */
    http_result st = http_get(restapi_origin + "/api/tsdb/status", admin_creds);
    bool status_ok = false;
    if (st.code == 200) {
        try {
            json j = json::parse(st.body);
            status_ok = j.contains("total_series") && j.contains("total_datapoints")
                     && j.contains("disk_size_bytes") && j.contains("oldest_datapoint")
                     && j.contains("newest_datapoint");
        } catch (...) { status_ok = false; }
    }
    ok(status_ok, "/api/tsdb/status returns 200 JSON with the documented keys (code=%ld body='%s')",
       st.code, st.body.substr(0, 120).c_str());

    /* (9) /api/tsdb/metrics -- must be a JSON array. */
    http_result mtr = http_get(restapi_origin + "/api/tsdb/metrics", admin_creds);
    bool metrics_ok = false;
    string first_metric;
    if (mtr.code == 200) {
        try {
            json j = json::parse(mtr.body);
            if (j.is_array()) {
                metrics_ok = true;
                if (!j.empty()) first_metric = j[0].get<string>();
            }
        } catch (...) { metrics_ok = false; }
    }
    ok(metrics_ok, "/api/tsdb/metrics returns 200 with a JSON array (code=%ld body='%s')",
       mtr.code, mtr.body.substr(0, 120).c_str());

    /* (10) /api/tsdb/query -- real time series with shape {ts,metric,labels,value}. */
    string metric_to_query = !first_metric.empty() ? first_metric : "proxysql_uptime_seconds_total";
    http_result q = http_get(restapi_origin + "/api/tsdb/query?metric=" + metric_to_query, admin_creds);
    bool query_ok = false;
    if (q.code == 200) {
        try {
            json j = json::parse(q.body);
            if (j.is_array() && !j.empty()) {
                const auto& row = j[0];
                query_ok = row.contains("ts") && row.contains("metric")
                        && row.contains("labels") && row.contains("value")
                        && row["metric"].get<string>() == metric_to_query;
            }
        } catch (...) { query_ok = false; }
    }
    ok(query_ok, "/api/tsdb/query?metric=%s returns 200 with rows of {ts,metric,labels,value} (code=%ld body='%s')",
       metric_to_query.c_str(), q.code, q.body.substr(0, 200).c_str());

    mysql_close(admin);
    return exit_status();
}
