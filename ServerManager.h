#ifndef SERVER_MANAGER_H
#define SERVER_MANAGER_H

#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include "Login.h"
#include "Command_Excute.h"
#include "Padding.h"
#include "convert_string_t.h"
#include "database/db.h"
#include "scan/portScan.h"
#include "utils_scan.h"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace utility;
using namespace web::http::client;
using namespace concurrency::streams;
using namespace std;

class ServerManager {
public:
    ServerManager();
    void open_listener();
    vector<ScanHostResult> scan_host_result;
    void fetch_and_padding_cves(map<std::string, vector<CVE>>& cpes, int limit = 10);
private:
    vector<event_t> new_Event;
    ServerInfo_t info_new;
    string_t global_ip;
    string_t global_pd;
    

    std::unique_ptr<http_listener> listener;

    void handle_options(http_request request);
    void handle_request(http_request request);
    void handle_get_userinfo(http_request request);
    void handle_post_login(http_request request);
    void handle_get_cve_scan(http_request request);
    
    json::value CVE_to_json(const CVE& cve);
    json::value ScanResult_to_json(const ScanResult& scan_result);
    json::value ScanHostResult_to_json(const ScanHostResult& scan_host_result);
};

#endif // SERVER_MANAGER_H
