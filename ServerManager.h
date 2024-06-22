//#ifndef SERVER_MANAGER_H
//#define SERVER_MANAGER_H
//
//#include <libssh/libssh.h>
//#include <fstream>
//#include <vector>
//#include <sstream>
//#include <string>
//#include <iostream>
//#include <cpprest/http_listener.h>
//#include <cpprest/json.h>
//#include <cpprest/http_client.h>
//#include <cpprest/filestream.h>
//#include "Login.h"
//#include "Command_Excute.h"
//#include "Padding.h"
//#include "convert_string_t.h"
//#include "database/db.h"
//#include "scan/portScan.h"
//#include "utils_scan.h"
//
//using namespace web;
//using namespace web::http;
//using namespace web::http::experimental::listener;
//using namespace utility;
//using namespace web::http::client;
//using namespace concurrency::streams;
//using namespace std;
//
//class ServerManager {
//public:
//    ServerManager();
//    void open_listener();
//    vector<ScanHostResult> scan_host_result;
//    void fetch_and_padding_cves(map<std::string, vector<CVE>>& cpes, int limit = 10);
//private:
//    vector<event_t> new_Event;
//    ServerInfo_t info_new;
//    string_t global_ip;
//    string_t global_pd;
//    
//
//    std::unique_ptr<http_listener> listener;
//
//    void handle_options(http_request request);
//    void handle_request(http_request request);
//    void handle_get_userinfo(http_request request);
//    void handle_post_login(http_request request);
//    void handle_get_cve_scan(http_request request);
//    
//    json::value CVE_to_json(const CVE& cve);
//    json::value ScanResult_to_json(const ScanResult& scan_result);
//    json::value ScanHostResult_to_json(const ScanHostResult& scan_host_result);
//};
//
//#endif // SERVER_MANAGER_H


#ifndef SERVERMANAGER_H
#define SERVERMANAGER_H

#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>
#include <cpprest/uri_builder.h>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include "db.h"
#include "db_config.h"
#include "poc.h"
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include "Login.h"
#include "Command_Excute.h"
#include "Padding.h"
#include "database/db.h"
#include "scan/portScan.h"
#include "utils_scan.h"
#include "convert_string_t.h"
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
    void start();
    void stop();
    vector<ScanHostResult> scan_host_result;
    void fetch_and_padding_cves(std::map<std::string, std::vector<CVE>>& cpes, int limit = 10);
private:
    std::unique_ptr<http_listener> listener;
    void handle_options(http_request request);
    void handle_request(http_request request);

    void handle_get_userinfo(http_request request);
    void handle_post_login(http_request request);
    void handle_get_cve_scan(http_request request);

    void handle_get_all_data(http_request request);
    void handle_search_data(http_request request);
    void handle_post_insert_data(http_request request);
    void handle_put_update_data_by_id(http_request request);
    void handle_delete_data_by_id(http_request request);

    

    json::value CVE_to_json(const CVE& cve);
    json::value ScanResult_to_json(const ScanResult& scan_result);
    json::value ScanHostResult_to_json(const ScanHostResult& scan_host_result);

    
    DatabaseManager dbManager;
    std::vector<POC> poc_list;

    // Additional member variables
    std::string global_ip;
    std::string global_pd;

    // Placeholder for SSH session and info
    // Define your own info_new and new_Event structures and initialize_ssh_session, fun, ConvertEvents, ServerInfo_Padding, convert functions accordingly.
    ServerInfo_t info_new;
    std::vector<event_t> new_Event;
};

#endif // SERVERMANAGER_H
