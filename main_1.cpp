#define _CRT_SECURE_NO_WARNINGS
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>
#include "Login.h"
#include "Command_Excute.h"
#include "Padding.h"
#include "convert_string_t.h"
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

class ServerManager {
public:
    vector<event_t> new_Event;
    ServerInfo_t info_new;
    utility::string_t global_ip;
    utility::string_t global_pd;

    void handle_options(http_request request) {
        http_response response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }

    void handle_get(http_request request) {
        json::value main_body = json::value::object();
        json::value ServerInfo = json::value::object();
        ServerInfo[U("arch")] = json::value::string(utility::conversions::to_string_t(info_new.arch));
        ServerInfo[U("cpu")] = json::value::string(utility::conversions::to_string_t(info_new.cpu));
        ServerInfo[U("cpuCore")] = json::value::string(utility::conversions::to_string_t(info_new.cpuCore));
        ServerInfo[U("cpuPhysical")] = json::value::string(utility::conversions::to_string_t(info_new.cpuPhysical));
        ServerInfo[U("free")] = json::value::string(utility::conversions::to_string_t(info_new.free));
        ServerInfo[U("hostname")] = json::value::string(utility::conversions::to_string_t(info_new.hostname));
        ServerInfo[U("isInternet")] = json::value::string(utility::conversions::to_string_t(info_new.isInternet));
        ServerInfo[U("ProductName")] = json::value::string(utility::conversions::to_string_t(info_new.ProductName));
        ServerInfo[U("version")] = json::value::string(utility::conversions::to_string_t(info_new.version));
        json::value response_data = json::value::array();

        for (size_t i = 0; i < new_Event.size(); ++i) {
            json::value user_data;
            user_data[U("basis")] = json::value::string(utility::conversions::to_string_t(new_Event[i].basis));
            user_data[U("command")] = json::value::string(utility::conversions::to_string_t(new_Event[i].command));
            user_data[U("description")] = json::value::string(utility::conversions::to_string_t(new_Event[i].description));
            user_data[U("IsComply")] = json::value::string(utility::conversions::to_string_t(new_Event[i].IsComply));
            user_data[U("recommend")] = json::value::string(utility::conversions::to_string_t(new_Event[i].recommend));
            user_data[U("result")] = json::value::string(utility::conversions::to_string_t(new_Event[i].result));
            response_data[i] = user_data;
        }
        main_body[U("ServerInfo")] = ServerInfo;
        main_body[U("Event_result")] = response_data;
        http_response response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.set_body(main_body);
        request.reply(response);
    }

    void handle_post(http_request request) {
        request.extract_json().then([this, &request](json::value jsonReq) {
            this->global_ip = jsonReq[U("ip")].as_string();
            this->global_pd = jsonReq[U("pd")].as_string();

            std::cout << global_ip << std::endl;
            std::cout << global_pd << std::endl;
            string ip = (global_ip);
            string pd = (global_pd);

            ssh_session session = initialize_ssh_session(ip.c_str(), "root", pd.c_str());
            if (session == NULL) {
                request.reply(status_codes::InternalError, U("SSH session failed to start."));
                return;
            }

            vector<event> Event;
            fun(Event, session);
            new_Event = ConvertEvents(Event);
            for (int i = 0; i < Event.size(); i++) {
                cout << "  描述信息：" << Event[i].description << "    "
                    << "执行指令:  " << Event[i].command << "    执行结果：" << Event[i].result << "  "
                    << "是否符合基线：  " << Event[i].IsComply
                    << endl;
            }

            ServerInfo info;
            ServerInfo_Padding(info, session);
            info_new = convert(info);

            ssh_disconnect(session);
            ssh_free(session);
            
            http_response response(status_codes::OK);
            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
            json::value response_data = json::value::object();
            response_data[U("message")] = json::value::string(U("Received"));
            response.set_body(response_data);
            request.reply(response);
            }).wait();
    }

    void handle_login_get(http_request request) {
        json::value jsonResponse;
        jsonResponse[U("ip")] = json::value::string(global_ip);
        jsonResponse[U("pd")] = json::value::string(global_pd);
        request.reply(status_codes::OK, jsonResponse);
    }
};

//int main(int argc, char** argv) {
//    utility::string_t address1 = U("http://localhost:8081/userinfo");
//    uri_builder uri(address1);
//    auto addr1 = uri.to_uri().to_string();
//    http_listener listener1(addr1);
//
//    utility::string_t address2 = U("http://localhost:8081/login");
//    uri_builder uri2(address2);
//    auto addr2 = uri2.to_uri().to_string();
//    http_listener listener2(addr2);
//
//    std::locale::global(std::locale(""));
//
//    ServerManager serverManager;
//    listener1.support(methods::GET, [&serverManager](http_request request) {
//        serverManager.handle_get(request);
//        });
//    listener1.support(methods::OPTIONS, [&serverManager](http_request request) {
//        serverManager.handle_options(request);
//        });
//
//    listener2.support(methods::POST, [&serverManager](http_request request) {
//        serverManager.handle_post(request);
//        });
//    listener2.support(methods::OPTIONS, [&serverManager](http_request request) {
//        serverManager.handle_options(request);
//        });
//    listener2.support(methods::GET, [&serverManager](http_request request) {
//        serverManager.handle_login_get(request);
//        });
//
//    try {
//        listener1.open().then([&listener1, &addr1]() {
//            std::cout << U("Starting to listen at ") << addr1 << std::endl;
//            }).wait();
//
//            listener2.open().then([&listener2, &addr2]() {
//                std::cout << U("Starting to listen at ") << addr2 << std::endl;
//                }).wait();
//
//                std::cout << U("Listening for requests at: ") << addr1 << std::endl;
//                std::string line;
//                std::cout << U("Press Enter to close the server.") << std::endl;
//                std::getline(std::cin, line);
//                listener1.close().wait();
//                listener2.close().wait();
//    }
//    catch (const std::exception& e) {
//        std::cerr << "An error occurred: " << e.what() << std::endl;
//    }
//    return 0;
//}
//
