#include "ServerManager.h"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

ServerManager::ServerManager() : dbManager(DB_PATH) {
    utility::string_t address = U("http://192.168.29.129:8081/");
    uri_builder uri(address);
    auto addr = uri.to_uri().to_string();
    listener = std::make_unique<http_listener>(addr);

    listener->support(methods::OPTIONS, std::bind(&ServerManager::handle_options, this, std::placeholders::_1));
    listener->support(methods::GET, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::POST, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::PUT, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::DEL, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
}

void ServerManager::open_listener() {
    listener->open().then([this]() {
        std::cout << "Starting to listen at: " << listener->uri().to_string() << std::endl;
        }).wait();
}

void ServerManager::handle_options(http_request request) {
    http_response response(status_codes::OK);
    response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
    response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
    response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
    request.reply(response);
}

void ServerManager::handle_request(http_request request) {
    auto path = uri::split_path(uri::decode(request.relative_uri().path()));
    if (path.empty()) {
        request.reply(status_codes::NotFound, U("Path not found"));
        return;
    }

    auto first_segment = path[0];
    if (first_segment == U("userinfo") && request.method() == methods::GET) {
        handle_get_userinfo(request);
    }
    else if (first_segment == U("login") && request.method() == methods::POST) {
        handle_post_login(request);
    }
    else if (first_segment == U("cveScan") && request.method() == methods::GET) {
        handle_get_cve_scan(request);
    }
    else if (first_segment == U("getAllData") && request.method() == methods::GET) {
        handle_get_all_data(request);
    }
    else if (first_segment == U("searchData") && request.method() == methods::GET) {
        handle_search_data(request);
    }
    else if (first_segment == U("insertData") && request.method() == methods::POST) {
        handle_post_insert_data(request);
    }
    else if (first_segment == U("updateDataById") && request.method() == methods::PUT) {
        handle_put_update_data_by_id(request);
    }
    else if (first_segment == U("deleteDataById") && request.method() == methods::DEL) {
        handle_delete_data_by_id(request);
    }
    else {
        request.reply(status_codes::NotFound, U("Path not found"));
    }
}

void ServerManager::handle_get_userinfo(http_request request) {
    json::value main_body = json::value::object();
    json::value ServerInfo = json::value::object();
    ServerInfo[U("arch")] = json::value::string(info_new.arch);
    ServerInfo[U("cpu")] = json::value::string(info_new.cpu);
    ServerInfo[U("cpuCore")] = json::value::string(info_new.cpuCore);
    ServerInfo[U("cpuPhysical")] = json::value::string(info_new.cpuPhysical);
    ServerInfo[U("free")] = json::value::string(info_new.free);
    ServerInfo[U("hostname")] = json::value::string(info_new.hostname);
    ServerInfo[U("isInternet")] = json::value::string(info_new.isInternet);
    ServerInfo[U("ProductName")] = json::value::string(info_new.ProductName);
    ServerInfo[U("version")] = json::value::string(info_new.version);
    json::value response_data = json::value::array();

    for (size_t i = 0; i < new_Event.size(); ++i) {
        json::value user_data;
        user_data[U("basis")] = json::value::string(new_Event[i].basis);
        user_data[U("command")] = json::value::string(new_Event[i].command);
        user_data[U("description")] = json::value::string(new_Event[i].description);
        user_data[U("IsComply")] = json::value::string(new_Event[i].IsComply);
        user_data[U("recommend")] = json::value::string(new_Event[i].recommend);
        user_data[U("result")] = json::value::string(new_Event[i].result);
        response_data[i] = user_data;
    }
    main_body[U("ServerInfo")] = ServerInfo;
    main_body[U("Event_result")] = response_data;
    http_response response(status_codes::OK);
    response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
    response.set_body(main_body);
    request.reply(response);
}

void ServerManager::handle_post_login(http_request request) {
    request.extract_json().then([&](json::value jsonReq) {
        this->global_ip = jsonReq[U("ip")].as_string();
        this->global_pd = jsonReq[U("pd")].as_string();

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
            cout << "描述信息：" << Event[i].description << " "
                << "执行指令:  " << Event[i].command << " 执行结果：" << Event[i].result << " "
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

void ServerManager::handle_get_cve_scan(http_request request) {
    web::json::value result = web::json::value::array();
    int index = 0;
    for (const auto& scan_host_result : scan_host_result) {
        result[index++] = ScanHostResult_to_json(scan_host_result);
    }
    request.reply(web::http::status_codes::OK, result);
}

void ServerManager::handle_get_all_data(http_request request) {
    poc_list = dbManager.getAllData();
    json::value all_data = json::value::array();
    for (size_t i = 0; i < poc_list.size(); i++) {
        json::value data;
        data[U("id")] = json::value::number(poc_list[i].id);
        data[U("cve_id")] = json::value::string(utility::conversions::to_string_t(poc_list[i].cve_id));
        data[U("type")] = json::value::string(utility::conversions::to_string_t(poc_list[i].type));
        data[U("description")] = json::value::string(utility::conversions::to_string_t(poc_list[i].description));
        data[U("script_type")] = json::value::string(utility::conversions::to_string_t(poc_list[i].script_type));
        data[U("script")] = json::value::string(utility::conversions::to_string_t(poc_list[i].script));
        data[U("timestamp")] = json::value::string(utility::conversions::to_string_t(poc_list[i].timestamp));
        all_data[i] = data;
    }
    http_response response(status_codes::OK);
    response.headers().add(U("Content-Type"), U("application/json; charset=utf-8"));
    response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
    response.set_body(all_data);
    request.reply(response);
}

void ServerManager::handle_search_data(http_request request) {
    auto query = uri::split_query(request.relative_uri().query());
    auto searchKeyword = uri::decode(query[U("keyword")]);
    auto poc_data = dbManager.searchData(searchKeyword);
    json::value search_data = json::value::array();
    for (size_t i = 0; i < poc_data.size(); i++) {
        json::value data;
        data[U("id")] = json::value::number(poc_data[i].id);
        data[U("cve_id")] = json::value::string(utility::conversions::to_string_t(poc_data[i].cve_id));
        data[U("type")] = json::value::string(utility::conversions::to_string_t(poc_data[i].type));
        data[U("description")] = json::value::string(utility::conversions::to_string_t(poc_data[i].description));
        data[U("script_type")] = json::value::string(utility::conversions::to_string_t(poc_data[i].script_type));
        data[U("script")] = json::value::string(utility::conversions::to_string_t(poc_data[i].script));
        data[U("timestamp")] = json::value::string(utility::conversions::to_string_t(poc_data[i].timestamp));
        search_data[i] = data;
    }
    http_response response(status_codes::OK);
    response.headers().add(U("Content-Type"), U("application/json; charset=utf-8"));
    response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
    response.set_body(search_data);
    request.reply(response);
}

void ServerManager::handle_post_insert_data(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        std::string cve_id = (body[U("cve_id")].as_string());
        std::string type = (body[U("type")].as_string());
        std::string description = (body[U("description")].as_string());
        std::string script_type = (body[U("script_type")].as_string());
        std::string script = (body[U("script")].as_string());
        bool success = dbManager.insertData(cve_id, type, description, script_type, script);

        http_response response;
        if (success) {
            poc_list = dbManager.getAllData();
            json::value response_data;
            response_data[U("message")] = json::value::string(U("添加成功！"));
            response.set_status_code(status_codes::OK);
            response.set_body(response_data);
        }
        else {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("添加失败！"));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
        }
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
        }).wait();
}

void ServerManager::handle_put_update_data_by_id(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        int id = body[U("id")].as_integer();
        POC poc;
        poc.cve_id = (body[U("cve_id")].as_string());
        poc.type = (body[U("type")].as_string());
        poc.description = (body[U("description")].as_string());
        poc.script_type = (body[U("script_type")].as_string());
        poc.script = (body[U("script")].as_string());
        bool success = dbManager.updateDataById(id, poc);

        http_response response;
        if (success) {
            poc_list = dbManager.getAllData();
            json::value response_data;
            response_data[U("message")] = json::value::string(U("更新成功"));
            response.set_status_code(status_codes::OK);
            response.set_body(response_data);
        }
        else {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("更新失败"));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
        }
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
        }).wait();
}

void ServerManager::handle_delete_data_by_id(http_request request) {
    request.extract_json().then([this, &request](json::value body) mutable {
        bool success = true;
        if (body[U("ids")].is_array()) {
            auto idsArray = body[U("ids")].as_array();
            for (auto& val : idsArray) {
                int id = val.as_integer();
                if (!dbManager.deleteDataById(id)) {
                    success = false;
                    break;
                }
            }
        }
        else {
            int id = body[U("ids")].as_integer();
            if (!dbManager.deleteDataById(id)) {
                success = false;
            }
        }

        http_response response;
        if (success) {
            poc_list = dbManager.getAllData();
            json::value response_data;
            response_data[U("message")] = json::value::string(U("删除成功"));
            response.set_status_code(status_codes::OK);
            response.set_body(response_data);
        }
        else {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("删除失败"));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
        }
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
        }).wait();
}

void ServerManager::fetch_and_padding_cves(map<std::string, vector<CVE>>& cpes, int limit) {
    std::string base_url = "http://192.168.29.129:5000/api/cvefor";
    std::string cpe_id = "";
    for (auto& cpe : cpes) {
        cpe_id = cpe.first;
        auto& vecCVE = cpe.second;
        uri_builder builder(U(base_url));
        builder.append_path(U(cpe_id));
        if (limit > 0) {
            builder.append_query(U("limit"), limit);
        }

        http_client client(builder.to_uri());
        try {
            client.request(methods::GET)
                .then([&](http_response response) -> pplx::task<json::value> {
                if (response.status_code() == status_codes::OK) {
                    return response.extract_json();
                }
                else {
                    std::cerr << "Failed to fetch CVE data for CPE: " << cpe_id << ", Status code: " << response.status_code() << std::endl;
                    return pplx::task_from_result(json::value());
                }
                    })
                .then([&](json::value jsonObject) {
                        if (!jsonObject.is_null()) {
                            auto cve_array = jsonObject.as_array();
                            for (auto& cve : cve_array) {
                                CVE tmp;
                                tmp.CVE_id = cve[U("id")].as_string();
                                std::cout << "CVE ID: " << cve[U("id")].as_string() << std::endl;
                                std::string cvss_str = "N/A";
                                if (cve.has_field(U("cvss"))) {
                                    auto cvss_value = cve[U("cvss")];
                                    if (cvss_value.is_string()) {
                                        cvss_str = cvss_value.as_string();
                                        std::cout << "CVSS Score: " << cvss_value.as_string() << std::endl;
                                    }
                                    else if (cvss_value.is_number()) {
                                        cvss_str = std::to_string(cvss_value.as_number().to_double());
                                        std::cout << "CVSS Score: " << cvss_value.as_number().to_double() << std::endl;
                                    }
                                    else {
                                        std::cout << "CVSS Score: N/A" << std::endl;
                                    }
                                }
                                else {
                                    std::cout << "CVSS Score: N/A" << std::endl;
                                }
                                tmp.CVSS = cvss_str;
                                if (cve.has_field(U("summary"))) {
                                    std::cout << "Summary: " << cve[U("summary")].as_string() << std::endl;
                                }
                                vecCVE.push_back(tmp);
                            }
                        }
                    }).wait();
        }
        catch (const std::exception& e) {
            std::cerr << "Exception occurred while fetching CVE data for CPE: " << cpe_id << ", Error: " << e.what() << std::endl;
        }
    }
}

json::value ServerManager::CVE_to_json(const CVE& cve) {
    json::value result;
    result[U("CVE_id")] = json::value::string(cve.CVE_id);
    result[U("CVSS")] = json::value::string(cve.CVSS);
    result[U("pocExist")] = json::value::boolean(cve.pocExist);
    result[U("vulExist")] = json::value::string(cve.vulExist);
    return result;
}

json::value ServerManager::ScanResult_to_json(const ScanResult& scan_result) {
    json::value result;
    result[U("portId")] = json::value::string(scan_result.portId);
    result[U("protocol")] = json::value::string(scan_result.protocol);
    result[U("status")] = json::value::string(scan_result.status);
    result[U("service_name")] = json::value::string(scan_result.service_name);
    result[U("version")] = json::value::string(scan_result.version);

    json::value cpes_json = json::value::object();
    for (const auto& cpe : scan_result.cpes) {
        json::value cves_json = json::value::array();
        int index = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index++] = CVE_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[U("cpes")] = cpes_json;
    return result;
}

json::value ServerManager::ScanHostResult_to_json(const ScanHostResult& scan_host_result) {
    json::value result;
    result[U("ip")] = json::value::string(scan_host_result.ip);

    json::value cpes_json = json::value::object();
    for (const auto& cpe : scan_host_result.cpes) {
        json::value cves_json = json::value::array();
        int index = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index++] = CVE_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[U("cpes")] = cpes_json;

    json::value ports_json = json::value::array();
    int index = 0;
    for (const auto& port : scan_host_result.ports) {
        ports_json[index++] = ScanResult_to_json(port);
    }
    result[U("ports")] = ports_json;

    return result;
}

void ServerManager::start() {
    try {
        listener->open().then([&listener = listener]() {
            ucout << "Starting to listen at: " << listener->uri().to_string() << std::endl;
            }).wait();
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
    }
}

void ServerManager::stop() {
    try {
        listener->close().wait();
        ucout << "Stopped listening." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred while stopping: " << e.what() << std::endl;
    }
}
