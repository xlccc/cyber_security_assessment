#include "ServerManager.h"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;

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

    // 检查并创建临时文件
    struct stat buffer;
    if (stat(TEMP_FILENAME.c_str(), &buffer) != 0) {
        std::ofstream temp_file(TEMP_FILENAME, std::ios::binary);
        if (!temp_file.is_open()) {
            throw std::runtime_error("Failed to create temporary file");
        }
        temp_file.close();
    }
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
    //返回基线检测的结果
    if (first_segment == U("userinfo") && request.method() == methods::GET) {
        handle_get_userinfo(request);
    }
    //基线检测的账号密码登录
    else if (first_segment == U("login") && request.method() == methods::POST) {
        handle_post_login(request);
    }
    //返回主机所有可能的cve漏洞，调用cve-search
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
    else if (first_segment == U("getNmapIp") && request.method() == methods::POST) {
        handle_post_get_Nmap(request);
    }
    else if (first_segment == U("getWeakPassword") && request.method() == methods::POST) {
        handle_post_hydra(request);
    }
    else if (first_segment == U("testWeakPassword") && request.method() == methods::POST) {
        handle_post_testWeak(request);
    }

    else if (first_segment == U("getPOCContent") && request.method() == methods::GET) {
        handle_get_poc_content(request);    //查看POC代码
    }
    else if (first_segment == U("pocSearch") && request.method() == methods::POST) {
        handle_post_poc_search(request);
    }
    else if (first_segment == U("pocVerify") && request.method() == methods::POST) {
        handle_post_poc_verify(request);
    }
    //根据前端传来的进行等级保护计算
    else if (first_segment == U("classifyProtect") && request.method() == methods::POST) {
        handle_post_classify_protect(request);
    }
    //    vector<scoreMeasure> vecScoreMeasure 转json传回前端
    else if (first_segment == U("classifyProtectGetRes") && request.method() == methods::GET) {
        handle_get_classify_protect(request);
    }
    else if (first_segment == U("pocExcute") && request.method() == methods::POST) {
        handle_post_poc_excute(request);
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

    for (size_t i = 0; i < Event.size(); ++i) {
        json::value user_data;

        user_data[U("basis")] = json::value::string(utility::conversions::to_string_t(Event[i].basis));
        user_data[U("command")] = json::value::string(utility::conversions::to_string_t(Event[i].command));
        user_data[U("description")] = json::value::string(utility::conversions::to_string_t(Event[i].description));
        user_data[U("IsComply")] = json::value::string(utility::conversions::to_string_t(Event[i].IsComply));
        user_data[U("recommend")] = json::value::string(utility::conversions::to_string_t(Event[i].recommend));
        user_data[U("result")] = json::value::string(utility::conversions::to_string_t(Event[i].result));
        user_data[U("importantLevel")] = json::value::string(utility::conversions::to_string_t(Event[i].importantLevel));
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

        //pd是密码
        string ip = (global_ip);
        string pd = (global_pd);

        ssh_session session = initialize_ssh_session(ip.c_str(), "root", pd.c_str());
        if (session == NULL) {
            request.reply(status_codes::InternalError, U("SSH session failed to start."));
            return;
        }


        fun(Event, session);

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
        data[U("vul_name")] = json::value::string(utility::conversions::to_string_t(poc_list[i].vul_name));
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
        data[U("vul_name")] = json::value::string(utility::conversions::to_string_t(poc_data[i].vul_name));
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
    try {
        // 检查是否为multipart/form-data格式
        auto content_type = request.headers().content_type();
        if (content_type.find(U("multipart/form-data")) == std::string::npos) {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("Invalid content type. Expected multipart/form-data."));
            http_response response(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 将请求体保存到临时文件
        save_request_to_temp_file(request);

        // 解析表单字段
        std::string cve_id, vul_name, type, description, script_type;
        std::ifstream temp_file(TEMP_FILENAME, std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
        temp_file.close();

        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos != std::string::npos) {
            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
            size_t pos = 0, next_pos;
            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
                std::string part = body.substr(pos, next_pos - pos);
                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

                auto header_end_pos = part.find("\r\n\r\n");
                if (header_end_pos == std::string::npos) continue;

                std::string headers = part.substr(0, header_end_pos);
                std::string data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF

                //std::cout << "Headers: " << headers << std::endl;
                //std::cout << "Data: " << data << std::endl;

                // 使用autoConvertToUTF8将数据从GBK转换为UTF-8
                std::string decoded_data = autoConvertToUTF8(data);

                if (headers.find("filename=") == std::string::npos) {
                    auto name_pos = headers.find("name=");
                    if (name_pos != std::string::npos) {
                        std::string name = headers.substr(name_pos + 6);
                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
                        if (name == "cve_id") cve_id = decoded_data;
                        else if (name == "vul_name") vul_name = decoded_data;
                        else if (name == "type") type = decoded_data;
                        else if (name == "description") description = decoded_data;
                        else if (name == "script_type") script_type = decoded_data;
                    }
                }
            }
        }

        // 检查CVE_ID是否已存在
        if (!dbManager.searchDataByCVE(cve_id).empty()) {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("CVE_ID already exists"));
            http_response response(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 处理文件上传，使用已经读取的请求体
        std::string filename = "";
        std::string error_message = "";
        std::string data = ""; //文件内容
        if (!check_and_get_filename(body, content_type, filename, data, error_message))
        {
            //有文件上传
            if(filename != "")
                upload_file(filename, data);
        }
        else
        {
            http_response response;
            json::value response_data;
            response_data[U("message")] = json::value::string(U("添加失败！文件名已存在，请修改！"));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }
        
        /*
        if (!error_message.empty()) {
            json::value response_data;
            response_data[U("message")] = json::value::string(U(error_message));
            http_response response(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }
        */

        // 插入数据到数据库
        bool success = dbManager.insertData(cve_id, vul_name, type, description, script_type, filename);

        json::value response_data;
        http_response response;
        if (success) {
            poc_list = dbManager.getAllData();  //更新POC列表
            response_data[U("message")] = json::value::string(U("添加成功！"));
            response.set_status_code(status_codes::OK);
        }
        else {
            response_data[U("message")] = json::value::string(U("添加失败！"));
            response.set_status_code(status_codes::BadRequest);
        }
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "General error during file upload: " << e.what() << std::endl;
        json::value response_data;
        response_data[U("message")] = json::value::string(U("An error occurred during file upload: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
}

/*
void ServerManager::handle_put_update_data_by_id(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        int id = body[U("id")].as_integer();
        POC poc;
        poc.cve_id = (body[U("cve_id")].as_string());
        poc.vul_name = (body[U("vul_name")].as_string());
        poc.type = (body[U("type")].as_string());
        poc.description = (body[U("description")].as_string());
        poc.script_type = (body[U("script_type")].as_string());
        //poc.script = (body[U("script")].as_string());



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
*/

void ServerManager::handle_put_update_data_by_id(http_request request)
{
    try {
        // 检查是否为multipart/form-data格式
        auto content_type = request.headers().content_type();
        if (content_type.find(U("multipart/form-data")) == std::string::npos) {
            json::value response_data;
            response_data[U("message")] = json::value::string(U("Invalid content type. Expected multipart/form-data."));
            http_response response(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 将请求体保存到临时文件
        save_request_to_temp_file(request);

        POC poc;

        // 解析表单字段
        std::ifstream temp_file(TEMP_FILENAME, std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
        temp_file.close();

        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos != std::string::npos) {
            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
            size_t pos = 0, next_pos;
            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
                std::string part = body.substr(pos, next_pos - pos);
                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

                auto header_end_pos = part.find("\r\n\r\n");
                if (header_end_pos == std::string::npos) continue;

                std::string headers = part.substr(0, header_end_pos);
                std::string data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF

                //std::cout << "Headers: " << headers << std::endl;
                //std::cout << "Data: " << data << std::endl;

                if (headers.find("filename=") == std::string::npos) {
                    auto name_pos = headers.find("name=");
                    if (name_pos != std::string::npos) {
                        std::string name = headers.substr(name_pos + 6);
                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
                        if (name == "id") poc.id = atoi(data.c_str());
                        else if (name == "cve_id") poc.cve_id = data;
                        else if (name == "vul_name") poc.vul_name = data;
                        else if (name == "type") poc.type = data;
                        else if (name == "description") poc.description = data;
                        else if (name == "script_type") poc.script_type = data;
                    }
                }
            }
        }


        // 处理文件上传，使用已经读取的请求体
        std::string filename = ""; //新文件名
        std::string POC_filename = dbManager.searchPOCById(poc.id); //原文件名
        std::string error_message = "";
        std::string data = ""; //文件内容

        //poc.script默认为原文件名
        poc.script = POC_filename.substr(POC_filename.find_last_of('/')+1);

        //文件名是否已经存在，并给filename赋值
        bool fileExist = check_and_get_filename(body, content_type, filename, data, error_message);
        
        //新上传了文件
        if (filename != "")
        {
            //有同名文件，且不是该POC记录的，报错
            if (fileExist && filename != poc.script)
            {
                http_response response;
                json::value response_data;
                response_data[U("message")] = json::value::string(U("更新失败！文件名已在其他漏洞的POC中存在，请修改！"));
                response.set_status_code(status_codes::BadRequest);
                response.set_body(response_data);
                request.reply(response);
                return;
            }

            // 删除原POC文件
            if (!POC_filename.empty())
            {
                //判断是一个文件，而非目录
                if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty()) {
                    if (std::remove(POC_filename.c_str()) != 0) {
                        std::cerr << "Error deleting file: " << POC_filename << std::endl;

                        http_response response;
                        json::value response_data;
                        response_data[U("message")] = json::value::string(U("更新失败！删除原POC文件失败，请联系管理员！"));
                        response.set_status_code(status_codes::BadRequest);
                        response.set_body(response_data);
                        request.reply(response);
                        return;
                    }
                }
            }
            //上传新文件
            upload_file(filename, data);
            //更新poc路径
            poc.script = filename;
        }


        // 更新数据
        bool success = dbManager.updateDataById(poc.id, poc);

        http_response response;
        json::value response_data;
        if (success) {
            poc_list = dbManager.getAllData();  //更新POC列表
            response_data[U("message")] = json::value::string(U("更新成功"));
            response.set_status_code(status_codes::OK);
            response.set_body(response_data);
        }
        else {
            response_data[U("message")] = json::value::string(U("更新失败"));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
        }
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing update data request: " << e.what() << std::endl;
        json::value response_data;
        response_data[U("message")] = json::value::string(U("An error occurred during the update process: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
}


void ServerManager::handle_delete_data_by_id(http_request request) {
    request.extract_json().then([this, &request](json::value body) mutable {
        bool dbSuccess = true, fileSuccess = true;

        if (body[U("ids")].is_array()) {
            auto idsArray = body[U("ids")].as_array();
            for (auto& val : idsArray) {
                int id = val.as_integer();
                std::string POC_filename = dbManager.searchPOCById(id);
                // 删除数据库信息
                if (!dbManager.deleteDataById(id)) {
                    dbSuccess = false;
                    break;
                }
                else
                {
                    // 删除本地POC文件
                    if (!POC_filename.empty()) {
                        if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty())
                        {
                            if (std::remove(POC_filename.c_str()) != 0) {
                                std::cerr << "Error deleting file: " << POC_filename << std::endl;
                                fileSuccess = false;

                                http_response response;
                                json::value response_data;
                                response_data[U("message")] = json::value::string(U("删除失败！删除POC文件失败，请联系管理员！"));
                                response.set_status_code(status_codes::BadRequest);
                                response.set_body(response_data);
                                request.reply(response);
                                return;
                            }
                        }
                    }
                }
            }
        }
        else {
            int id = body[U("ids")].as_integer();
            std::string POC_filename = dbManager.searchPOCById(id);

            // 删除数据库信息
            if (!dbManager.deleteDataById(id)) {
                dbSuccess = false;
            }
            else {
                // 删除本地POC文件
                if (!POC_filename.empty()) {
                    if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty())
                    {
                        if (std::remove(POC_filename.c_str()) != 0) {
                            std::cerr << "Error deleting file: " << POC_filename << std::endl;
                            fileSuccess = false;

                            http_response response;
                            json::value response_data;
                            response_data[U("message")] = json::value::string(U("删除失败！删除POC文件失败，请联系管理员！"));
                            response.set_status_code(status_codes::BadRequest);
                            response.set_body(response_data);
                            request.reply(response);
                            return;
                        }
                    }
                }
            }  

        }

        http_response response;
        json::value response_data;

        if (dbSuccess && fileSuccess) {
            poc_list = dbManager.getAllData();
            response_data[U("message")] = json::value::string(U("删除成功"));
            response.set_status_code(status_codes::OK);
        }
        else if (!dbSuccess) {
            response_data[U("message")] = json::value::string(U("数据库记录删除失败"));
            response.set_status_code(status_codes::BadRequest);
        }
        else { // 文件删除失败，但数据库操作成功
            response_data[U("message")] = json::value::string(U("文件删除失败，数据库记录已删除"));
            response.set_status_code(status_codes::PartialContent); // 或选择适合的状态码
        }

        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
        }).wait();
}

void ServerManager::handle_post_get_Nmap(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        std::string ip = body[U("ip")].as_string();

        std::string outputPath = performPortScan(ip);

        //std::string test_outputFileName = "output_192.168.117.100_2024-07-13_14_46_32.xml";
        //std::string outputPath = "../../output_nmap/" + test_outputFileName;

        cout << outputPath << endl;
        scan_host_result = parseXmlFile(outputPath);

        for (auto& scanHostResult : scan_host_result) {
            for (auto& port : scanHostResult.ports) {
                port_services[port.service_name] = port.portId;
            }
            auto& cpes = scanHostResult.cpes;
            fetch_and_padding_cves(cpes);
            auto& ports = scanHostResult.ports;
            for (auto& scanResult : ports) {
                fetch_and_padding_cves(scanResult.cpes);
            }
        }


        // 创建响应
        http_response response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));

        json::value response_data;
        response_data[U("message")] = json::value::string(U("Nmap scan completed and CVE data fetched."));
        response.set_body(response_data);
        request.reply(response);

        }).wait();

}

void ServerManager::handle_post_hydra(http_request request){
    request.extract_json().then([this, &request](json::value body) {
        cout << "测试2：";
        try {
            if (!body.has_field(U("ip")) || !body.has_field(U("service_name")) || !body.has_field(U("portId"))) {
                throw std::runtime_error("Invalid input JSON");
            }

            std::string ip = body[U("ip")].as_string();
            std::string service_name = body[U("service_name")].as_string();
            std::string portId_name = body[U("portId")].as_string();

            std::string usernameFile = "/hydra/usernames.txt";
            std::string passwordFile = "/hydra/passwords.txt";

            //说明有这个服务
            if (port_services.find(service_name) != port_services.end()) {
                // Construct the hydra command
                std::string command = "hydra -L " + usernameFile + " -P " + passwordFile + " -f " + service_name + "://" + ip;

                // Execute the command and get the output
                std::string output = exec(command.c_str());

                std::string res = extract_login_info(output);

                std::regex pattern(R"(\[(\d+)\]\[([^\]]+)\] host:\s*([^\s]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+))");
                std::smatch match;
                int port = 0;
                std::string service = "";
                std::string host = "";
                std::string login = "";
                std::string password = "";

                // Search for the pattern in the input string
                if (std::regex_search(res, match, pattern)) {
                    port = std::stoi(match[1].str());
                    service = match[2].str();
                    host = match[3].str();
                    login = match[4].str();
                    password = match[5].str();
                }
                else {
                    throw std::runtime_error("No matching info found");
                }

                json::value json_obj = json::value::object();
                json_obj[U("port")] = json::value::number(port);
                json_obj[U("service")] = json::value::string(service);
                json_obj[U("host")] = json::value::string(host);
                json_obj[U("login")] = json::value::string(login);
                json_obj[U("password")] = json::value::string(password);

                // Create a JSON array and add the JSON object to it
                json::value json_array = json::value::array();
                json_array[0] = json_obj;

                // 创建响应
                http_response response(status_codes::OK);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));

                response.set_body(json_array);
                request.reply(response);
            }
            else {
                // 服务不存在，返回错误信息
                json::value error_response = json::value::object();
                error_response[U("error")] = json::value::string(U("Service not found"));
                error_response[U("service_name")] = json::value::string(service_name);

                // 创建响应
                http_response response(status_codes::NotFound);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));

                response.set_body(error_response);
                request.reply(response);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "An error occurred: " << e.what() << std::endl;
            http_response response(status_codes::InternalError);
            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
            response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
            json::value error_response = json::value::object();
            error_response[U("error")] = json::value::string(U("Internal server error"));
            error_response[U("details")] = json::value::string(U(e.what()));
            response.set_body(error_response);
            request.reply(response);
        }
        }).wait();
}

void ServerManager::handle_post_testWeak(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        std::string password = body[U("pd")].as_string();
        PasswordStrength strength = checkPasswordStrength(password);

        string message = passwordStrengthToString(strength);


        // 创建响应
        http_response response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));

        json::value response_data;
        response_data[U("message")] = json::value::string(U(message));
        response.set_body(response_data);
        request.reply(response);

        }).wait();
}

void ServerManager::handle_post_classify_protect(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        try {
            // 清空现有数据
            vecScoreMeasure.clear();

            // 检查 JSON 结构
            if (body.is_object() && body.has_field(U("scoreMeasures")) && body.at(U("scoreMeasures")).is_array()) {
                auto json_array = body.at(U("scoreMeasures")).as_array();
                for (auto& item : json_array) {
                    if (item.is_object()) {
                        scoreMeasure measure;
                        measure.importantLevelJson = utility::conversions::to_utf8string(item.at(U("importantLevelJson")).as_string());
                        measure.IsComplyLevel = utility::conversions::to_utf8string(item.at(U("IsComplyLevel")).as_string());
                        vecScoreMeasure.push_back(measure);
                    }
                }
                int n = vecScoreMeasure.size(); // 项数
                double sum = 0.0;
                // 累加每一项的得分
                for (int k = 0; k < n; k++) {
                    double importantLevel = stod(vecScoreMeasure[k].importantLevelJson);
                    double complyLevel = stod(vecScoreMeasure[k].IsComplyLevel);
                    sum += importantLevel * (1.0 - complyLevel);

                    // 输出每一项的计算值用于调试
                    std::cout << "Item " << k << ": importantLevel = " << importantLevel << ", complyLevel = " << complyLevel << ", partialSum = " << sum << std::endl;
                }

                // 输出总和用于调试
                std::cout << "Total sum: " << sum << std::endl;

                // 计算最终评分
                double M = 100.0 - (100.0 * sum / n);

                // 输出最终评分用于调试
                std::cout << "Final score (M): " << M << std::endl;
                // 构造响应消息
                json::value response_data;
                response_data[U("message")] = json::value::string("Scores received and processed successfully");
                response_data[U("score")] = json::value::number(M); // 将评分结果添加到响应中
                // 创建响应
                http_response response(status_codes::OK);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
                response.set_body(response_data);

                // 发送响应
                request.reply(response);
            }
            else {
                // JSON 结构不符合预期
                json::value response_data;
                response_data[U("message")] = json::value::string("Invalid JSON structure");

                http_response response(status_codes::BadRequest);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
            }
        }
        catch (const std::exception& e) {
            json::value response_data;
            response_data[U("message")] = json::value::string("Exception occurred: " + std::string(e.what()));

            http_response response(status_codes::InternalError);
            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
            response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
            response.set_body(response_data);

            request.reply(response);
        }
        }).wait();
}
void ServerManager::handle_get_classify_protect(http_request request) {
    // 创建 JSON 数组
    json::value json_array = json::value::array();

    // 填充 JSON 数组
    size_t index = 0;
    for (const auto& measure : vecScoreMeasure) {
        json::value json_object;
        json_object[U("importantLevelJson")] = json::value::string(measure.importantLevelJson);
        json_object[U("IsComplyLevel")] = json::value::string(measure.IsComplyLevel);
        json_array[index++] = json_object;
    }

    // 创建响应
    json::value response_data;
    response_data[U("scoreMeasures")] = json_array;

    http_response response(status_codes::OK);
    response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
    response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
    response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
    response.set_body(response_data);

    // 发送响应
    request.reply(response);
}
//void ServerManager::handle_post_hydra(http_request request)
//{
//    request.extract_json().then([this, &request](json::value body) {
//        std::string ip = body[U("ip")].as_string();
//        std::string service_name = body[U("service_name")].as_string();
//        std::string portId_name = body[U("portId_name")].as_string();
//
//        std::string usernameFile = "/hydra/usernames.txt";
//        std::string passwordFile = "/hydra/passwords.txt";
//
//        //说明有这个服务
//        if (port_services.find(service_name) != port_services.end()) {
//            // Construct the hydra command
//            std::string command = "hydra -L " + usernameFile + " -P " + passwordFile + " -f" + service_name + "://" + ip;
//
//            // Execute the command and get the output
//            std::string output = exec(command.c_str());
//
//
//            string res = extract_login_info(output);
//
//
//            std::regex pattern(R"(\[(\d+)\]\[([^\]]+)\] host:\s*([^\s]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+))");
//            std::smatch match;
//            int port = 0;
//            string service = "";
//            string host = "";
//            string login = "";
//            string password = "";
//            // Search for the pattern in the input string
//            if (std::regex_search(res, match, pattern)) {
//                port = std::stoi(match[1].str());
//                service = match[2].str();
//                host = match[3].str();
//                login = match[4].str();
//                password = match[5].str();
//            }
//            else {
//                throw std::runtime_error("No matching info found");
//            }
//            json::value json_obj = json::value::object();
//            json_obj[U("port")] = json::value::number(port);
//            json_obj[U("service")] = json::value::string(service);
//            json_obj[U("host")] = json::value::string(host);
//            json_obj[U("login")] = json::value::string(login);
//            json_obj[U("password")] = json::value::string(password);
//
//            // Create a JSON array and add the JSON object to it
//            json::value json_array = json::value::array();
//            json_array[0] = json_obj;
//
//            // 创建响应
//            http_response response(status_codes::OK);
//            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
//            response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
//            response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
//
//            //json::value response_data;
//            //response_data[U("message")] = json::value::string(U(res));
//            response.set_body(json_array);
//            request.reply(response);
//        }
//        else {
//            // 服务不存在，返回错误信息
//            json::value error_response = json::value::object();
//            error_response[U("error")] = json::value::string(U("Service not found"));
//            error_response[U("service_name")] = json::value::string(service_name);
//
//            // 创建响应
//            http_response response(status_codes::NotFound);
//            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
//            response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
//            response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
//
//            response.set_body(error_response);
//            request.reply(response);
//        }
//        }).wait();
//}

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
                                //std::cout << "CVE ID: " << cve[U("id")].as_string() << std::endl;
                                std::string cvss_str = "N/A";
                                if (cve.has_field(U("cvss"))) {
                                    auto cvss_value = cve[U("cvss")];
                                    if (cvss_value.is_string()) {
                                        cvss_str = cvss_value.as_string();
                                        //std::cout << "CVSS Score: " << cvss_value.as_string() << std::endl;
                                    }
                                    else if (cvss_value.is_number()) {
                                        cvss_str = std::to_string(cvss_value.as_number().to_double());
                                        //std::cout << "CVSS Score: " << cvss_value.as_number().to_double() << std::endl;
                                    }
                                    else {
                                        //std::cout << "CVSS Score: N/A" << std::endl;
                                    }
                                }
                                else {
                                    //std::cout << "CVSS Score: N/A" << std::endl;
                                }
                                tmp.CVSS = cvss_str;
                                if (cve.has_field(U("summary"))) {
                                    //std::cout << "Summary: " << cve[U("summary")].as_string() << std::endl;
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
    result[U("vul_name")] = json::value::string(cve.vul_name);
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

    //新添
    json::value os_matches_json = json::value::array();
    int index_os = 0;
    for (const auto& os_match : scan_host_result.os_matches) {
        os_matches_json[index_os++] = json::value::string(os_match);
    }
    result[U("os_matches")] = os_matches_json;


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

//检验文件是否存在，并获取文件名
bool ServerManager::check_and_get_filename(const std::string& body, const std::string& content_type, std::string& filename, std::string& data, std::string& error_message) {
    auto boundary_pos = content_type.find("boundary=");
    if (boundary_pos != std::string::npos) {
        std::string boundary = "--" + content_type.substr(boundary_pos + 9);
        size_t pos = 0, next_pos;
        while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
            std::string part = body.substr(pos, next_pos - pos);
            pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

            auto header_end_pos = part.find("\r\n\r\n");
            if (header_end_pos == std::string::npos) continue;

            std::string headers = part.substr(0, header_end_pos);

            if (headers.find("filename=") != std::string::npos) {
                auto name_pos = headers.find("filename=");
                if (name_pos != std::string::npos) {
                    filename = headers.substr(name_pos + 10);  // 10 = length of 'filename="'
                    filename = filename.substr(0, filename.find("\""));  // Remove trailing quote
                    std::cout << "Extracted filename: " << filename << std::endl;

                    // 构建文件路径
                    auto path = U("../../../src/scan/scripts/") + utility::conversions::to_string_t(filename);

                    // 解析并返回文件内容
                    data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6);  // Exclude trailing CRLF
                    
                    // 检查文件是否已经存在
                    std::ifstream infile(path);
                    if (infile.good() && filename != "") {
                        error_message = "File already exists";
                        return true;  // 文件已存在
                    }
                    return false;  // 文件不存在
                }
            }
        }
    }
    error_message = "No valid filename found in the request";
    return false;  // 文件不存在
}

//上传文件
void ServerManager::upload_file(const std::string& filename, const std::string& data) {
    // 构建文件路径
    auto path = U("../../../src/scan/scripts/") + utility::conversions::to_string_t(filename);

    // 打开输出流并写入数据
    concurrency::streams::fstream::open_ostream(path).then([=](concurrency::streams::ostream outFile) mutable {
        auto fileStream = std::make_shared<concurrency::streams::ostream>(outFile);
        std::vector<uint8_t> file_data(data.begin(), data.end());  // 将string数据转换为字节数组
        auto buf = concurrency::streams::container_buffer<std::vector<uint8_t>>(std::move(file_data));
        fileStream->write(buf, buf.size()).then([=](size_t) {
            fileStream->close().get();  // 关闭文件流
            }).wait();
        }).wait();
}


//POC上传文件的工具函数
void ServerManager::save_request_to_temp_file(http_request request) {
    auto bodyStream = request.body();
    concurrency::streams::container_buffer<std::vector<uint8_t>> buffer;
    bodyStream.read_to_end(buffer).get();
    std::string body(buffer.collection().begin(), buffer.collection().end());

    // 写入临时文件（覆盖之前的内容）
    std::ofstream temp_file(TEMP_FILENAME, std::ios::binary | std::ios::trunc);
    if (!temp_file.is_open()) {
        throw std::runtime_error("Failed to open temporary file for writing");
    }
    temp_file.write(body.data(), body.size());
    temp_file.close();
}

//查看POC内容
void ServerManager::handle_get_poc_content(http_request request) {
    try {
        // 解析请求URL中的参数
        auto query = uri::split_query(request.request_uri().query());
        if (query.find(U("id")) == query.end()) {
            request.reply(status_codes::BadRequest, U("Missing 'id' parameter"));
            return;
        }

        int poc_id = std::stoi(query[U("id")]);

        // 查询POC记录获取文件名
        std::string poc_filename = dbManager.searchPOCById(poc_id);
        if (poc_filename.empty()) {
            request.reply(status_codes::OK, U("{\"content\": \"\"}"));
            return;
        }

        //验证路径是否为文件
        if (is_directory(poc_filename)) {
            std::cerr << "The path is a directory, not a file（no POC file）: " << poc_filename << std::endl;
            request.reply(status_codes::InternalError, U("{\"error\": \"缺少POC文件\"}"));
            return;
        }


        // 读取文件内容
        std::ifstream file(poc_filename, std::ios::binary);
        if (!file.is_open()) {
            request.reply(status_codes::OK, U("{\"content\": \"\"}"));
            return;
        }

        std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // 返回文件内容
        json::value response_data;
        response_data[U("content")] = json::value::string(utility::conversions::to_string_t(file_content));

        http_response response(status_codes::OK);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing get POC content request: " << e.what() << std::endl;
        json::value response_data;
        response_data[U("message")] = json::value::string(U("An error occurred while processing the request: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
}

//POC搜索
void ServerManager::handle_post_poc_search(http_request request) {
    try {
        // 执行 POC 搜索
        for (auto& scanHostResult : scan_host_result) {
            searchPOCs(scanHostResult, dbManager);
        }

        // 使用 handle_get_cve_scan 返回搜索结果
        handle_get_cve_scan(request);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing POC search request: " << e.what() << std::endl;
        json::value response_data;
        response_data[U("message")] = json::value::string(U("An error occurred during POC search: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
}

//POC验证
void ServerManager::handle_post_poc_verify(http_request request) {
    try {
        // 获取请求的 JSON 数据
        request.extract_json().then([this, &request](json::value body) {
            std::vector<std::string> cve_ids;
            for (const auto& id : body[U("cve_ids")].as_array()) {
                cve_ids.push_back(id.as_string());
            }

            // 设置 ifCheck 标志
            for (auto& scanHostResult : scan_host_result) {
                setIfCheckByIds(scanHostResult, cve_ids, true);
            }

            // 执行 POC 验证
            verifyPOCs(scan_host_result);

            // 重置 ifCheck 标志
            for (auto& scanHostResult : scan_host_result) {
                setIfCheckByIds(scanHostResult, cve_ids, false);
            }

            // 使用 handle_get_cve_scan 返回验证结果
            handle_get_cve_scan(request);
            }).wait();
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing POC verify request: " << e.what() << std::endl;
        json::value response_data;
        response_data[U("message")] = json::value::string(U("An error occurred during POC verification: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }
}


// 设置需要执行POC验证的CVE条目
void ServerManager::setIfCheckByIds(ScanHostResult& hostResult, const std::vector<std::string>& cve_ids, bool value) {
    for (auto& cpe : hostResult.cpes) {
        for (auto& cve : cpe.second) {
            if (std::find(cve_ids.begin(), cve_ids.end(), cve.CVE_id) != cve_ids.end()) {
                cve.ifCheck = value;
            }
        }
    }

    for (auto& port : hostResult.ports) {
        for (auto& cpe : port.cpes) {
            for (auto& cve : cpe.second) {
                if (std::find(cve_ids.begin(), cve_ids.end(), cve.CVE_id) != cve_ids.end()) {
                    cve.ifCheck = value;
                }
            }
        }
    }
}

void ServerManager::handle_post_poc_excute(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        std::string CVE_id = body[U("CVE_id")].as_string();
        std::string script = findScriptByCveId(scan_host_result, CVE_id);
        std::string portId = findPortIdByCveId(scan_host_result, CVE_id);
        std::string ip = scan_host_result[0].ip;
        std::string url = scan_host_result[0].url;

        std::string result = runPythonWithOutput(script, url,ip, std::stoi(portId));

        // 创建响应
        http_response response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));

        json::value response_data;
        response_data[U("message")] = json::value::string(result);
        response.set_body(response_data);
        request.reply(response);

    }).wait();
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


