#include"db.h"
#include"db_config.h"
#include"poc.h"
#include <iostream>
#include"../convert_string_t.h"


using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

class DBServer {
private:
    http_listener listener;
    DatabaseManager dbManager;
    std::vector<POC> poc_list;

public:

    DBServer() : listener(web::uri(U("http://localhost:8081"))), dbManager(DB_PATH) {

        //this为DBServer实例，std::placeholders::_1为调用时传入的第一个参数，即一个http_request
        listener.support(methods::OPTIONS, std::bind(&DBServer::handleOptions, this, std::placeholders::_1));
        listener.support(methods::GET, std::bind(&DBServer::handleGet, this, std::placeholders::_1));
        listener.support(methods::POST, std::bind(&DBServer::handlePost, this, std::placeholders::_1));
        listener.support(methods::PUT, std::bind(&DBServer::handlePut, this, std::placeholders::_1));
        listener.support(methods::DEL, std::bind(&DBServer::handleDelete, this, std::placeholders::_1));
    }

    //处理 CORS 预检请求（OPTIONS 请求）并为所有响应添加必要的头部
    void handleOptions(http_request request) {
        http_response response(status_codes::OK);

        auto path = request.relative_uri().path();
        std::cout << "Received OPTIONS request for path: " << path << std::endl;

        response.headers().add(U("Allow"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        response.headers().add(U("Access-Control-Allow-Methods"), U("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        request.reply(response);
    }

    void handleGet(http_request request) {

        auto path = request.relative_uri().path();
        std::cout << "Received GET request for path: " << path << std::endl;

        //显示所有POC
        if (path == U("/getAllData")) {

            std::cout << "Fetching all POC data from the database." << std::endl;

            //获取所有数据库POC数据
            poc_list = dbManager.getAllData();
            // 将数据转换为 JSON 数组并发送
            json::value all_data = json::value::array();

            for (size_t i = 0; i < poc_list.size(); i++)
            {
                /* poc结构体定义：
                struct POC {
                    int id;                    //id序号，唯一，由数据库中的id序号所定
                    std::string cve_id;         //CVE编号
                    std::string type;           //漏洞类型
                    std::string description;    //漏洞描述
                    std::string script_type;    //POC脚本类型（可包括python、c、c++、yaml。目前只支持python脚本）
                    std::string script;         //POC脚本代码（目前只支持python脚本）
                    std::string timestamp;      // 添加时间，格式为"YYYY-MM-DD HH:MM:SS"
                };*/

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
        //关键词搜索POC数据
        else if (path == U("/searchData")) {

            // 获取查询参数，例如 ?keyword=xxx
            //uri::split_query将一个query分成键值对的map形式
            auto query = uri::split_query(request.relative_uri().query());
            std::cout << "Received GET request for path: " << path << std::endl;

            //当搜索词为中文时需要解码
            auto searchKeyword = uri::decode(query[U("keyword")]);


            // 调用数据库管理器进行搜索
            auto poc_data = dbManager.searchData(searchKeyword);
            // 将数据转换为 JSON 并发送...
            json::value search_data = json::value::array();

            for (size_t i = 0; i < poc_data.size(); i++)
            {
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
        else {
            std::cout << "Path not found: " << path << ". Sending 404 Not Found." << std::endl;
            request.reply(status_codes::NotFound);
            }
    }

    //添加新的POC
    void handlePost(http_request request) {
        auto path = request.relative_uri().path();
        if (path == U("/insertData")) {
            std::cout << "Received Post request for path: " << path << std::endl;
            //then 是一个异步操作，它会在JSON数据被成功提取后执行。wait 函数是用来等待这个异步操作完成的。
            request.extract_json().then([this, &request](json::value body) {
                //json::value的[]接收utility::string_t时是公有接口
                std::string cve_id = (body[U("cve_id")].as_string());
                std::string type = (body[U("type")].as_string());
                std::string description = (body[U("description")].as_string());
                std::string script_type = (body[U("script_type")].as_string());
                std::string script = (body[U("script")].as_string());
                bool success = dbManager.insertData(cve_id, type, description, script_type, script);
                
                http_response response;
                if (success) {
                    //更新poc_list
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
        else {
            request.reply(status_codes::NotFound);
        }
    }

    //修改POC数据
    void handlePut(http_request request) {
        auto path = request.relative_uri().path();
        if (path == U("/updateDataById")) {
            std::cout << "Received update request for path: " << path << std::endl;

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
                // 返回更新操作的结果
                if (success) {
                    //更新poc_list
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
        else {
            request.reply(status_codes::NotFound);
        }
    }

    //删除选中的一个或多个POC
    void handleDelete(http_request request) {
        auto path = request.relative_uri().path();
        if (path == U("/deleteDataById")) {
            std::cout << "Received Delete request for path: " << path << std::endl;
            request.extract_json().then([this, &request](json::value body) mutable {
                /*前端发来的请求体应包含类似以下内容：
                   {
                    ids: [1, 2, 3]
                   }
                   或
                   {
                    ids: 1
                    }
                */
                bool success = true;
                if (body[U("ids")].is_array()) {
                    auto idsArray = body[U("ids")].as_array();
                    for (auto& val : idsArray) {
                        int id = val.as_integer();
                        if (!dbManager.deleteDataById(id)) {
                            success = false;
                            break;  // 如果任何删除操作失败，停止删除并返回失败响应
                        }
                    }
                }
                else
                {
                    int id = body[U("ids")].as_integer();
                    if (!dbManager.deleteDataById(id)) {
                        success = false;
                    }
                }

                http_response response;
                // 根据操作结果返回响应
                if (success) {
                    //更新poc_list
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
                }).wait();  // 
        }
        else {
            request.reply(status_codes::NotFound);
        }
    }

    // 启动监听器
    void start() {
        try {
            listener
                .open()
                .then([&listener = listener]() {
                ucout << "Starting to listen at: " << listener.uri().to_string() << std::endl;
                    })
                .wait();

        }
        catch (const std::exception& e) {
            std::cerr << "An error occurred: " << e.what() << std::endl;
        }
    }

    void stop() {
        try {
            listener.close().wait();
            ucout << "Stopped listening." << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "An error occurred while stopping: " << e.what() << std::endl;
        }

    }

};




//测试POC数据库
int POC_db() {


    DBServer DBServer;
    DBServer.start();

    std::cout << "Press Enter to stop the server." << std::endl;
    std::cin.get(); // 等待用户输入，确保程序在启动监听器后不会立即退出

    DBServer.stop();



    //// 创建数据库管理对象，指定数据库文件路径
    DatabaseManager dbManager(DB_PATH);

    //std::vector<POC> records;

    //// 创建表
    //dbManager.createTable();
    // 
    ////获取所有数据
    //records = dbManager.getAllData();
    //
    //int id = 2;     //假设要删的是id为2的数据
    //bool delete_success = dbManager.deleteDataById(id);
    //if (delete_success != true)
    //{
    //    std::cout << "SQL error: " << " 不存在id为："<<  id <<"的数据" <<  std::endl;
    //}
    //records = dbManager.getAllData();
    //
    //////测试更新
    ////POC poc_update;
    ////poc_update.id = 1;
    ////poc_update.cve_id = "";
    ////poc_update.description = "wdadwdas  a";
    ////poc_update.script_type = "python";
    ////poc_update.script = "dadsa";
    ////poc_update.type = "sad";
    ////dbManager.updateDataById(poc_update.id, poc_update);


    return 0;
}


