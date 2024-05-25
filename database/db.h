#ifndef SERVER_H
#define SERVER_H

#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <iostream>
#include "DatabaseManager.h" 

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

class Server {
private:
    http_listener listener; // HTTP监听器
    DatabaseManager dbManager; // 数据库管理器实例

public:
    Server(); // 构造函数
    void handleOptions(http_request request); //处理 CORS 预检请求
    void handleGet(http_request request); // 处理GET请求
    void handlePost(http_request request); // 处理POST请求
    void handlePut(http_request request); // 处理PUT请求
    void handleDelete(http_request request); // 处理DELETE请求
    void start(); // 启动服务器监听
    void stop();  //关闭服务器
};


//测试POC数据库
int POC_db();

#endif // SERVER_H