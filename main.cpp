#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
//main函数
#include<iostream>
#include <mysqlx/xdevapi.h>
#include"ServerManager.h"
#include <unistd.h>
#include "utils/utils.h"
#include "utils/CommonDefs.h"
#include "utils_scan.h"
#include "log/log.h"
#include "Event.h"
#include <vector>
#include <string>
#include <sstream>
#include <regex>
#include <fstream>

using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;

int main()
{
    char cwd[10000];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::cout << "Current working directory: " << cwd << std::endl;

        //system_logger->info("System started. Current working directory: {}", cwd);
    }
    else {
        std::cerr << "Error getting current working directory" << std::endl;
    }

    // 注意：必须先加载配置
    try {
        CONFIG.load("../../../src/utils/config.json");  
    }
    catch (const std::exception& e) {
        std::cerr << "配置加载失败: " << e.what() << std::endl;
        return 1;
    }

    // 初始化日志系统
    init_logs();

    // 初始化Python解释器
    initializePython();

    ServerManager serverManager;

    serverManager.open_listener();

    std::string line;
    std::cout << "Press Enter to close the server." << std::endl;
    std::getline(std::cin, line);

    // 终止Python解释器
    finalizePython();
    return 0;
}


