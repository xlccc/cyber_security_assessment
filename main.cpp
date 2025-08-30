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
#include "database/DatabaseHandler.h"
#include <csignal>
#include <atomic>

using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;

// 全局标志
std::atomic<bool> running(true);

// 信号处理函数
void signal_handler(int signum) {
    running = false;
}
int main()
{
    // 设置信号处理
    std::signal(SIGINT, signal_handler);  // Ctrl+C
    std::signal(SIGTERM, signal_handler); // kill命令

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
    serverManager.InitializeAdminDatabase();
    serverManager.open_listener();

  
    // 主循环
    std::cout << "Server is running. Press Ctrl+C to close the server." << std::endl;

    while (running) {
        try {
            // 使用更短的睡眠间隔，提高响应性
            for (int i = 0; i < 10 && running; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        catch (const std::exception& e) {
            // 处理睡眠中断异常
            if (std::string(e.what()).find("Interrupt") != std::string::npos) {
                // 睡眠被中断，检查是否需要退出
                continue;
            }
            else {
                std::cerr << "Unexpected exception: " << e.what() << std::endl;
                running = false;
            }
        }
    }

    // 终止Python解释器
    finalizePython();
  
    return 0;
}


