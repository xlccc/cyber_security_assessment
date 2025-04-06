#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
//main函数
#include <mysqlx/xdevapi.h>
#include"ServerManager.h"
#include <unistd.h>
#include "utils/utils.h"
#include "utils/CommonDefs.h"
#include "utils_scan.h"
#include "log/log.h"
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



//// 检查防火墙配置是否符合三级等保要求
//bool checkFirewallCompliance() {
//    try {
//        // 1. 检查防火墙是否开启
//        std::string statusOutput = exec("sudo ufw status verbose");
//        if (statusOutput.find("状态：激活") == std::string::npos &&
//            statusOutput.find("Status: active") == std::string::npos) {
//            std::cout << "防火墙未开启" << std::endl;
//            return false;
//        }
//
//        // 2. 检查默认策略是否符合要求
//        // 检查入站默认策略是否为拒绝
//        if (statusOutput.find("默认：deny (incoming)") == std::string::npos &&
//            statusOutput.find("Default: deny (incoming)") == std::string::npos) {
//            std::cout << "入站默认策略不是deny" << std::endl;
//            return false;
//        }
//
//        // 检查出站默认策略是否为允许
//        if (statusOutput.find("allow (outgoing)") == std::string::npos) {
//            std::cout << "出站默认策略不是allow" << std::endl;
//            return false;
//        }
//
//        // 检查路由默认策略是否为拒绝
//        if (statusOutput.find("deny (routed)") == std::string::npos) {
//            std::cout << "路由默认策略不是deny" << std::endl;
//            return false;
//        }
//
//        // 3. 检查是否存在Anywhere规则
//        std::string rulesOutput = exec("sudo ufw status numbered");
//
//        // 使用正则表达式检查入站规则中是否有Anywhere
//        std::regex incomingAnywherePattern("ALLOW\\s+IN\\s+Anywhere");
//        std::smatch matches;
//        if (std::regex_search(rulesOutput, matches, incomingAnywherePattern)) {
//            std::cout << "发现入站规则允许Anywhere访问，不符合白名单机制" << std::endl;
//            return false;
//        }
//
//        // 所有检查都通过
//        std::cout << "防火墙配置符合三级等保要求" << std::endl;
//        return true;
//    }
//    catch (const std::exception& e) {
//        std::cerr << "发生错误: " << e.what() << std::endl;
//        return false;
//    }
//}
//
//// 主函数，用于测试
//int main() {
//    bool isCompliant = checkFirewallCompliance();
//
//    if (isCompliant) {
//        std::cout << "结果: 防火墙配置符合要求" << std::endl;
//    }
//    else {
//        std::cout << "结果: 防火墙配置不符合要求" << std::endl;
//    }
//
//    return 0;
//}