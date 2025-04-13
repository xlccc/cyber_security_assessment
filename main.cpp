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


//int main() {
//    try {
//        // 获取UFW防火墙规则
//        std::string ufwOutput;
//
//        // 尝试从命令执行获取规则
//        try {
//            ufwOutput = exec("sudo ufw status numbered");
//            std::cout << "成功执行UFW命令获取防火墙规则。" << std::endl;
//        }
//        catch (const std::exception& e) {
//            std::cerr << "执行UFW命令失败: " << e.what() << std::endl;
//            std::cerr << "请确保您有sudo权限并且UFW已安装。" << std::endl;
//            return 1;
//        }
//
//        // 确保输出不为空
//        if (ufwOutput.empty()) {
//            std::cerr << "UFW命令返回空输出，请确保UFW已启用且有规则存在。" << std::endl;
//            return 1;
//        }
//
//        // 过滤出带编号的规则
//        std::string numberedRulesStr = filterNumberedRules(ufwOutput);
//
//        if (numberedRulesStr.empty()) {
//            std::cout << "未找到UFW规则，防火墙可能未启用或没有配置规则。" << std::endl;
//            return 0;
//        }
//
//        // 解析UFW规则
//        std::vector<UfwRule> rules = parseUfwRules(numberedRulesStr);
//
//        if (rules.empty()) {
//            std::cout << "没有解析到任何规则，可能是解析失败或防火墙没有规则。" << std::endl;
//            return 0;
//        }
//
//        std::cout << "共解析到 " << rules.size() << " 条防火墙规则:" << std::endl;
//        for (const auto& rule : rules) {
//            rule.print();
//        }
//        std::cout << std::endl;
//
//        // 查找冗余规则
//        std::cout << "正在检测冗余规则..." << std::endl;
//        std::vector<UfwRule> redundantRules = findRedundantRules(rules);
//
//        if (redundantRules.empty()) {
//            std::cout << "未发现冗余规则，当前防火墙配置是高效的。" << std::endl;
//        }
//        else {
//            std::cout << "发现 " << redundantRules.size() << " 条冗余规则:" << std::endl;
//
//            // 打印冗余规则编号
//            std::cout << "冗余规则编号: ";
//            for (size_t i = 0; i < redundantRules.size(); ++i) {
//                if (i > 0) std::cout << ", ";
//                std::cout << redundantRules[i].number;
//            }
//            std::cout << std::endl << std::endl;
//
//            // 打印冗余规则的详细信息
//            std::cout << "冗余规则详细信息:" << std::endl;
//
//            for (const auto& redundantRule : redundantRules) {
//                // 查找包含该冗余规则的规则
//                for (const auto& rule : rules) {
//                    if (rule.number != redundantRule.number && isRuleContained(rule, redundantRule)) {
//                        std::cout << "规则 [" << redundantRule.number << "] 是冗余的，被规则 ["
//                            << rule.number << "] 包含" << std::endl;
//
//                        std::cout << "规则 [" << rule.number << "]: ";
//                        rule.print();
//
//                        std::cout << "规则 [" << redundantRule.number << "]: ";
//                        redundantRule.print();
//
//                        std::cout << std::endl;
//                        break;
//                    }
//                }
//            }
//
//            // 提供删除冗余规则的建议命令
//            std::cout << "建议的删除命令:" << std::endl;
//
//            // 按照从大到小的顺序删除，避免删除一条规则后编号变化导致删错规则
//            std::sort(redundantRules.begin(), redundantRules.end(),
//                [](const UfwRule& a, const UfwRule& b) { return a.number > b.number; });
//
//            for (const auto& rule : redundantRules) {
//                std::cout << "sudo ufw delete " << rule.number << std::endl;
//            }
//
//            // 提示用户谨慎删除
//            std::cout << "\n注意：请在删除规则前仔细检查，确保理解规则包含关系。" << std::endl;
//            std::cout << "删除规则后请验证防火墙功能是否正常工作。" << std::endl;
//        }
//
//    }
//    catch (const std::exception& e) {
//        std::cerr << "程序执行过程中发生错误: " << e.what() << std::endl;
//        return 1;
//    }
//
//    return 0;
//}