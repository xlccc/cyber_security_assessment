#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
//main函数
#include <mysqlx/xdevapi.h>
#include"ServerManager.h"
#include <unistd.h>

#include "utils/utils.h"
#include "utils_scan.h"
using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;


int main()
{
    // 初始化Python解释器
    initializePython();

    char cwd[10000];
	if (getcwd(cwd, sizeof(cwd)) != nullptr) {
		std::cout << "Current working directory: " << cwd << std::endl;
	}
	else {
		std::cerr << "Error getting current working directory" << std::endl;
	}

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
//    // 定义参数
//    std::string scriptPath = "CVE_2017_12617.py"; // Python脚本名
//    std::string url = "";                            // 空字符串
//    std::string ip = "192.168.29.111";              // IP地址
//    int port = 8080;                                // 端口号
//
//    // 调用函数并获取结果
//    
//    std::string result = runPythonWithOutput(scriptPath, url, ip, port);
//    //std::string result = runPythonScript(scriptPath, url, ip, port);
//    // 输出结果
//    std::cout << "执行结果:\n" << result << std::endl;
//    std::string line;
//    std::cout << "Press Enter to close the server." << std::endl;
//    std::getline(std::cin, line);
//
//    return 0;
//}



//测试主机发现
/*
#include"ServerManager.h"
#include <unistd.h>
#include "utils/utils.h"
#include "utils_scan.h"
#include"scan/hostDiscovery.h"
using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;

int main() {
    std::string network;
    std::cout << "Enter network (e.g., 192.168.1.0/16): ";
    std::cin >> network;

    // 记录开始时间
    auto start = std::chrono::high_resolution_clock::now();


    try {
        HostDiscovery discovery(network);
        std::vector<std::string> aliveHosts = discovery.scan();

        std::cout << "\nAlive hosts in the network " << network << ":\n";
        if (aliveHosts.empty()) {
            std::cout << "No alive hosts found." << std::endl;
        }
        else {
            for (const auto& ip : aliveHosts) {
                std::cout << ip << std::endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception: " << e.what() << std::endl;
    }

    // 记录结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Host Discovery executed in " << elapsed.count() << " seconds." << std::endl;

    return 0;
}*/