//#include<iostream>
//#include<libssh/libssh.h>
//#include<vector>
//#include"Login.h"
//#include"Padding.h"
//#include<stdio.h>
//#include<string>
//#include"database/db.h"
//#include"scan/portScan.h"	
//#include"utils_scan.h"

//int main()
//{
//	////测试SQLite POC数据库
//	////POC_db();
//
//	char cwd[10000];
//	if (getcwd(cwd, sizeof(cwd)) != nullptr) {
//		std::cout << "Current working directory: " << cwd << std::endl;
//	}
//	else {
//		std::cerr << "Error getting current working directory" << std::endl;
//	}
//
//	////测试端口扫描
//	////std::string outputPath = performPortScan("192.168.183.200");
//
//	//std::vector<ScanHostResult> scan_host_result = parseXmlFile("../../output_nmap/output_192.168.183.200_2024-05-25_23_07_52.xml");
//
//	//std::cout << "wait.." << endl;
//
//	//测试POC执行
//
//	std::string scriptPath = "Weblogic_CVE_2017_10271_RCE";
//	std::string url = "192.168.117.100";
//	std::string ip = "192.168.117.100";
//	int port = 7001;
//
//	std::string output = runPythonScript(scriptPath, url, ip, port);
//	if (output.empty())
//	{
//		std::cout << " No vuln" << endl;
//	}
//	else
//	{
//		std::cout << "POC Result: " << output << std::endl;
//	}
//	
//
//
//	//system("pause");
//	return 0;
//}



//std::string exec(const char* cmd) {
//    char buffer[128];
//    std::string result = "";
//    file* pipe = _popen(cmd, "r");
//    if (!pipe) throw std::runtime_error("popen() failed!");
//    try {
//        while (fgets(buffer, sizeof(buffer), pipe) != null) {
//            result += buffer;
//        }
//    }
//    catch (...) {
//        _pclose(pipe);
//        throw;
//    }
//    _pclose(pipe);
//    return result;
//}
//
////测试nmap
//int main() {
//    // 执行nmap扫描命令
//    std::string output = exec("nmap -sv 192.168.117.1");
//
//    // 解析nmap扫描结果
//    // 这里你可以编写代码来提取所需的信息，例如开放端口和服务版本号
//    // 这里只是简单地将nmap的输出打印到控制台
//    std::cout << "nmap scan result:" << std::endl;
//    std::cout << output << std::endl;
//
//    system("pause");
//    return 0;
//}
//
////测试ssh链接+基线检测
////int main(int argc, char** argv)
////{
////    //若以root登录，需配置/etc/ssh/sshd_config中的PermitRootLogin yes
////    ssh_session session = initialize_ssh_session("192.168.117.129", "root", "123456");
////    if (session == NULL)
////    {
////        return -1;
////    }
////    vector<event> Event;
////    fun(Event, session);
////    //cout << Event[0].result << endl;
////    ssh_disconnect(session);
////    ssh_free(session);
////
////
////    system("pause");
////    return 0;
////}
//


//main函数
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