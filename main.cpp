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
