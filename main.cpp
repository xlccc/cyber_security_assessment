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


//#include<iostream>
//#include<vector>
//#include<cmath>
//using namespace std;
//
//class Point
//{
//private:
//	float x;
//	float y;
//public:
//	Point(float x, float y)
//	{
//		this->x = x;
//		this->y = y;
//	}
//	float getX() const
//	{
//		return this->x;
//	}
//	float getY() const
//	{
//		return this->y;
//	}
//};
//class Line
//{
//private:
//	vector<Point> point;
//	int count;
//public:
//	//int familarDegree(const Line& line2)
//	//{
//	//	//计算点数差距
//	//	//计算采样间距差距
//
//	//	//综合
//	//}
//	////计算点数差距
//	//int countDiff(const Line& line2)
//	//{
//	//	return abs(this->count - line2.count);
//	//}
//	//计算采样间距差距
//	Line(const std::initializer_list<Point>& l):point(l),count(static_cast<int>(l.size())){}
//
//	int disDiff(const Line& line2)
//	{
//		float result = 0;
//		
//		for (int i = 0; i < count; i++)
//		{
//			int x_d = abs(this->point[i].getX() - line2.point[i].getX());
//			int y_d = abs(this->point[i].getY() - line2.point[i].getY());
//			result += x_d * x_d + y_d * y_d;
//		}
//		return result;
//	}
//};
//int main()
//{
//	Line line1{ {0, 0}, {10, 0}, {20, 0} };
//	Line line2{ {1, 3}, {8, 7}, {16, 25} };
//
//	cout << line1.disDiff(line2) << endl;
//
//	return 0;
//}