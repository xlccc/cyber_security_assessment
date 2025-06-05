#pragma once
#include<vector>
#include<string>
#include <iostream>  // 提供 std::cout
#include <vector>
#include <string>
#include <sstream>
#include <regex>
#include <fstream>
using namespace std;

struct event {
	string description; //待检查项
	string basis;//判定依据
	string command;//待检查口令
	string result;//待检查的结果
    string IsComply = "false";//返回true还是false，或者half_true，分别对应IsComplyLevel的 1 0 0.5
    string tmp_IsComply = "false";//返回true还是false，或者half_true，分别对应IsComplyLevel的 1 0 0.5 用于给予测试人员手动选择是否满足
	string recommend; //建议
    string importantLevel;// 重要程度，分为1，2，3
    string tmp_importantLevel;// 重要程度，分为1，2，3
	int item_id; //检查项id
    string check_time; //检查时间
};
struct scoreMeasure {
    int item_id;
    string importantLevelJson;//重要程度，分为1，2，3
    string IsComplyLevel; //包含0，0.5, 1
};

//目标主机相关信息
struct ServerInfo {
    string hostname; //目标主机名
    string arch; // 目标主机的架构
    string cpu; //目标主机cpu信息
    string cpuPhysical; //目标主机物理cpu个数
    string cpuCore; //目标主机物理CPU核心数
    string free; //目标主机空闲内存
    string ProductName; //硬件型号
    string version;  //目标主机版本信息
    string osName;   //操作系统名称
    string isInternet; // 联网检测
};
// 定义增强版防火墙规则结构体
struct UfwRule {
    int number;                     // 规则编号
    std::string action;             // 动作(ALLOW/DENY)
    std::string direction;          // 方向(IN/OUT)

    std::string from_ip;            // 来源IP/网络
    std::string from_port;          // 来源端口或端口范围
    std::string from_port_protocol; // 来源端口协议
    bool from_is_port_range;        // 来源端口是否为范围

    std::string to_ip;              // 目标IP/网络
    std::string to_port;            // 目标端口或端口范围
    std::string to_port_protocol;   // 目标端口协议
    bool to_is_port_range;          // 目标端口是否为范围

    bool is_v6;                     // 是否IPv6规则
    std::string extra_info;         // 额外信息，如(out)标记

    // 默认构造函数
    UfwRule() : number(0),
        from_is_port_range(false),
        to_is_port_range(false),
        is_v6(false) {}

    // 打印规则信息
    void print() const {
        std::cout << "[" << number << "] ";

        // 打印目标信息
        if (to_ip != "Anywhere" || !to_port.empty()) {
            if (to_ip != "Anywhere") {
                std::cout << to_ip << " ";
            }

            if (!to_port.empty()) {
                std::cout << to_port;
                if (!to_port_protocol.empty()) {
                    std::cout << "/" << to_port_protocol;
                }
                std::cout << " ";
            }
        }
        else {
            std::cout << "Anywhere ";
        }

        // 打印动作和方向
        std::cout << action << " " << direction << " ";

        // 打印来源信息
        if (from_ip != "Anywhere" || !from_port.empty()) {
            std::cout << from_ip;

            if (!from_port.empty()) {
                std::cout << " " << from_port;
                if (!from_port_protocol.empty()) {
                    std::cout << "/" << from_port_protocol;
                }
            }
        }
        else {
            std::cout << "Anywhere";
        }

        // 打印v6和额外信息
        if (is_v6) {
            std::cout << " (v6)";
        }

        if (!extra_info.empty()) {
            std::cout << " (" << extra_info << ")";
        }

        std::cout << std::endl;
    }

    // 详细打印所有字段（调试用）
    void printDetailed() const {
        std::cout << "规则编号: " << number << std::endl;
        std::cout << "动作: " << action << std::endl;
        std::cout << "方向: " << direction << std::endl;
        std::cout << "来源IP: " << from_ip << std::endl;
        std::cout << "来源端口: " << from_port << std::endl;
        std::cout << "来源端口协议: " << from_port_protocol << std::endl;
        std::cout << "来源端口是范围: " << (from_is_port_range ? "是" : "否") << std::endl;
        std::cout << "目标IP: " << to_ip << std::endl;
        std::cout << "目标端口: " << to_port << std::endl;
        std::cout << "目标端口协议: " << to_port_protocol << std::endl;
        std::cout << "目标端口是范围: " << (to_is_port_range ? "是" : "否") << std::endl;
        std::cout << "IPv6规则: " << (is_v6 ? "是" : "否") << std::endl;
        std::cout << "额外信息: " << extra_info << std::endl;
        std::cout << "----------------------------" << std::endl;
    }
};

