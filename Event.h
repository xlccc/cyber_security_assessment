#pragma once
#include<vector>
#include<string>
using namespace std;

struct event {
	string description; //待检查项
	string basis;//判定依据
	string command;//待检查口令
	string result;//待检查的结果
    string IsComply = "false";//返回true还是false（旧版）
	string recommend; //建议
    string importantLevel;// 重要程度，分为1，2，3
	int item_id; //检查项id
};
struct scoreMeasure {
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
