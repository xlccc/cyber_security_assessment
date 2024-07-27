#pragma once
#include<vector>
#include<string>
using namespace std;
struct event {
	string description; //待检查项
	string basis;//判定依据
	string command;//待检查口令
	string result;//待检查的结果
	string IsComply;//返回true还是false
	string recommend; //建议
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
    string isInternet; // 联网检测
};
