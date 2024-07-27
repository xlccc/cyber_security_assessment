#pragma once
#include <string>
#include <vector>
#include <cpprest/details/basic_types.h> // 引入 utility::string_t

// 新的事件结构体，使用 utility::string_t
struct event_t {
    utility::string_t description; // 待检查项
    utility::string_t basis; // 判定依据
    utility::string_t command; // 待检查口令
    utility::string_t result; // 待检查的结果
    utility::string_t IsComply; // 返回 "true" 或 "false"
    utility::string_t recommend; // 建议
};

//目标主机相关信息
struct ServerInfo_t {
    utility::string_t hostname; //目标主机名
    utility::string_t arch; // 目标主机的架构
    utility::string_t cpu; //目标主机cpu信息
    utility::string_t cpuPhysical; //目标主机物理cpu个数
    utility::string_t cpuCore; //目标主机物理CPU核心数
    utility::string_t free; //目标主机空闲内存
    utility::string_t ProductName; //硬件型号
    utility::string_t version;  //目标主机版本信息
    utility::string_t isInternet; // 联网检测
};