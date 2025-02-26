#pragma once
#ifndef LOG_H
#define LOG_H

#include <experimental/filesystem> // C++14 的实验性特性
#include <iostream>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <spdlog/sinks/rotating_file_sink.h>
namespace fs = std::experimental::filesystem;

//全局静态变量，所有文件可以直接访问。
extern std::shared_ptr<spdlog::logger> system_logger;
extern std::shared_ptr<spdlog::logger> user_logger;
extern std::shared_ptr<spdlog::logger> console;

// 获取日志路径
std::string get_log_path(const std::string& log_type);

//初始化日志系统
void init_logs();


#endif // LOG_H


