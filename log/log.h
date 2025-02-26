#pragma once
#ifndef LOG_H
#define LOG_H

#include <experimental/filesystem> // C++14 ��ʵ��������
#include <iostream>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <spdlog/sinks/rotating_file_sink.h>
namespace fs = std::experimental::filesystem;

//ȫ�־�̬�����������ļ�����ֱ�ӷ��ʡ�
extern std::shared_ptr<spdlog::logger> system_logger;
extern std::shared_ptr<spdlog::logger> user_logger;
extern std::shared_ptr<spdlog::logger> console;

// ��ȡ��־·��
std::string get_log_path(const std::string& log_type);

//��ʼ����־ϵͳ
void init_logs();


#endif // LOG_H


