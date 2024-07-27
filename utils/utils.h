#pragma once
// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <string>
#include<chrono>    //用于获取当前系统时间和处理时间相关的操作。
#include<ctime>     //用于将时间转换为本地时间并格式化时间字符串。
#include<sstream>   //用于使用字符串流构造格式化的时间字符串。
#include<iomanip>   //用于使用std::put_time进行时间的格式化。
#include <unicode/unistr.h>  // ICU header
#include"database/db_config.h"
#include<algorithm>
#include <regex>

//获取当前时间
std::string getCurrentTimestamp();

//GBK转UTF-8编码
std::string convertToUTF8(const std::string& input, const std::string& fromEncoding);

// Function to execute a command and get the output
std::string exec(const char* cmd);

// Function to extract login information from hydra output

std::string extract_login_info(const std::string& output);

bool isValidPassword(const std::string& password);

//判断上传的POC是否为平台支持的格式
bool is_supported_extension(const std::string& filename);

//去掉文件名后缀
std::string removeExtension(const std::string& filename);

#endif // UTILS_H