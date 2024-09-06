#pragma once
// utils.h
#ifndef UTILS_H
#define UTILS_H
#include <Python.h>
#include <string>
#include<chrono>    //用于获取当前系统时间和处理时间相关的操作。
#include<ctime>     //用于将时间转换为本地时间并格式化时间字符串。
#include<sstream>   //用于使用字符串流构造格式化的时间字符串。
#include<iomanip>   //用于使用std::put_time进行时间的格式化。
#include <unicode/unistr.h>  // ICU header
#include"database/db_config.h"
#include<algorithm>
#include <regex>
#include <uchardet/uchardet.h>
#include <iconv.h>
#include<sys/stat.h>

//获取当前时间
std::string getCurrentTimestamp(int choice = 1);
//GBK转UTF-8编码
std::string convertToUTF8(const std::string& input, const std::string& fromEncoding);

//转换编码
std::string convertEncoding(const std::string& input, const char* fromEncoding, const char* toEncoding);

//自动识别编码转utf-8
std::string autoConvertToUTF8(const std::string& input);

// Function to execute a command and get the output
std::string exec(const char* cmd);

// Function to extract login information from hydra output

std::string extract_login_info(const std::string& output);

bool isValidPassword(const std::string& password);

//判断上传的POC是否为平台支持的格式
bool is_supported_extension(const std::string& filename);

//去掉文件名后缀
std::string removeExtension(const std::string& filename);

//// 初始化Python解释器
void initializePython();

//// 终止Python解释器
void finalizePython();


enum class PasswordStrength {
    WEAK,
    MEDIUM,
    STRONG,
    INVALID
};

const std::regex WEAK_PATTERN("^(\\d{6,18}|[a-z]{6,18}|[A-Z]{6,18})$");
const std::regex MEDIUM_PATTERN("^(?=.*[0-9])(?=.*[a-zA-Z]).{6,18}$|^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{6,18}$|^(?=.*[0-9])(?=.*[^a-zA-Z0-9\\s]).{6,18}$|^(?=.*[a-z])(?=.*[^a-zA-Z0-9\\s]).{6,18}$|^(?=.*[A-Z])(?=.*[^a-zA-Z0-9\\s]).{6,18}$");
const std::regex STRONG_PATTERN("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[^\\w\\s]).{6,18}$");

PasswordStrength checkPasswordStrength(const std::string& password);
std::string passwordStrengthToString(PasswordStrength strength);

// 判断路径是否为目录
bool is_directory(const std::string& path);



#endif // UTILS_H