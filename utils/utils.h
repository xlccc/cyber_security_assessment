#pragma once
// utils.h
#ifndef UTILS_H
#define UTILS_H
#include <arpa/inet.h>
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
#include <unordered_map>
#include <iconv.h>
#include<sys/stat.h>
#include <string>
#include <random>
#include <fstream>
#include<iostream>
#include <signal.h>  // 用于 SIGTERM, SIGKILL 和 kill 函数
#include <unistd.h>  // 用于 usleep 函数和 pid_t 类型
#include"CommonDefs.h"    //配置文件
#include"../Event.h"
extern PyObject* global_importlib; // 仅声明，不定义
extern PyObject* global_io;         // 仅声明，不定义

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

std::string exec_hydra(const char* cmd);
// Function to extract login information from hydra output

std::string extract_login_info(const std::string& output);

bool isValidPassword(const std::string& password);

//判断上传的POC是否为平台支持的格式
bool is_supported_extension(const std::string& filename);

//去掉文件名后缀
std::string removeExtension(const std::string& filename);

//// 初始化Python解释器
void initializePython();

// 转换字符串为小写
std::string toLower(const std::string& str);
// 匹配服务类型
std::string matchServiceType(const std::string& serviceName, const std::unordered_map<std::string, std::vector<std::string>>& rules);

//匹配漏洞类型
std::string matchVulnType(const std::string& vulnSummary, const std::unordered_map<std::string, std::vector<std::string>>& rules);
// 终止Python解释器
void finalizePython();

// 检查字符串是否是括号内容
bool isParenthesisContent(const std::string& str);

// 从括号中提取内容
std::string extractFromParenthesis(const std::string& str);

// 解析端口字符串
std::tuple<std::string, std::string, bool> parsePortString(const std::string& portStr);

// 解析UFW规则
std::vector<UfwRule> parseUfwRules(const std::string& rulesStr);

// 从文件读取UFW状态
std::string readUfwStatusFromFile(const std::string& filePath);

// 从字符串解析UFW规则
std::vector<UfwRule> parseUfwRulesFromString(const std::string& str);

std::string filterNumberedRules(const std::string& statusOutput);

//判断子网包含的情况
bool isNetworkContained(const std::string& networkA, const std::string& networkB);

// 判断端口范围A是否包含端口范围B
bool isPortRangeContained(const std::string& portRangeA, const std::string& portRangeB);

// 判断规则A是否包含规则B（B是否是冗余的）
bool isRuleContained(const UfwRule& ruleA, const UfwRule& ruleB);

// 查找所有冗余规则（被其他规则包含的规则）
std::vector<UfwRule> findRedundantRules(const std::vector<UfwRule>& rules);
// 打印冗余规则及包含它们的规则
void printRedundantRules(const std::vector<UfwRule>& rules);
enum class PasswordStrength {
    WEAK,
    MEDIUM,
    STRONG,
    INVALID
};

const std::regex WEAK_PATTERN("^(\\d{6,18}|[a-z]{6,18}|[A-Z]{6,18})$");
const std::regex MEDIUM_PATTERN("^(?=.*[0-9])(?=.*[a-zA-Z]).{6,18}$|^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{6,18}$|^(?=.*[0-9])(?=.*[^a-zA-Z0-9\\s]).{6,18}$|^(?=.*[a-z])(?=.*[^a-zA-Z0-9\\s]).{6,18}$|^(?=.*[A-Z])(?=.*[^a-zA-Z0-9\\s]).{6,18}$");
const std::regex STRONG_PATTERN("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[^\\w\\s]).{6,18}$");
// 定义类型与关键字的映射规则（使用哈希表）
extern std::unordered_map<std::string, std::vector<std::string>> rules;
extern std::unordered_map<std::string, std::vector<std::string>> vulnTypes;
PasswordStrength checkPasswordStrength(const std::string& password);
std::string passwordStrengthToString(PasswordStrength strength);

//// 判断规则是否包含所有必要参数
bool isRuleComplete(const UfwRule& rule);
// 判断路径是否为目录
bool is_directory(const std::string& path);

// 生成随机字符串
inline std::string generate_random_string(size_t length = 10) {
    const std::string chars =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    return result;
}

// 保存上传的文件
inline void save_uploaded_file(const std::string& filepath, const std::vector<unsigned char>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create file: " + filepath);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();

#ifdef __unix__
    chmod(filepath.c_str(), S_IRUSR | S_IWUSR);
#endif
}

// 删除文件
inline bool remove_file(const std::string& filepath) {
    try {
        if (std::remove(filepath.c_str()) != 0) {
            std::cerr << "Error deleting file: " << filepath << std::endl;
            return false;
        }
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception when deleting file: " << e.what() << std::endl;
        return false;
    }
}

#endif // UTILS_H