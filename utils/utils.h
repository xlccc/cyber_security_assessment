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

std::string getCurrentTimestamp();

std::string convertToUTF8(const std::string& input, const std::string& fromEncoding);

#endif // UTILS_H