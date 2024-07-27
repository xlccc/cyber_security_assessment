#pragma once
#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include<vector>
#include<string>

// 定义数据库文件路径的全局常量
//const char* const DB_PATH = "./database/poc.db";
const char* const DB_PATH = "/root/.vs/cyber_seproject2/8cf44de5-c72a-44b7-b30d-6effcd345537/src/database/poc.db";
const char* const DB_PATH = "/home/c/.vs/网络安全测试平台-新-linux-2.0-CMake/26bbbde1-7e92-4836-b250-1203a21a6665/src/database/poc.db";


//支持的poc脚本类型
extern std::vector<std::string> supported_extensions;

// 上传POC文件所需要的固定的临时文件名
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";


#endif