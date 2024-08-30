#pragma once
#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include<vector>
#include<string>

// 定义数据库文件路径的全局常量
//const char* const DB_PATH = "./database/poc.db";
//const char* const DB_PATH = "/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/database/poc.db";
const char* const DB_PATH = "/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/database/poc.db";


//支持的poc脚本类型
extern std::vector<std::string> supported_extensions;

// 上传POC文件所需要的固定的临时文件名
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";


#endif#pragma once
