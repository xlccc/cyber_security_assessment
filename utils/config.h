#include <string>
#ifndef CONFIG_H
#define CONFIG_H


// 上传POC文件的临时文件名
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";

// POC代码文件保存路径
const std::string POC_DIRECTORY = "/home/r/.vs/c-new/10bab9bf-c3d9-4bcf-8536-de18e3a412fa/src/scan/scripts/";
//基线检测脚本路径
const std::string Win_REMOTEPATH = "/home/r/.vs/c-new/10bab9bf-c3d9-4bcf-8536-de18e3a412fa/src/baslinescripts/";

//插件化扫描相关参数
constexpr int max_threads = 20; // 最大线程数
constexpr int task_timeout_seconds = 5; // 任务超时时间

//线程个数
const int threadCount = 4;

#include <string>

#endif // CONFIG_H