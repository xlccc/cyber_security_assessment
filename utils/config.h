#ifndef CONFIG_H
#define CONFIG_H


// 上传POC文件的临时文件名
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";


// POC代码文件保存路径
const std::string POC_DIRECTORY = "/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/scan/scripts/";


//插件化扫描相关参数
constexpr int max_threads = 20; // 最大线程数
constexpr int task_timeout_seconds = 5; // 任务超时时间

//线程个数
const int threadCount = 4;

#endif // CONFIG_H