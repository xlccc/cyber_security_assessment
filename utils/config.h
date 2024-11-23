#pragma once

// 上传POC文件所需要的固定的临时文件名
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";


//插件化扫描相关参数
constexpr int max_threads = 20; // 最大线程数
constexpr int task_timeout_seconds = 5; // 任务超时时间
const std::string POC_DIRECTORY = "/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/scan/scripts/";
