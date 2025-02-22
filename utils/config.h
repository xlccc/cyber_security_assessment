#ifndef CONFIG_H
#define CONFIG_H


// �ϴ�POC�ļ�����Ҫ�Ĺ̶�����ʱ�ļ���
const std::string TEMP_FILENAME = "/tmp/uploaded_body_temp";


// POC代码文件保存路径
const std::string POC_DIRECTORY = "/root/.vs/cyber_seproject2/8cf44de5-c72a-44b7-b30d-6effcd345537/src/scan/scripts/";


//�����ɨ����ز���
constexpr int max_threads = 20; // ����߳���
constexpr int task_timeout_seconds = 5; // ����ʱʱ��

// POC代码文件保存路径
const std::string POC_DIRECTORY = "/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/scan/scripts/";

//插件化扫描相关参数
constexpr int max_threads = 20; // 最大线程数
constexpr int task_timeout_seconds = 5; // 任务超时时间

//线程个数
const int threadCount = 4;

#endif // CONFIG_H