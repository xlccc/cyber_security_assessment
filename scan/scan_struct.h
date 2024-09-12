#ifndef SCAN_STRUCT_H
#define SCAN_STRUCT_H

#include <string>
#include <map>
#include <vector>
#include<unordered_map>
#include <chrono> 

//CVE条目
struct CVE
{
    std::string CVE_id;     //CVE编号
    std::string vul_name;   //漏洞名称
    std::string script;     //插件名称
    std::string CVSS;       //严重程度
    std::string summary;    //漏洞描述（英文）
    bool        pocExist = false;   //对应CVE编号的POC是否存在于POC库中
    bool        ifCheck =  false;   //是否打算poc验证
    std::string vulExist = "未验证";    //是否存在该漏洞，分为三种：存在、不存在、未验证
};

//针对端口的漏洞扫描的每一条的结果
struct ScanResult {
    std::string portId;     //端口号
    std::string protocol;   //协议
    std::string status;     //开放状态
    std::string service_name;    //服务
    std::string version;    //版本
    std::map<std::string, std::vector<CVE>> cpes; //服务的cpes与潜在CVEs对应信息
};

//针对主机、操作系统的漏洞扫描每条结果
struct ScanHostResult {
    std::string url;        //url（待补充）
    std::string ip;         //ip
    std::vector<std::string> os_matches;     //操作系统版本
    std::map<std::string, std::vector<CVE>> cpes; //操作系统的cpes与潜在CVEs对应信息
    std::vector<ScanResult> ports;  //端口扫描结果
    std::string scan_time;// 新增扫描时间成员
};

// 历史扫描数据存储（用于增量扫描）
struct HistoricalScanData {
    std::unordered_map<std::string, ScanHostResult> data; // 使用 IP 作为键
};


#endif