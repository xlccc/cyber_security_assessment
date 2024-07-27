#ifndef SCAN_STRUCT_H
#define SCAN_STRUCT_H

#include <string>
#include <map>
#include <vector>

//CVE条目
struct CVE
{
    std::string CVE_id;     //CVE编号
    std::string vul_name;   //漏洞名称（补充）
    std::string script;     //插件名称（补充）
    std::string CVSS;       //严重程度
    bool        pocExist = false;   //对应CVE编号的POC是否存在于POC库中
    bool        ifCheck =  false;   //是否打算poc验证（补充） 
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
    std::string url;        //url（补充）
    std::string ip;         //ip
    std::vector<std::string> os_matches;     //操作系统版本（补充）
    std::map<std::string, std::vector<CVE>> cpes; //操作系统的cpes与潜在CVEs对应信息
    std::vector<ScanResult> ports;  //端口扫描结果
};

#endif