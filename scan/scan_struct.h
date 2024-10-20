#ifndef SCAN_STRUCT_H
#define SCAN_STRUCT_H

#include <string>
#include <map>
#include <vector>
#include<unordered_map>
#include <chrono> 
#include<set>

//漏洞条目（修改）
struct Vuln
{
    std::string Vuln_id;     //CVE编号或其他编号（修改）
    std::string vul_name;   //漏洞名称
    std::string script;     //插件名称
    std::string CVSS;       //严重程度
    std::string summary;    //漏洞描述（英文）
    bool        pocExist = false;   //对应CVE编号的POC是否存在于POC库中
    bool        ifCheck =  false;   //是否打算poc验证
    std::string vulExist = "未验证";    //是否存在该漏洞，分为三种：存在、不存在、未验证



    // 重载 == 运算符
    bool operator==(const Vuln& other) const {
        if (!Vuln_id.empty() && !other.Vuln_id.empty()) {
            return Vuln_id == other.Vuln_id;
        }
        else {
            return vul_name == other.vul_name;
        }
    }

    //Vuln_id和vul_name组成唯一键
    // 重载 < 运算符 (用于在 std::set 中排序)
    bool operator<(const Vuln& other) const {
        if (!Vuln_id.empty() && !other.Vuln_id.empty()) {
            return Vuln_id < other.Vuln_id;
        }
        else {
            return vul_name < other.vul_name;
        }
    }
};

//针对端口的漏洞扫描的每一条的结果
struct ScanResult {
    std::string portId;     //端口号
    std::string protocol;   //协议
    std::string status;     //开放状态
    std::string service_name;    //服务或协议名称，通常包含应用层协议或服务类型，如"http", "https"。
    std::string product;    //应用名称，更加准确，如Apache httpd等软件名称（新增）
    std::string version;    //版本
    std::map<std::string, std::vector<Vuln>> cpes; //服务的cpes与潜在CVEs对应信息
    std::set<Vuln> vuln_result; //存放漏洞扫描结果（新增）
    bool is_merged = false; // 标识是否合并两种漏洞扫描方法的结果 （新增）
};

//针对主机、操作系统的漏洞扫描每条结果
struct ScanHostResult {
    std::string url;        //url（待补充）
    std::string ip;         //ip
    std::set<std::string> os_list;       //目标系统的通用操作系统类别。（新增）
    std::vector<std::string> os_matches;     //操作系统版本
    std::map<std::string, std::vector<Vuln>> cpes; //操作系统的cpes与潜在CVEs对应信息
    std::vector<ScanResult> ports;  //端口扫描结果
    std::string scan_time;// 扫描时间
    std::set<Vuln> vuln_result; //存放操作系统的漏洞扫描结果（新增）
    bool is_merged; // 标识是否合并两种漏洞扫描方法的结果 （新增）
    
};

// 历史扫描数据存储（用于增量扫描）
struct HistoricalScanData {
    std::unordered_map<std::string, ScanHostResult> data; // 使用 IP 作为键
};

struct POCTask {
    std::string url;
    std::string ip;
    std::string port;
    Vuln vuln;

    // 定义 < 操作符，仅基于 url, ip 和 port 排序
    bool operator<(const POCTask& other) const {
        return std::tie(url, ip, port) < std::tie(other.url, other.ip, other.port);
    }
};

#endif