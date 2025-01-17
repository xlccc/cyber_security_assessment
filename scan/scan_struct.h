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
    std::string vulnType;  //漏洞类型
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
    std::string softwareType;   //软件类型（数据库，中间件， web应用）
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
    std::string os_type; //操作系统类型
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

    // 定义 < 操作符，仅基于 url, ip 和 port 排序，加入 vuln 的比较以区分不同任务
    bool operator<(const POCTask& other) const {
        return std::tie(url, ip, port, vuln) < std::tie(other.url, other.ip, other.port, other.vuln);
    }
};

// 定义漏洞数据结构
struct VulnerabilityInfo {
    std::string vuln_id;
    std::string vuln_name;
    std::string cvss;
    std::string summary;
    std::string vulExist;
    std::string softwareType;//类型（操作系统,数据库，中间件， web应用)
    std::string vulType; //漏洞类型

    
};

struct PortVulnerabilityInfo : VulnerabilityInfo {
    int port_id;
    std::string service_name; //软件资产的服务名称
};

// IP对应的所有漏洞信息
struct IpVulnerabilities {
    std::string ip;
    std::vector<VulnerabilityInfo> host_vulnerabilities;
    std::vector<PortVulnerabilityInfo> port_vulnerabilities;
};


#endif