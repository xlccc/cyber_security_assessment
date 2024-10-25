#pragma once
#include<string>

struct POC{
    int id;                    //id序号，唯一，由数据库中的id序号所定
    std::string vuln_id;         //CVE编号或其他编号
    std::string vul_name;       //漏洞名称
    std::string type;           //漏洞类型
    std::string description;    //漏洞描述
    std::string affected_infra; //受影响的基础设施（操作系统或软件或协议、非空）(新增）
    std::string script_type;    //POC脚本类型（可包括python、c、c++、yaml。目前只支持python脚本）   
    std::string script;         //插件名称
    std::string timestamp;      // 添加时间，格式为"YYYY-MM-DD HH:MM:SS"

    //（未使用）
    // 重载 == 运算符，用于判断是否为相同 POC
    bool operator==(const POC& other) const {
        if (!vuln_id.empty() && !other.vuln_id.empty()) {
            return vuln_id == other.vuln_id;
        }
        else {
            return vul_name == other.vul_name;
        }
    }
};