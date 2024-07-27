#pragma once
#include<string>

struct POC{
    int id;                    //id序号，唯一，由数据库中的id序号所定
    std::string cve_id;         //CVE编号
    std::string vul_name;       //漏洞名称（补充）
    std::string type;           //漏洞类型
    std::string description;    //漏洞描述
    std::string script_type;    //POC脚本类型（可包括python、c、c++、yaml。目前只支持python脚本）   
    std::string script;         //插件名称
    std::string timestamp;      // 添加时间，格式为"YYYY-MM-DD HH:MM:SS"
};