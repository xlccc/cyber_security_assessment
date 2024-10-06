#include"poc_check.h"

//搜索POC是否存在、并加载POC插件路径
void searchPOCs(ScanHostResult& hostResult, DatabaseManager& dbManager) {
    
    // 搜索操作系统相关的POC
    for (auto& cpe : hostResult.cpes) {
        for (auto& cve : cpe.second) {
            auto pocRecords = dbManager.searchDataByCVE(cve.CVE_id);
            if (!pocRecords.empty()) {
                cve.vul_name = pocRecords[0].vul_name;

                if (!pocRecords[0].script.empty())
                {
                    cve.pocExist = true;
                    cve.script = pocRecords[0].script; // 将 script 字段更新为数据库中的相应值
                }
            }
        }
    }

    // 搜索端口相关的POC
    for (auto& port : hostResult.ports) {
        for (auto& cpe : port.cpes) {
            for (auto& cve : cpe.second) {
                auto pocRecords = dbManager.searchDataByCVE(cve.CVE_id);
                if (!pocRecords.empty()) {
                    cve.vul_name = pocRecords[0].vul_name;
                    
                    if (!pocRecords[0].script.empty())
                    {
                        cve.pocExist = true;
                        cve.script = pocRecords[0].script; // 将 script 字段更新为数据库中的相应值
                    }
                }
            }
        }
    }
}

//执行选中的POC脚本进行漏洞验证
void verifyPOCs(std::vector<ScanHostResult>& scanHostResults) {
    //std::cout << "共有主机数：" << scanHostResults.size() << std::endl;


    for (auto& hostResult : scanHostResults) {

        std::cout << "------扫描操作系统漏洞-----" << std::endl;
        // 操作系统级别漏洞进行POC验证
        for (auto& cpeEntry : hostResult.cpes) {
            for (auto& cve : cpeEntry.second) {
                if (cve.pocExist && cve.ifCheck && cve.vulExist == "未验证") {
                    std::string result = runPythonWithOutput(cve.script, hostResult.url, hostResult.ip, 0);
                    // 检查result中是否包含[!]来判断漏洞是否存在
                    if (result.find("[!]") != std::string::npos) {
                        cve.vulExist = "存在";
                    }
                    else {
                        cve.vulExist = "不存在";
                    }
                }
            }
        }
        std::cout << "------扫描端口漏洞-----" << std::endl;
        // 端口级别漏洞进行POC验证
        for (auto& portResult : hostResult.ports) {
            for (auto& cpeEntry : portResult.cpes) {
                for (auto& cve : cpeEntry.second) {
                    //std::cout << "cve_id :  " << cve.CVE_id << std::endl << "script:  " << cve.script << std::endl;
                    if (cve.pocExist && cve.ifCheck) {

                        //测试
                        std::cout << "POC脚本：" << cve.script << std::endl;

                        std::string result = runPythonWithOutput(cve.script, hostResult.url, hostResult.ip, std::stoi(portResult.portId));

                        std::cout << result << std::endl;
                        // 检查result中是否包含[!]来判断漏洞是否存在
                        if (result.find("[!]") != std::string::npos) {
                            cve.vulExist = "存在";
                        }
                        else if (result.find("[SAFE]") != std::string::npos) {
                            cve.vulExist = "不存在";
                        }
                        else
                        {
                            cve.vulExist = "未验证";
                        }
                    }
                }
            }
        }
    }
}