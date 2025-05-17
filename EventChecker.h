#pragma once
#include "Event.h"
#include "Command_Excute.h"
#include <libssh/libssh.h>
#include <memory>
#include <future>
#include "ThreadPool.h"
#include "SSHConnectionPool.h"
#include <map>
#include <algorithm>   // std::remove_if
#include <cctype>      // ::isspace
#include <regex>
#include <sstream>
#include"utils/utils.h"
class EventChecker {
public:
    EventChecker(size_t threadCount, SSHConnectionPool& pool)
        : threadPool(threadCount), sshPool(pool) {
        initializeCheckFunctions();
    }

    // 检查三级等保合规性
    void checkLevel3Events(std::vector<event>& events, const std::vector<int>& ids = {}) {
        std::vector<std::future<event>> futures;
        if (ids.empty()) {
            // 如果没有指定 ID，执行所有三级等保检查
            for (const auto& pair : level3ComplianceFunctions) {
                futures.push_back(threadPool.enqueue(pair.second));
            }
        }
        else {
            // 只执行指定 ID 的三级等保检查
            for (int id : ids) {
                auto it = level3ComplianceFunctions.find(id);
                if (it != level3ComplianceFunctions.end()) {
                    futures.push_back(threadPool.enqueue(it->second));
                }
                else {
                    std::cerr << "Warning: Level 3 Compliance Check ID " << id << " not found" << std::endl;
                }
            }
        }

        // 收集结果
        for (auto& future : futures) {
            event eventResult = future.get();
            events.push_back(eventResult);
        }
    }

    void checkEvents(std::vector<event>& events, const std::vector<int>& ids = {}) {
        std::vector<std::future<event>> futures;

        if (ids.empty()) {
            // 如果没有指定 ID，执行所有检查
            for (const auto& pair : checkFunctions) {
                futures.push_back(threadPool.enqueue(pair.second));
            }
        }
        else {
            // 只执行指定 ID 的检查
            for (int id : ids) {
                auto it = checkFunctions.find(id);
                if (it != checkFunctions.end()) {
                    futures.push_back(threadPool.enqueue(it->second));
                }
                else {
                    std::cerr << "Warning: Check ID " << id << " not found" << std::endl;
                }
            }
        }

        

        // 收集结果
        for (auto& future : futures) {
			event eventtest = future.get();
            events.push_back(eventtest);
        }

    }

private:
    ThreadPool threadPool;
    SSHConnectionPool& sshPool;
    string temp;
    string is_install;
    string rpm_command = "rpm -qa | grep -E 'vsftpd|pure-ftpd' &> /dev/null && (rpm -qa | grep -q 'vsftpd' && echo \"vsftpd\") || (rpm -qa | grep -q 'pure-ftpd' && echo \"pure-ftpd\") || echo \"Neither\"";
    string Debian_command = "dpkg -l | grep -E 'vsftpd|pure-ftpd' &> /dev/null && (dpkg -l | grep -q 'vsftpd' && echo \"vsftpd\") || (dpkg -l | grep -q 'pure-ftpd' && echo \"pure-ftpd\") || echo \"Neither\"";
    string soft_ware;

    std::map<int, std::function<event()>> checkFunctions;

    // 三级等保检查函数映射
    std::map<int, std::function<event()>> level3ComplianceFunctions;

    void initializeCheckFunctions() {
        checkFunctions = {
            {1, [this] { event e = checkPasswordLifetime(); e.item_id = 1; e.tmp_IsComply = e.IsComply;  return e; }},
            {2, [this] { event e = checkPasswordMinLength(); e.item_id = 2; e.tmp_IsComply = e.IsComply; return e; }},
            {3, [this] { event e = checkPasswordWarnDays(); e.item_id = 3; e.tmp_IsComply = e.IsComply; return e; }},
            {4, [this] { event e = checkPasswordComplex(); e.item_id = 4; e.tmp_IsComply = e.IsComply;  return e; }},
            {5, [this] { event e = checkEmptyPassword(); e.item_id = 5; e.tmp_IsComply = e.IsComply;  return e; }},
            {6, [this] { event e = checkUID0ExceptRoot(); e.item_id = 6; e.tmp_IsComply = e.IsComply;  return e; }},
            {7, [this] { event e = checkUmaskCshrc(); e.item_id = 7; e.tmp_IsComply = e.IsComply;  return e; }},
            {8, [this] { event e = checkUmaskBashrc(); e.item_id = 8; e.tmp_IsComply = e.IsComply;  return e; }},
            {9, [this] { event e = checkUmaskProfile(); e.item_id = 9; e.tmp_IsComply = e.IsComply;  return e; }},
            {10, [this] { event e = checkModXinetd(); e.item_id = 10; e.tmp_IsComply = e.IsComply;  return e; }},
            {11, [this] { event e = checkModGroup(); e.item_id = 11; e.tmp_IsComply = e.IsComply;  return e; }},
            {12, [this] { event e = checkModShadow(); e.item_id = 12; e.tmp_IsComply = e.IsComply; return e; }},
            {13, [this] { event e = checkModServices(); e.item_id = 13; e.tmp_IsComply = e.IsComply;  return e; }},
            {14, [this] { event e = checkModSecurity(); e.item_id = 14; e.tmp_IsComply = e.IsComply;  return e; }},
            {15, [this] { event e = checkModPasswd(); e.item_id = 15; e.tmp_IsComply = e.IsComply;  return e; }},
            {16, [this] { event e = checkModRc6(); e.item_id = 16; e.tmp_IsComply = e.IsComply;  return e; }},
            {17, [this] { event e = checkModRc0(); e.item_id = 17; e.tmp_IsComply = e.IsComply;  return e; }},
            {18, [this] { event e = checkModRc1(); e.item_id = 18; e.tmp_IsComply = e.IsComply;  return e; }},
            {19, [this] { event e = checkModRc2(); e.item_id = 19; e.tmp_IsComply = e.IsComply;  return e; }},
            {20, [this] { event e = checkModEtc(); e.item_id = 20; e.tmp_IsComply = e.IsComply;  return e; }},
            {21, [this] { event e = checkModRc4(); e.item_id = 21; e.tmp_IsComply = e.IsComply;  return e; }},
            {22, [this] { event e = checkModRc5(); e.item_id = 22; e.tmp_IsComply = e.IsComply;  return e; }},
            {23, [this] { event e = checkModRc3(); e.item_id = 23; e.tmp_IsComply = e.IsComply;  return e; }},
            {24, [this] { event e = checkModInit(); e.item_id = 24; e.tmp_IsComply = e.IsComply;  return e; }},
            {25, [this] { event e = checkModTmp(); e.item_id = 25; e.tmp_IsComply = e.IsComply;  return e; }},
            {26, [this] { event e = checkModGrub(); e.item_id = 26; e.tmp_IsComply = e.IsComply;  return e; }},
            {27, [this] { event e = checkModGrubGrub(); e.item_id = 27; e.tmp_IsComply = e.IsComply;  return e; }},
            {28, [this] { event e = checkModLilo(); e.item_id = 28; e.tmp_IsComply = e.IsComply;  return e; }},
            {29, [this] { event e = checkAttributePasswd(); e.item_id = 29; e.tmp_IsComply = e.IsComply;  return e; }},
            {30, [this] { event e = checkAttributeShadow(); e.item_id = 30; e.tmp_IsComply = e.IsComply;  return e; }},
            {31, [this] { event e = checkAttributeGroup(); e.item_id = 31; e.tmp_IsComply = e.IsComply;  return e; }},
            {32, [this] { event e = checkAttributeGshadow(); e.item_id = 32; e.tmp_IsComply = e.IsComply;  return e; }},
            {33, [this] { event e = checkUmaskLogin(); e.item_id = 33; e.tmp_IsComply = e.IsComply;  return e; }},
            {34, [this] { event e = checkSshBanner(); e.item_id = 34; e.tmp_IsComply = e.IsComply;  return e; }},
            {35, [this] { event e = checkeNg(); e.item_id = 35; e.tmp_IsComply = e.IsComply;  return e; }},
            {36, [this] { event e = checkRsyslog(); e.item_id = 36; e.tmp_IsComply = e.IsComply;  return e; }},
            {37, [this] { event e = checkSyslog(); e.item_id = 37; e.tmp_IsComply = e.IsComply;  return e; }},
            {38, [this] { event e = checkSyslogNgSafe(); e.item_id = 38; e.tmp_IsComply = e.IsComply;  return e; }},
            {39, [this] { event e = checkRsyslogSafe(); e.item_id = 39; e.tmp_IsComply = e.IsComply;  return e; }},
            {40, [this] { event e = checkSyslogSafe(); e.item_id = 40; e.tmp_IsComply = e.IsComply;  return e; }},
            {41, [this] { event e = checkCron(); e.item_id = 41; e.tmp_IsComply = e.IsComply;  return e; }},
            {42, [this] { event e = checkSecure(); e.item_id = 42; e.tmp_IsComply = e.IsComply;  return e; }},
            {43, [this] { event e = checkMessage(); e.item_id = 43; e.tmp_IsComply = e.IsComply;  return e; }},
            {44, [this] { event e = checkBootLog(); e.item_id = 44; e.tmp_IsComply = e.IsComply;  return e; }},
            {45, [this] { event e = checkMail(); e.item_id = 45; e.tmp_IsComply = e.IsComply;  return e; }},
            {46, [this] { event e = checkSpooler(); e.item_id = 46; e.tmp_IsComply = e.IsComply;  return e; }},
            {47, [this] { event e = checkLocalMessages(); e.item_id = 47; e.tmp_IsComply = e.IsComply;  return e; }},
            {48, [this] { event e = checkMaillog(); e.item_id = 48; e.tmp_IsComply = e.IsComply;  return e; }},
            {49, [this] { event e = checkLast(); e.item_id = 49; e.tmp_IsComply = e.IsComply;  return e; }},
            {50, [this] { event e = checkSuLog(); e.item_id = 50; e.tmp_IsComply = e.IsComply;  return e; }},
            {51, [this] { event e = checkOpensshConfig(); e.item_id = 51; e.tmp_IsComply = e.IsComply;  return e; }},
            {52, [this] { event e = checkRunningSnmp(); e.item_id = 52; e.tmp_IsComply = e.IsComply;  return e; }},
            {53, [this] { event e = checkSnmpConfig(); e.item_id = 53; e.tmp_IsComply = e.IsComply;  return e; }},
            {54, [this] { event e = checkSshConfig(); e.item_id = 54; e.tmp_IsComply = e.IsComply;  return e; }},
            {55, [this] { event e = checkTelnetConfig(); e.item_id = 55; e.tmp_IsComply = e.IsComply;  return e; }},
            {56, [this] { event e = checkRunningFtp(); e.item_id = 56; e.tmp_IsComply = e.IsComply;  return e; }},
            {57, [this] { event e = checkFtpConfig(); e.item_id = 57; e.tmp_IsComply = e.IsComply;  return e; }},
            {58, [this] { event e = checkAnonymousFtp(); e.item_id = 58; e.tmp_IsComply = e.IsComply;  return e; }},
            {59, [this] { event e = checkCmdTimeout(); e.item_id = 59; e.tmp_IsComply = e.IsComply;  return e; }},
            {60, [this] { event e = checkPasswordBootloader(); e.item_id = 60; e.tmp_IsComply = e.IsComply;  return e; }},
            {61, [this] { event e = checkCoreDump(); e.item_id = 61; e.tmp_IsComply = e.IsComply;  return e; }},
            {62, [this] { event e = checkHistSize(); e.item_id = 62; e.tmp_IsComply = e.IsComply;  return e; }},
            {63, [this] { event e = checkGroupWheel(); e.item_id = 63; e.tmp_IsComply = e.IsComply;  return e; }},
            {64, [this] { event e = checkInterLogin(); e.item_id = 64; e.tmp_IsComply = e.IsComply;  return e; }},
            {65, [this] { event e = checkPasswordRepeatlimit(); e.item_id = 65; e.tmp_IsComply = e.IsComply;  return e; }},
            {66, [this] { event e = checkAuthFailtimes(); e.item_id = 66; e.tmp_IsComply = e.IsComply;  return e; }},
            {67, [this] { event e = checkMultiIp(); e.item_id = 67; e.tmp_IsComply = e.IsComply;  return e; }},
            {68, [this] { event e = checkLoginRemoteIp(); e.item_id = 68; e.tmp_IsComply = e.IsComply;  return e; }},
            {69, [this] { event e = checkAliasesUnnecessary(); e.item_id = 69; e.tmp_IsComply = e.IsComply;  return e; }},
            {70, [this] { event e = checkPermSuidSgid(); e.item_id = 70; e.tmp_IsComply = e.IsComply;  return e; }},
            {71, [this] { event e = checkScreenAutolock(); e.item_id = 71; e.tmp_IsComply = e.IsComply;  return e; }},
            {72, [this] { event e = checkTcpSyncookies(); e.item_id = 72; e.tmp_IsComply = e.IsComply;  return e; }},
            {73, [this] { event e = checkGroupManage(); e.item_id = 73; e.tmp_IsComply = e.IsComply;  return e; }},
            {74, [this] { event e = checkRootPathCheck(); e.item_id = 74; e.tmp_IsComply = e.IsComply;  return e; }},
            {75, [this] { event e = checkCtrlAltDelDisabled(); e.item_id = 75; e.tmp_IsComply = e.IsComply;  return e; }},
            {76, [this] { event e = checkSysTrustMechanism(); e.item_id = 76; e.tmp_IsComply = e.IsComply;  return e; }},
            {77, [this] { event e = checkDiskPartitionUsageRate(); e.item_id = 77; e.tmp_IsComply = e.IsComply;  return e; }},
            {78, [this] { event e = checkPotentialRiskFiles(); e.item_id = 78; e.tmp_IsComply = e.IsComply;  return e; }},
            {79, [this] { event e = checkUserMinPermission(); e.item_id = 79; e.tmp_IsComply = e.IsComply;  return e; }},
            {80, [this] { event e = checkPacketForwardFunc(); e.item_id = 80; e.tmp_IsComply = e.IsComply;  return e; }},
            {81, [this] { event e = checkNtpSyncStatus(); e.item_id = 81; e.tmp_IsComply = e.IsComply;  return e; }},
            {82, [this] { event e = checkNfsServer(); e.item_id = 82; e.tmp_IsComply = e.IsComply; return e; }},
            {83, [this] { event e = checkSshBanner2(); e.item_id = 83; e.tmp_IsComply = e.IsComply; return e; }},
            {84, [this] { event e = checkUploadFtp(); e.item_id = 84; e.tmp_IsComply = e.IsComply;  return e; }},
            {85, [this] { event e = checkFtpBaner(); e.item_id = 85; e.tmp_IsComply = e.IsComply;  return e; }},
            {86, [this] { event e = checkBinOwner(); e.item_id = 86; e.tmp_IsComply = e.IsComply;  return e; }},
            {87, [this] { event e = checkTelnetBanner(); e.item_id = 87; e.tmp_IsComply = e.IsComply; return e; }},
            {88, [this] { event e = checkFtpDirectory(); e.item_id = 88; e.tmp_IsComply = e.IsComply; return e; }},
            {89, [this] { event e = checkKernel_cve_2021_43267(); e.item_id = 89; e.tmp_IsComply = e.IsComply;  return e; }},
        };

        // 三级等保检查条目初始化
        level3ComplianceFunctions = {
            {1, [this] { event e = checkFirewallCompliance(); e.item_id = 1; e.tmp_IsComply = e.IsComply;  return e; }},
            {2, [this] { event e = checkFirewallRedundancy(); e.item_id = 2; e.tmp_IsComply = e.IsComply;  return e; }},
            {3, [this] { event e = checkFirewallRuleCompleteness(); e.item_id = 3; e.tmp_IsComply = e.IsComply;  return e; }},
            {4, [this] { event e = checkSessionControlCompliance(); e.item_id = 4; e.tmp_IsComply = e.IsComply;  return e; }},
            {5, [this] { event e = checkApplicationControlCompliance(); e.item_id = 5; e.tmp_IsComply = e.IsComply;  return e; }},
            {6, [this] { event e = checkIDSIPSWAFStatus(); e.item_id = 6; e.tmp_IsComply = e.IsComply;  return e; }},
            {7, [this] { event e = checkIDSIPSWAFStatus2(); e.item_id = 7; e.tmp_IsComply = e.IsComply;   return e; }},
            {8, [this] { event e = checkIDSIPSWAFStatus3(); e.item_id = 8; e.tmp_IsComply = e.IsComply;   return e; }},
            {9, [this] { event e = checkIDSIPSWAFStatus4(); e.item_id = 9; e.tmp_IsComply = e.IsComply;  return e; }},
            {10, [this] { event e = checkMalwareProtectionCompliance(); e.item_id = 10; e.tmp_IsComply = e.IsComply;  return e; }},
            {11, [this] { event e = checkSpamMailProtectionCompliance(); e.item_id = 11; e.tmp_IsComply = e.IsComply;  return e; }},
            // 可以继续添加更多三级等保检查项
        };

    }

    event checkFirewallCompliance() {
        SSHConnectionGuard guard(sshPool);//guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.2.a";
        e.importantLevel = "3";
        e.basis = "应在网络边界或区域之间根据访问控制策略设置访问控制规则，默认情况下除允许通信外受控接口拒绝所有通信";
        e.IsComply = "false";
        // 1. 检查防火墙是否开启
        std::string command = "sudo ufw status verbose";
        std::string statusOutput = execute_commands(guard.get(), command);
        if (statusOutput.find("状态：激活") == std::string::npos &&
            statusOutput.find("Status: active") == std::string::npos) {
            e.result = "防火墙未开启";
            e.recommend = "应开启防火墙";
            std::cout << "防火墙未开启" << std::endl;
            return e;
        }
        // 2. 检查默认策略是否符合要求
        // 检查入站默认策略是否为拒绝
        if (statusOutput.find("默认：deny (incoming)") == std::string::npos &&
            statusOutput.find("Default: deny (incoming)") == std::string::npos) {
            e.result = "入站默认策略不是deny";
            e.recommend = "应符合入站默认策略是deny";
            std::cout << "入站默认策略不是deny" << std::endl;
            return e;
        }

        // 检查出站默认策略是否为允许
        if (statusOutput.find("allow (outgoing)") == std::string::npos) {
            e.result = "出站默认策略不是allow";
            e.recommend = "应符合出站默认策略是allow";
            std::cout << "出站默认策略不是allow" << std::endl;
            return e;
        }

        // 检查路由默认策略是否为拒绝
        if (statusOutput.find("deny (routed)") == std::string::npos) {
            e.result = "路由默认策略不是deny";
            e.recommend = "应符合路由默认策略是deny";
            std::cout << "路由默认策略不是deny" << std::endl;
            return e;
        }

        // 3. 检查是否存在Anywhere规则
        command = "sudo ufw status numbered";
        std::string rulesOutput = execute_commands(guard.get(), command);

        // 使用正则表达式检查入站规则中是否有Anywhere
        std::regex incomingAnywherePattern("ALLOW\\s+IN\\s+Anywhere");
        std::smatch matches;
        if (std::regex_search(rulesOutput, matches, incomingAnywherePattern)) {
            e.result = "发现入站规则允许Anywhere访问，不符合白名单机制";
            e.recommend = "应符合白名单机制";
            
            std::cout << "发现入站规则允许Anywhere访问，不符合白名单机制" << std::endl;
            return e;
        }

        // 所有检查都通过
        e.result = "防火墙配置符合三级等保要求";
        e.IsComply = "true";
        return e;


    }

    event checkFirewallRedundancy() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.2.b";
        e.importantLevel = "3";
        e.basis = "应删除多余或无效的访问控制规则，优化访问控制列表，并保证访问控制规则数量最小化";
        e.IsComply = "false";

        try {
            // 获取UFW防火墙规则
            std::string ufwOutput;

            // 尝试从命令执行获取规则
            std::string command = "sudo ufw status numbered";
            ufwOutput = execute_commands(guard.get(), command);

            // 确保输出不为空
            if (ufwOutput.empty()) {
                e.result = "无法获取防火墙规则，请确保UFW已启用且有规则存在";
                e.recommend = "应开启防火墙";
                return e;
            }

            // 过滤出带编号的规则
            std::string numberedRulesStr = filterNumberedRules(ufwOutput);

            if (numberedRulesStr.empty()) {
                e.result = "未找到UFW规则，防火墙可能未启用或没有配置规则";
                e.recommend = "应开启防火墙或配置规则";
                return e;
            }

            // 解析UFW规则
            std::vector<UfwRule> rules = parseUfwRules(numberedRulesStr);

            if (rules.empty()) {
                e.result = "没有解析到任何规则，可能是解析失败或防火墙没有规则";
                e.recommend = "应开启防火墙或配置规则";
                return e;
            }

            // 查找冗余规则
            std::vector<UfwRule> redundantRules = findRedundantRules(rules);

            if (redundantRules.empty()) {
                e.result = "防火墙规则配置已优化，没有发现冗余规则";
                e.IsComply = "true";
            }
            else {
                // 构建冗余规则编号的字符串
                std::stringstream redundantInfo;
                redundantInfo << "发现 " << redundantRules.size() << " 条冗余规则，编号: ";

                for (size_t i = 0; i < redundantRules.size(); ++i) {
                    if (i > 0) redundantInfo << ", ";
                    redundantInfo << redundantRules[i].number;
                }

                // 生成删除建议命令
                std::stringstream recommendCommands;
                recommendCommands << "建议执行以下命令删除冗余规则:\n";

                // 按照从大到小的顺序删除，避免删除一条规则后编号变化导致删错规则
                std::sort(redundantRules.begin(), redundantRules.end(),
                    [](const UfwRule& a, const UfwRule& b) { return a.number > b.number; });

                for (const auto& rule : redundantRules) {
                    recommendCommands << "sudo ufw delete " << rule.number << "\n";
                }

                e.result = redundantInfo.str();
                e.recommend = recommendCommands.str();
            }

        }
        catch (const std::exception& err) {
            e.result = "检查防火墙冗余规则过程中发生错误: " + std::string(err.what());
        }

        return e;
    }

    event checkFirewallRuleCompleteness() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.2.c";
        e.importantLevel = "3";
        e.basis = "应对源地址、目的地址、源端口、目的端口和协议等进行检查，以允许/拒绝数据包进出。";
        e.IsComply = "false";
        try {
            // 获取UFW防火墙规则
            std::string ufwOutput;
            // 尝试从命令执行获取规则
            std::string command = "sudo ufw status numbered";
            ufwOutput = execute_commands(guard.get(), command);
            // 确保输出不为空
            if (ufwOutput.empty()) {
                e.result = "无法获取防火墙规则，请确保UFW已启用且有规则存在";
                e.recommend = "应开启防火墙";
                return e;
            }
            // 过滤出带编号的规则
            std::string numberedRulesStr = filterNumberedRules(ufwOutput);
            if (numberedRulesStr.empty()) {
                e.result = "未找到UFW规则，防火墙可能未启用或没有配置规则";
                e.recommend = "应开启防火墙或配置规则";
                return e;
            }
            // 解析UFW规则
            std::vector<UfwRule> rules = parseUfwRules(numberedRulesStr);
            if (rules.empty()) {
                e.result = "没有解析到任何规则，可能是解析失败或防火墙没有规则";
                e.recommend = "应配置合规的防火墙规则";
                return e;
            }

            // 检查每条规则是否包含完整参数
            std::vector<UfwRule> incompleteRules;
            for (const auto& rule : rules) {
                if (!isRuleComplete(rule)) {
                    incompleteRules.push_back(rule);
                }
            }

            if (incompleteRules.empty()) {
                e.result = "所有防火墙规则都包含完整的参数配置（源地址、目的地址、源端口、目的端口和协议）";
                e.IsComply = "true";
            }
            else {
                // 构建不完整规则编号的字符串
                std::stringstream incompleteInfo;
                incompleteInfo << "存在不合规的防火墙规则。不合规规则编号: ";
                for (size_t i = 0; i < incompleteRules.size(); ++i) {
                    if (i > 0) incompleteInfo << ", ";
                    incompleteInfo << incompleteRules[i].number;
                }

                // 生成简单的修改建议
                std::stringstream recommendStr;
                recommendStr << "建议配置包含完整参数的防火墙规则，示例命令:\n";
                recommendStr << "sudo ufw allow proto tcp from 192.168.1.0/24 port 1024:65535 to 10.0.0.1 port 22";

                e.result = incompleteInfo.str();
                e.recommend = recommendStr.str();
            }
        }
        catch (const std::exception& err) {
            e.result = "对防火墙源地址、目的地址、源端口、目的端口和协议等进行检查时发生错误 " + std::string(err.what());
        }
        return e;
    }

    event checkSessionControlCompliance() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "8.1.3.2.d";
        e.importantLevel = "3";
        e.basis = "应能根据会话状态信息为进出数据流提供明确的允许/拒绝访问能力";
        e.IsComply = "false";
        std::vector<std::string> problems;   // 存储所有问题描述
        std::vector<std::string> recommends; // 存储所有修复建议

        // 1. 防火墙服务状态检查 - 最基础的要求
        std::string fw_status = execute_commands(guard.get(), "systemctl is-active firewalld 2>/dev/null || systemctl is-active iptables 2>/dev/null || systemctl is-active nftables 2>/dev/null || echo 'inactive'");
        if (fw_status.find("active") == std::string::npos) {
            problems.emplace_back("防火墙服务未运行");
            recommends.emplace_back("启动防火墙服务：systemctl start firewalld 或 systemctl start iptables 或 systemctl start nftables");
        }

        // 2. 防火墙默认策略检查 - 核心要求：明确的拒绝能力
        std::string default_policy = execute_commands(guard.get(), "iptables -L -vn | grep policy");
        bool hasDefaultDrop = false;

        if (default_policy.find("policy DROP") != std::string::npos ||
            default_policy.find("policy REJECT") != std::string::npos) {
            hasDefaultDrop = true;
        }
        else {
            std::string nft_policy = execute_commands(guard.get(), "nft list ruleset | grep -E 'policy (drop|reject)'");
            if (!nft_policy.empty()) {
                hasDefaultDrop = true;
            }
        }

        if (!hasDefaultDrop) {
            problems.emplace_back("防火墙未配置默认拒绝策略");
            recommends.emplace_back("配置默认拒绝策略：iptables -P INPUT DROP 和 iptables -P FORWARD DROP");
        }

        // 3. 状态防火墙规则检查 - 核心要求：基于会话状态的允许能力
        bool hasStateRule = false;

        // 检查iptables状态规则
        std::string state_rules = execute_commands(guard.get(), "iptables -L -vn | grep -E 'RELATED,ESTABLISHED|ESTABLISHED,RELATED'");
        if (!state_rules.empty()) {
            hasStateRule = true;
        }
        else {
            // 检查nftables状态规则
            std::string nft_state = execute_commands(guard.get(), "nft list ruleset | grep 'ct state'");
            if (!nft_state.empty()) {
                hasStateRule = true;
            }
        }

        if (!hasStateRule) {
            problems.emplace_back("未配置基于会话状态的访问控制规则");
            recommends.emplace_back("添加规则：iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
        }

        // 4. 明确的允许规则检查 - 明确的允许能力
        std::string accept_rules = execute_commands(guard.get(), "iptables -L -vn | grep ACCEPT");
        if (accept_rules.empty()) {
            std::string nft_accept = execute_commands(guard.get(), "nft list ruleset | grep accept");
            if (nft_accept.empty()) {
                problems.emplace_back("未配置明确的允许规则");
                recommends.emplace_back("配置明确的服务允许规则，例如：iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
            }
        }

        // 5. 会话跟踪模块检查 - 状态防火墙的基础
        std::string conntrack_check = execute_commands(guard.get(), "lsmod | grep -E 'nf_conntrack|ip_conntrack'");
        if (conntrack_check.empty()) {
            problems.emplace_back("连接跟踪模块未加载");
            recommends.emplace_back("加载模块：modprobe nf_conntrack && echo 'nf_conntrack' >> /etc/modules");
        }

        // 结果合成
        if (!problems.empty()) {
            std::stringstream result;
            result << "发现" << problems.size() << "个不符合项：\n";
            for (size_t i = 0; i < problems.size(); ++i) {
                result << i + 1 << ". " << problems[i] << "\n";
            }
            e.result = result.str();
            // 拼接所有修复建议
            std::stringstream recommendStream;
            recommendStream << "建议修复操作：\n";
            for (size_t i = 0; i < recommends.size(); ++i) {
                recommendStream << i + 1 << ". " << recommends[i] << "\n";
            }
            e.recommend = recommendStream.str();
        }
        else {
            e.result = "会话状态访问控制机制符合要求";
            e.IsComply = "true";
        }
        return e;
    }

    event checkApplicationControlCompliance() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "8.1.3.2.e";
        e.importantLevel = "3";
        e.basis = "应对进出网络的数据流实现基于应用协议和应用内容的访问控制";
        e.IsComply = "false";

        std::vector<std::string> problems;    // 存储所有问题描述
        std::vector<std::string> recommends;  // 存储所有修复建议

        // 1. 检查防火墙服务是否运行
        std::string fw_status = execute_commands(guard.get(),
            "systemctl is-active firewalld 2>/dev/null || "
            "systemctl is-active iptables 2>/dev/null || "
            "systemctl is-active nftables 2>/dev/null || "
            "echo 'inactive'");

        if (fw_status.find("active") == std::string::npos) {
            problems.emplace_back("防火墙服务未运行");
            recommends.emplace_back("启动防火墙服务：systemctl start firewalld 或 systemctl start iptables");
        }

        // 2. 检查是否有基于应用协议的访问控制规则
        bool hasProtocolRules = false;

        // 检查iptables中的协议规则
        std::string port_rules = execute_commands(guard.get(),
            "iptables -L -vn | grep -E 'dpt:(21|22|25|53|80|110|143|443|993|995)'");
        if (!port_rules.empty()) {
            hasProtocolRules = true;
        }

        if (!hasProtocolRules) {
            problems.emplace_back("未配置基于应用协议的访问控制规则");
            recommends.emplace_back("添加基于协议的访问控制规则，例如：iptables -A INPUT -p tcp --dport 80 -j ACCEPT");
        }

        // 3. 检查是否有内容检测能力
        bool hasContentInspection = false;

        // 检查是否安装了应用层防火墙
        std::string app_fw_check = execute_commands(guard.get(),
            "dpkg -l | grep -E '(squid|snort|suricata)' || "
            "which squid snort suricata 2>/dev/null");

        // 过滤掉错误信息
        if (!app_fw_check.empty() && app_fw_check.find("not found") == std::string::npos) {
            hasContentInspection = true;
        }

        // 检查iptables是否有字符串匹配能力和相关规则
        std::string string_match_support = execute_commands(guard.get(),
            "iptables -m string --help 2>&1 | grep 'string match'");

        if (!string_match_support.empty()) {
            std::string l7_rules = execute_commands(guard.get(),
                "iptables -L -vn | grep -E '(string|content)'");

            if (!l7_rules.empty()) {
                hasContentInspection = true;
            }
        }

        if (!hasContentInspection) {
            problems.emplace_back("未配置基于应用内容的访问控制能力");
            if (!string_match_support.empty()) {
                recommends.emplace_back("添加基于内容的访问控制规则：iptables -A INPUT -p tcp --dport 80 -m string --string \"malicious\" --algo bm -j DROP");
            }
            else {
                recommends.emplace_back("安装应用层防火墙：apt install suricata");
            }
        }

        // 结果合成
        if (!problems.empty()) {
            std::stringstream result;
            result << "发现" << problems.size() << "个不符合项：\n";
            for (size_t i = 0; i < problems.size(); ++i) {
                result << i + 1 << ". " << problems[i] << "\n";
            }
            e.result = result.str();

            // 拼接所有修复建议
            std::stringstream recommendStream;
            recommendStream << "建议修复操作：\n";
            for (size_t i = 0; i < recommends.size(); ++i) {
                recommendStream << i + 1 << ". " << recommends[i] << "\n";
            }
            e.recommend = recommendStream.str();
        }
        else {
            e.result = "基于应用协议和应用内容的访问控制机制符合要求";
            e.IsComply = "true";
        }

        return e;
    }

    event checkIDSIPSWAFStatus() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.3.a";
        e.importantLevel = "3";
        e.basis = "应在关键网络节点处检测、防止或限制从外部发起的网络攻击行为";
        e.IsComply = "false";

        try {
            // 执行命令检查是否有IDS/IPS/WAF相关的进程
            std::vector<std::string> services = { "snort", "suricata", "fail2ban", "apache2" };
            std::vector<std::string> runningServices;

            for (const auto& service : services) {
                // 排除grep进程本身
                std::string command = "ps aux | grep -v grep | grep " + service;
                std::string output = execute_commands(guard.get(), command);

                // 检查输出是否包含实际服务进程
                if (!output.empty()) {
                    runningServices.push_back(service);
                }
            }

            // 判断哪些服务在运行
            if (runningServices.empty()) {
                e.result = "未发现任何IDS、IPS或WAF相关进程，可能没有安装或未启动相关服务。";
                e.recommend = "建议安装并启动相关的IDS/IPS/WAF工具，例如Snort、Suricata、Fail2Ban、ModSecurity等。";
            }
            else {
                // 构建运行中的服务字符串
                std::stringstream runningInfo;
                runningInfo << "以下IDS、IPS或WAF服务正在运行: ";
                for (size_t i = 0; i < runningServices.size(); ++i) {
                    if (i > 0) runningInfo << ", ";
                    runningInfo << runningServices[i];
                }
                e.result = runningInfo.str();
                e.IsComply = "true";
            }
        }
        catch (const std::exception& err) {
            e.result = "在检查IDS、IPS或WAF状态时发生错误: " + std::string(err.what());
        }

        return e;
    }

    event checkIDSIPSWAFStatus2() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.3.b";
        e.importantLevel = "3";
        e.basis = "应在关键网络节点处检测、防止或限制从内部发起的网络政击行为";
        e.IsComply = "false";

        try {
            // 执行命令检查是否有IDS/IPS/WAF相关的进程
            std::vector<std::string> services = { "snort", "suricata", "fail2ban", "apache2" };
            std::vector<std::string> runningServices;

            for (const auto& service : services) {
                // 排除grep进程本身
                std::string command = "ps aux | grep -v grep | grep " + service;
                std::string output = execute_commands(guard.get(), command);

                // 检查输出是否包含实际服务进程
                if (!output.empty()) {
                    runningServices.push_back(service);
                }
            }

            // 判断哪些服务在运行
            if (runningServices.empty()) {
                e.result = "未发现任何IDS、IPS或WAF相关进程，可能没有安装或未启动相关服务。";
                e.recommend = "建议安装并启动相关的IDS/IPS/WAF工具，例如Snort、Suricata、Fail2Ban、ModSecurity等。";
            }
            else {
                // 构建运行中的服务字符串
                std::stringstream runningInfo;
                runningInfo << "以下IDS、IPS或WAF服务正在运行: ";
                for (size_t i = 0; i < runningServices.size(); ++i) {
                    if (i > 0) runningInfo << ", ";
                    runningInfo << runningServices[i];
                }
                e.result = runningInfo.str();
                e.IsComply = "true";
            }
        }
        catch (const std::exception& err) {
            e.result = "在检查IDS、IPS或WAF状态时发生错误: " + std::string(err.what());
        }

        return e;
    }


    event checkIDSIPSWAFStatus3() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.3.c";
        e.importantLevel = "3";
        e.basis = "应采取技术措施对网络行为进行分析实现对网络攻击特别是新型网络攻击行为的分析";
        e.IsComply = "false";

        try {
            // 执行命令检查是否有IDS/IPS/WAF相关的进程
            std::vector<std::string> services = {
            "snort", "suricata", "fail2ban",
            "zeek", "bro",         // 网络回溯系统
            "ossec", "wazuh",      // 主机入侵检测/抗APT
            "clamav-daemon",       // 反病毒/反恶意软件
            "moloch", "arkime",    // 全流量捕获系统
            "elastalert", "filebeat", "auditd"  // 日志和审计
            };
            std::vector<std::string> runningServices;

            for (const auto& service : services) {
                // 排除grep进程本身
                std::string command = "ps aux | grep -v grep | grep " + service;
                std::string output = execute_commands(guard.get(), command);

                // 检查输出是否包含实际服务进程
                if (!output.empty()) {
                    runningServices.push_back(service);
                }
            }

            // 判断哪些服务在运行
            if (runningServices.empty()) {
                e.result = "未发现任何回溯系统或抗APT攻击系统等相关进程，可能没有安装或未启动相关服务。";
                e.recommend = "建议安装部署网络回溯系统，如Zeek(Bro)、Moloch(Arkime)，配置全流量捕获等。";
            }
            else {
                // 构建运行中的服务字符串
                std::stringstream runningInfo;
                runningInfo << "以下网络回溯系统服务正在运行: ";
                for (size_t i = 0; i < runningServices.size(); ++i) {
                    if (i > 0) runningInfo << ", ";
                    runningInfo << runningServices[i];
                }
                e.result = runningInfo.str();
                e.IsComply = "true";
            }
        }
        catch (const std::exception& err) {
            e.result = "在检查网络回溯系统状态时发生错误: " + std::string(err.what());
        }

        return e;
    }

    event checkIDSIPSWAFStatus4() {
        SSHConnectionGuard guard(sshPool);  // guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "8.1.3.3.d";
        e.importantLevel = "3";
        e.basis = "当检测到攻击行为时，记录攻击源IP、攻击类型、攻击目标、攻击时间，在发生严重入侵事件时应提供报警";
        e.IsComply = "false";

        try {
            // 执行命令检查是否有IDS/IPS/WAF相关的进程
            std::vector<std::string> services = {
            "snort", "suricata", "fail2ban",
            "zeek", "bro",         // 网络回溯系统
            "ossec", "wazuh",      // 主机入侵检测/抗APT
            "clamav-daemon",       // 反病毒/反恶意软件
            "moloch", "arkime",    // 全流量捕获系统
            "elastalert", "filebeat", "auditd"  // 日志和审计
            };
            std::vector<std::string> runningServices;

            for (const auto& service : services) {
                // 排除grep进程本身
                std::string command = "ps aux | grep -v grep | grep " + service;
                std::string output = execute_commands(guard.get(), command);

                // 检查输出是否包含实际服务进程
                if (!output.empty()) {
                    runningServices.push_back(service);
                }
            }

            // 判断哪些服务在运行
            if (runningServices.empty()) {
                e.result = "未发现任何发生严重入侵事件时应提供报警等相关进程，可能没有安装或未启动相关服务。";
                e.recommend = "建议安装部署告警系统。";
            }
            else {
                // 构建运行中的服务字符串
                std::stringstream runningInfo;
                runningInfo << "以下网络回溯系统服务正在运行: ";
                for (size_t i = 0; i < runningServices.size(); ++i) {
                    if (i > 0) runningInfo << ", ";
                    runningInfo << runningServices[i];
                }
                e.result = runningInfo.str();
                e.IsComply = "true";
            }
        }
        catch (const std::exception& err) {
            e.result = "在告警系统状态时发生错误: " + std::string(err.what());
        }

        return e;
    }

    event checkMalwareProtectionCompliance() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "8.1.3.4.a";
        e.importantLevel = "3";
        e.basis = "应在关键网络节点处对恶意代码进行检测和清除，并维护恶意代码防护机制的升级和更新";
        e.IsComply = "false";

        // 1. 检查是否安装了防病毒软件
        std::string command = "dpkg -l | grep -i \"clamav\\|sophos\\|rkhunter\\|chkrootkit\" || rpm -qa | grep -i \"clamav\\|sophos\\|rkhunter\\|chkrootkit\"";
        std::string installedOutput = execute_commands(guard.get(), command);

        // 检查是否安装了至少一种防病毒软件
        bool hasClamAV = (installedOutput.find("clamav") != std::string::npos);
        bool hasSophos = (installedOutput.find("sophos") != std::string::npos);
        bool hasRkhunter = (installedOutput.find("rkhunter") != std::string::npos);
        bool hasChkrootkit = (installedOutput.find("chkrootkit") != std::string::npos);

        if (!hasClamAV && !hasSophos && !hasRkhunter && !hasChkrootkit) {
            e.result = "未安装任何恶意代码防护软件";
            e.recommend = "应安装恶意代码防护软件（如ClamAV、Sophos、rkhunter或chkrootkit）";
            std::cout << "未安装任何恶意代码防护软件" << std::endl;
            return e;
        }

        // 2. 检查防病毒软件是否运行
        bool isRunning = false;
        std::string runningService = "";

        // 检查ClamAV服务
        if (hasClamAV) {
            command = "systemctl is-active --quiet clamav-daemon && echo 'active' || echo 'inactive'";
            std::string clamavStatus = execute_commands(guard.get(), command);
            if (clamavStatus.find("active") != std::string::npos) {
                isRunning = true;
                runningService = "ClamAV";
            }
        }

        // 检查Sophos服务
        if (hasSophos && !isRunning) {
            command = "ps aux | grep -i sophos | grep -v grep";
            std::string sophosStatus = execute_commands(guard.get(), command);
            if (!sophosStatus.empty()) {
                isRunning = true;
                runningService = "Sophos";
            }
        }

        // 检查rkhunter和chkrootkit（这些通常不是持续运行的服务）
        if ((hasRkhunter || hasChkrootkit) && !isRunning) {
            // 检查是否有定期扫描任务
            command = "crontab -l | grep -i \"rkhunter\\|chkrootkit\" || cat /etc/cron.*/rkhunter || cat /etc/cron.*/chkrootkit";
            std::string cronOutput = execute_commands(guard.get(), command);
            if (!cronOutput.empty()) {
                isRunning = true;
                runningService = hasRkhunter ? "rkhunter (cron)" : "chkrootkit (cron)";
            }
        }

        if (!isRunning) {
            e.result = "已安装恶意代码防护软件但未运行";
            e.recommend = "应启动恶意代码防护服务并确保其正常运行";
            std::cout << "已安装恶意代码防护软件但未运行" << std::endl;
            return e;
        }

        // 3. 检查病毒库更新
        if (hasClamAV) {
            command = "freshclam --version && systemctl is-active --quiet clamav-freshclam && echo 'update_active' || echo 'update_inactive'";
            std::string updateStatus = execute_commands(guard.get(), command);
            if (updateStatus.find("update_inactive") != std::string::npos) {
                e.result = "恶意代码防护软件病毒库更新服务未运行";
                e.recommend = "应启动病毒库自动更新服务以确保防护的有效性";
                std::cout << "恶意代码防护软件病毒库更新服务未运行" << std::endl;
                return e;
            }
        }

        // 所有检查都通过
        e.result = "恶意代码防护配置符合要求（" + runningService + "运行中）";
        e.IsComply = "true";
        return e;
    }

    event checkSpamMailProtectionCompliance() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "8.1.3.4.b";
        e.importantLevel = "3";
        e.basis = "应在关键网络节点处对垃圾邮件进行检测和防护，并维护垃圾邮件防护机制的升级和更新";
        e.IsComply = "false";

        // 1. 检查邮件服务器是否安装
        std::string command = "dpkg -l | grep -i \"postfix\\|sendmail\\|exim\\|zimbra\\|dovecot\" || rpm -qa | grep -i \"postfix\\|sendmail\\|exim\\|zimbra\\|dovecot\"";
        std::string mailServerOutput = execute_commands(guard.get(), command);

        // 如果没有邮件服务器，则不适用此检查
        if (mailServerOutput.empty()) {
            e.result = "系统未安装邮件服务器，不适用垃圾邮件防护检查";
            e.recommend = "应安装安装邮件服务器,并开启垃圾邮件的检测和防护";
            e.IsComply = "false";
            std::cout << "系统未安装邮件服务器，不适用垃圾邮件防护检查" << std::endl;
            return e;
        }

        // 2. 检查是否安装了垃圾邮件防护软件
        command = "dpkg -l | grep -i \"spamassassin\\|amavis\\|rspamd\\|mailscanner\\|postgrey\" || rpm -qa | grep -i \"spamassassin\\|amavis\\|rspamd\\|mailscanner\\|postgrey\"";
        std::string spamFilterOutput = execute_commands(guard.get(), command);

        bool hasSpamAssassin = (spamFilterOutput.find("spamassassin") != std::string::npos);
        bool hasAmavis = (spamFilterOutput.find("amavis") != std::string::npos);
        bool hasRspamd = (spamFilterOutput.find("rspamd") != std::string::npos);
        bool hasMailScanner = (spamFilterOutput.find("mailscanner") != std::string::npos);
        bool hasPostgrey = (spamFilterOutput.find("postgrey") != std::string::npos);

        if (!hasSpamAssassin && !hasAmavis && !hasRspamd && !hasMailScanner && !hasPostgrey) {
            e.result = "未安装垃圾邮件防护软件";
            e.recommend = "应安装垃圾邮件防护软件（如SpamAssassin、Amavis、rspamd等）";
            std::cout << "未安装垃圾邮件防护软件" << std::endl;
            return e;
        }

        // 3. 检查垃圾邮件防护服务是否运行
        bool isRunning = false;
        std::string runningService = "";

        // 检查SpamAssassin服务
        if (hasSpamAssassin) {
            command = "systemctl is-active --quiet spamassassin && echo 'active' || echo 'inactive'";
            std::string spamassassinStatus = execute_commands(guard.get(), command);
            if (spamassassinStatus.find("active") != std::string::npos) {
                isRunning = true;
                runningService = "SpamAssassin";
            }
            else {
                // 检查spamd进程
                command = "ps aux | grep -i spamd | grep -v grep";
                spamassassinStatus = execute_commands(guard.get(), command);
                if (!spamassassinStatus.empty()) {
                    isRunning = true;
                    runningService = "SpamAssassin (spamd)";
                }
            }
        }

        // 检查Amavis服务
        if (hasAmavis && !isRunning) {
            command = "systemctl is-active --quiet amavis && echo 'active' || echo 'inactive'";
            std::string amavisStatus = execute_commands(guard.get(), command);
            if (amavisStatus.find("active") != std::string::npos) {
                isRunning = true;
                runningService = "Amavis";
            }
        }

        // 检查rspamd服务
        if (hasRspamd && !isRunning) {
            command = "systemctl is-active --quiet rspamd && echo 'active' || echo 'inactive'";
            std::string rspamdStatus = execute_commands(guard.get(), command);
            if (rspamdStatus.find("active") != std::string::npos) {
                isRunning = true;
                runningService = "rspamd";
            }
        }

        // 检查Postgrey服务
        if (hasPostgrey && !isRunning) {
            command = "systemctl is-active --quiet postgrey && echo 'active' || echo 'inactive'";
            std::string postgreyStatus = execute_commands(guard.get(), command);
            if (postgreyStatus.find("active") != std::string::npos) {
                isRunning = true;
                runningService = "Postgrey";
            }
        }

        if (!isRunning) {
            e.result = "已安装垃圾邮件防护软件但未运行";
            e.recommend = "应启动垃圾邮件防护服务并确保其正常运行";
            std::cout << "已安装垃圾邮件防护软件但未运行" << std::endl;
            return e;
        }

        // 4. 检查邮件服务器配置中是否集成了反垃圾邮件
        command = "grep -i \"spamassassin\\|amavis\\|rspamd\\|content_filter\" /etc/postfix/main.cf";
        std::string postfixIntegration = execute_commands(guard.get(), command);

        if (postfixIntegration.empty()) {
            // 再检查master.cf
            command = "grep -i \"spamassassin\\|amavis\\|rspamd\\|content_filter\" /etc/postfix/master.cf";
            postfixIntegration = execute_commands(guard.get(), command);

            if (postfixIntegration.empty()) {
                e.result = "垃圾邮件防护软件未与邮件服务器集成";
                e.recommend = "应配置邮件服务器集成垃圾邮件防护功能";
                std::cout << "垃圾邮件防护软件未与邮件服务器集成" << std::endl;
                return e;
            }
        }

        // 5. 检查更新机制
        if (hasSpamAssassin) {
            command = "crontab -l | grep -i \"sa-update\" || cat /etc/cron.*/sa-update || systemctl is-active --quiet sa-update.timer && echo 'update_active' || echo 'update_inactive'";
            std::string updateStatus = execute_commands(guard.get(), command);
            if (updateStatus.find("update_inactive") != std::string::npos && updateStatus.find("sa-update") == std::string::npos) {
                e.result = "垃圾邮件防护规则库更新机制未配置";
                e.recommend = "应配置垃圾邮件规则库自动更新机制";
                std::cout << "垃圾邮件防护规则库更新机制未配置" << std::endl;
                return e;
            }
        }

        // 所有检查都通过
        e.result = "垃圾邮件防护配置符合要求（" + runningService + "运行中）";
        e.IsComply = "true";
        return e;
    }
    event checkPasswordLifetime() {
        SSHConnectionGuard guard(sshPool);//guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "检查口令生存周期";
        e.basis = "<=90天";
        e.command = "cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}' ";
        e.result = execute_commands(guard.get(), e.command);//guard.get() 获取 ssh_session 对象，在该对象上执行命令。
        e.recommend = "口令生存周期为不大于3个月的时间";
        e.importantLevel = "3";
		e.item_id = 1;// 设置检查项 ID
        // Rest of the implementation...
        // (Similar to original code but for a single event)
        size_t pos = e.result.find_last_not_of('\n');
        if (pos != string::npos) {

            // 从开头到最后一个非换行符的字符复制字符串
            e.result = e.result.substr(0, pos + 1);
        }
        else {
            // 如果没有找到，说明没有换行符，直接复制原始字符串
            e.result = e.result;
        }

        //将生存周期转为Int来比较
        int num = atoi(e.result.c_str());
        if (e.result.compare(""))
        {
            if (num <= 90)
            {
                e.IsComply = "true";
            }
            else {
                e.IsComply = "false";
            }
            e.result += "天";
        }
        else
        {
            e.result = "未开启";
            e.IsComply = "pending";
            e.recommend = "开启口令生存周期要求";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        
        //std::cout << "Completed check: " << e.description
            //<< " [ThreadID: " << std::this_thread::get_id() << "]\n";

        return e;
    }

    event checkPasswordMinLength() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查口令最小长度";
        e.basis = ">=8";
        // Rest of the implementation...
        e.command = "cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}' ";
        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "口令最小长度不小于8";
        e.importantLevel = "3";
		e.item_id = 2;
        int num = atoi(e.result.c_str());
        if (e.result.compare(""))
        {
            if (num >= 8)
            {
                e.IsComply = "true";

            }
            else {
                e.IsComply = "false";
            }
        }
        else
        {
            e.result = "未开启";
            e.IsComply = "pending";
            e.recommend = "开启口令最小长度要求";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        //std::cout << "Completed check: " << e.description
          //  << " [ThreadID: " << std::this_thread::get_id() << "]\n";
        return e;
    }

    // Implement other check methods similarly...
    event checkPasswordWarnDays() {
        SSHConnectionGuard guard(sshPool);
        event e;

        e.description = "检查口令过期前警告天数";
        e.basis = ">=30天";
        e.command = "cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#| awk '{print $2}' ";
        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "口令过期前应至少提前30天警告";
        e.importantLevel = "3";
		e.item_id = 3;
        int num = atoi(e.result.c_str());
        if (e.result.compare(""))
        {
            if (num >= 8)
            {
                e.IsComply = "true";
            }
            else {
                e.IsComply = "false";
            }
            e.result += "天";

        }
        else
        {
            e.result = "未开启";
            e.IsComply = "pending";
            e.recommend = "开启口令过期前警告天数要求";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    event checkPasswordComplex() {
        SSHConnectionGuard guard(sshPool);
        event e;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        string fileIsExist;
        bool findFile = false;

        e.description = "检查设备密码复杂度策略";
        e.basis = "至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
        e.recommend = "密码至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
        e.importantLevel = "3";
		e.item_id = 4;
        //此部分要求不一，检查/etc/pam.d/system-auth和/etc/security/pwquality.conf
        //先检查/etc/pam.d/system-auth
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        fileIsExist = "cat /etc/pam.d/system-auth 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            //e.command = "cat /etc/pam.d/system-auth | grep password | grep requisite";

            //dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数
            string dcredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'dcredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
            string ucredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'ucredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
            string ocredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'ocredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
            string lcredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'lcredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";

            dcredit = execute_commands(guard.get(), dcredit);
            ucredit = execute_commands(guard.get(), ucredit);
            ocredit = execute_commands(guard.get(), ocredit);
            lcredit = execute_commands(guard.get(), lcredit);
            //e.result = execute_commands(guard.get(), e.command);
            if (dcredit.compare("") && ucredit.compare("") && ocredit.compare("") && lcredit.compare(""))
            {
                int num1 = atoi(dcredit.c_str());
                int num2 = atoi(ucredit.c_str());
                int num3 = atoi(ocredit.c_str());
                int num4 = atoi(lcredit.c_str());
                if (num1 <= -1 && num2 <= -1 && num3 <= -1 && num4 <= -1)
                {
                    e.result = "密码复杂度达到要求";
                    e.IsComply = "true";
                }
                else
                {
                    e.result = "密码复杂度要求过低";
                    e.recommend = "密码复杂度提高，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
                }
            }
            else
            {
                e.result = "未全部开启";
                e.recommend = "开启检查密码复杂度要求，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
            }
        }

        //检查/etc/security/pwquality.conf
        //minlen为密码字符串长度，minclass为字符类别
        if (!findFile)
        {
            fileIsExist = "cat /etc/security/pwquality.conf 2>&1 | grep cat: ";
            fileIsExist = execute_commands(guard.get(), fileIsExist);

            if (fileIsExist.compare("") == 0)
            {
                findFile = true;

                e.command = "cat /etc/security/pwquality.conf | grep minclass | grep -v ^# | awk -F ' = ' '{print $2}' | tr -d '\n'";
                e.result = execute_commands(guard.get(), e.command);

                if (e.result.compare(""))
                {
                    int num = atoi(e.result.c_str());
                    if (num >= 4)
                    {
                        e.IsComply = "true";
                        e.result = "密码复杂度达到要求";
                    }
                    else
                    {
                        e.result = "密码复杂度要求过低";
                        e.recommend = "密码复杂度提高，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
                    }
                }
                else
                {
                    e.result = "未开启";
                    e.recommend = "开启检查密码复杂度要求，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
                }
            }

        }

        if (!findFile)
        {
            //e.result = "未找到配置文件 'system-auth' 或者 'pwquality.conf'";
            e.result = "未找到配置文件";
            e.IsComply = "pending";

        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        // Implementation...
        return e;
    }

    event checkEmptyPassword() {
        SSHConnectionGuard guard(sshPool);
        event e;
        // Implementation...
        e.importantLevel = "3";
        e.description = "检查是否存在空口令账号";
        e.basis = "不存在空口令账号";
        //" "内要加"时需要转义：\"
        e.command = "cat /etc/shadow | awk -F: '($2 == \"\" ) '";
        //e.command = "cat /etc/shadow";
        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "空口令会让攻击者不需要口令进入系统，存在较大风险。应删除空口令账号或者为其添加口令";
		e.item_id = 5;

        if (e.result.compare("") == 0)
        {
            e.IsComply = "true";
            e.result = "不存在空口令账号";
        }
        else
        {
            e.result = "存在空口令账号";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        //cout << e.IsComply << endl;
        return e;
    }

    event checkUID0ExceptRoot() {
        SSHConnectionGuard guard(sshPool);
        event e;
        // Implementation...
        e.description = "检查是否设置除root之外UID为0的用户";
        e.basis = "普通用户的UID全为非0";
        e.command = "cat /etc/passwd | awk -F: '($3 == 0 ){ print $1 }'| grep -v '^root'";

        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "不可设置除了root之外，第二个具有root权限的账号。root之外的用户其UID应为0。";
        e.importantLevel = "2";
		e.item_id = 6;
        if (e.result.compare("") == 0)
        {
            e.result= "普通用户的UID全为非0";
            e.IsComply = "true";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        
        //cout << e.IsComply << endl;
        return e;
    }

    event checkUmaskCshrc() {
        SSHConnectionGuard guard(sshPool);
        event e;
        // Implementation...
        e.description = "检查/etc/csh.cshrc中的用户umask设置";
        e.basis = "=027 或 =077";
        e.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
        e.importantLevel = "2";
		e.item_id = 7;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/csh.cshrc 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            //旧版：多个输出的情况不适用
            //e.command = "cat /etc/csh.cshrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            //e.result = execute_commands(session, e.command);

            e.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/csh.cshrc)";
            std::string result_raw = execute_commands(guard.get(), e.command);
            e.result = result_raw;

            if (!result_raw.empty())
            {
                std::istringstream iss(result_raw);
                std::string line;
                bool all_good = true;
                std::vector<std::string> umask_values;

                while (std::getline(iss, line))
                {
                    // 清除空格
                    line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

                    if (!line.empty())
                    {
                        umask_values.push_back(line);

                        if (line != "027" && line != "077")
                        {
                            all_good = false;
                        }
                    }
                }

                // 格式化为 “027或077” 形式
                if (!umask_values.empty())
                {
                    e.result = umask_values[0];
                    for (size_t i = 1; i < umask_values.size(); ++i)
                    {
                        e.result += "或" + umask_values[i];
                    }
                }
                else
                {
                    e.result = "未设置";
                    all_good = false;
                }

                e.IsComply = all_good ? "true" : "false";
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启 /etc/csh.cshrc 中的用户 umask 设置，且 umask 应为027或者077";
                e.IsComply = "false";
            }
        }
        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    event checkUmaskBashrc() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/bashrc中的用户umask设置";
        e.basis = "=027 或 =077";
        e.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
        e.importantLevel = "2";
		e.item_id = 8;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/bashrc 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            //旧版:有的情况不适用
            // e.command = "/bin/cat /etc/bashrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            e.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/bashrc)";
            std::string result_raw = execute_commands(guard.get(), e.command);
            e.result = result_raw;

            //旧版:有的情况不适用
            //if (e.result.compare(""))
            //{
            //	if (e.result.compare("077") || e.result.compare("027"))
            //	{
            //		e.IsComply = "true";
            //	}
            //}
            if (!result_raw.empty())
            {
                std::istringstream iss(result_raw);
                std::string line;
                bool all_good = true;
                std::vector<std::string> umask_values;

                while (std::getline(iss, line))
                {
                    // 清理空格、换行等
                    line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

                    if (!line.empty())
                    {
                        umask_values.push_back(line);

                        if (line != "027" && line != "077")
                        {
                            all_good = false;
                        }
                    }
                }

                // 拼接结果为 "027或077" 的形式
                if (!umask_values.empty())
                {
                    e.result = umask_values[0];
                    for (size_t i = 1; i < umask_values.size(); ++i)
                    {
                        e.result += "或" + umask_values[i];
                    }
                }
                else
                {
                    e.result = "未设置";
                    all_good = false;
                }

                e.IsComply = all_good ? "true" : "false";
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启/etc/bashrc中的用户umask设置，且umask应为027或者077";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

        //std::cout << "Completed check: " << e.description
            //<< " [ThreadID: " << std::this_thread::get_id() << "]\n";
        // Implementation...
        return e;
    }

    event checkUmaskProfile() {
        SSHConnectionGuard guard(sshPool);
        event e;
        // Implementation...
        e.description = "检查/etc/profile中的用户umask设置";
        e.basis = "=027 或 =077";
        e.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
        e.importantLevel = "2";
		e.item_id = 9;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            //旧版：多种情况不适用
            //e.command = "/bin/cat /etc/profile| grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            //e.result = execute_commands(guard.get(), e.command);

            //if (e.result.compare(""))
            //{
            //	if (e.result.compare("077") || e.result.compare("027"))
            //	{
            //		e.IsComply = "true";
            //	}
            //}
            //else
            //{
            //	e.result = "未开启";
            //	e.recommend = "开启/etc/profile中的用户umask设置，且umask应为027或者077";
            //}

            e.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/profile)";
            std::string result_raw = execute_commands(guard.get(), e.command);
            e.result = result_raw;

            if (!result_raw.empty())
            {
                std::istringstream iss(result_raw);
                std::string line;
                bool all_good = true;
                std::vector<std::string> umask_values;

                while (std::getline(iss, line))
                {
                    // 去掉空格
                    line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

                    if (!line.empty())
                    {
                        umask_values.push_back(line);

                        if (line != "027" && line != "077")
                        {
                            all_good = false;
                        }
                    }
                }

                // 拼接结果为 "027或077"
                if (!umask_values.empty())
                {
                    e.result = umask_values[0];
                    for (size_t i = 1; i < umask_values.size(); ++i)
                    {
                        e.result += "或" + umask_values[i];
                    }
                }
                else
                {
                    e.result = "未设置";
                    all_good = false;
                }

                e.IsComply = all_good ? "true" : "false";
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启 /etc/profile 中的用户 umask 设置，且 umask 应为027或者077";
                e.IsComply = "false";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2检查重要目录或文件权限设置
    //3.2.1检查/etc/xinetd.conf文件权限
    event checkModXinetd() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/xinetd.conf文件权限";
        e.basis = "<=600";
        e.recommend = "/etc/xinted.conf的权限应该小于等于600";
        e.importantLevel = "2";
		e.item_id = 10;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/xineted.conf 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/xineted.conf | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 600)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.2检查/etc/group文件权限
    event checkModGroup() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/group文件权限";
        e.basis = "<=644";
        e.recommend = "/etc/group的权限应该小于等于644";
        e.importantLevel = "2";
		e.item_id = 11;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/group 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/group | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 644)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.3检查/etc/shadow文件权限
    event checkModShadow() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/shadow文件权限";
        e.basis = "<=400";
        e.recommend = "/etc/shadow的权限应该小于等于400";
        e.importantLevel = "2";
		e.item_id = 12;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/shadow 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/shadow | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 400)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.4检查/etc/services文件权限
    event checkModServices() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/services文件权限";
        e.basis = "<=644";
        e.recommend = "/etc/services的权限应该小于等于644";
        e.importantLevel = "2";
		e.item_id = 13;
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/services 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/services | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 644)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.5检查/etc/security目录权限
    event checkModSecurity() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/security目录权限";
        e.basis = "<=600";
        e.recommend = "/etc/security的权限应该小于等于600";
        e.importantLevel = "2";
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/security 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/security | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 600)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.6检查/etc/passwd文件权限
    event checkModPasswd() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/passwd文件权限";
        e.basis = "<=644";
        e.recommend = "/etc/passwd的权限应该小于等于644";
        e.importantLevel = "2";
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/passwd 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/passwd | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 644)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.7检查/etc/rc6.d目录权限
    event checkModRc6() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查/etc/rc6.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc6.d的权限应该小于等于750";
        e.importantLevel = "2";
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc6.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc6.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.8检查/etc/rc0.d目录权限
    event checkModRc0() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc0.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc0.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc0.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc0.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.9检查/etc/rc1.d目录权限
    event checkModRc1() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc1.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc1.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc1.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc1.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.10检查/etc/rc2.d目录权限
    event checkModRc2() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/xinetd.conf文件权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc2.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc2.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc2.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.11检查/etc目录权限
    event checkModEtc() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.12检查/etc/rc4.d目录权限
    event checkModRc4() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc4.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc4.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc4.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc4.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.13检查/etc/rc5.d目录权限
    event checkModRc5() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc5.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc5.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc5.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc5.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.14检查/etc/rc3.d目录权限
    event checkModRc3() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc3.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc3.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc3.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc3.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.15检查/etc/rc.d/init.d目录权限
    event checkModInit() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/rc.d/init.d目录权限";
        e.basis = "<=750";
        e.recommend = "/etc/rc.d/init.d的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/rc.d/init.d 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/rc.d/init.d | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.16检查/tmp目录权限
    event checkModTmp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/tmp目录权限";
        e.basis = "<=750";
        e.recommend = "/tmp的权限应该小于等于750";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /tmp 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            //e.command = "stat -c %a /tmp | tr -d ' ' | tr -d '\n'";
            
            e.command = "stat -c %a /tmp | tr -d ' ' | tr -d '\n' | sed 's/^1//'";

            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 750)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.17检查/etc/grub.conf文件权限
    event checkModGrub() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/grub.conf文件权限";
        e.basis = "<=600";
        e.recommend = "/etc/grub.conf的权限应该小于等于600";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/grub.conf 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/grub.conf | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 600)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.18检查/etc/grub/grub.conf文件权限
    event checkModGrubGrub() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/grub/grub.conf文件权限";
        e.basis = "<=600";
        e.recommend = "/etc/grub/grub.conf的权限应该小于等于600";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/grub/grub.conf 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/grub/grub.conf | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 600)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.2.19检查/etc/lilo.conf文件权限
    event checkModLilo() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/lilo.conf文件权限";
        e.basis = "<=600";
        e.recommend = "/etc/lilo.conf的权限应该小于等于600";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "stat -c %a /etc/lilo.conf 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "stat -c %a /etc/lilo.conf | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            int num = atoi(e.result.c_str());

            if (num <= 600)
            {

                e.IsComply = "true";

            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.3检查重要文件属性设置
    //3.3.1检查/etc/passwd的文件属性
    event checkAttributePasswd() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/passwd的文件属性";
        e.basis = "是否设置了i属性";
        e.recommend = "应设置重要文件为i属性（如：chattr +i /etc/passwd），设定文件不能删除、改名、设定链接关系等";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "lsattr /etc/passwd 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "lsattr /etc/passwd | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare("i") == 0)
            {

                e.IsComply = "true";
                e.result = "已设置i属性";

            }
            else {
                e.IsComply = "false";
                e.result = "未设置i属性";
            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.3.2检查/etc/shadow的文件属性
    event checkAttributeShadow() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/shadow的文件属性";
        e.basis = "设置i属性";
        e.recommend = "应设置重要文件为i属性（如：chattr +i /etc/shadow），设定文件不能删除、改名、设定链接关系等";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "lsattr /etc/shadow 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "lsattr /etc/shadow | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare("i") == 0)
            {
                e.IsComply = "true";
                e.result = "已设置i属性";

            }
            else {
                e.IsComply = "false";
                e.result = "未设置i属性";
            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.3.3检查/etc/group的文件属性
    event checkAttributeGroup() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/group的文件属性";
        e.basis = "设置i属性";
        e.recommend = "应设置重要文件为i属性（如：chattr +i /etc/group），设定文件不能删除、改名、设定链接关系等";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "lsattr /etc/group 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "lsattr /etc/group | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare("i") == 0)
            {

                e.IsComply = "true";
                e.result = "已设置i属性";

            }
            else {
                e.IsComply = "false";
                e.result = "未设置i属性";
            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.3.4检查/etc/gshadow的文件属性
    event checkAttributeGshadow() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查/etc/gshadow的文件属性";
        e.basis = "设置i属性";
        e.recommend = "应设置重要文件为i属性（如：chattr +i /etc/gshadow），设定文件不能删除、改名、设定链接关系等";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "lsattr /etc/gshadow 2>&1 | grep stat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);

        if (fileIsExist.compare("") == 0)
        {

            e.command = "lsattr /etc/gshadow | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare("i") == 0)
            {

                e.IsComply = "true";
                e.result = "已设置i属性";

            }
            else {
                e.IsComply = "false";
                e.result = "未设置i属性";
            }
        }
        else
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.4检查用户目录缺省访问权限设置
    event checkUmaskLogin() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查用户目录缺省访问权限设置";
        e.basis = "=027";
        e.recommend = "文件目录缺省访问权限修改为 027";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/login.defs 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/login.defs | grep umask | grep -v ^#";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                e.command = "cat /etc/login.defs | grep umask | grep -v ^# | grep 027";
                string command_result2 = "cat /etc/login.defs | grep UMASK | grep -v ^# | grep 027";

                e.result = execute_commands(guard.get(), e.command);
                command_result2 = execute_commands(guard.get(), command_result2);

                if (e.result.compare("") || command_result2.compare(""))
                {
                    e.IsComply = "true";
                }
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启/etc/login.defs中的umask设置，且文件目录缺省访问权限修改为 027";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //3.5检查是否设置ssh登录前警告Banner
    event checkSshBanner() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否设置ssh登录前警告Banner";
        e.basis = "/etc/ssh/sshd_config 是否开启 Banner";
        e.recommend = "检查SSH配置文件:/etc/ssh/sshd_config，启用banner或合理设置banner的内容";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/ssh/sshd_config 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}' | grep -v '^#' | grep -v 'none'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                e.IsComply = "true";
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启/etc/ssh/sshd_config中的Banner设置,合理设置Banner的内容";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.1检查是否配置远程日志功能
    //4.1.1 e-ng是否配置远程日志功能
    event checkeNg() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查e-ng是否配置远程日志功能";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep  '^destination logserver' /etc/e-ng/e-ng.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置e-ng远程日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置e-ng远程日志功能";
            e.IsComply = "true";
        }
        e.importantLevel = "1";
        e.recommend = "/etc/e-ng/e-ng.conf中配置远程日志功能";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.1.2 rsyslog是否配置远程日志功能
    event checkRsyslog() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "rsyslog是否配置远程日志功能";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep '^*.* @' /etc/rsyslog.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置ryslog远程日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置ryslog远程日志功能";
            e.IsComply = "true";
        }
        e.recommend = "/etc/rsyslog.conf中配置远程日志功能";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.1.3 syslog是否配置远程日志功能
    event checkSyslog() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "syslog是否配置远程日志功能";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep '^*.* @' /etc/syslog.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置syslog远程日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置syslog远程日志功能";
            e.IsComply = "true";
        }
        e.recommend = "syslog配置远程日志功能，/etc/syslog.conf末行添加相关配置";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.2检查是否配置安全事件日志
    //4.2.1 syslog_ng是否配置安全事件日志
    event checkSyslogNgSafe() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "syslog_ng是否配置安全事件日志";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep  \"filter f_msgs\" /etc/syslog-ng/syslog-ng.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置syslog_ng安全事件日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置syslog_ng安全事件日志功能";
            e.IsComply = "true";
        }
        e.recommend = "应配置安全事件日志功能,/etc/syslog-ng/syslog-ng.conf文件中修改";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.2.2 rsyslog是否配置安全事件日志
    event checkRsyslogSafe() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "rsyslog_safe是否配置安全事件日志";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep '^\\*\\.err;kern\\.debug;daemon\\.notice /var/adm/es' /etc/rsyslog.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置rsyslog安全事件日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置rsyslog安全事件日志功能";
            e.IsComply = "true";
        }
        e.recommend = "应该配置安全事件日志功能,/etc/rsyslog.conf中修改 ";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.2.3 检查syslog是否配置安全事件日志 
    event checkSyslogSafe() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "rsyslog_safe是否配置安全事件日志";
        e.basis = "查找配置文件是否有相应行";
        e.command = "grep -E 'auth\\.|authpriv\\.|daemon\\.|kern\\.' /etc/syslog.conf";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置rsyslog安全事件日志功能";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置rsyslog安全事件日志功能";
            e.IsComply = "true";
        }
        e.recommend = "配置rsyslog安全事件日志功能,/etc/syslog.conf中修改";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3检查日志文件是否other用户不可写
    //4.3.1检查/var/log/e日志文件是否other用户不可写
    event checkCron() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/cron日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/cron";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        
        string command_Iscomply = "ls -l /var/log/cron | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        if (e.IsComply == "true") {
            e.result = "other用户不可写";
        }else {
            e.result = "other用户可写";
        }
        e.recommend = "/var/log/cron日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.2检查/var/log/e日志文件是否other用户不可写";
    event checkSecure() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/secure日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/secure";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        string command_Iscomply = "ls -l /var/log/secure | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        if (e.IsComply == "true") {
            e.result = "other用户不可写";
        }
        else {
            e.result = "other用户可写";
        }
        e.recommend = "/var/log/secure日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.3 检查/var/log/es日志文件是否other用户不可写
    event checkMessage() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/messages日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/messages";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        string command_Iscomply = "ls -l /var/log/messages | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        if (e.IsComply == "true") {
            e.result = "other用户不可写";
        }
        else {
            e.result = "other用户可写";
        }
        e.recommend = "/var/log/messages日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.4 检查/var/log/boot.log日志文件是否other用户不可写

    event checkBootLog() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/boot.log日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/boot.log";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        string command_Iscomply = "ls -l /var/log/boot.log | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        if (e.IsComply == "true") {
            e.result = "other用户不可写";
        }
        else {
            e.result = "other用户可写";
        }
        e.recommend = "/var/log/boot.log日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.5检查/var/log/e日志文件是否other用户不可写
    event checkMail() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/mail日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/mail";
        string command = "ls -l /var/log/boot.log";
        e.result = execute_commands(guard.get(), command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        else {
            string command_Iscomply = "ls -l /var/log/boot | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
            e.IsComply = execute_commands(guard.get(), command_Iscomply);
            if (e.IsComply == "true") {
                e.result = "other用户不可写";
            }
            else {
                e.result = "other用户可写";
            }
            e.recommend = "/var/log/boot日志文件other用户不可写";
        }
        
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.6 检查/var/log/e日志文件是否other用户不可写
    event checkSpooler() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/spooler日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/spooler";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
        }
        string command_Iscomply = "ls -l /var/log/spooler | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        if (e.IsComply == "true") {
            e.result = "other用户不可写";
        }
        else {
            e.result = "other用户可写";
        }
        e.recommend = "/var/log/spooler日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.7 检查/var/log/localmessages日志文件是否other用户不可写
    event checkLocalMessages() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/localmessages日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/localmessages";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";

        }
        string command_Iscomply = "ls -l /var/log/localmessages | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        e.recommend = "/var/log/spooler日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.3.8 检查/var/log/maillog日志文件是否other用户不可写
    event checkMaillog() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查/var/log/maillog日志文件是否other用户不可写";
        e.basis = "other用户不可写";
        e.command = "ls -l /var/log/maillog";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有这个文件";
            e.IsComply = "pending";
        }
        else
        {
            string command_Iscomply = "ls -l /var/log/maillog | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
            e.IsComply = execute_commands(guard.get(), command_Iscomply);
            if (e.IsComply == "true") {
                e.result = "other用户不可写";
            }
            else {
                e.result = "other用户可写";
            }
        }

        e.recommend = "应/var/log/maillog日志文件other用户不可写";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //4.4是否对登录进行日志记录
    event checkLast() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "是否对登录进行日志记录";
        e.basis = "last检查";
        e.command = "last";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未对登录进行日志记录";
            e.IsComply = "false";
        }
        else {
            e.result = "已对登录进行日志记录";
            e.IsComply = "true";
        }
        e.recommend = "要对登录进行日志记录";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //检查是否配置su命令使用情况记录
    event checkSuLog() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "是否对su命令进行日志记录";
        e.basis = "基于Debian或者RPM访问不同的文件";
        string type_os = execute_commands(guard.get(), "command -v apt >/dev/null 2>&1 && echo \"Debian\" || (command -v yum >/dev/null 2>&1 && echo \"RPM\" || echo \"Unknown\")");
        if (type_os == "Debian") {
            e.command = "grep 'su' /var/log/auth.log";
            e.result = execute_commands(guard.get(), e.command);
        }
        else {
            e.command = "grep 'su' /var/log/secure";
            e.result = execute_commands(guard.get(), e.command);
        }
        if (e.result == "") {
            e.result = "未对登录进行日志记录";
            e.IsComply = "false";
        }
        else {
            e.result = "已对登录进行日志记录,结果太长，已忽略";
            e.IsComply = "true";
        }
        e.recommend = "要对登录进行日志记录";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.1检查系统openssh安全配置
    event checkOpensshConfig() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查系统openssh安全配置";
        e.basis = "/etc/ssh/sshd_config中的Protocol配置值为2";
        e.command = "grep - i Protocol / etc / ssh / sshd_config | egrep - v '^\s*#' | awk '{print $2}'";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有Protocol这一行";
        }
        if (e.result == "2") {
            e.IsComply = "true";
        }
        else {
            e.IsComply = "false";
        }
        e.recommend = "建议把/etc/ssh/sshd_config中的Protocol配置值为2";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.2检查是否已修改snmp默认团体字
    //5.2.1 检查SNMP服务是否运行
    event checkRunningSnmp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查SNMP服务是否在运行";
        e.basis = "查看是否存在SNMP进程";
        e.command = "ps -ef|grep \"snmpd\"|grep -v \"grep\"";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "snmp进程没有运行";
            e.IsComply = "true";
            temp= "true";
        }
        else {
            e.result = "snmp进程正在运行,需要进一步检测";
            e.IsComply = "false";
            temp = "false";
        }
        e.recommend = "无";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.2.2检查是否已修改snmp默认团体字，进程未开启就不用
    event checkSnmpConfig() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查是否已修改snmp默认团体字";
        e.basis = "检查是否已修改snmp默认团体字";
        e.command = "cat /etc/snmp/snmpd.conf | grep com2sec  | grep public | grep -v ^#";

        if (temp == "true") {
            e.result = "snmp进程未运行，不用检测修改";
            e.IsComply = "true";
        }
        else {
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "已修改snmp默认团体字";
                e.IsComply = "true";
            }
            else {
                e.IsComply = "false";
            }

        }
        e.recommend = "/etc/snmp/snmpd.conf 文件中修改默认团体字";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.3检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议
    //5.3.1是否配置ssh协议
    event checkSshConfig() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "是否配置ssh协议";
        e.basis = "根据22号端口是否开放检测是否配置ssh协议";
        e.command = "ss -tuln | grep \":22\"";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置ssh协议";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置ssh协议";
            e.IsComply = "true";
        }
        e.recommend = "需要配置ssh协议即要开启ssh服务";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.3.2是否配置telnet协议
    event checkTelnetConfig() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "由于telnet明文传输，所以应该禁止telnet协议";
        e.basis = "根据23号端口是否开放检测是否配置telnet协议";
        e.command = "ss -tuln | grep \":23\"";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未配置telnet协议";
            e.IsComply = "true";
        }
        else {
            e.result = "已配置telnet协议";
            e.IsComply = "false";
        }
        e.recommend = "应该禁止配置telnet协议";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.4检查是否禁止root用户登录ftp
    //5.4.1检查是否在运行ftp服务
    event checkRunningFtp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查是否在运行ftp";
        e.basis = "判断相应的服务是否后台运行";
        e.command = "ps -ef | grep ftp | grep -v grep";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "ftp服务没有在运行，检测通过";
            e.IsComply = "true";
            temp = "true";
        }
        else {
            e.result = "ftp服务在运行，还要进一步检测配置文件";
            e.IsComply = "false";
            temp = "true";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    event checkFtpConfig() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查是否禁止root用户登录ftp";
        e.basis = "/etc/vsftpd/ftpusers文件中包含root用户即为禁止了";
        e.command = "grep '^[^#]*root' /etc/vsftpd/ftpusers";
        if (temp == "true") {
            e.result = "ftp未运行，不用判断";
            e.IsComply = "true";
        }
        else {
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "未禁止root用户登录ftp";
                e.IsComply = "false";
            }
            else {
                e.result = "已禁止root用户登录ftp";
                e.IsComply = "true";
            }
        }
        e.recommend = "应该禁止root用户登录ftp";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //5.5检查是否禁止匿名用户登录FTP
    event checkAnonymousFtp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查是否禁止匿名用户登录FTP";
        e.basis = "/etc/vsftpd/vsftpd.conf文件中是否存在anonymous_enable=NO配置";
        e.command = "cat /etc/vsftpd/vsftpd.conf | grep \"anonymous_enable=NO\" | grep -v ^#";
        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未禁止匿名登录";
            e.IsComply = "false";
        }
        else {
            e.IsComply = "true";
        }
        e.recommend = "禁止匿名用户登录FTP  /etc/vsftpd/vsftpd.conf中检查相关配置";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6其他配置操作
    //6.1检查是否设置命令行界面超时退出
    event checkCmdTimeout() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查是否设置命令行界面超时退出";
        e.basis = "开启TMOUT且TMOUNT<=600秒";
        e.recommend = "建议命令行界面超时自动登出时间TMOUT应不大于600秒，检查项建议系统管理员根据系统情况自行判断";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/profile |grep -i TMOUT | grep -v ^#";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                e.command = "cat /etc/profile |grep -i TMOUT | grep -v ^# | awk -F '=' '{print $2}' | tr -d ' ' | tr -d '\n'";
                e.result = execute_commands(guard.get(), e.command);
                int num = atoi(e.result.c_str());
                if (num <= 600 && num >= 0)
                {
                    e.IsComply = "true";
                }
                e.result += "秒";
            }
            else
            {
                e.result = "未开启TMOUT设置";
                e.recommend = "开启/etc/profile中的TMOUT设置，且TMOUT值应不大于600秒";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";

        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.2检查是否设置系统引导管理器密码
    event checkPasswordBootloader() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否设置系统引导管理器密码";
        e.basis = "系统引导管理器（GRUB2、GRUB 或 LILO）应设置密码";
        e.recommend = "根据引导器类型（GRUB2、GRUB 或 LILO），为其设置引导管理器密码。";

        bool findFile = false;
        bool passwordFound = false; // 用于跟踪是否找到了密码配置

        // 1. 检查 GRUB 1
        string grubFiles[] = { "/boot/grub/menu.lst", "/etc/grub.conf", "/boot/grub/grub.cfg" };
        for (const auto& file : grubFiles) {
            string fileCheckCmd = "test -f " + file + " && echo exist || echo not_exist";
            string fileCheckResult = execute_commands(guard.get(), fileCheckCmd);

            if (fileCheckResult == "exist") {
                findFile = true;

                e.command = "grep -E 'password|password_pbkdf2' " + file + " 2>/dev/null";
                e.result = execute_commands(guard.get(), e.command);

                if (!e.result.empty()) {
                    e.IsComply = "true";
                    passwordFound = true;
                    break; // 找到密码后可以提前结束
                }
            }
        }

        // 2. 检查 GRUB2
        if (!findFile) {
            string grub2Files[] = { "/boot/grub2/menu.lst", "/etc/grub2.conf", "/boot/grub2/grub2.cfg" };
            for (const auto& file : grub2Files) {
                string fileCheckCmd = "test -f " + file + " && echo exist || echo not_exist";
                string fileCheckResult = execute_commands(guard.get(), fileCheckCmd);

                if (fileCheckResult == "exist") {
                    findFile = true;

                    e.command = "grep -E 'password|password_pbkdf2' " + file + " 2>/dev/null";
                    e.result = execute_commands(guard.get(), e.command);

                    if (!e.result.empty()) {
                        e.IsComply = "true";
                        passwordFound = true;
                        break;
                    }
                }
            }
        }

        // 3. 检查 LILO
        if (!findFile) {
            string liloFile = "/etc/lilo.conf";
            string fileCheckCmd = "test -f " + liloFile + " && echo exist || echo not_exist";
            string fileCheckResult = execute_commands(guard.get(), fileCheckCmd);

            if (fileCheckResult == "exist") {
                findFile = true;

                e.command = "grep -i 'password' " + liloFile + " 2>/dev/null";
                e.result = execute_commands(guard.get(), e.command);

                if (!e.result.empty()) {
                    e.IsComply = "true";
                    passwordFound = true;
                }
            }
        }

        // 4. 处理各种情况，确保 e.result 不为空
        if (!findFile) {
            e.result = "未找到相关配置文件，系统可能使用了其他引导管理器或配置文件已被删除。";
            e.IsComply = "pending";
        }
        else if (!passwordFound) {
            e.result = "已找到引导管理器配置文件，但未检测到密码设置，建议配置密码以增强安全性。";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

        return e;
    }

    //event checkPasswordBootloader() {
    //    SSHConnectionGuard guard(sshPool);
    //    event e;
    //    e.importantLevel = "1";
    //    e.description = "检查是否设置系统引导管理器密码";
    //    e.basis = "系统引导管理器grub2或grub或lilo是否设置了密码";
    //    e.recommend = "根据引导器不同类型（grub2或grub或lilo），为其设置引导管理器密码。";

    //    //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
    //    //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
    //    string fileIsExist = "cat /boot/grub/menu.lst 2>&1 | grep cat: ";
    //    string command_result2 = "cat /etc/grub.conf 2>&1 | grep cat:";
    //    string command_result3 = "cat /boot/grub/grub.cfg 2>&1 | grep cat:";

    //    fileIsExist = execute_commands(guard.get(), fileIsExist);
    //    command_result2 = execute_commands(guard.get(), command_result2);
    //    command_result3 = execute_commands(guard.get(), command_result3);

    //    bool findFile = false;

    //    if (fileIsExist.compare("") == 0 || command_result2.compare("") == 0 || command_result3.compare("") == 0)
    //    {
    //        findFile = true;

    //        //cout << "系统引导器为grub！" << endl;

    //        e.command = "echo $grub | grep password | tr -d '\n'";
    //        e.result = execute_commands(guard.get(), e.command);

    //        if (e.result.compare(""))
    //        {
    //            e.IsComply = "true";
    //        }

    //    }

    //    if (!findFile)
    //    {
    //        fileIsExist = "cat /boot/grub2/menu.lst 2>&1 | grep cat: ";
    //        command_result2 = "cat /etc/grub2.conf 2>&1 | grep cat:";
    //        command_result3 = "cat /boot/grub2/grub2.cfg 2>&1 | grep cat:";

    //        fileIsExist = execute_commands(guard.get(), fileIsExist);
    //        command_result2 = execute_commands(guard.get(), command_result2);
    //        command_result3 = execute_commands(guard.get(), command_result3);

    //        if (fileIsExist.compare("") == 0 || command_result2.compare("") == 0 || command_result3.compare("") == 0)
    //        {
    //            findFile = true;

    //            //cout << "系统引导器为grub2！" << endl;

    //            e.command = "echo $grub2 | grep password | tr -d '\n'";
    //            e.result = execute_commands(guard.get(), e.command);

    //            if (e.result.compare(""))
    //            {
    //                e.IsComply = "true";
    //            }

    //        }

    //    }

    //    if (!findFile)
    //    {
    //        fileIsExist = "cat /etc/lilo.conf 2>&1 | grep cat: ";
    //        fileIsExist = execute_commands(guard.get(), fileIsExist);

    //        if (fileIsExist.compare("") == 0)
    //        {
    //            findFile = true;

    //            //cout << "系统引导器为lilo！" << endl;

    //            e.command = "echo $lilo | grep password | tr -d '\n'";
    //            e.result = execute_commands(guard.get(), e.command);

    //            if (e.result.compare(""))
    //            {
    //                e.IsComply = "true";
    //            }

    //        }

    //    }

    //    if (!findFile)
    //    {
    //        e.result = "未找到配置文件";
    //    }

    //    std::cout << "Completed check: " << e.description
    //        << " [ThreadID: " << std::this_thread::get_id()
    //        << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
    //    return e;
    //}

    //6.3检查系统coredump设置
    event checkCoreDump() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查系统coredump设置";
        e.basis = "在文件/etc/security/limits.conf中配置* hard core 0 和 * soft core 0";
        e.recommend = "检查系统core dump设置，在文件/etc/security/limits.conf中配置* hard core 0 和 * soft core 0";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/security/limits.conf 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/security/limits.conf | grep soft | grep core | grep 0 | grep ^*";
            string command_result2 = "cat /etc/security/limits.conf | grep hard | grep core | grep 0 | grep ^*";

            e.result = execute_commands(guard.get(), e.command);
            command_result2 = execute_commands(guard.get(), command_result2);

            if (e.result.compare("") && command_result2.compare(""))
            {
                e.IsComply = "true";
                e.result = "coredump 配置正确:\n" + e.result + "\n" + command_result2;
            }
            else
            {
                e.result = "文件存在，但 coredump 未正确配置，缺少 `* soft core 0` 或 `* hard core 0`";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件 `/etc/security/limits.conf`，系统可能未进行 Core Dump 限制。";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }


    //6.4检查历史命令设置
    event checkHistSize() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查历史命令设置";
        e.basis = "HISTFILESIZE 和 HISTSIZE 的值 <= 5";
        e.recommend = "历史命令文件 HISTFILESIZE 和 HISTSIZE 的值应小于等于 5";

        bool findFile = false;
        bool correctlyConfigured = false;

        // 检查 /etc/profile 是否存在
        string fileCheckCmd = "test -f /etc/profile && echo exist || echo not_exist";
        string fileIsExist = execute_commands(guard.get(), fileCheckCmd);

        if (fileIsExist == "exist") {
            findFile = true;

            // 获取 HISTSIZE 和 HISTFILESIZE 的值
            e.command = "grep -E '^[^#]*HISTSIZE' /etc/profile | awk -F '=' '{print $2}' | tr -d ' ' | tr -d '\n'";
            string command_result2 = "grep -E '^[^#]*HISTFILESIZE' /etc/profile | awk -F '=' '{print $2}' | tr -d ' ' | tr -d '\n'";

            e.result = execute_commands(guard.get(), e.command);
            command_result2 = execute_commands(guard.get(), command_result2);

            if (!e.result.empty() && !command_result2.empty()) {
                int num1 = atoi(e.result.c_str());
                int num2 = atoi(command_result2.c_str());

                if (num1 <= 5 && num2 <= 5) {
                    e.IsComply = "true";
                    correctlyConfigured = true;
                    e.result = "HISTSIZE 和 HISTFILESIZE 均符合要求（≤5）：\nHISTSIZE=" + e.result + "\nHISTFILESIZE=" + command_result2;
                }
                else {
                    e.result = "HISTSIZE 或 HISTFILESIZE 超出要求值（>5）：\nHISTSIZE=" + e.result + "\nHISTFILESIZE=" + command_result2;
                }
            }
            else {
                e.result = "未检测到 HISTSIZE 或 HISTFILESIZE 配置，请检查 /etc/profile 是否正确配置。";
            }
        }

        if (!findFile) {
            e.result = "未找到配置文件 `/etc/profile`，请检查文件是否存在。";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

        return e;
    }


    //6.5检查是否使用PAM认证模块禁止wheel组之外的用户su为root
    event checkGroupWheel() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查是否使用PAM认证模块禁止wheel组之外的用户su为root";
        e.basis = "在 /etc/pam.d/su 文件中配置: \n  auth sufficient pam_rootok.so \n  auth required pam_wheel.so group=wheel";
        e.recommend = "禁止 wheel 组外用户使用 su 命令，提高操作系统的完整性。";

        bool findFile = false;
        bool isCompliant = false;

        // 检查 /etc/pam.d/su 是否存在
        string fileCheckCmd = "test -f /etc/pam.d/su && echo exist || echo not_exist";
        string fileIsExist = execute_commands(guard.get(), fileCheckCmd);
        size_t pos = fileIsExist.find_last_not_of('\n');
        if (pos != string::npos) {
            // 从开头到最后一个非换行符的字符复制字符串
            fileIsExist = fileIsExist.substr(0, pos + 1);
        }
        else {
            // 如果没有找到，说明没有换行符，直接复制原始字符串
            fileIsExist = fileIsExist;
        }

        std::cout << fileIsExist;

        if (fileIsExist=="exist") {
            findFile = true;

            // 查找 pam_rootok.so 和 pam_wheel.so group=wheel 配置
            e.command = "cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#";
            string command_result2 = "cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#";

            e.result = execute_commands(guard.get(), e.command);
            command_result2 = execute_commands(guard.get(), command_result2);

            if (!e.result.empty() && !command_result2.empty()) {
                e.IsComply = "true";
                isCompliant = true;
                e.result = "PAM 配置符合要求：\n" + e.result + "\n" + command_result2;
            }
            else {
                e.result = "PAM 配置不完整：\n";
                if (e.result.empty()) {
                    e.result += "缺少 `auth sufficient pam_rootok.so`\n";
                }
                if (command_result2.empty()) {
                    e.result += "缺少 `auth required pam_wheel.so group=wheel`\n";
                }
            }
        }

        if (fileIsExist== "not_exist") {
            e.result = "未找到配置文件 `/etc/pam.d/su`，系统可能未启用 PAM 认证。";
            e.IsComply = "pending";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

        return e;
    }


    //event checkGroupWheel() {
    //    SSHConnectionGuard guard(sshPool);
    //    event e;
    //    e.importantLevel = "3";
    //    e.description = "检查是否使用PAM认证模块禁止wheel组之外的用户su为root";
    //    e.basis = "在/etc/pam.d/su文件中配置: auth  sufficient pam_rootok.so 和 auth  required pam_wheel.so group=wheel";
    //    e.recommend = "禁止wheel组外用户使用su命令，提高操作系统的完整性";

    //    //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
    //    //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
    //    string fileIsExist = "cat /etc/pam.d/su 2>&1 | grep cat: ";
    //    fileIsExist = execute_commands(guard.get(), fileIsExist);
    //    bool findFile = false;

    //    if (fileIsExist.compare("") == 0)
    //    {
    //        findFile = true;

    //        e.command = "cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#";
    //        string command_result2 = "cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#";

    //        e.result = execute_commands(guard.get(), e.command);
    //        command_result2 = execute_commands(guard.get(), command_result2);


    //        if (e.result.compare("") && command_result2.compare(""))
    //        {
    //            e.IsComply = "true";
    //        }
    //        else
    //        {
    //            e.result = "未开启";
    //        }
    //    }

    //    if (!findFile)
    //    {
    //        e.result = "未找到配置文件";
    //    }
    //    std::cout << "Completed check: " << e.description
    //        << " [ThreadID: " << std::this_thread::get_id()
    //        << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
    //    return e;
    //}

    //6.6检查是否对系统账户进行登录限制
    event checkInterLogin() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否对系统账户进行登录限制";
        e.basis = "请手动检查文件文件/etc/passwd，/etc/shadow，并使用命令：usermod -s /sbin/nologin username";
        e.recommend = "对系统账户登录进行限制，禁止账户交互式登录。";
        e.result = "手动检查";
        e.IsComply = "pending";

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.7检查密码重复使用次数限制
    event checkPasswordRepeatlimit() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查密码重复使用次数限制";
        e.basis = ">=5";
        e.recommend = "检查密码重复使用次数，使用户不能重复使用最近5次（含5次）内已使用的口令，预防密码重复使用被爆破的风险。";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/pam.d/system-auth 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^#";
            e.result = execute_commands(guard.get(), e.command);


            if (e.result.compare(""))
            {
                e.command = "cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^# | awk -F 'remember=' '{print $2}' | tr -d '\n'";
                e.result = execute_commands(guard.get(), e.command);

                int num = atoi(e.result.c_str());
                if (num >= 5)
                {
                    e.IsComply = "true";
                }
            }
            else
            {
                e.result = "未开启";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.8检查账户认证失败次数限制
    event checkAuthFailtimes() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查账户认证失败次数限制";
        e.basis = "登录失败限制可以使用pam_tally或pam.d，请手工检测/etc/pam.d/system-auth、/etc/pam.d/passwd、/etc/pam.d/common-auth文件。";
        e.recommend = "应配置密码失败次数限制，预防密码被爆破的风险。";
        e.result = "手动检查";

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.9检查是否关闭绑定多ip功能
    event checkMultiIp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否关闭绑定多ip功能";
        e.basis = "/etc/host.conf中设置 multi off";
        e.recommend = "应关闭绑定多ip功能，使系统操作责任到人。";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/host.conf 2>&1 | grep cat: ";//文件存在则不会返回任何内容
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        std::cout << fileIsExist;
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/host.conf | grep -v ^# | grep multi | grep off";
            e.result = execute_commands(guard.get(), e.command);


            if (e.result.compare("")!=0)
            {
                e.result = "已设置关闭绑定多ip功能";
                e.IsComply = "true";
            }
            else {
                e.result = "未设置关闭绑定多ip功能";
            }
        }

        if (!findFile)
        {
            e.result = "未设置关闭绑定多ip功能";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.10检查是否限制远程登录IP范围
    event checkLoginRemoteIp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否限制远程登录IP范围";
        e.basis = "请手工查看/etc/hosts.allow和/etc/hosts.deny两个文件";
        e.recommend = "应配置相关设置防止未知ip远程登录，此检查项建议系统管理员根据系统情况自行判断。";
        e.result = "手动检查";

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.11检查别名文件
    event checkAliasesUnnecessary() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查别名文件";
        e.basis = "请手工查看/etc/aliases和/etc/mail/aliases两个文件";
        e.recommend = "检查是否禁用不必要的别名，此检查项建议系统管理员根据系统情况自行判断。";
        e.result = "手动检查";
        e.IsComply = "pending";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.12检查重要文件是否存在suid和sgid权限
    event checkPermSuidSgid() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查重要文件是否存在suid和sgid权限";
        e.basis = "重要文件应该不存在suid和sgid权限";
        e.recommend = "对于重要文件建议关闭suid和sgid";


        e.command = "find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm /6000";
        e.result = execute_commands(guard.get(), e.command);


        if (e.result.compare("") == 0){
            e.IsComply = "true";
            e.result = "未发现存在 SUID 或 SGID 权限的文件，符合安全要求。";
        }
        else {
            e.IsComply = "false";
            e.result = "以下文件存在 SUID 或 SGID 权限，需要检查或移除：\n" + e.result;
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.13检查是否配置定时自动屏幕锁定（适用于图形化界面）
    event checkScreenAutolock() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否配置定时自动屏幕锁定（适用于图形化界面）";
        e.basis = "在屏幕上面的面板中，打开“系统”-->“首选项”-->“屏幕保护程序”";
        e.recommend = "对具有图形化界面的设备应配置定时自动屏幕锁定";
        e.result = "手动检查";
        e.IsComply = "pending";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.14检查系统内核参数配置（可能不全）
    event checkTcpSyncookies() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查系统内核参数配置";
        e.basis = "=1";
        e.recommend = "该项配置主要为了缓解拒绝服务攻击。调整内核安全参数，增强系统安全性，e的值应设为1";

        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /proc/sys/net/ipv4/e 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /proc/sys/net/ipv4/e | tr -d '\n' | tr -d ' '";
            e.result = execute_commands(guard.get(), e.command);


            if (e.result.compare("1") == 0)
            {
                e.IsComply = "true";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
            e.IsComply = "pending";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.15检查是否按组进行账号管理
    event checkGroupManage() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否按组进行账号管理";
        e.basis = "请手工查看/etc/group等文件";
        e.recommend = "此配置项主要偏向于对系统用户的管理，如账户已分组管理，该检查项可以跳过。此检查项建议系统管理员根据系统情况自行判断";
        e.result = "手动检查";
        e.IsComply = "pending";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.17 检查root用户的path环境变量
    event checkRootPathCheck() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查root用户的path环境变量内容";
        e.basis = "不包含（.和..）的路径";
        e.command = "sudo sh -c 'echo $PATH' | grep -o -e '\\.\\.' -e '\\.' | wc -l";
        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "修改文件/etc/profile或/root/.bash_profile 在环境变量$PATH中删除包含（.和..）的路径";


        //转为Int来比较
        int numm = atoi(e.result.c_str());

        if (numm == 0)
        {
            e.IsComply = "true";
            e.result = "不包含（.和..）的路径";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.18 检查系统是否禁用ctrl+alt+del组合键
    event checkCtrlAltDelDisabled() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查系统是否禁用ctrl+alt+del组合键";
        e.basis = "禁用Ctrl+Alt+Delete组合键重启系统";
        string type_os = execute_commands(guard.get(), "command -v apt >/dev/null 2>&1 && echo \"Debian\" || (command -v yum >/dev/null 2>&1 && echo \"RPM\" || echo \"Unknown\")");
        if (type_os == "RPM") { //centos7
            e.command = "cat /usr/lib/systemd/system/ctrl-alt-del.target | grep \"Alias=ctrl-alt-del.target\" | grep -v ^#";
            e.recommend = "系统应该禁用ctrl+alt+del组合键，具体操作：vi /usr/lib/systemd/system/ctrl-alt-del.target。找到下面行并注释掉：Alias = ctrl - alt - del.target。";
        }
        else if (type_os == "Debian") { //ubuntu
            e.command = "cat /lib/systemd/system/ctrl-alt-del.target | grep \"Alias=ctrl-alt-del.target\" | grep -v ^#";
            e.recommend = "系统应该禁用ctrl+alt+del组合键，具体操作：vi /lib/systemd/system/ctrl-alt-del.target。找到下面行并注释掉：Alias = ctrl - alt - del.target。";
        }

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "已经禁用这个快捷键,符合基线";
            e.IsComply = "true";
        }
        else {
            e.IsComply = "false";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.19 检查是否关闭系统信任机制
    event checkSysTrustMechanism() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.description = "检查是否关闭系统信任机制";
        e.basis = "关闭系统信任机制";
        e.importantLevel = "3";
        e.command = "find / -maxdepth 3 -type f -name .rhosts 2>/dev/null; find / -maxdepth 2 -name hosts.equiv 2>/dev/null";
        e.recommend = "1.执行命令find / -maxdepth 2 -name hosts.equiv 进入到. hosts.equiv文件存在的目录，执行命令：mv hosts.equiv hosts.equiv.bak。2.执行命令find / -maxdepth 3 -type f -name .rhosts 2>/dev/null 进入到.rhosts文件存在的目录，执行命令：mv .rhosts .rhosts.bak。";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "已经关闭系统信任机制,符合基线";
            e.IsComply = "true";
        }
        else {
            e.IsComply = "false";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.20 检查系统磁盘分区使用率
    event checkDiskPartitionUsageRate() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查系统磁盘分区使用率";
        e.basis = "系统磁盘分区使用率均<=80%";

        e.command = "df -h | awk 'NR>1 {sub(/%/,\"\",$5); if ($5+0 > 80) print $5 \" % \" \" \" $6}'";
        e.recommend = "磁盘动态分区空间不足，建议管理员扩充磁盘容量。命令：df - h";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "系统磁盘分区使用率均<=80%,符合基线";
            e.IsComply = "true";
        }
        else {
            e.result = "系统磁盘分区使用率存在>80%的情况";
            e.IsComply = "false";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.21 检查是否删除了潜在危险文件
    event checkPotentialRiskFiles() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查是否删除了潜在危险文件";
        e.basis = "删除潜在危险文件，包括hosts.equiv文件 .rhosts文件和 .netrc 文件";

        e.command = "find / -type f \\( -name \".rhosts\" -o -name \".netrc\" -o -name \"hosts.equiv\" \\) 2>/dev/null";
        e.recommend = "应该删除潜在危险文件 hosts.equiv文件 .rhosts文件和 .netrc 文件";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "已删除潜在危险文件";
            e.IsComply = "true";
        }
        else {
            e.IsComply = "false";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.22 检查是否删除与设备运行，维护等工作无关的账号 手动检查

    //6.23 检查是否配置用户所需最小权限
    event checkUserMinPermission() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "2";
        e.description = "检查是否配置用户所需最小权限";
        e.basis = "配置用户所需最小权限,/etc/passwd为644；/etc/group为644；/etc/shadow为600";

        e.command = "[ $(stat -c \" % a\" /etc/passwd) -le 644 ] || stat -c \" % a % n\" /etc/passwd; [ $(stat -c \" % a\" /etc/shadow) -le 600 ] || stat -c \" % a % n\" /etc/shadow; [ $(stat -c \" % a\" /etc/group) -le 644 ] || stat -c \" % a % n\" /etc/group";
        e.recommend = "应配置用户所需最小权限,chmod 644 /etc/passwd；chmod 644 /etc/group；chmod 600 /etc/shadow";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "已配置用户最小权限，符合基线";
            e.IsComply = "true";
        }
        else {
            e.result = "存在未配置用户最小权限："+ e.result;
            e.IsComply = "false";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.24 检查是否关闭数据包转发功能（适用于不做路由功能的系统）-对于集群系统或者需要数据包转发的系统不做该配置
    event checkPacketForwardFunc() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否关闭数据包转发功能";
        e.basis = "对于不做路由功能的系统，应该关闭数据包转发功能";

        e.command = "cat /proc/sys/net/ipv4/ip_forward";
        e.recommend = "应该关闭数据包转发功能；命令： #sysctl -w net.ipv4.ip_forward=0";

        e.result = execute_commands(guard.get(), e.command);

        int num11 = atoi(e.result.c_str());
        if (e.result.compare(""))
        {
            if (num11 == 0)
            {
                e.result = "已关闭数据包转发功能，符合基线";
                e.IsComply = "true";
            }
            else {
                e.result = "未关闭数据包转发功能";
                e.IsComply = "false";
            }
        }
        else
        {
            e.IsComply = "false";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.25检查是否禁用不必要的系统服务 手动检查
    // 
    //6.26 检查是否使用NTP（网络时间协议）保持时间同步
    event checkNtpSyncStatus() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否使用NTP（网络时间协议）保持时间同步";
        e.basis = "检查ntp服务是否开启，若开启则需配置NTP服务器地址";
        //没有使用ntp，则输出no ntp；使用ntp但没配置地址，则输出no server；使用ntp且配置了地址，则输出配置。
        e.command = "ps -ef | egrep \"ntp | ntpd\" | grep -v grep | grep \" / usr / sbin / ntpd\" >/dev/null && (grep \" ^ server\" /etc/ntp.conf || echo \"no server\") || echo \"no ntp\"";

        e.result = execute_commands(guard.get(), e.command);

        if (e.result.find("no ntp") != std::string::npos) {
            e.result = "未开启NTP服务";
            e.recommend = "开启ntp服务： redhat为：/etc/init.d/ntpd start ；suse9为：/etc/init.d/xntpd start ；suse10,11为：/etc/init.d/ntp start。";
            e.IsComply = "false";
        }
        else if (e.result.find("no server") != std::string::npos) {
            e.result = "未配置NTP服务器地址";
            e.recommend = "编辑ntp的配置文件： #vi / etc / ntp.conf,配置：server IP地址（提供ntp服务的机器）,如：server 192.168.1.1 ";
            e.IsComply = "false";
        }
        else {
            e.result = "已配置NTP服务器地址";
            e.IsComply = "true";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.27 检查NFS（网络文件系统）服务设置
    event checkNfsServer() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查NFS（网络文件系统）服务设置";
        e.basis = "如果需要NFS服务，需要限制能够访问NFS服务的IP范围；如果没有必要，需要停止NFS服务";
        //1."no nfs": 没有NFS服务在运行。2. 输出非注释非空行: 显示了/etc/hosts.allow和/etc/hosts.deny中配置的IP访问限制规则。3."no ip limitation": NFS服务在运行，但没有配置任何IP访问限制规则。
        e.command = "netstat -lntp | grep -q nfs && { cat /etc/hosts.allow /etc/hosts.deny | grep -v ^# | sed '/^$/d' || echo \"no ip limitation\"; } || echo \"no nfs\"";

        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "停止NFS服务或限制能够访问NFS服务的IP范围";

        if (e.result.find("no nfs") != std::string::npos) {
            e.result = "没有NFS服务在运行";
            e.recommend = "停止NFS服务或限制能够访问NFS服务的IP范围";
            e.IsComply = "true";
        }
        else if (e.result.find("no ip limitation") != std::string::npos) {
            e.result = "NFS服务在运行，但没有配置任何IP访问限制规则";
            e.recommend = "限制能够访问NFS服务的IP范围： 编辑文件：vi /etc/hosts.allow 增加一行:portmap: 允许访问的IP。或停止nfs服务： Suse系统：/etc/init.d/nfsserver stop ；Redhat系统：/etc/init.d/nfs stop";
            e.IsComply = "false";
        }
        else {
            e.result = "已开启NFS服务并限制能够访问NFS服务的IP范围";
            e.IsComply = "true";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.28 检查是否安装OS补丁 手动

    //6.29 检查是否设置ssh成功登陆后Banner
    event checkSshBanner2() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否设置ssh成功登陆后Banner";
        e.basis = "设置ssh成功登陆后Banner";

        e.command = "systemctl status sshd | grep -q running && [ -s /etc/motd ] && cat /etc/motd || true";
        e.recommend = "为了保证信息安全的抗抵赖性，需要设置ssh成功登录后Banner";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "未设置ssh成功登陆后Banner";
            e.recommend = "为了保证信息安全的抗抵赖性，需要设置ssh成功登录后Banner：修改文件/etc/motd的内容，如没有该文件，则创建它。 #echo \"Login success.All activity will be monitored and reported \" > /etc/motd根据实际需要修改该文件的内容";
            e.IsComply = "false";
        }
        else {
            e.IsComply = "false";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.30 检查FTP用户上传的文件所具有的权限
    event checkUploadFtp() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查FTP用户上传的文件所具有的权限";
        e.basis = "检查是否安装vsftpd或者pure-ftpd，且上传权限设置正确";
        string type_os = execute_commands(guard.get(), "command -v apt >/dev/null 2>&1 && echo \"Debian\" || (command -v yum >/dev/null 2>&1 && echo \"RPM\" || echo \"Unknown\")");
        if (type_os == "RPM") {
            soft_ware = execute_commands(guard.get(), rpm_command);
        }
        else {
            soft_ware = execute_commands(guard.get(), Debian_command);
        }
        // 查找最后一个不是换行符(\n)的字符
        size_t pos = soft_ware.find_last_not_of('\n');
        if (pos != std::string::npos) {
            // 从开头到最后一个非换行符的字符复制字符串
            soft_ware = soft_ware.substr(0, pos + 1);
        }
        else {
            // 如果没有找到，说明没有换行符，直接复制原始字符串
            soft_ware = soft_ware;
        }
        if (soft_ware == "vsftpd") {
            e.command = "grep -E \"^(write_enable=YES|ls_recurse_enable=YES|local_umask=022|anon_umask=022)\" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf";
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "未对FTP用户上传的文件所具有的权限检查";
                e.IsComply = "false";
            }
            else {
                e.IsComply = "true";
                e.recommend = "对FTP用户上传的文件所具有的权限检查";
            }
        }
        else if (soft_ware == "pure-ftpd") {
            e.command = "grep -E \"^Umask 177:077\" /etc/pure-ftpd/pure-ftpd.conf";
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "未对FTP用户上传的文件所具有的权限检查";
                e.IsComply = "false";
            }
            else {
                e.IsComply = "true";
            }
        }
        else {
            e.command = "None";
            e.result = "未安装vsftpd或者pure-ftpd";
            e.IsComply = "false";
            e.recommend = "要安装vsftpd或者pure-ftpd并设置上传权限";

        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.31检查是否更改默认的ftp登陆警告Banner
    event checkFtpBaner() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "是否更改默认的ftp登陆警告Banner";
        e.basis = "需要自己检查自定义的banner";

        if (soft_ware == "vsftpd") {
            e.command = "grep -E \"^[^#]*ftpd_banner\" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf";
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "未更改默认的ftp登陆警告Banner";
                e.IsComply = "false";
            }
            else {
                e.IsComply = "false";
            }
        }
        else if (soft_ware == "pure-ftpd") {
            e.command = "grep -v '^#' /etc/pure-ftpd/pure-ftpd.conf | grep 'FortunesFile'";
            e.result = execute_commands(guard.get(), e.command);
            if (e.result == "") {
                e.result = "未更改默认的ftp登陆警告Banner";
                e.IsComply = "false";
                e.recommend = "更改默认的ftp登陆警告Banner";
            }
            else {
                e.IsComply = "false";
            }
        }
        else {
            e.command = "None";
            e.result = "未安装vsftpd或者pure-ftpd";
            e.IsComply = "false";
            e.recommend = "安装vsftpd或者pure-ftpd";
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.32检查/usr/bin/目录下可执行文件的拥有者属性
    event checkBinOwner() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "为了保证信息安全的可靠性，需要检查可执行文件的拥有者属性";
        e.basis = "所有含有“s”属性的文件，把不必要的“s”属性去掉，或者把不用的直接删除。";
        e.command = "find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; ";
        e.result = "手动检查";
        e.IsComply = "pending";
        e.recommend = "s属性在运行时可以获得拥有者的权限，所以为了安全需要，需要做出修改";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.33 检查telnet Banner设置
    event checkTelnetBanner() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否更改默认的telnet登录警告Banner";
        e.basis = "请手动检查修改文件/etc/issue 和/etc/issue.net中的内容";
        e.recommend = "请手动检查修改文件/etc/issue 和/etc/issue.net中的内容";
        e.IsComply = "pending";
        e.result = "手动检查";
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.34 检查是否限制FTP用户登录后能访问的目录
    event checkFtpDirectory() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "1";
        e.description = "检查是否限制FTP用户登录后能访问的目录";
        e.basis = "应该限制FTP用户登录后能访问的目录";

        e.command = "ps -ef | grep ftp | grep -v grep";
        e.recommend = "为了保证信息安全的可靠性，需要限制FTP用户登录后能访问的目录";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result == "") {
            e.result = "没有FTP服务在运行，符合基线";
            e.IsComply = "true";
        }
        else {
            string command1 = "[ -f /etc/vsftpd/vsftpd.conf ] && grep '^chroot_local_user=NO' /etc/vsftpd/vsftpd.conf && grep '^chroot_list_enable=YES' /etc/vsftpd/vsftpd.conf && grep '^chroot_list_file=/etc/vsftpd/chroot_list' /etc/vsftpd/vsftpd.conf && echo \"All configurations are as expected\"";
            string result1 = execute_commands(guard.get(), command1);
            if (result1 == "") {
                e.result = "未限制FTP用户登录后能访问的目录，不符合基线";
                e.IsComply = "false";
            }
            else {
                e.IsComply = "true";
            }
        }
        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6.36 检查内核版本是否处于CVE-2021-43267漏洞影响版本
    event checkKernel_cve_2021_43267() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查内核版本是否处于CVE-2021-43267漏洞影响版本";
        e.basis = "内核版本不在5.10和5.14.16之间";
        //内核版本在5.10和5.14.16之间则输出版本号，不在则输出"不受CVE - 2021 - 43267影响"
        e.command = "kernel=$(uname -r | awk -F- '{print $1}'); kernel_major=$(echo $kernel | cut -d. -f1); kernel_minor=$(echo $kernel | cut -d. -f2); kernel_patch=$(echo $kernel | cut -d. -f3); if [[ \"$kernel_major\" -eq 5 && (\"$kernel_minor\" -gt 10 || (\"$kernel_minor\" -eq 10 && \"$kernel_patch\" -ge 0)) && (\"$kernel_minor\" -lt 14 || (\"$kernel_minor\" -eq 14 && \"$kernel_patch\" -lt 16)) ]]; then echo $kernel; else echo \"不受CVE - 2021 - 43267影响\"; fi";
        e.recommend = "内核版本不能在5.10和5.14.16之间";

        e.result = execute_commands(guard.get(), e.command);
        if (e.result.find("不受CVE - 2021 - 43267影响") != std::string::npos) {
            e.result = "内核版本不受CVE-2021-43267漏洞影响，符合基线";
            e.IsComply = "true";
        }
        else {
            e.IsComply = "false";
            e.recommend = "该内核范围存在漏洞，请升级内核或打上补丁";
        }

        //std::cout << "Completed check: " << e.description
        //    << " [ThreadID: " << std::this_thread::get_id()
        //    << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

};