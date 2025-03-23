#pragma once
#include "Event.h"
#include "Command_Excute.h"
#include <libssh/libssh.h>
#include <memory>
#include <future>
#include "ThreadPool.h"
#include "SSHConnectionPool.h"
#include <map>

class EventChecker {
public:
    EventChecker(size_t threadCount, SSHConnectionPool& pool)
        : threadPool(threadCount), sshPool(pool) {
        initializeCheckFunctions();
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

        

        // Check password lifetime
        //futures.push_back(threadPool.enqueue(&EventChecker::checkPasswordLifetime, this));

        // Check password min length
        //futures.push_back(threadPool.enqueue(&EventChecker::checkPasswordMinLength, this));

        // Check password warn days
        //futures.push_back(threadPool.enqueue(&EventChecker::checkPasswordWarnDays, this));

        // Check password complexity
        //futures.push_back(threadPool.enqueue(&EventChecker::checkPasswordComplex, this));

        // Check empty password
        //futures.push_back(threadPool.enqueue(&EventChecker::checkEmptyPassword, this));

        // Check UID 0 except root
        //futures.push_back(threadPool.enqueue(&EventChecker::checkUID0ExceptRoot, this));

        // Check umask settings
        //futures.push_back(threadPool.enqueue(&EventChecker::checkUmaskCshrc, this));
        //futures.push_back(threadPool.enqueue(&EventChecker::checkUmaskBashrc, this));
        //futures.push_back(threadPool.enqueue(&EventChecker::checkUmaskProfile, this));

        // 收集结果
        for (auto& future : futures) {
            events.push_back(future.get());
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

    void initializeCheckFunctions() {
        // 使用ID映射每个检查函数
        checkFunctions = {
            {1, std::bind(&EventChecker::checkPasswordLifetime, this)},
            {2, std::bind(&EventChecker::checkPasswordMinLength, this)},
            {3, std::bind(&EventChecker::checkPasswordWarnDays, this)},
            {4, std::bind(&EventChecker::checkPasswordComplex, this)},
            {5, std::bind(&EventChecker::checkEmptyPassword, this)},
            {6, std::bind(&EventChecker::checkUID0ExceptRoot, this)},
            {7, std::bind(&EventChecker::checkUmaskCshrc, this)},
            {8, std::bind(&EventChecker::checkUmaskBashrc, this)},
            {9, std::bind(&EventChecker::checkUmaskProfile, this)},
            {10, std::bind(&EventChecker::checkModXinetd, this)},
            {11, std::bind(&EventChecker::checkModGroup, this)},
            {12, std::bind(&EventChecker::checkModShadow, this)},
            {13, std::bind(&EventChecker::checkModServices, this)},
            {14, std::bind(&EventChecker::checkModSecurity, this)},
            {15, std::bind(&EventChecker::checkModPasswd, this)},
            {16, std::bind(&EventChecker::checkModRc6, this)},
            {17, std::bind(&EventChecker::checkModRc0, this)},
            {18, std::bind(&EventChecker::checkModRc1, this)},
            {19, std::bind(&EventChecker::checkModRc2, this)},
            {20, std::bind(&EventChecker::checkModEtc, this)},
            {21, std::bind(&EventChecker::checkModRc4, this)},
            {22, std::bind(&EventChecker::checkModRc5, this)},
            {23, std::bind(&EventChecker::checkModRc3, this)},
            {24, std::bind(&EventChecker::checkModInit, this)},
            {25, std::bind(&EventChecker::checkModTmp, this)},
            {26, std::bind(&EventChecker::checkModGrub, this)},
            {27, std::bind(&EventChecker::checkModGrubGrub, this)},
            {28, std::bind(&EventChecker::checkModLilo, this)},
            {29, std::bind(&EventChecker::checkAttributePasswd, this)},
            {30, std::bind(&EventChecker::checkAttributeShadow, this)},
            {31, std::bind(&EventChecker::checkAttributeGroup, this)},
            {32, std::bind(&EventChecker::checkAttributeGshadow, this)},
            {33, std::bind(&EventChecker::checkUmaskLogin, this)},
            {34, std::bind(&EventChecker::checkSshBanner, this)},
            {35, std::bind(&EventChecker::checkeNg, this)},
            {36, std::bind(&EventChecker::checkRsyslog, this)},
            {37, std::bind(&EventChecker::checkSyslog, this)},
            {38, std::bind(&EventChecker::checkSyslogNgSafe, this)},
            {39, std::bind(&EventChecker::checkRsyslogSafe, this)},
            {40, std::bind(&EventChecker::checkSyslogSafe, this)},
            {41, std::bind(&EventChecker::checkCron, this)},
            {42, std::bind(&EventChecker::checkSecure, this)},
            {43, std::bind(&EventChecker::checkMessage, this)},
            {44, std::bind(&EventChecker::checkBootLog, this)},
            {45, std::bind(&EventChecker::checkMail, this)},
            {46, std::bind(&EventChecker::checkSpooler, this)},
            {47, std::bind(&EventChecker::checkLocalMessages, this)},
            {48, std::bind(&EventChecker::checkMaillog, this)},
            {49, std::bind(&EventChecker::checkLast, this)},
            {50, std::bind(&EventChecker::checkSuLog, this)},
            {51, std::bind(&EventChecker::checkOpensshConfig, this)},
            {52, std::bind(&EventChecker::checkRunningSnmp, this)},
            {53, std::bind(&EventChecker::checkSnmpConfig, this)},
            {54, std::bind(&EventChecker::checkSshConfig, this)},
            {55, std::bind(&EventChecker::checkTelnetConfig, this)},
            {56, std::bind(&EventChecker::checkRunningFtp, this)},
            {57, std::bind(&EventChecker::checkFtpConfig, this)},
            {58, std::bind(&EventChecker::checkAnonymousFtp, this)},
            {59, std::bind(&EventChecker::checkCmdTimeout, this)},
            {60, std::bind(&EventChecker::checkPasswordBootloader, this)},
            {61, std::bind(&EventChecker::checkCoreDump, this)},
            {62, std::bind(&EventChecker::checkHistSize, this)},
            {63, std::bind(&EventChecker::checkGroupWheel, this)},
            {64, std::bind(&EventChecker::checkInterLogin, this)},
            {65, std::bind(&EventChecker::checkPasswordRepeatlimit, this)},
            {66, std::bind(&EventChecker::checkAuthFailtimes, this)},
            {67, std::bind(&EventChecker::checkMultiIp, this)},
            {68, std::bind(&EventChecker::checkLoginRemoteIp, this)},
            {69, std::bind(&EventChecker::checkAliasesUnnecessary, this)},
            {70, std::bind(&EventChecker::checkPermSuidSgid, this)},
            {71, std::bind(&EventChecker::checkScreenAutolock, this)},
            {72, std::bind(&EventChecker::checkTcpSyncookies, this)},
            {73, std::bind(&EventChecker::checkGroupManage, this)},
            {74, std::bind(&EventChecker::checkRootPathCheck, this)},
            {75, std::bind(&EventChecker::checkCtrlAltDelDisabled, this)},
            {76, std::bind(&EventChecker::checkSysTrustMechanism, this)},
            {77, std::bind(&EventChecker::checkDiskPartitionUsageRate, this)},
            {78, std::bind(&EventChecker::checkPotentialRiskFiles, this)},
            {79, std::bind(&EventChecker::checkUserMinPermission, this)},
            {80, std::bind(&EventChecker::checkPacketForwardFunc, this)},
            {81, std::bind(&EventChecker::checkNtpSyncStatus, this)},
            {82, std::bind(&EventChecker::checkNfsServer, this)},
            {83, std::bind(&EventChecker::checkSshBanner2, this)},
            {84, std::bind(&EventChecker::checkUploadFtp, this)},
            {85, std::bind(&EventChecker::checkFtpBaner, this)},
            {86, std::bind(&EventChecker::checkBinOwner, this)},
            {87, std::bind(&EventChecker::checkTelnetBanner, this)},
            {88, std::bind(&EventChecker::checkFtpDirectory, this)},
            {89, std::bind(&EventChecker::checkKernel_cve_2021_43267, this)}
        };
    }

    event checkPasswordLifetime() {
        SSHConnectionGuard guard(sshPool);//guard 从 sshPool 获取一个空闲的 SSH 连接
        event e;
        e.description = "检查口令生存周期";
        e.basis = "<=90";
        e.command = "cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}' ";
        e.result = execute_commands(guard.get(), e.command);//guard.get() 获取 ssh_session 对象，在该对象上执行命令。
        e.recommend = "口令生存周期为不大于3个月的时间";
        e.importantLevel = "3";

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

        }
        else
        {
            e.result = "未开启";
            e.recommend = "开启口令生存周期要求";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        e.basis = ">=30";
        e.command = "cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#| awk '{print $2}' ";
        e.result = execute_commands(guard.get(), e.command);
        e.recommend = "口令过期前应至少提前30天警告";
        e.importantLevel = "3";
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
                    e.IsComply = "true";
                }
                else
                {
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

        if (e.result.compare("") == 0)
        {
            e.IsComply = "true";
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
        if (e.result.compare("") == 0)
        {
            e.result= "普通用户的UID全为非0";
            e.IsComply = "true";
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/csh.cshrc 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "cat /etc/csh.cshrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                if (e.result.compare("077") || e.result.compare("027"))
                {
                    e.IsComply = "true";
                }
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启/etc/csh.cshrc中的用户umask设置，且umask应为027或者077";
            }
        }
        if (!findFile)
        {
            e.result = "未找到配置文件";
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
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/bashrc 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "/bin/cat /etc/bashrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                if (e.result.compare("077") || e.result.compare("027"))
                {
                    e.IsComply = "true";
                }
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
        //fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
        //将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
        string fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
        fileIsExist = execute_commands(guard.get(), fileIsExist);
        bool findFile = false;

        if (fileIsExist.compare("") == 0)
        {
            findFile = true;

            e.command = "/bin/cat /etc/profile| grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
            e.result = execute_commands(guard.get(), e.command);

            if (e.result.compare(""))
            {
                if (e.result.compare("077") || e.result.compare("027"))
                {
                    e.IsComply = "true";
                }
            }
            else
            {
                e.result = "未开启";
                e.recommend = "开启/etc/profile中的用户umask设置，且umask应为027或者077";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

            e.command = "stat -c %a /tmp | tr -d ' ' | tr -d '\n'";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        e.recommend = "/var/log/cron日志文件other用户不可写";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        e.recommend = "/var/log/secure日志文件other用户不可写";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        e.recommend = "/var/log/messages日志文件other用户不可写";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        e.recommend = "/var/log/spooler日志文件other用户不可写";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        string command_Iscomply = "ls -l /var/log/maillog | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
        e.IsComply = execute_commands(guard.get(), command_Iscomply);
        e.recommend = "应/var/log/maillog日志文件other用户不可写";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
            e.result = "已对登录进行日志记录,结果太长，已忽略";
            e.IsComply = "true";
        }
        e.recommend = "要对登录进行日志记录";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
            temp = "false";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

    //6其他配置操作
    //6.1检查是否设置命令行界面超时退出
    event checkCmdTimeout() {
        SSHConnectionGuard guard(sshPool);
        event e;
        e.importantLevel = "3";
        e.description = "检查是否设置命令行界面超时退出";
        e.basis = "开启TMOUT且TMOUNT<=600";
        e.recommend = "建议命令行界面超时自动登出时间TMOUT应不大于600s，检查项建议系统管理员根据系统情况自行判断";

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
            }
            else
            {
                e.result = "未开启TMOUT设置";
                e.recommend = "开启/etc/profile中的TMOUT设置，且TMOUT值应不大于600";
            }
        }

        if (!findFile)
        {
            e.result = "未找到配置文件";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        else if (!passwordFound) {
            e.result = "已找到引导管理器配置文件，但未检测到密码设置，建议配置密码以增强安全性。";
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

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
        }

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";

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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        }
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        e.IsComply = "false";
        e.recommend = "s属性在运行时可以获得拥有者的权限，所以为了安全需要，需要做出修改";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        e.IsComply = "false";
        e.result = "手动检查";
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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
        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
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

        std::cout << "Completed check: " << e.description
            << " [ThreadID: " << std::this_thread::get_id()
            << ", SSHConnectionID: " << guard.getConnectionID() << "]\n";
        return e;
    }

};