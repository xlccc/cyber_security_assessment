#include"ServerManager.h"
#include"windowsbaseline.h"
#include"execute_win.h"
// 左右结构读取函数
std::string parseValueFromOutput(const std::string& output, const std::string& keyword) {
    // 查找关键词在输出中的位置
    size_t pos = output.find(keyword);
    if (pos == std::string::npos) {
        return "";  // 未找到关键词，返回空字符串
    }
    // 找到关键词后面的第一个非空白字符
    size_t start = output.find_first_not_of(" \t\r\n", pos + keyword.size());
    if (start == std::string::npos) {
        return "";  // 没有找到有效值
    }

    // 查找值的结尾，可以使用空格、换行符等作为终止符
    size_t end = output.find_first_of(" \t\r\n", start);
    if (end == std::string::npos) {
        end = output.size();  // 如果没有找到终止符，取到字符串末尾
    }

    return output.substr(start, end - start);  // 返回提取的字符串
}
//上下结构读取函数
std::string parseCommandOutput(const std::string& output) {
    std::istringstream stream(output);
    std::string line, result;
    // 跳过第一行（标题）
    if (std::getline(stream, line)) {
        // 读取第二行（真正的数据）
        if (std::getline(stream, result)) {
            // 去除前后空格和换行符
            result.erase(0, result.find_first_not_of(" \n\r\t"));
            result.erase(result.find_last_not_of(" \n\r\t") + 1);
            return result;
        }
    }

    return "Unknown"; // 如果没有数据，返回 "Unknown"
}

int getExitCode(std::string input) {
    // 找到冒号的位置
    size_t colonPos = input.find(':');
    if (colonPos == std::string::npos) {
        throw std::invalid_argument("Invalid format: No colon found");
    }
    // 提取冒号之前的子串并转换为整数
    input = input.substr(0, colonPos);
    return std::stoi(input);
}

std::string getEcho(std::string input) {
    std::regex pattern(":([a-zA-Z0-9]+)");  // 匹配冒号后的字母数字
    std::smatch matches;

    if (std::regex_search(input, matches, pattern)) {
        return matches[1].str();  // 返回第一个捕获组
    }
    return "";
}
//// 创建 SSHClient 对象，连接到远程服务器（在调用整个函数的时候使用）
//SSHClient sshClient(ip, port, username, password);

//判断windows操作系统版本
std::string getWindowsVersion(SSHClient& sshClient) {
    std::string command = "wmic os get Version";
    std::string version_info = sshClient.executeCommand(command);

    // 去除换行和空格
    version_info.erase(0, version_info.find_first_not_of(" \n\r\t"));
    version_info.erase(version_info.find_last_not_of(" \n\r\t") + 1);

    // 查找版本号起始位置（跳过 "Version" 字样）
    size_t pos = version_info.find("10.0.");
    if (pos == std::string::npos) {
        pos = version_info.find("6.");
    }

    if (pos == std::string::npos) {
        return "Unknown Windows version";  // 未找到版本号
    }

    std::string version = version_info.substr(pos);

    // 判断 Windows 版本
    if (version.find("6.1") == 0) {
        return "Windows 7";
    }
    else if (version.find("6.2") == 0) {
        return "Windows 8";
    }
    else if (version.find("10.0.") == 0) {  // Windows 10 / 11 / Server
        size_t start = version.find("10.0.") + 5;
        int buildNumber = std::stoi(version.substr(start));

        if (buildNumber >= 22000) {
            return "Windows 11";
        }
        else if (buildNumber >= 10240 && buildNumber <= 19046) {
            return "Windows 10";
        }
        else if (buildNumber == 14393) {
            return "Windows Server 2016";
        }
        else if (buildNumber == 17763) {
            return "Windows Server 2019";
        }
        else if (buildNumber == 19042) {
            return "Windows Server 2022";
        }
    }

    return "Unknown Windows version";
}


//定义六十条检测命令，将每条命令放入有key值的map容器,利用key值进行编号
void initialize_basline(vector<event_t>& Event, map<int, event_t>& allBaseline ,SSHClient& sshClient)

{
    int i = 0;//记录命令的key值
    // 获取当前Windows版本
    string osVersion = getWindowsVersion(sshClient);

    // 设置不同版本的检测阈值
    struct ThresholdConfig {
        int passwordMinLength;
        int passwordHistory;
        int passwordMaxAge;
        int accountLockThreshold;
        int logFileMaxSize;
       
    };

    // 默认配置（windows普通版本）
    ThresholdConfig thresholds = {
        12,  // 密码最小长度
        5,   // 密码历史
        90,  // 密码最大使用期限(天)
        6,   // 账户锁定阈值
        8192 // 日志文件最大大小(KB)
      
    };

    // 根据操作系统版本调整阈值
    if (osVersion.find("Server") != std::string::npos) {
        // 服务器版本使用更严格的标准
        thresholds.passwordMinLength = 14;
        thresholds.passwordHistory = 24;
        thresholds.passwordMaxAge = 60;
        thresholds.accountLockThreshold = 5; 
        thresholds.logFileMaxSize = 16384;        
    }
  

    // 然后检测项使用以下方式判断
   
        // 执行检测项1
   

    //1、检查密码长度最小值：验证最小密码长度是否小于12。
    event_t password_min_length;
    password_min_length.description = "检查Windows密码最小长度";
    password_min_length.basis = "密码最小长度应该限制为" + std::to_string(thresholds.passwordMinLength) + "或更高";
    password_min_length.command = "net accounts";
    password_min_length.recommend = "为了保证信息安全，密码最小长度应该大于或等于"+ std::to_string(thresholds.passwordMinLength);

    password_min_length.result = sshClient.executeCommand(password_min_length.command);
    //编码转换，防止出现中文乱码
    password_min_length.result = convertEncoding(password_min_length.result, "GB2312", "UTF-8");
    if (password_min_length.result == "") {
        password_min_length.result = "未能获取密码最小长度信息";
        password_min_length.IsComply = "false";
    }
    else {
        // 解析命令输出获取最小密码长度
        string minpasswordLength = parseValueFromOutput(password_min_length.result, "密码长度最小值:");
        int minPasswordLength_value = atoi(minpasswordLength.c_str());  // 转换为整数
        if (minPasswordLength_value == -1) {
            password_min_length.result = "未能解析密码最小长度";
            password_min_length.IsComply = "false";
        }
        else {
            if (minPasswordLength_value >= thresholds.passwordMinLength) {
                password_min_length.result = "密码最小长度为" + minpasswordLength +"，符合基线";
                password_min_length.IsComply = "true";
            }
            else {
                password_min_length.result = "密码最小长度为" + minpasswordLength+"，小于"+ std::to_string(thresholds.passwordMinLength);
                password_min_length.IsComply = "false";
            }
        }
    }
    Event.push_back(password_min_length);
    allBaseline[i++] = password_min_length;

    //2、 检查是否已启用密码复杂性要求：确认密码复杂性设置是否启用。
    event_t password_complexity_enabled;
   
    password_complexity_enabled.description = "检查Windows密码复杂性要求是否启用";
    password_complexity_enabled.basis = "密码复杂性要求应启用以增加安全性";
    password_complexity_enabled.command = executeRemotePSScript(Win_REMOTEPATH+"2_password_complexity_enabled.ps1");
    password_complexity_enabled.recommend = "为了提高安全性，建议启用密码复杂性要求";
    password_complexity_enabled.result = sshClient.executeCommand(password_complexity_enabled.command);
    password_complexity_enabled.result = extractResultCode(password_complexity_enabled.result);
    int password_complexity_enabled_value = stoi(password_complexity_enabled.result);

    if (password_complexity_enabled_value == -1) {
        password_complexity_enabled.result = "未能获取密码复杂性要求信息";
            password_complexity_enabled.IsComply = "false";
    }
    else {
        // 解析命令输出，确认是否启用了密码复杂性要求
        if (password_complexity_enabled_value == 1) {
            password_complexity_enabled.IsComply = "true";
            password_complexity_enabled.result = "已启用,符合基线";
        }
        else if(password_complexity_enabled_value == 0) {
            password_complexity_enabled.result = "密码复杂性要求未启用";
            password_complexity_enabled.IsComply = "false";
        }
    }
    Event.push_back(password_complexity_enabled);
     allBaseline[i++] = password_complexity_enabled;


    // 3、检查是否已禁用来宾 (Guest) 帐户：验证来宾账户状态是否为禁用

    event_t guest_account_disabled;
    
    guest_account_disabled.description = "检查Windows来宾账户是否禁用";
    guest_account_disabled.basis = "来宾账户应被禁用以增强系统安全性";
    guest_account_disabled.command = "net user guest";
    guest_account_disabled.recommend = "为了提高安全性，应禁用来宾账户";
    guest_account_disabled.result = sshClient.executeCommand(guest_account_disabled.command);
    guest_account_disabled.result = convertEncoding(guest_account_disabled.result, "GB2312", "UTF-8");
    if (guest_account_disabled.result == "") {
        guest_account_disabled.result = "未能获取来宾账户状态信息";
        guest_account_disabled.IsComply = "false";
    }
    else {
        // 检查命令输出，确认来宾账户是否禁用
        string guestaccount = parseValueFromOutput(password_min_length.result, "帐户启用");
        if (guestaccount == "No") {
            guest_account_disabled.IsComply = "true";
            guest_account_disabled.result = "已禁用，符合基线";
        }
        else {
            guest_account_disabled.result = "来宾账户未禁用";
            guest_account_disabled.IsComply = "false";
        }
    }
    Event.push_back(guest_account_disabled);
     allBaseline[i++] = guest_account_disabled;


    //4、检查“强制密码历史”个数：验证密码历史的数量是否小于5。

    event_t password_history_check;
   
    password_history_check.description = "检查强制密码历史的个数是否小于" + std::to_string(thresholds.passwordHistory);
    password_history_check.basis = "强制密码历史有助于防止用户重复使用之前的密码，从而增强安全性";
    password_history_check.command = executeRemotePSScript(Win_REMOTEPATH+"4_password_history_check.ps1");
    password_history_check.recommend = "为了提高安全性，密码历史应设置为至少保留" + std::to_string(thresholds.passwordHistory)+"个历史密码";

    password_history_check.result = sshClient.executeCommand(password_history_check.command);
    password_history_check.result = extractResultCode(password_history_check.result);
    int password_history_check_value = stoi(password_history_check.result);

    if (password_history_check_value == -1) {
        password_history_check.result = "未能获取密码历史设置";
        password_history_check.IsComply = "false";
    }
    else {
        // 查找命令输出中的“密码历史”部分，并解析历史密码的数量
        if (password_history_check_value >= thresholds.passwordHistory) {
            password_history_check.IsComply = "true";
            password_history_check.result = "密码历史个数为" + password_history_check.result +",符合基线";
        }
        else {
            password_history_check.result = "密码历史个数为" + password_history_check.result +"，小于" + std::to_string(thresholds.passwordHistory);
            password_history_check.IsComply = "false";
        }
    }
    Event.push_back(password_history_check);
     allBaseline[i++] = password_history_check;


    //5、检查已启用的本地用户的个数：确认本地启用用户是否少于2。
    event_t local_user_check;
  
    local_user_check.description = "检查已启用的本地用户的个数是否少于2";
    local_user_check.basis = "过多的已启用本地用户可能会增加系统的安全风险，应限制启用的本地用户数量";
    local_user_check.command = executeRemotePSScript(Win_REMOTEPATH+"5_local_user_check.ps1");
    local_user_check.recommend = "为了提高安全性，建议启用的本地用户个数应少于2";
    local_user_check.result = sshClient.executeCommand(local_user_check.command);

    if (local_user_check.result == "") {
        local_user_check.result = "未能获取本地用户列表";
        local_user_check.IsComply = "false";
    }
    else {
        // 查找命令输出中的已启用用户数量
        int enabled_user_count = stoi(local_user_check.result);
        if (enabled_user_count < 2) {
            local_user_check.result = "启用的本地用户个数为"+ std::to_string(enabled_user_count) + ",符合基线";
            local_user_check.IsComply = "true";
        }
        else {
            local_user_check.result = "启用的本地用户个数为" +  std::to_string(enabled_user_count)+"，大于或等于2";
            local_user_check.IsComply = "false";
        }
    }
    Event.push_back(local_user_check);
     allBaseline[i++] = local_user_check;

    //6、检查密码最长使用期限：验证密码最大有效期是否少于90天。
    event_t password_max_age;
  
    password_max_age.description = "检查Windows密码最长使用期限";
    password_max_age.basis = "密码最长使用期限应该小于或等于"+std::to_string(thresholds.passwordMaxAge)+"天";
    password_max_age.command = "net accounts";
    password_max_age.recommend = "为了保证信息安全，密码最大使用期限应该设置为" + std::to_string(thresholds.passwordMaxAge) + "天或更短";
    password_max_age.result = sshClient.executeCommand(password_max_age.command);
    password_max_age.result = convertEncoding(password_max_age.result, "GB2312", "UTF-8");
    if (password_max_age.result == "") {
        password_max_age.result = "未能获取密码最长使用期限信息";
        password_max_age.IsComply = "false";
    }
    else {
        // 解析命令输出获取最大密码有效期
        string maxPasswordAge = parseValueFromOutput(password_max_age.result, "密码最长使用期限(天):");
       
        if (maxPasswordAge == "") {
            password_max_age.result = "未能解析密码最大有效期";
            password_max_age.IsComply = "false";
        }
        else {
            int maxPasswordAgeValue = stoi(maxPasswordAge);  // 转换为整数
            if (maxPasswordAgeValue <= thresholds.passwordMaxAge) {
                password_max_age.result = "密码最大使用期限为" + maxPasswordAge + "天，符合基线";
                password_max_age.IsComply = "true";
            }
            else {
                password_max_age.result = "密码最大使用期限为" + maxPasswordAge + "天,超过" + std::to_string(thresholds.passwordMaxAge) + "天";
                password_max_age.IsComply = "false";
            }
        }
    }
    Event.push_back(password_max_age);
     allBaseline[i++] = password_max_age;

    //7、检查密码最长使用期限是否不为0：确认密码有效期是否为0。
    event_t password_max_age_zero;
  
    password_max_age_zero.description = "检查密码最长使用期限是否不为0";
    password_max_age_zero.basis = "密码最长使用期限应大于0，以确保密码不会被设置为永不过期";
    password_max_age_zero.command = "net accounts";
    password_max_age_zero.recommend = "为了提高安全性，密码最大使用期限不应为0";
    password_max_age_zero.result = sshClient.executeCommand(password_max_age_zero.command);
    password_max_age_zero.result = convertEncoding(password_max_age_zero.result, "GB2312", "UTF-8");
    if (password_max_age_zero.result == "") {
        password_max_age_zero.result = "未能获取密码最长使用期限信息";
        password_max_age_zero.IsComply = "false";
    }
    else {
        // 解析命令输出获取最大密码有效期
        string maxPasswordAge = parseValueFromOutput(password_max_age_zero.result, "密码最长使用期限(天):");
        
        if (maxPasswordAge == "") {
            password_max_age_zero.result = "未能解析密码最大有效期";
            password_max_age_zero.IsComply = "false";
        }
        else {
            int maxPasswordAgeValue = atoi(maxPasswordAge.c_str());  // 转换为整数
            if (maxPasswordAgeValue > 0) {
                password_max_age_zero.result = "密码最大使用期限为"+ maxPasswordAge+"天，符合基线";
                password_max_age_zero.IsComply = "true";
            }
            else {
                password_max_age_zero.result = "密码最大使用期限为0";
                password_max_age_zero.IsComply = "false";
            }
        }
    }
    Event.push_back(password_max_age_zero);
     allBaseline[i++] = password_max_age_zero;

    //8、检查帐户锁定阈值：验证帐户锁定阈值是否小于6。
    event_t account_lock_threshold_check;
  
    account_lock_threshold_check.description = "检查帐户锁定阈值是否小于" + std::to_string(thresholds.accountLockThreshold);
    account_lock_threshold_check.basis = "帐户锁定阈值过低可能会导致正常用户帐户被意外锁定";
    account_lock_threshold_check.command = "net accounts";
    account_lock_threshold_check.recommend = "为了确保安全性，帐户锁定阈值应设置为大于或等于"+std::to_string(thresholds.accountLockThreshold);
    account_lock_threshold_check.result = sshClient.executeCommand(account_lock_threshold_check.command);
    account_lock_threshold_check.result= convertEncoding(account_lock_threshold_check.result, "GB2312", "UTF-8");
    if (account_lock_threshold_check.result == "") {
        account_lock_threshold_check.result = "未能获取帐户锁定阈值信息";
        account_lock_threshold_check.IsComply = "false";
    }
    else {
        // 解析命令输出获取帐户锁定阈值
        string lockThreshold = parseValueFromOutput(account_lock_threshold_check.result, "锁定阈值:");
       
        if (lockThreshold == "") {
            account_lock_threshold_check.result = "未能解析帐户锁定阈值";
            account_lock_threshold_check.IsComply = "false";
        }
        else {
            int lockThresholdValue = atoi(lockThreshold.c_str());  // 转换为整数
            if (lockThresholdValue < thresholds.accountLockThreshold) {
                account_lock_threshold_check.result = "帐户锁定阈值小于"+std::to_string(thresholds.accountLockThreshold);
                account_lock_threshold_check.IsComply = "false";
            }
            else {
                account_lock_threshold_check.result = "帐户锁定阈值为" + lockThreshold+"，符合基线";
                account_lock_threshold_check.IsComply = "true";
            }
        }
    }
    Event.push_back(account_lock_threshold_check);
     allBaseline[i++] = account_lock_threshold_check;

    //9、检查帐户锁定阈值是否不为0：确认锁定阈值是否为0。
    event_t account_lock_threshold_non_zero_check;
    
    account_lock_threshold_non_zero_check.description = "检查帐户锁定阈值是否不为0";
    account_lock_threshold_non_zero_check.basis = "帐户锁定阈值为0时，可能导致用户帐户永远不会被锁定，增加安全风险";
    account_lock_threshold_non_zero_check.command = "net accounts";
    account_lock_threshold_non_zero_check.recommend = "为了提高安全性，帐户锁定阈值应大于0";
    account_lock_threshold_non_zero_check.result = sshClient.executeCommand(account_lock_threshold_non_zero_check.command);
    account_lock_threshold_non_zero_check.result = convertEncoding(account_lock_threshold_non_zero_check.result, "GB2312", "UTF-8");
    if (account_lock_threshold_non_zero_check.result == "") {
        account_lock_threshold_non_zero_check.result = "未能获取帐户锁定阈值信息";
        account_lock_threshold_non_zero_check.IsComply = "false";
    }
    else {
        // 解析命令输出获取帐户锁定阈值
        string lockThreshold = parseValueFromOutput(account_lock_threshold_non_zero_check.result, "锁定阈值:");
   
        if (lockThreshold == "") {
            account_lock_threshold_non_zero_check.result = "未能解析帐户锁定阈值";
            account_lock_threshold_non_zero_check.IsComply = "false";
        }
        else {
            int lockThresholdValue = atoi(lockThreshold.c_str());  // 转换为整数
            if (lockThresholdValue == 0) {
                account_lock_threshold_non_zero_check.result = "帐户锁定阈值为0";
                account_lock_threshold_non_zero_check.IsComply = "false";
            }
            else {
                account_lock_threshold_non_zero_check.result = "帐户锁定阈值为"+ lockThreshold+"，符合基线";
                account_lock_threshold_non_zero_check.IsComply = "true";
            }
        }
    }
    Event.push_back(account_lock_threshold_non_zero_check);
     allBaseline[i++] = account_lock_threshold_non_zero_check;

   //10、检查“取得文件或其它对象的所有权”的帐户和组：检查管理员组的配置
    event_t check_take_ownership_account_group;
 
    check_take_ownership_account_group.description = "检查取得文件或其它对象的所有权的帐户和组";
    check_take_ownership_account_group.basis = "只有授权的账户和组才能拥有敏感文件或对象的所有权，避免未经授权的权限滥用";
    check_take_ownership_account_group.command = executeRemotePSScript(Win_REMOTEPATH+"10_check_take_ownership_account_group.ps1");
    check_take_ownership_account_group.recommend = "确保取得文件或其它对象的所有权功能仅由管理员或受信任的账户进行配置";
    check_take_ownership_account_group.result = sshClient.executeCommand(check_take_ownership_account_group.command);
    check_take_ownership_account_group.result = extractResultCode(check_take_ownership_account_group.result);
    // 解析命令输出并查找“取得文件或其它对象的所有权”配置
     int takeOwnershipGroup = stoi(check_take_ownership_account_group.result);
    if (takeOwnershipGroup == -1) {
        check_take_ownership_account_group.result = "未能获取文件或对象的所有权配置";
        check_take_ownership_account_group.IsComply = "false";
    }
    else {
            // 检查是否存在未经授权的账户或组
            if (takeOwnershipGroup == 1) {
                check_take_ownership_account_group.result = "符合基线";
                check_take_ownership_account_group.IsComply = "true";
            }
            else if(takeOwnershipGroup == 0) {
                check_take_ownership_account_group.result = "取得文件或其它对象的所有权配置不符合要求";
                check_take_ownership_account_group.IsComply = "false";
            }
        }
    Event.push_back(check_take_ownership_account_group);
     allBaseline[i++] = check_take_ownership_account_group;

//11、检查可从远端关闭系统的帐户和组：同样检查管理员组的配置。
    event_t check_remote_shutdown_account_group;
   
    check_remote_shutdown_account_group.description = "检查可从远端关闭系统的帐户和组";
    check_remote_shutdown_account_group.basis = "为了防止未经授权的人员远程关闭系统，应该只允许管理员或受信任的账户具有此权限";
    check_remote_shutdown_account_group.command = executeRemotePSScript(Win_REMOTEPATH+"11_check_remote_shutdown_account_group.ps1");
    check_remote_shutdown_account_group.recommend = "确保只有授权账户（如管理员或受信任账户）可以远程关闭系统";
    check_remote_shutdown_account_group.result = sshClient.executeCommand(check_remote_shutdown_account_group.command);
    check_remote_shutdown_account_group.result = extractResultCode(check_remote_shutdown_account_group.result);
    int check_remote_shutdown_account_group_value = stoi(check_remote_shutdown_account_group.result);

    if (check_remote_shutdown_account_group_value == -1) {
        check_remote_shutdown_account_group.result = "未能获取远程关机权限配置";
        check_remote_shutdown_account_group.IsComply = "false";
    }
    else {
            // 检查是否存在未经授权的账户或组
            if (check_remote_shutdown_account_group_value == 1) {
                check_remote_shutdown_account_group.result = "符合基线";
                check_remote_shutdown_account_group.IsComply = "true";
            }
            else if(check_remote_shutdown_account_group_value == 0) {
                check_remote_shutdown_account_group.result = "远程关机权限配置不符合要求";
                check_remote_shutdown_account_group.IsComply = "false";
            }
        }
    Event.push_back(check_remote_shutdown_account_group);
     allBaseline[i++] = check_remote_shutdown_account_group;

    //12、检查是否已禁止 SAM 帐户的匿名枚举：检查注册表设置。
    event_t check_sam_account_anonymous_enum;
   
    check_sam_account_anonymous_enum.description = "检查是否已禁止 SAM 帐户的匿名枚举";
    check_sam_account_anonymous_enum.basis = "为了防止匿名访问者枚举本地帐户，应该禁用 SAM 帐户的匿名枚举";
    check_sam_account_anonymous_enum.command = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM";
    check_sam_account_anonymous_enum.recommend = "确保已配置注册表设置以禁用 SAM 帐户的匿名枚举";
    check_sam_account_anonymous_enum.result = sshClient.executeCommand(check_sam_account_anonymous_enum.command);

    if (check_sam_account_anonymous_enum.result == "") {
        check_sam_account_anonymous_enum.result = "未能获取 SAM 帐户匿名枚举配置";
        check_sam_account_anonymous_enum.IsComply = "false";
    }
    else {
            string restrictAnonymousValue = parseValueFromOutput(check_sam_account_anonymous_enum.result, "REG_DWORD");

            if (restrictAnonymousValue == "0x0") {
                check_sam_account_anonymous_enum.result = "SAM 帐户匿名枚举未被禁用";
                check_sam_account_anonymous_enum.IsComply = "false";
            }
            else if (restrictAnonymousValue =="0x1" || restrictAnonymousValue == "0x2") {
                check_sam_account_anonymous_enum.result = "已禁用，符合基线";
                check_sam_account_anonymous_enum.IsComply = "true";
            }
            else {
                check_sam_account_anonymous_enum.result = "未知的注册表配置值";
                check_sam_account_anonymous_enum.IsComply = "false";
            }
        }
    Event.push_back(check_sam_account_anonymous_enum);
     allBaseline[i++] = check_sam_account_anonymous_enum;

    //13、检查是否已禁止共享的匿名枚举：检查注册表设置
    event_t check_account_anonymous_enum;
   
    check_account_anonymous_enum.description = "检查是否已禁止帐户的匿名枚举";
    check_account_anonymous_enum.basis = "为了防止匿名访问者枚举本地帐户，应该禁用帐户的匿名枚举";
    check_account_anonymous_enum.command = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous";
    check_account_anonymous_enum.recommend = "确保已配置注册表设置以禁用帐户的匿名枚举";
    check_account_anonymous_enum.result = sshClient.executeCommand(check_account_anonymous_enum.command);

    if (check_account_anonymous_enum.result == "") {
        check_account_anonymous_enum.result = "未能获取帐户匿名枚举配置";
        check_account_anonymous_enum.IsComply = "false";
    }
    else {
        string restrictAnonymousValue = parseValueFromOutput(check_account_anonymous_enum.result, "REG_DWORD");

        if (restrictAnonymousValue == "0x0") {
            check_account_anonymous_enum.result = "帐户匿名枚举未被禁用";
            check_account_anonymous_enum.IsComply = "false";
        }
        else if (restrictAnonymousValue == "0x1" || restrictAnonymousValue == "0x2") {
            check_account_anonymous_enum.result = "已禁用，符合基线";
            check_account_anonymous_enum.IsComply = "true";
        }
        else {
            check_account_anonymous_enum.result = "未知的注册表配置值";
            check_account_anonymous_enum.IsComply = "false";
        }
    }
    Event.push_back(check_account_anonymous_enum);
     allBaseline[i++] = check_account_anonymous_enum;

//14、检查可远程访问的注册表路径：检查注册表是否可远程访问
    event_t check_registry_remote_access;

    check_registry_remote_access.description = "检查注册表是否可远程访问";
    check_registry_remote_access.basis = "远程访问注册表可能允许未授权用户获取系统信息或修改关键设置，应该限制远程注册表访问以提高系统安全性";
    check_registry_remote_access.command = "sc qc RemoteRegistry | findstr START_TYPE";
    check_registry_remote_access.recommend = "禁用访问远程注册表服务";
    check_registry_remote_access.result = sshClient.executeCommand(check_registry_remote_access.command);
    if (check_registry_remote_access.result == "") {
        check_registry_remote_access.result = "未能获取远程注册表服务状态";
        check_registry_remote_access.IsComply = "false";
    }
    else {
        // 检查输出中是否包含服务已禁用的信息
        if (check_registry_remote_access.result.find("4   DISABLED") != string::npos) {
            check_registry_remote_access.result = "已禁用，符合基线";
            check_registry_remote_access.IsComply = "true";
        }
        else {
            check_registry_remote_access.result = "远程注册表服务未被禁用";
            check_registry_remote_access.IsComply = "false";
        }
    }
    Event.push_back(check_registry_remote_access);
     allBaseline[i++] = check_registry_remote_access;

//15、检查可匿名访问的共享：检查是否有共享文件夹可以匿名访问
    event_t check_anonymous_share;
    check_anonymous_share.description = "检查共享信息是否含有匿名访问相关标识";
    check_anonymous_share.basis = "共享设置中允许匿名访问可能导致未授权用户访问系统文件，增加安全风险";
    check_anonymous_share.command = "net share";
    check_anonymous_share.recommend = "确保所有共享目录不允许匿名访问，并限制共享权限为授权用户";
    check_anonymous_share.result = sshClient.executeCommand(check_anonymous_share.command);
    check_anonymous_share.result = convertEncoding(check_anonymous_share.result, "GB2312", "UTF-8");
    if (check_anonymous_share.result == "") {
        check_anonymous_share.result = "未能获取共享信息";
        check_anonymous_share.IsComply = "false";
    }
    else {
        // 解析命令输出，检查是否包含“Everyone”或“所有人”
        if (check_anonymous_share.result.find("Everyone") != string::npos ||
            check_anonymous_share.result.find("所有人") != string::npos) {
            check_anonymous_share.result = "检测到共享允许匿名访问（Everyone/所有人）";
            check_anonymous_share.IsComply = "false";
        }
        else {
            check_anonymous_share.IsComply = "true";
            check_anonymous_share.result = "符合基线";
        }
    }

    Event.push_back(check_anonymous_share);
     allBaseline[i++] = check_anonymous_share;
   //16、检查可匿名访问的命名管道：检查命名管道的访问权限。
    event_t check_anonymous_pipe_access;
 
    check_anonymous_pipe_access.description = "检查命名管道的访问权限";
    check_anonymous_pipe_access.basis = "允许匿名访问命名管道可能导致未经授权的用户获得对敏感数据或资源的访问权限，应当限制匿名用户对命名管道的访问";
    check_anonymous_pipe_access.command = "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v NullSessionPipes";
    check_anonymous_pipe_access.recommend = "应确保 NullSessionPipes 为空，以禁止匿名访问命名管道";
    check_anonymous_pipe_access.result = sshClient.executeCommand(check_anonymous_pipe_access.command);

    if (check_anonymous_pipe_access.result == "") {
        check_anonymous_pipe_access.result = "未能获取 NullSessionPipes 设置";
        check_anonymous_pipe_access.IsComply = "false";
    }
    else {
        // 解析查询结果，检查 NullSessionPipes 的值是否为空
        string nullSessionPipesValue = parseValueFromOutput(check_anonymous_pipe_access.result, "REG_MULTI_SZ");
        if (nullSessionPipesValue == "" || nullSessionPipesValue == " " || nullSessionPipesValue == "none") {
            check_anonymous_pipe_access.IsComply = "true";
            check_anonymous_pipe_access.result = "已禁用，符合基线";
        }
        else {
            check_anonymous_pipe_access.result = "命名管道允许匿名访问：" + nullSessionPipesValue;
            check_anonymous_pipe_access.IsComply = "false";
        }
    }

    Event.push_back(check_anonymous_pipe_access);
     allBaseline[i++] = check_anonymous_pipe_access;

//17、 检查是否只有授权用户或组通过远程桌面服务连接访问远程设备
    event_t check_remote_desktop_access;

    check_remote_desktop_access.description = "检查是否只有授权用户或组通过远程桌面服务连接访问远程设备的登录屏幕";
    check_remote_desktop_access.basis = "远程桌面连接可能允许未经授权的用户远程登录并访问设备，应限制哪些用户或组可以通过远程桌面登录";
    check_remote_desktop_access.command = executeRemotePSScript(Win_REMOTEPATH+"17_check_remote_desktop_access.ps1");
    check_remote_desktop_access.recommend = "仅允许授权的用户或组通过远程桌面连接登录设备，禁用不必要的账户或限制登录权限";

    // 执行命令获取安全配置
    check_remote_desktop_access.result = sshClient.executeCommand(check_remote_desktop_access.command);
    check_remote_desktop_access.result = extractResultCode(check_remote_desktop_access.result);
    int check_remote_desktop_access_vaule = stoi(check_remote_desktop_access.result);
    if (check_remote_desktop_access_vaule == -1) {
        check_remote_desktop_access.result = "未能获取远程桌面连接状态";
        check_remote_desktop_access.IsComply = "false";
    }
    else {
            // 检查是否存在未经授权的账户或组
            if (check_remote_desktop_access_vaule == 1) {
                check_remote_desktop_access.IsComply = "true";
                check_remote_desktop_access.result = "符合基线";
            }
            else if (check_remote_desktop_access_vaule == 0) {
                check_remote_desktop_access.result = "有未授权的用户或组通过远程桌面连接登录设备";
                check_remote_desktop_access.IsComply = "false";
            }
        }
        Event.push_back(check_remote_desktop_access);
         allBaseline[i++] = check_remote_desktop_access;

  //18、检查允许本地登录的用户和组：检查本地登录权限设置。
 
        event_t check_local_login_access;
   
        check_local_login_access.description = "检查是否只有授权用户或组允许通过本地登录访问远程设备";
        check_local_login_access.basis = "本地登录权限设置过宽，可能导致未经授权的用户本地登录设备，应限制哪些用户或组可以本地登录";
        check_local_login_access.command = executeRemotePSScript(Win_REMOTEPATH+"18_check_local_login_access.ps1");
        check_local_login_access.recommend = "仅允许授权的用户或组本地登录设备，禁用不必要的账户或限制登录权限";

        // 执行命令获取安全配置
        check_local_login_access.result = sshClient.executeCommand(check_local_login_access.command);
        check_local_login_access.result = extractResultCode(check_local_login_access.result);
        int check_local_login_access_vaule = stoi(check_local_login_access.result);
        if (check_local_login_access_vaule == -1) {
            check_local_login_access.result = "未能获取本地登录权限设置";
            check_local_login_access.IsComply = "false";
        }
        else {
            // 检查是否存在未经授权的账户或组
            if (check_local_login_access_vaule == 1) {
                check_local_login_access.IsComply = "true";
                check_local_login_access.result = "符合基线";
            }
            else if (check_local_login_access_vaule == 0) {
                check_local_login_access.result = "有未授权的用户或组允许本地登录设备";
                check_local_login_access.IsComply = "false";
            }
        }
        Event.push_back(check_local_login_access);
         allBaseline[i++] = check_local_login_access;

//19、检查应用程序日志文件达到最大大小时的动作：确认日志文件溢出处理设置。
        event_t log_file_overflow_check;
        log_file_overflow_check.description = "检查Windows事件日志的溢出处理设置";
        log_file_overflow_check.basis = "日志文件未正确设置溢出处理可能导致磁盘空间不足，或者丢失重要的事件信息";
        log_file_overflow_check.command = "wevtutil gl Application"; // 获取事件日志配置
        log_file_overflow_check.recommend = "为了确保系统稳定性，应配置合理的日志文件最大大小，并设置溢出处理策略";
        log_file_overflow_check.result = sshClient.executeCommand(log_file_overflow_check.command);

        if (log_file_overflow_check.result == "") {
            log_file_overflow_check.result = "未能获取日志溢出处理配置";
            log_file_overflow_check.IsComply = "false";
        }
        else {
            // 解析命令输出获取日志最大大小和保留策略
            string maxSize = parseValueFromOutput(log_file_overflow_check.result, "maxSize:");
            string retention = parseValueFromOutput(log_file_overflow_check.result, "retention:");

            int maxLogSizeValue = atoi(maxSize.c_str());  // 转换为整数
            if (maxLogSizeValue == 0) {
                log_file_overflow_check.result = "日志文件最大大小为0，未设置合理的溢出处理";
                log_file_overflow_check.IsComply = "false";
            }
            else {
                if (retention == "false") {
                    log_file_overflow_check.result = "日志未设置保留策略，可能导致数据丢失";
                    log_file_overflow_check.IsComply = "false";
                }
                else {
                    log_file_overflow_check.result = "符合基线";
                    log_file_overflow_check.IsComply = "true";
                }
            }
        }
        Event.push_back(log_file_overflow_check);
         allBaseline[i++] = log_file_overflow_check;

//20、检查应用程序日志文件最大大小：确认日志文件的最大大小设置。
        event_t log_file_max_size_check;

        log_file_max_size_check.description = "检查Windows日志文件的最大大小设置";
        log_file_max_size_check.basis = "日志文件过大可能导致磁盘空间不足，影响系统性能或导致服务中断";
        log_file_max_size_check.command = "wevtutil gl Application"; 
        log_file_max_size_check.recommend = "为了提高系统性能和稳定性，应设置合理的日志文件最大大小";
        log_file_max_size_check.result = sshClient.executeCommand(log_file_max_size_check.command);

        if (log_file_max_size_check.result == "") {
            log_file_max_size_check.result = "未能获取日志文件最大大小配置信息";
            log_file_max_size_check.IsComply = "false";
        }
        else {
            // 解析命令输出获取日志文件最大大小（该命令仅用于设置日志文件最大大小，若要获取值需用不同命令）
            string maxLogSize = parseValueFromOutput(log_file_max_size_check.result, "maxSize:");
         
            if (maxLogSize == "") {
                log_file_max_size_check.result = "未能解析日志文件最大大小";
                log_file_max_size_check.IsComply = "false";
            }
            else {
                int maxLogSizeValue = atoi(maxLogSize.c_str());  // 转换为整数
                if (maxLogSizeValue == 0) {
                    log_file_max_size_check.result = "日志文件最大大小为0";
                    log_file_max_size_check.IsComply = "false";
                }
                else if (maxLogSizeValue < thresholds.logFileMaxSize) {
                    log_file_max_size_check.result = "日志文件最大大小小于"+std::to_string(thresholds.logFileMaxSize);
                    log_file_max_size_check.IsComply = "false";
                }
                else {
                    log_file_max_size_check.IsComply = "true";
                    log_file_max_size_check.result = "日志文件最大大小为" + maxLogSize;
                }
            }
        }
        Event.push_back(log_file_max_size_check);
         allBaseline[i++] = log_file_max_size_check;

//21、检查“审核对象访问”级别：检查文件系统的审核策略。

        event_t check_object_access;
   
        check_object_access.description = "检查是否启用了审核对象访问";
        check_object_access.basis = "未启用审核对象访问可能导致无法记录访问敏感文件和目录，增加潜在的安全风险";
        check_object_access.command = executeRemotePSScript(Win_REMOTEPATH+"21_check_object_access.ps1");
        check_object_access.recommend = "应启用审核对象访问，并配置成功和失败事件记录";
       

        // 执行命令获取安全配置
        check_object_access.result = sshClient.executeCommand(check_object_access.command);
        check_object_access.result = extractResultCode(check_object_access.result);
        int checkAuditObjectAccess_value = stoi(check_object_access.result);

        if (checkAuditObjectAccess_value == -1) {
            check_object_access.result = "未能获取审核对象访问配置";
            check_object_access.IsComply = "false";
        }
        else {
            
            // 检查是否启用了审核对象访问
            if (checkAuditObjectAccess_value ==0) {
                check_object_access.IsComply = "false";
                check_object_access.result = "未启用审核对象访问";
            }
            else if (checkAuditObjectAccess_value == 1) {
                check_object_access.IsComply = "false";
                check_object_access.result = "只启用了审核成功";
            }
            else if (checkAuditObjectAccess_value == 2) {
                check_object_access.IsComply = "false";
                check_object_access.result = "只启用了审核失败";
            }
            else {
                check_object_access.IsComply = "true";
                check_object_access.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_object_access);
         allBaseline[i++] = check_object_access;

//22、检查“审核特权使用”级别：检查特权使用的审核策略。
      
        event_t check_privilege_use;
       
        check_privilege_use.description = "检查是否启用了审核特权使用";
        check_privilege_use.basis = "未启用审核特权使用可能导致无法记录特权账户的敏感操作，增加潜在的安全风险";
        check_privilege_use.command = executeRemotePSScript(Win_REMOTEPATH+"22_check_privilege_use.ps1");
        check_privilege_use.recommend = "应启用审核特权使用，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_privilege_use.result = sshClient.executeCommand(check_privilege_use.command);
        check_privilege_use.result = extractResultCode(check_privilege_use.result);
        int check_privilege_use_value = stoi(check_privilege_use.result);

        if (check_privilege_use_value == -1) {
            check_privilege_use.result = "未能获取审核特权使用配置";
            check_privilege_use.IsComply = "false";
        }
        else {

            // 检查是否启用了审核特权使用
            if (check_privilege_use_value == 0) {
                check_privilege_use.IsComply = "false";
                check_privilege_use.result = "未启用审核特权使用";
            }
            else if (check_privilege_use_value == 1) {
                check_privilege_use.IsComply = "false";
                check_privilege_use.result = "只启用了审核成功";
            }
            else if (check_privilege_use_value == 2) {
                check_privilege_use.IsComply = "false";
                check_privilege_use.result = "只启用了审核失败";
            }
            else {
                check_privilege_use.IsComply = "true";
                check_privilege_use.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_privilege_use);
         allBaseline[i++] = check_privilege_use;

//23、检查“审核进程跟踪”级别：检查进程创建的审核策略。
       
        event_t check_process_tracking;
      
        check_process_tracking.description = "检查是否启用了审核进程跟踪";
        check_process_tracking.basis = "未启用审核进程跟踪可能导致无法记录关键进程活动，增加潜在的安全风险";
        check_process_tracking.command = executeRemotePSScript(Win_REMOTEPATH+"23_check_process_tracking.ps1");
        check_process_tracking.recommend = "应启用审核进程跟踪，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_process_tracking.result = sshClient.executeCommand(check_process_tracking.command);
        check_process_tracking.result = extractResultCode(check_process_tracking.result);
        int check_process_tracking_value = stoi(check_process_tracking.result);

        if (check_process_tracking_value == -1) {
            check_process_tracking.result = "未能获取审核进程跟踪配置";
            check_process_tracking.IsComply = "false";
        }
        else {
            
            // 检查是否启用了审核进程跟踪
            if (check_process_tracking_value == 0) {
                check_process_tracking.IsComply = "false";
                check_process_tracking.result = "未启用审核进程跟踪";
            }
            else if (check_process_tracking_value == 1) {
                check_process_tracking.IsComply = "false";
                check_process_tracking.result = "只启用了审核成功";
            }
            else if (check_process_tracking_value == 2) {
                check_process_tracking.IsComply = "false";
                check_process_tracking.result = "只启用了审核失败";
            }
            else {
                check_process_tracking.IsComply = "true";
                check_process_tracking.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_process_tracking);
         allBaseline[i++] = check_process_tracking;

//24、检查“审核登录事件”级别：检查登录事件的审核策略。
        
        event_t check_logon_events;
      
        check_logon_events.description = "检查是否启用了审核登录事件";
        check_logon_events.basis = "未启用审核登录事件可能导致无法记录用户登录/注销活动，增加潜在的安全风险";
        check_logon_events.command = executeRemotePSScript(Win_REMOTEPATH+"24_check_logon_events.ps1");
        check_logon_events.recommend = "应启用审核登录事件，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_logon_events.result = sshClient.executeCommand(check_logon_events.command);
        check_logon_events.result = extractResultCode(check_logon_events.result);
        int check_logon_events_value = stoi(check_logon_events.result);

        if (check_logon_events_value == -1) {
            check_logon_events.result = "未能获取审核登录事件配置";
            check_logon_events.IsComply = "false";
        }
        else {
            // 检查是否启用了审核登录事件
            if (check_logon_events_value == 0) {
                check_logon_events.IsComply = "false";
                check_logon_events.result = "未启用审核登录事件";
            }
            else if (check_logon_events_value == 1) {
                check_logon_events.IsComply = "false";
                check_logon_events.result = "只启用了审核成功";
            }
            else if (check_logon_events_value == 2) {
                check_logon_events.IsComply = "false";
                check_logon_events.result = "只启用了审核失败";
            }
            else {
                check_logon_events.IsComply = "true";
                check_logon_events.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_logon_events);
         allBaseline[i++] = check_logon_events;

 //25、检查“审核目录服务访问”级别：检查目录服务访问的审核策略。
        if(osVersion== "Windows Server 2016" || osVersion == "Windows Server 2019" || osVersion == "Windows Server2022" ){
        event_t check_directory_service_access;
 
        check_directory_service_access.description = "检查是否启用了审核目录服务访问";
        check_directory_service_access.basis = "未启用审核目录服务访问可能导致无法记录对目录服务的访问，增加潜在的安全风险";
        check_directory_service_access.command = executeRemotePSScript(Win_REMOTEPATH+"25_check_directory_service_access.ps1");
        check_directory_service_access.recommend = "应启用审核目录服务访问，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_directory_service_access.result = sshClient.executeCommand(check_directory_service_access.command);
        check_directory_service_access.result = extractResultCode(check_directory_service_access.result);
        int check_directory_service_access_value = stoi(check_directory_service_access.result);

        if (check_directory_service_access_value == -1) {
            check_directory_service_access.result = "未能获取审核目录服务访问配置";
            check_directory_service_access.IsComply = "false";
        }
        else {
           
            // 检查是否启用了审核目录服务访问
            if (check_directory_service_access_value == 0) {
                check_directory_service_access.IsComply = "false";
                check_directory_service_access.result = "未启用审核目录服务访问";
            }
            else if (check_directory_service_access_value == 1) {
                check_directory_service_access.IsComply = "false";
                check_directory_service_access.result = "只启用了审核成功";
            }
            else if (check_directory_service_access_value == 2) {
                check_directory_service_access.IsComply = "false";
                check_directory_service_access.result = "只启用了审核失败";
            }
            else {
                check_directory_service_access.IsComply = "true";
                check_directory_service_access.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_directory_service_access);
         allBaseline[i++] = check_directory_service_access;
        }
 //26、检查“审核系统事件”级别：检查系统事件的审核策略。
        
        event_t check_system_events;
     
        check_system_events.description = "检查是否启用了审核系统事件";
        check_system_events.basis = "未启用审核系统事件可能导致无法记录系统级别的敏感操作，增加潜在的安全风险";
        check_system_events.command = executeRemotePSScript(Win_REMOTEPATH+"26_check_system_events.ps1");
        check_system_events.recommend = "应启用审核系统事件，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_system_events.result = sshClient.executeCommand(check_system_events.command);
        check_system_events.result = extractResultCode(check_system_events.result);
        int check_system_events_value = stoi(check_system_events.result);

        if (check_system_events_value == -1) {
            check_system_events.result = "未能获取审核系统事件配置";
            check_system_events.IsComply = "false";
        }
       
        else {
     
            // 检查是否启用了审核系统事件
            if (check_system_events_value == 0) {
                check_system_events.IsComply = "false";
                check_system_events.result = "未启用审核系统事件";
            }
            else if (check_system_events_value ==1) {
                check_system_events.IsComply = "false";
                check_system_events.result = "只启用了审核成功";
            }
            else if (check_system_events_value == 2) {
                check_system_events.IsComply = "false";
                check_system_events.result = "只启用了审核失败";
            }
            else {
                check_system_events.IsComply = "true";
                check_system_events.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_system_events);
         allBaseline[i++] = check_system_events;


   //27、检查“审核帐户登录事件”级别：检查帐户登录事件的审核策略。
       

        event_t check_account_logon_events;
       
        check_account_logon_events.description = "检查是否启用了审核帐户登录事件";
        check_account_logon_events.basis = "未启用审核帐户登录事件可能导致无法记录帐户登录和注销活动，增加潜在的安全风险";
        check_account_logon_events.command = executeRemotePSScript(Win_REMOTEPATH+"27_check_account_logon_events.ps1");
        check_account_logon_events.recommend = "应启用审核帐户登录事件，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_account_logon_events.result = sshClient.executeCommand(check_account_logon_events.command);
        check_account_logon_events.result = extractResultCode(check_account_logon_events.result);
        int check_account_logon_events_value = stoi(check_account_logon_events.result);

        if (check_account_logon_events_value == -1) {
            check_account_logon_events.result = "未能获取审核帐户登录事件配置";
            check_account_logon_events.IsComply = "false";
        }
        else {
            // 检查是否启用了审核帐户登录事件
            if (check_account_logon_events_value == 0) {
                check_account_logon_events.IsComply = "false";
                check_account_logon_events.result = "未启用审核帐户登录事件";
            }
            else  if (check_account_logon_events_value == 1) {
                check_account_logon_events.IsComply = "false";
                check_account_logon_events.result = "只启用了审核成功";
            }
            else if (check_account_logon_events_value == 2) {
                check_account_logon_events.IsComply = "false";
                check_account_logon_events.result = "只启用了审核失败";
            }
            else {
                check_account_logon_events.IsComply = "true";
                check_account_logon_events.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_account_logon_events);
         allBaseline[i++] = check_account_logon_events;

  //28、检查“审核策略更改”级别：检查审核策略变更的审核策略。
        event_t check_audit_policy_change;
        
        check_audit_policy_change.description = "检查是否启用了审核策略更改";
        check_audit_policy_change.basis = "未启用审核策略更改可能导致无法记录安全策略的更改，增加潜在的安全风险";
        check_audit_policy_change.command = executeRemotePSScript(Win_REMOTEPATH+"28_check_audit_policy_change.ps1");
        check_audit_policy_change.recommend = "应启用审核策略更改，并配置成功和失败事件记录";

        // 执行命令获取安全配置
        check_audit_policy_change.result = sshClient.executeCommand(check_audit_policy_change.command);
        check_audit_policy_change.result = extractResultCode(check_audit_policy_change.result);
        int check_audit_policy_value = stoi(check_audit_policy_change.result);

        if (check_audit_policy_value == -1) {
            check_audit_policy_change.result = "未能获取审核策略更改配置";
            check_audit_policy_change.IsComply = "false";
        }
        else {
       
            // 检查是否启用了审核策略更改
            if (check_audit_policy_value == 0) {
                check_audit_policy_change.IsComply = "false";
                check_audit_policy_change.result = "未启用审核策略更改";
            }
            else if (check_audit_policy_value == 1) {
                check_audit_policy_change.IsComply = "false";
                check_audit_policy_change.result = "只启用了审核成功";
            }
            else if (check_audit_policy_value ==2) {
                check_audit_policy_change.IsComply = "false";
                check_audit_policy_change.result = "只启用了审核失败";
            }
            else {
                check_audit_policy_change.IsComply = "true";
                check_audit_policy_change.result = "已启用，符合基线";
            }
        }

        Event.push_back(check_audit_policy_change);
         allBaseline[i++] = check_audit_policy_change;
       
        //29、检查“审核帐户管理”级别：检查用户账户管理的审核策略。

event_t check_account_management;

check_account_management.description = "检查是否启用了审核帐户管理";
check_account_management.basis = "未启用审核帐户管理可能导致无法记录账户的创建、删除或修改等重要操作，增加潜在的安全风险";
check_account_management.command = executeRemotePSScript(Win_REMOTEPATH+"29_check_account_management.ps1");
check_account_management.recommend = "应启用审核帐户管理，并配置成功和失败事件记录";

// 执行命令获取安全配置
check_account_management.result = sshClient.executeCommand(check_account_management.command);
check_account_management.result = extractResultCode(check_account_management.result);
int check_account_management_value = stoi(check_account_management.result);

if (check_account_management_value == -1) {
    check_account_management.result = "未能获取审核帐户管理配置";
    check_account_management.IsComply = "false";
}
else {
    int checkAuditAccountManagement = stoi(check_account_management.result);

    // 检查是否启用了审核帐户管理
    if (check_account_management_value == 0) {
        check_account_management.IsComply = "false";
        check_account_management.result = "未启用审核帐户管理";
    }
    else if (check_account_management_value == 1) {
        check_account_management.IsComply = "false";
        check_account_management.result = "只启用了审核成功";
    }
    else if (check_account_management_value == 2) {
        check_account_management.IsComply = "false";
        check_account_management.result = "只启用了审核失败";
    }
    else {
        check_account_management.IsComply = "true";
        check_account_management.result = "已启用，符合基线";
    }
}

Event.push_back(check_account_management);
 allBaseline[i++] = check_account_management;

    // 30. 检查 Windows 防火墙状态

    event_t e30;
   
    e30.description = "检查防火墙是否开启";
    e30.basis = "未启用防火墙可能增加被入侵风险";
    e30.result = sshClient.executeBat("30.bat");
    e30.recommend = "启用防火墙。";

    if (!getExitCode(e30.result))
    {
        e30.IsComply = "false";
        e30.result = "防火墙未开启";
    }
    else
    {
        e30.IsComply = "true";
        e30.result = "防火墙已开启";
    }
    Event.push_back(e30);
    allBaseline[i++] = e30;

    // 31. 检查远程桌面 (RDP) 服务端口
    event_t e31;
  
    e31.description = "检查远程桌面 (RDP) 服务端口";
    e31.basis = "若RDP服务为默认端口（3389）则可能增加被攻击风险";
    e31.result = sshClient.executeBat("31.bat");
    e31.recommend = "请修改端口";

    if (!getExitCode(e31.result))
    {
        e31.IsComply = "false";
        e31.result = "为默认端口";
    }
    else
    {
        e31.IsComply = "true";
        e31.result = "不为默认端口";
    }
    Event.push_back(e31);
     allBaseline[i++] = e31;

    // 32. 检查源路由配置
    event_t e32;
    
    e32.description = "检查源路由配置";
    e32.basis = "检查源路由配置的主要目的是提高网络安全性，防止潜在的网络攻击";
    e32.result = sshClient.executeBat("32.bat");
    e32.recommend = "请确保注册表项中有对应表项（DisableIPSourceRouting），且表项对应值为2";

    if (!getExitCode(e32.result))
    {
        e32.IsComply = "false";
        if (getEcho(e32.result) == "null")
        {
            e32.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e32.result = "注册表项未正确设置，推荐值为1，当前值为" + getEcho(e32.result);
        }
    }
    else
    {
        e32.IsComply = "true";
        e32.result = "通过";
    }
    Event.push_back(e32);
     allBaseline[i++] = e32;

    // 33. 检查 TCP 连接请求阈值
    event_t e33;
  
    e33.description = "检查 TCP 连接请求阈值";
    e33.basis = "有效的TCP 连接请求阈值的配置可以防范 SYN Flood 攻击";
    e33.result = sshClient.executeBat("33.bat");
    e33.recommend = "建议对应值小于5";

    if (!getExitCode(e33.result))
    {
        e33.IsComply = "false";
        if (getEcho(e33.result) == "null")
        {
            e33.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e33.result = "注册表项未正确设置，推荐值小于5，当前值为" + getEcho(e33.result);
        }
    }
    else
    {
        e33.IsComply = "true";
        e33.result = "通过";
    }
    Event.push_back(e33);
     allBaseline[i++] = e33;
    // 34. 检查是否已启用 SYN 攻击保护
    event_t e34;
    
    e34.description = "检查是否已启用 SYN 攻击保护";
    e34.basis = "启用 SYN 攻击保护可以显著提高系统抵御网络攻击";
    e34.result = sshClient.executeBat("34.bat");
    e34.recommend = "将对应值设置为1";

    if (!getExitCode(e34.result))
    {
        e34.IsComply = "false";
        if (getEcho(e34.result) == "null")
        {
            e34.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e34.result = "注册表项存在但值不为1，当前表项值为：" + getEcho(e34.result);
        }
    }
    else
    {
        e34.IsComply = "true";
        e34.result = "通过";
    }
    Event.push_back(e34);
     allBaseline[i++] = e34;
    // 35. 检查取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数
    event_t e35;
    
    e35.description = "检查取消尝试响应 SYN 请求之前要重新传输 SYN-ACK 的次数";
    e35.basis = "限制重新传输 SYN-ACK 次数可以平衡连接可靠性与资源利用，提升系统安全性并降低遭受 SYN Flood 攻击的风险";
    e35.result = sshClient.executeBat("35.bat");
    e35.recommend = "将对应值设置为2";

    if (!getExitCode(e35.result))
    {
        e35.IsComply = "false";
        if (getEcho(e35.result) == "null")
        {
            e35.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e35.result = "注册表项存在但值不为2，当前表项值为：" + getEcho(e35.result);
        }
    }
    else
    {
        e35.IsComply = "true";
        e35.result = "通过";
    }
    Event.push_back(e35);
     allBaseline[i++] = e35;
    // 36. 检查处于SYN_RCVD状态下的TCP连接阈值
    event_t e36;
  
    e36.description = "检查处于SYN_RCVD状态下的TCP连接阈值";
    e36.basis = "设置处于 SYN_RCVD 状态的 TCP 连接阈值可以防止过多未完成连接耗尽系统资源，提高防御 SYN Flood 攻击的能力。";
    e36.result = sshClient.executeBat("36.bat");
    e36.recommend = "将对应表项值设置为500";

    if (!getExitCode(e36.result))
    {
        e36.IsComply = "false";
        if (getEcho(e36.result) == "null")
        {
            e36.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e36.result = "注册表项存在但值不为500，当前表项值为：" + getEcho(e36.result);
        }
    }
    else
    {
        e36.IsComply = "true";
        e36.result = "通过";
    }
    Event.push_back(e36);
     allBaseline[i++] = e36;
    // 37. 检查处于SYN_RCVD状态下，且至少已经进行了一次重新传输的TCP连接阈值
    event_t e37;
   
    e37.description = "检查处于SYN_RCVD状态下，且至少已经进行了一次重新传输的TCP连接阈值";
    e37.basis = "防范恶意攻击，提升系统稳定性，增强网络安全性。";
    e37.result = sshClient.executeBat("37.bat");
    e37.recommend = "将对应表项值设置为400";

    if (!getExitCode(e37.result))
    {
        e37.IsComply = "false";
        if (getEcho(e37.result) == "null")
        {
            e37.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e37.result = "注册表项存在但值不为400，当前表项值为：" + getEcho(e37.result);
        }
    }
    else
    {
        e37.IsComply = "true";
        e37.result = "通过";
    }
    Event.push_back(e37);
     allBaseline[i++] = e37;
    // 38. 检查是否已删除SNMP服务的默认public团体
    event_t e38;
   
    e38.description = "检查是否已删除SNMP服务的默认public团体";
    e38.basis = "如果删除或更改默认团体名称，可以有效降低被攻击的风险";
    e38.result = sshClient.executeBat("38.bat");
    e38.recommend = "删除对应注册表项";

    if (!getExitCode(e38.result))
    {
        e38.IsComply = "false";
        e38.result = "不通过";
    }
    else
    {
        e38.IsComply = "true";
        e38.result = "通过";
    }
    Event.push_back(e38);
     allBaseline[i++] = e38;
    // 39. 检查是否已启用TCP最大传输单元(MTU)大小自动探测
    event_t e39;
  
    e39.description = "检查是否已启用TCP最大传输单元(MTU)大小自动探测";
    e39.basis = "启用 MTU 自动探测的主要作用是优化网络性能和可靠性";
    e39.result = sshClient.executeBat("39.bat");
    e39.recommend = "将对应的注册表值设置为1";

    if (!getExitCode(e39.result))
    {
        e39.IsComply = "false";
        if (getEcho(e39.result) == "null")
        {
            e39.result = "注册表项不存在，请手动添加。";
        }
        else
        {
            e39.result = "注册表项存在但值不为1，当前表项值为：" + getEcho(e39.result);
        }
    }
    else
    {
        e39.IsComply = "true";
        e39.result = "通过";
    }
    Event.push_back(e39);
     allBaseline[i++] = e39;

    // 40. 检查Remote Access Connection Manager服务状态
    event_t e40;
    
    e40.description = "检查Remote Access Connection Manager服务状态";
    e40.basis = "关闭 Remote Access Connection Manager 能提高系统安全性";
    e40.result = sshClient.executeBat("40.bat");
    e40.recommend = "通过服务管理器将该服务关闭";

    if (!getExitCode(e40.result))
    {
        e40.IsComply = "false";
        e40.result = "服务未关闭。";

    }
    else
    {
        e40.result = "通过";
        e40.IsComply = "true";
    }
    Event.push_back(e40);
     allBaseline[i++] = e40;
    // 41. 检查Message Queuing服务状态
    event_t e41;
   
    e41.description = "检查Message Queuing服务状态";
    e41.basis = "关闭Message Queuing可以减少被攻击的可能性";
    e41.result = sshClient.executeBat("41.bat");
    e41.recommend = "通过服务管理器将该服务关闭";

    if (!getExitCode(e41.result))
    {
        e41.IsComply = "false";
        e41.result = "服务未关闭";

    }
    else
    {
        e41.IsComply = "true";
        e41.result = "通过";
        if (getEcho(e41.result) == "null")
        {
            e41.result = "服务未安装";
        }
    }
    Event.push_back(e41);
     allBaseline[i++] = e41;
    // 42. 检查DHCP Server服务状态
    event_t e42;
    
    e42.description = "检查DHCP Server服务状态";
    e42.basis = "关闭DHCP Server服务可以减少被攻击的可能性";
    e42.result = sshClient.executeBat("42.bat");
    e42.recommend = "通过服务管理器将该服务关闭";

    if (!getExitCode(e42.result))
    {
        e42.IsComply = "false";
        e42.result = "未关闭服务。";
    }
    else
    {
        e42.IsComply = "true";
        e42.result = "通过";
    }
    Event.push_back(e42);
     allBaseline[i++] = e42;
    // 43. 检查DHCP Client服务状态
    event_t e43;
  
    e43.description = "检查DHCP Client服务状态";
    e43.basis = "关闭DHCP动态分配可以增加网络稳定性";
    e43.result = sshClient.executeBat("43.bat");
    e43.recommend = "通过服务管理器将该服务关闭";

    if (!getExitCode(e43.result))
    {
        e43.IsComply = "false";
        e43.result = "未关闭服务。";
    }
    else
    {   
        e43.result = "通过";
        e43.IsComply = "true";
    }
    Event.push_back(e43);
     allBaseline[i++] = e43;
    // 44. 检查Simple Mail Transport Protocol (SMTP)服务状态
    event_t e44;
    
    e44.description = "检查Simple Mail Transport Protocol (SMTP)服务状态";
    e44.basis = "SMTP 服务可能被攻击者利用来发送垃圾邮件或传播恶意软件";
    e44.result = sshClient.executeBat("44.bat");
    e44.recommend = "关闭该服务";

    if (!getExitCode(e44.result))
    {
        e44.IsComply = "false";
        e44.result = "服务未关闭";
    }
    else
    {
        e44.result = "通过";
        e44.IsComply = "true";
    }
    Event.push_back(e44);
     allBaseline[i++] = e44;
    // 45. 检查Windows Internet Name Service (WINS)服务状态
    event_t e45;
  
    e45.description = "检查Windows Internet Name Service (WINS)服务状态";
    e45.basis = "关闭该服务可以减少潜在的漏洞利用机会。";
    e45.result = sshClient.executeBat("45.bat");
    e45.recommend = "关闭该服务";

    if (!getExitCode(e45.result))
    {
        e45.result = "服务未关闭";
        e45.IsComply = "false";
    }
    else
    {
        e45.result = "通过";
        e45.IsComply = "true";
    }
    Event.push_back(e45);
     allBaseline[i++] = e45;
    // 46. 检查Simple TCP/IP Services服务状态
    event_t e46;
   
    e46.description = "检查Simple TCP/IP Services服务状态";
    e46.basis = "关闭该服务可以减少潜在的漏洞利用机会。";
    e46.result = sshClient.executeBat("46.bat");
    e46.recommend = "关闭该服务";

    if (!getExitCode(e46.result))
    {
        e46.IsComply = "false";
    }
    else
    {
        e46.result = "通过";
        e46.IsComply = "true";
    }
    Event.push_back(e46);
     allBaseline[i++] = e46;
    // 47. 检查Windows 自动登录设置
    event_t e47;
  
    e47.description = "检查 Windows 自动登录设置";
    e47.basis = "启用了自动登录会让攻击者更容易绕过身份验证，获取访问权限。";
    e47.result = sshClient.executeBat("47.bat");
    e47.recommend = "修改对应注册表值";

    if (!getExitCode(e47.result))
    {
        e47.IsComply = "false";
        e47.result = "对应值不为0。";
    }
    else
    {
        e47.result = "通过";
        e47.IsComply = "true";
    }
    Event.push_back(e47);
     allBaseline[i++] = e47;
    // 48. 检查共享文件夹的共享权限
    event_t e48;
   
    e48.description = "检查共享文件夹的共享权限";
    e48.basis = "如果共享文件夹的分享包含所有人可用字段（everyone）可能造成数据丢失";
    e48.result = sshClient.executeBat("48.bat");
    e48.recommend = "关闭所有人可用权限";

    if (!getExitCode(e48.result))
    {
        e48.IsComply = "false";
        e48.result = "共享字段中包含everyone";
    }
    else
    {
        e48.result = "通过";
        e48.IsComply = "true";
    }
    Event.push_back(e48);
     allBaseline[i++] = e48;
    // 49. 检查所有磁盘分区的文件系统格式
    event_t e49;
   
    e49.description = "检查所有磁盘分区的文件系统格式";
    e49.basis = "在Windows系统中，将硬盘格式设为NTFS格式能大大提高安全性";
    e49.result = sshClient.executeBat("49.bat");
    e49.recommend = "使用NTFS格式的硬盘";

    if (!getExitCode(e49.result))
    {
        e49.IsComply = "false";
        e49.result = "硬盘格式不全为NTFS";
    }
    else
    {
        e49.result = "通过";
        e49.IsComply = "true";
    }
    Event.push_back(e49);
     allBaseline[i++] = e49;
    // 50. 检查是否已对所有驱动器关闭 Windows 自动播放
    event_t e50;
    
    e50.description = "检查是否已对所有驱动器关闭 Windows 自动播放";
    e50.basis = "关闭自动播放以减少潜在的威胁入口";
    e50.result = sshClient.executeBat("50.bat");
    e50.recommend = "修改对应的注册表项";

    if (!getExitCode(e50.result))
    {
        e50.IsComply = "false";
        e50.result = "推荐值为:255，你的值为" + getEcho(e50.result);
    }
    else
    {
        e50.IsComply = "true";
        e50.result = "通过";
    }
    Event.push_back(e50);
     allBaseline[i++] = e50;

    // 51. 检查是否已禁用 Windows 硬盘默认共享
    event_t e51;
   
    e51.description = "检查是否已禁用 Windows 硬盘默认共享";
    e51.basis = "禁用 Windows 硬盘默认共享可以防止未经授权访问，降低被攻击风险，增强系统安全性";
    e51.result = sshClient.executeBat("51.bat");
    e51.recommend = "设置对应注册表值";

    if (!getExitCode(e51.result))
    {
        e51.IsComply = "false";
        if (getEcho(e51.result) == "null")
        {
            e51.result = "注册表项不存在，请手动添加并设置正确的值";
        }
        else
        {
            e51.result = "对应表项值设置不正确。";
        }
    }
    else
    {
        e51.IsComply = "true";
        e51.result = "通过";

    }
    Event.push_back(e51);
     allBaseline[i++] = e51;
/*
    // 52. 检查服务器在暂停会话前所需的空闲时间量
    event_t e52;
    
    e52.description = "检查服务器在暂停会话前所需的空闲时间量";
    e52.basis = "有助于释放资源、提高效率，同时减少因意外断开导致会话终止的风险。";
    e52.result = sshClient.executeBat("52.bat");
    e52.recommend = "将值设置为合理的值（此处为15分钟）";

    if (!getExitCode(e52.result))
    {
        e52.IsComply = "false";
        if (getEcho(e51.result) == "null")
        {
            e52.result = "注册表项不存在，请手动添加并设置正确的值";
        }
        else
        {
            e52.result = "对应表项值设置不正确，推荐值15，你的值为"+getEcho(e51.result);
        }
    }
    else
    {
        e52.IsComply = "true";
    }
    Event.push_back(e52);
     allBaseline[i++] = e52;
     */
    // 53. 检查是否正确配置 NTP 时间同步服务器
    event_t e53;
   
    e53.description = "检查是否正确配置 NTP 时间同步服务器";
    e53.basis = "在分布式系统中，时间同步对于日志记录、事务处理和数据一致性至关重要";
    e53.result = sshClient.executeBat("53.bat");
    e53.recommend = "勾选 与 Internet 时间服务器同步";

    if (!getExitCode(e53.result))
    {
        e53.IsComply = "false";
        e53.result = "正确配置时间同步时间服务器";
    }
    else
    {
        e53.IsComply = "true";
        e53.result = "通过";
    }
    Event.push_back(e53);
     allBaseline[i++] = e53;
    // 54. 检查是否正确配置 DNS 服务器
    event_t e54;
   
    e54.description = "检查是否正确配置 DNS 服务器";
    e54.basis = "正确配置 DNS 服务器可以降低被攻击的风险";
    e54.result = sshClient.executeBat("54.bat");
    e54.recommend = "添加DNS服务器：114.114.114.114";

    if (!getExitCode(e54.result))
    {
        e54.IsComply = "false";
        e54.result = "未正确配置DNS服务器";
    }
    else
    {
        e54.IsComply = "true";
        e54.result = "通过";
    }
    Event.push_back(e54);
     allBaseline[i++] = e54;
    // 55. 检查是否已开启数据DEP功能
    event_t e55;
   
    e55.description = "检查是否已开启数据DEP功能";
    e55.basis = "启用 DEP 功能可以有效防止恶意代码执行";
    e55.result = sshClient.executeBat("55.bat");
    e55.recommend = "进入“高级系统设置”中手动开启";

    if (!getExitCode(e55.result))
    {
        e55.IsComply = "false";
        e55.result = "DEP保护未开启";
    }
    else
    {
        e55.IsComply = "true";
        e55.result = "通过";

    }
    Event.push_back(e55);
     allBaseline[i++] = e55;
    // 56. 检查是否已开启 UAC 安全提示
    event_t e56;
    
    e56.description = "检查是否已开启 UAC 安全提示";
    e56.basis = "启用 UAC 安全提示可以有效降低被攻击的风险";
    e56.result = sshClient.executeBat("56.bat");
    e56.recommend = "进入控制面板手动开启";

    if (!getExitCode(e56.result))
    {
        e56.IsComply = "false";
        e56.result = "UAC 安全提示未开启";
    }
    else
    {
        e56.IsComply = "true";
        e56.result = "通过";
    }
    Event.push_back(e56);
     allBaseline[i++] = e56; 
}







void ServerInfo_win(ServerInfo& info, SSHClient& sshClient) {
    // 获取主机名
    string commandOutput;
    string hostname = "hostname";
    hostname = sshClient.executeCommand(hostname);
    hostname.erase(0, hostname.find_first_not_of(" \n\r\t"));
    hostname.erase(hostname.find_last_not_of(" \n\r\t") + 1);
    info.hostname = hostname;
    // 获取系统架构
    string Arch = "wmic os get OSArchitecture";
    commandOutput = sshClient.executeCommand(Arch);
    Arch = parseCommandOutput(commandOutput);
    Arch = convertEncoding(Arch, "GB2312", "UTF-8");
    info.arch = Arch;

    // 获取 CPU 信息
    string Cpu = "wmic cpu get caption";
    commandOutput = sshClient.executeCommand(Cpu);
    info.cpu = parseCommandOutput(commandOutput);

    // 获取物理 CPU 数量
    string CpuPhysical = "wmic computersystem get NumberOfProcessors";
    commandOutput = sshClient.executeCommand(CpuPhysical);
    info.cpuPhysical = parseCommandOutput(commandOutput);

    // 获取 CPU 核心数量
    string CpuCore = "wmic cpu get NumberOfCores";
    commandOutput = sshClient.executeCommand(CpuCore);
    info.cpuCore = parseCommandOutput(commandOutput);

    // 获取操作系统类型
    string type_os = getWindowsVersion(sshClient);
    info.version = type_os;

    // 获取硬件型号
    string ProductName = "wmic computersystem get model";
    commandOutput = sshClient.executeCommand(ProductName);
    info.ProductName = parseCommandOutput(commandOutput);

    // 获取内存信息
    string free = "wmic computersystem get TotalPhysicalMemory";
    commandOutput = sshClient.executeCommand(free);
    long long value = std::stoll(parseCommandOutput(commandOutput)); // 使用 stoll 防止大内存整数溢出
    double val_GB = static_cast<double>(value) / 1024 / 1024 / 1024;   // 转为 double，单位为 GB
    std::ostringstream oss; // 使用 stringstream 保留两位小数并转换为字符串
    oss << std::fixed << std::setprecision(2) << val_GB;
    info.free = oss.str() + "GB";


    // 检查是否能访问互联网
    string ping = "ping -n 1 8.8.8.8 > nul 2>&1 && echo true || echo false\\"; //Windows 用 ping -n
    string isInternet = sshClient.executeCommand(ping);
    isInternet.erase(std::remove(isInternet.begin(), isInternet.end(), '\r'), isInternet.end());//去除结果的换行符
    isInternet.erase(std::remove(isInternet.begin(), isInternet.end(), '\n'), isInternet.end()); 
    info.isInternet = isInternet;
}
