#include"utils.h"
#include <iostream>

std::unordered_map<std::string, std::vector<std::string>> rules = {
    {"操作系统类型", {"Windows", "Linux", "macOS", "FreeBSD", "Solaris"}},
    {"数据库", {"MySQL", "PostgreSQL", "MongoDB", "Redis", "Oracle", "SQL Server", "MariaDB", "Cassandra", "TiDB", "Neo4j"}},
    {"中间件", {"WebLogic", "WebSphere", "JBoss", "Tomcat", "Kafka", "RabbitMQ", "ActiveMQ", "Elasticsearch", "Dubbo", "Spring"}},
    {"Web应用", {"Nginx", "Apache", "IIS", "Django", "Flask", "Express", "WordPress", "Drupal", "React", "Vue", "Kibana", "Grafana"}},
    {"系统工具", {"OpenSSH", "OpenSSL", "Telnet", "RDP", "FTP", "NFS"}}
};

// 创建哈希表，键是漏洞类型，值是关键字列表
std::unordered_map<std::string, std::vector<std::string>> vulnTypes = {
    {"缓冲区溢出", {"Buffer Overflow", "Stack Overflow", "Heap Overflow", "Out-of-Bounds Write", "Out-of-Bounds Read",
                    "缓冲区溢出", "栈溢出", "堆溢出", "越界写", "越界读"}},

    {"文件上传漏洞", {"Arbitrary File Upload", "Unrestricted File Upload", "File Inclusion", "Remote File Execution",
                      "任意文件上传", "不受限制的文件上传", "文件包含", "远程文件执行", "文件上传", "PUTs enabled", "readonly parameter", "JSP file upload"}},

    {"代码注入", {"Command Injection", "Code Injection", "Arbitrary Code Execution",
                  "命令注入", "代码注入", "任意代码执行"}},

    {"SQL 注入", {"SQL Injection", "SQLi", "Crafted SQL Query",
                  "SQL注入", "SQLi", "构造SQL查询"}},

    {"跨站脚本攻击 (XSS)", {"Cross-Site Scripting", "XSS", "Script Injection", "Malicious Input",
                            "跨站脚本攻击", "XSS", "脚本注入", "恶意输入"}},

    {"权限提升", {"Privilege Escalation", "Elevation of Privileges", "Unauthorized Access",
                  "权限提升", "权限升级", "未经授权的访问"}},

    {"拒绝服务攻击 (DoS)", {"Denial of Service", "DoS", "Crash", "Infinite Loop", "Resource Exhaustion",
                            "拒绝服务", "DoS", "程序崩溃", "死循环", "资源耗尽"}},

    {"身份验证绕过", {"Authentication Bypass", "Unauthorized Access", "Token Manipulation",
                      "身份验证绕过", "未经授权的访问", "令牌篡改"}},

    {"路径遍历", {"Path Traversal", "Directory Traversal", "File Inclusion",
                  "路径遍历", "目录遍历", "文件包含"}},

    {"信息泄露", {"Information Disclosure", "Data Leakage", "Sensitive Information Exposure",
                  "信息泄露", "数据泄露", "敏感信息暴露"}},

    {"跨站请求伪造 (CSRF)", {"CSRF", "Cross-Site Request Forgery", "Unauthorized Actions",
                              "跨站请求伪造", "CSRF", "未经授权的操作"}},

    {"XML 外部实体注入 (XXE)", {"XXE", "XML External Entity", "XML Parsing",
                                 "XML外部实体注入", "XXE", "XML解析漏洞"}},

    {"远程代码执行 (RCE)", {"Remote Code Execution", "RCE", "Arbitrary Code Execution",
                            "远程代码执行", "RCE", "任意代码执行","服务器执行"}},

    {"会话劫持", {"Session Hijacking", "Session Fixation", "Token Theft",
                  "会话劫持", "会话固定", "令牌窃取"}},

    {"未经授权的访问", {"Unauthorized Access", "Access Control Bypass", "Security Restriction Bypass",
                        "未经授权的访问", "访问控制绕过", "安全限制绕过"}}
};

PyObject* global_importlib = nullptr; // 定义
PyObject* global_io = nullptr;        // 定义
//获取当前时间，字符串表示
//choice = 1时，用于文件名附加时间
//choice = 2时，用于漏洞扫描时间
std::string getCurrentTimestamp(int choice) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::tm timestamp;

    //预处理器指令#if defined(_WIN32)来检查代码是否在Windows平台上编译。如果是，使用localtime_s。
    //对于POSIX兼容的系统（如Linux和macOS），使用localtime_r，这是localtime的线程安全版本。
#if defined(_WIN32)
    localtime_s(&timestamp, &in_time_t); // 使用localtime_s在Windows平台上
#else
    localtime_r(&in_time_t, &timestamp); // 使用localtime_r在POSIX平台上
#endif

    std::stringstream ss;
    
    switch (choice) {
        case 1:
            ss << std::put_time(&timestamp, "%Y-%m-%d %X");
            break;
        case 2:
            ss << std::put_time(&timestamp, "%Y-%m-%d %H:%M:%S");
            break;
    }
    
    return ss.str();
}



std::string convertToUTF8(const std::string& input, const std::string& fromEncoding)
{
    // 如果输入数据已经是 UTF-8 编码，直接返回原始数据
    if (fromEncoding == "UTF-8") {
        return input;
    }

    icu::UnicodeString sourceStr(input.c_str(), fromEncoding.c_str());
    std::string output;
    sourceStr.toUTF8String(output);

    // 输出调试信息
    //std::cout << "Original data (" << fromEncoding << "): " << input << std::endl;
    //std::cout << "Converted data (UTF-8): " << output << std::endl;

    return output;
}

//转换编码
std::string convertEncoding(const std::string& input, const char* fromEncoding, const char* toEncoding) {
    iconv_t cd = iconv_open(toEncoding, fromEncoding);
    if (cd == (iconv_t)-1) {
        std::cerr << "Error: iconv_open failed" << std::endl;
        return "";
    }

    size_t inBytesLeft = input.size();
    size_t outBytesLeft = input.size() * 4; // Output buffer should be larger to accommodate larger characters
    char* inBuf = const_cast<char*>(input.c_str());
    std::string output(outBytesLeft, '\0');
    char* outBuf = &output[0];

    if (iconv(cd, &inBuf, &inBytesLeft, &outBuf, &outBytesLeft) == (size_t)-1) {
        std::cerr << "Error: iconv conversion failed" << std::endl;
        iconv_close(cd);
        return "";
    }

    iconv_close(cd);
    output.resize(output.size() - outBytesLeft); // Resize output string to actual converted size
    return output;
}
//识别编码并转换
std::string autoConvertToUTF8(const std::string& input) {
    // 使用 uchardet 检测编码
    uchardet_t ud = uchardet_new();
    uchardet_handle_data(ud, input.c_str(), input.size());
    uchardet_data_end(ud);
    const char* detectedEncoding = uchardet_get_charset(ud);

    std::string output;
    if (strcmp(detectedEncoding, "UTF-8") == 0) {
        output = input; // 如果已是UTF-8编码，直接使用
    }
    else {
        output = convertEncoding(input, detectedEncoding, "UTF-8");
    }

    //std::cout << "Original data (" << detectedEncoding << "): " << input << std::endl;
    //std::cout << "Converted data (UTF-8): " << output << std::endl;

    uchardet_delete(ud);
    return output;
}

// Function to execute a command and get the output
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

//std::string exec_hydra(const char* cmd)
//{
//    std::array<char, 128> buffer;
//    std::string result;
//    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
//    if (!pipe) {
//        throw std::runtime_error("popen() failed!");
//    }
//    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
//        std::string line = buffer.data();
//        result += line;
//
//        // 检查是否包含主机阻塞的错误信息
//        if (line.find("Host") != std::string::npos &&
//            line.find("is blocked") != std::string::npos) {
//            // 发现错误，提前结束循环
//            break;
//        }
//    }
//    return result;
//}
std::string exec_hydra(const char* cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    // 添加 2>&1 将stderr重定向到stdout
    std::string command = std::string(cmd) + " 2>&1";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    bool connection_error = false; // 标记是否出现连接错误
    int connection_error_count = 0; // 计数连接错误次数

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::string line = buffer.data();
        std::cout << line + "这是输出" << std::endl;
        result += line;

        // 检查是否包含主机阻塞的错误信息
        if (line.find("Host") != std::string::npos &&
            line.find("is blocked") != std::string::npos) {
            // 确保所有hydra进程终止
            exec("pkill -9 hydra");
            // 稍等片刻让系统完成清理
            usleep(500000);  // 500毫秒
            break;
        }
    }
    return result;
}

// Function to extract login information from hydra output
std::string extract_login_info(const std::string& output) {
    std::regex pattern(R"(\[\d+\]\[[^\]]+\] host:\s*[^\s]+\s+login:\s*[^\s]+\s+password:\s*[^\s]+)");
    std::smatch match;
    if (std::regex_search(output, match, pattern)) {
        return match.str(0);
    }
    return "No login info found";
}


//判断上传的POC是否为平台支持的格式
bool is_supported_extension(const std::string& filename) {
    auto pos = filename.find_last_of(".");
    if (pos == std::string::npos) {
        return false;
    }
    std::string extension = filename.substr(pos + 1);
    return std::find(supported_extensions.begin(), supported_extensions.end(), extension) != supported_extensions.end();
}

//去掉文件名后缀
std::string removeExtension(const std::string& filename) {
    // 查找最后一个"."的位置
    size_t dotPosition = filename.find_last_of(".");

    // 如果找到了"."，且它不是字符串的第一个字符（防止像 ".txt" 这样的情况）
    if (dotPosition != std::string::npos && dotPosition != 0) {
        // 去掉后缀返回
        return filename.substr(0, dotPosition);
    }
    else {
        // 没有找到后缀，原样返回文件名
        return filename;
    }
}
void initializePython()
{
    // 初始化Python解释器
    Py_Initialize();
    global_importlib = PyImport_ImportModule("importlib");
    if (!global_importlib) {
        std::cerr << "Failed to import importlib module." << std::endl;
        return;
    }
    global_io = PyImport_ImportModule("io");
    if (!global_io) {
        std::cerr << "Failed to import io module." << std::endl;
        Py_DECREF(global_importlib);
        return;
    }


    // 设置sys.path
    PyObject* sys = PyImport_ImportModule("sys");
    PyObject* sys_path = PyObject_GetAttrString(sys, "path");

    //新版，获取配置
    auto paths = CONFIG.getPythonPaths();
    for (const auto& path : paths) {
        PyList_Append(sys_path, PyUnicode_FromString(path.c_str()));
    }
    //旧版，可用
    //PyList_Append(sys_path, PyUnicode_FromString("/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/scan/lib"));
    //PyList_Append(sys_path, PyUnicode_FromString("/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/scan/scripts"));
    //PyList_Append(sys_path, PyUnicode_FromString("/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src/scan"));
    //PyList_Append(sys_path, PyUnicode_FromString("/home/c/.vs/cyber_security_assessment/8e509499-79aa-4583-a94f-9ac2aefdaefd/src"));


}
// 转换字符串为小写
std::string toLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
    return lowerStr;
}
// 匹配漏洞类型
std::string matchVulnType(const std::string& vulnSummary, const std::unordered_map<std::string, std::vector<std::string>>& rules) {
    if (vulnSummary.empty()) {
        return "未知类型"; // 或者返回一个特殊标识，表示输入无效
    }
    std::string vulNameLower = toLower(vulnSummary); // 转换服务名称为小写
    for (const auto& rule : rules) {
        for (const auto& keyword : rule.second) {
            if (vulNameLower.find(toLower(keyword)) != std::string::npos) { // 部分匹配
                return rule.first; // 返回匹配到的类型
            }
        }
    }
    return "未知类型"; // 没有匹配到的情况
}

// 匹配服务类型
std::string matchServiceType(const std::string& serviceName, const std::unordered_map<std::string, std::vector<std::string>>& rules) {
    if (serviceName.empty()) {
        return "未知类型"; // 或者返回一个特殊标识，表示输入无效
    }
    std::string serviceNameLower = toLower(serviceName); // 转换服务名称为小写
    for (const auto& rule : rules) {
        for (const auto& keyword : rule.second) {
            if (serviceNameLower.find(toLower(keyword)) != std::string::npos) { // 部分匹配
                return rule.first; // 返回匹配到的类型
            }
        }
    }
    return "未知类型"; // 没有匹配到的情况
}
void finalizePython()
{
    // 终止Python解释器
    Py_XDECREF(global_importlib);
    Py_XDECREF(global_io);
    Py_Finalize();

}
//检查密码复杂度
bool isValidPassword(const std::string& password)
{
    if (password.length() < 8 || password.length() > 12) {
        return false;
    }

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;

    for (char ch : password) {
        if (std::islower(ch)) {
            hasLower = true;
        }
        else if (std::isupper(ch)) {
            hasUpper = true;
        }
        else if (std::isdigit(ch)) {
            hasDigit = true;
        }
        else if (std::ispunct(ch)) {
            // If there's any special character, the password is invalid
            return false;
        }

        // If all conditions are met, we can stop checking further
        if (hasLower && hasUpper && hasDigit) {
            return true;
        }
    }

    // If any condition is not met
    return hasLower && hasUpper && hasDigit;
}

PasswordStrength checkPasswordStrength(const std::string& password)
{
    if (std::regex_match(password, STRONG_PATTERN)) {
        return PasswordStrength::STRONG;
    }
    else if (std::regex_match(password, MEDIUM_PATTERN)) {
        return PasswordStrength::MEDIUM;
    }
    else if (std::regex_match(password, WEAK_PATTERN)) {
        return PasswordStrength::WEAK;
    }
    else {
        return PasswordStrength::INVALID;
    }
}
std::string passwordStrengthToString(PasswordStrength strength)
{
    switch (strength) {
    case PasswordStrength::WEAK:
        return "Weak";
    case PasswordStrength::MEDIUM:
        return "Medium";
    case PasswordStrength::STRONG:
        return "Strong";
    case PasswordStrength::INVALID:
    default:
        return "Invalid";
    }
}

// 判断路径是否为目录
bool is_directory(const std::string& path) {
    struct stat s;
    if (stat(path.c_str(), &s) == 0) {
        return S_ISDIR(s.st_mode);
    }
    return false;
}

// 检查字符串是否为括号内容 (xxx)
bool isParenthesisContent(const std::string& str) {
    return str.size() >= 3 && str[0] == '(' && str[str.size() - 1] == ')';
}

// 从括号中提取内容
std::string extractFromParenthesis(const std::string& str) {
    if (isParenthesisContent(str)) {
        return str.substr(1, str.size() - 2);
    }
    return str;
}

// 解析端口字符串，提取端口和协议信息
// 返回: {端口或端口范围, 协议, 是否为端口范围}
std::tuple<std::string, std::string, bool> parsePortString(const std::string& portStr) {
    // 如果输入是括号内容，如 (out)，则不是端口
    if (isParenthesisContent(portStr)) {
        return std::make_tuple("", "", false);
    }

    std::string port, protocol;
    bool isRange = false;

    // 检查是否包含协议信息
    std::size_t protocolPos = portStr.find("/");
    if (protocolPos != std::string::npos) {
        port = portStr.substr(0, protocolPos);
        protocol = portStr.substr(protocolPos + 1);
    }
    else {
        port = portStr;
    }

    // 检查是否为端口范围
    if (port.find(":") != std::string::npos) {
        isRange = true;
    }

    return std::make_tuple(port, protocol, isRange);
}

// 解析UFW规则函数
std::vector<UfwRule> parseUfwRules(const std::string& output) {
    std::vector<UfwRule> rules;
    std::istringstream iss(output);
    std::string line;

    // 跳过状态行（如果有）
    if (output.find("状态：") != std::string::npos || output.find("Status:") != std::string::npos) {
        std::getline(iss, line);
        // 跳过表头行
        std::getline(iss, line);
        std::getline(iss, line);
    }

    // 正则表达式匹配规则
    std::regex rule_regex(R"(\[\s*(\d+)\]\s+([^\s]+(?:\s+[^\s]+)*)?\s+(ALLOW|DENY)\s+(IN|OUT)\s+([^\s]+(?:\s+[^\s]+)*)(?:\s+\(([^)]+)\))?)");

    // 逐行解析
    while (std::getline(iss, line) && !line.empty()) {
        std::smatch matches;
        if (std::regex_search(line, matches, rule_regex)) {
            UfwRule rule;

            // 解析规则编号
            rule.number = std::stoi(matches[1]);

            // 解析动作和方向
            rule.action = matches[3];
            rule.direction = matches[4];

            // 处理IPv6标记
            rule.is_v6 = (line.find("(v6)") != std::string::npos);

            // 处理额外信息
            if (matches[6].matched) {
                rule.extra_info = matches[6];
                // 如果额外信息就是v6，则清空，因为已经在is_v6标记中处理了
                if (rule.extra_info == "v6") {
                    rule.extra_info.clear();
                }
            }

            // 分析第2部分（目标部分）和第5部分（来源部分）
            std::string targetPart = matches[2];
            std::string sourcePart = matches[5];

            // 预处理来源部分，检查是否有括号标记
            std::istringstream sourceStream(sourcePart);
            std::vector<std::string> sourceTokens;
            std::string token;
            while (sourceStream >> token) {
                sourceTokens.push_back(token);
            }

            // 检查来源部分的最后一个标记是否是括号标记 (out)
            if (!sourceTokens.empty() && isParenthesisContent(sourceTokens.back())) {
                // 如果额外信息为空，则设置额外信息
                if (rule.extra_info.empty()) {
                    rule.extra_info = extractFromParenthesis(sourceTokens.back());
                }
                sourceTokens.pop_back(); // 从来源部分移除这个标记

                // 重建来源部分字符串
                std::stringstream rebuildSource;
                for (size_t i = 0; i < sourceTokens.size(); ++i) {
                    if (i > 0) rebuildSource << " ";
                    rebuildSource << sourceTokens[i];
                }
                sourcePart = rebuildSource.str();

                // 如果来源部分为空，则设为"Anywhere"
                if (sourcePart.empty()) {
                    sourcePart = "Anywhere";
                }
            }

            // 处理目标部分 (matches[2])
            if (targetPart == "Anywhere") {
                rule.to_ip = "Anywhere";
            }
            else {
                // 目标可能是 "IP", "端口/协议", "IP 端口", "IP 端口/协议", "端口范围/协议" 等多种情况
                std::istringstream tss(targetPart);
                std::string firstToken, secondToken;
                tss >> firstToken;

                // 检查第一个标记是IP还是端口
                if (firstToken.find(":") != std::string::npos &&
                    firstToken.find("/") != std::string::npos) {
                    // 端口范围带协议，如 "8000:8100/tcp"
                    rule.to_ip = "Anywhere";
                    auto portInfo = parsePortString(firstToken);
                    rule.to_port = std::get<0>(portInfo);
                    rule.to_port_protocol = std::get<1>(portInfo);
                    rule.to_is_port_range = std::get<2>(portInfo);
                }
                else if (firstToken.find("/") != std::string::npos) {
                    // 端口带协议，如 "80/tcp"
                    rule.to_ip = "Anywhere";
                    auto portInfo = parsePortString(firstToken);
                    rule.to_port = std::get<0>(portInfo);
                    rule.to_port_protocol = std::get<1>(portInfo);
                    rule.to_is_port_range = std::get<2>(portInfo);
                }
                else if (std::regex_match(firstToken, std::regex("^\\d+$")) ||
                    firstToken.find(":") != std::string::npos) {
                    // 纯数字端口或端口范围
                    rule.to_ip = "Anywhere";
                    rule.to_port = firstToken;
                    rule.to_is_port_range = (firstToken.find(":") != std::string::npos);
                }
                else {
                    // 假设是IP地址或网络
                    rule.to_ip = firstToken;

                    // 检查是否有第二个标记（可能是端口）
                    if (tss >> secondToken) {
                        if (secondToken.find("/") != std::string::npos) {
                            // 端口带协议
                            auto portInfo = parsePortString(secondToken);
                            rule.to_port = std::get<0>(portInfo);
                            rule.to_port_protocol = std::get<1>(portInfo);
                            rule.to_is_port_range = std::get<2>(portInfo);
                        }
                        else {
                            // 纯端口
                            rule.to_port = secondToken;
                            rule.to_is_port_range = (secondToken.find(":") != std::string::npos);
                        }
                    }
                }
            }

            // 处理来源部分 (sourcePart 已经去除了括号标记)
            if (sourcePart == "Anywhere") {
                rule.from_ip = "Anywhere";
                if (rule.is_v6) {
                    rule.from_ip += " (v6)";
                }
            }
            else {
                // 来源可能是 "IP", "IP 端口", "IP 端口/协议", "IP 端口范围/协议" 等多种情况
                std::istringstream sss(sourcePart);
                std::string firstToken, secondToken;
                sss >> firstToken;

                // 首先假设是IP地址或网络
                rule.from_ip = firstToken;

                // 检查是否有第二个标记（可能是端口）
                if (sss >> secondToken) {
                    // 检查是否为括号内容
                    if (isParenthesisContent(secondToken)) {
                        if (rule.extra_info.empty()) {
                            rule.extra_info = extractFromParenthesis(secondToken);
                        }
                    }
                    else if (secondToken.find("/") != std::string::npos) {
                        // 端口带协议
                        auto portInfo = parsePortString(secondToken);
                        rule.from_port = std::get<0>(portInfo);
                        rule.from_port_protocol = std::get<1>(portInfo);
                        rule.from_is_port_range = std::get<2>(portInfo);
                    }
                    else {
                        // 纯端口或端口范围，先检查是否是数字或包含冒号
                        if (std::regex_match(secondToken, std::regex("^\\d+$")) ||
                            secondToken.find(":") != std::string::npos) {
                            rule.from_port = secondToken;
                            rule.from_is_port_range = (secondToken.find(":") != std::string::npos);
                        }
                        else {
                            // 如果不是标准端口格式，可能是其他信息
                            if (rule.extra_info.empty() && isParenthesisContent(secondToken)) {
                                rule.extra_info = extractFromParenthesis(secondToken);
                            }
                        }
                    }
                }
            }

            // 规则方向处理：对于OUT规则，需要调整来源和目标的理解
            if (rule.direction == "OUT") {
                // 交换来源和目标
                std::swap(rule.to_ip, rule.from_ip);
                std::swap(rule.to_port, rule.from_port);
                std::swap(rule.to_port_protocol, rule.from_port_protocol);
                std::swap(rule.to_is_port_range, rule.from_is_port_range);
            }

            rules.push_back(rule);
        }
    }

    return rules;
}

// 从文件读取UFW状态输出
std::string readUfwStatusFromFile(const std::string& filename) {
    std::ifstream file(filename);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// 从字符串读取UFW状态输出
std::vector<UfwRule> parseUfwRulesFromString(const std::string& output) {
    return parseUfwRules(output);
}

std::string filterNumberedRules(const std::string& statusOutput) {
    std::regex pattern(R"(\[\s*\d+\].*$)");
    std::stringstream result;
    std::stringstream ss(statusOutput);
    std::string line;

    while (std::getline(ss, line)) {
        // 如果行匹配 [数字] 开头的模式
        if (std::regex_search(line, pattern)) {
            result << line << std::endl;
        }
    }

    return result.str();
}

// 判断网络A是否包含网络B
bool isNetworkContained(const std::string& networkA, const std::string& networkB) {
    // 如果A是"Anywhere"，它包含任何网络
    if (networkA == "Anywhere") {
        return true;
    }

    // 如果B是"Anywhere"但A不是，则A不可能包含B
    if (networkB == "Anywhere" && networkA != "Anywhere") {
        return false;
    }

    // 如果两者都是具体IP地址（不包含CIDR格式），检查是否相同
    if (networkA.find('/') == std::string::npos && networkB.find('/') == std::string::npos) {
        return networkA == networkB;
    }

    // 解析CIDR格式，例如192.168.1.0/24
    std::regex cidr_pattern("(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)");
    std::smatch matchesA, matchesB;

    bool isA_CIDR = std::regex_search(networkA, matchesA, cidr_pattern);
    bool isB_CIDR = std::regex_search(networkB, matchesB, cidr_pattern);

    // 如果A不是CIDR格式但B是，A不可能包含B的整个网段
    if (!isA_CIDR && isB_CIDR) {
        return false;
    }

    // 如果A是CIDR格式但B不是（B是单个IP地址），检查B是否在A的网段内
    if (isA_CIDR && !isB_CIDR) {
        // 解析A的网络地址和前缀
        std::string ipA = matchesA[1].str();
        int prefixA = std::stoi(matchesA[2].str());

        // 转换为网络字节序的整数
        struct in_addr addrA, addrB;
        if (inet_pton(AF_INET, ipA.c_str(), &addrA) != 1 ||
            inet_pton(AF_INET, networkB.c_str(), &addrB) != 1) {
            return false;  // 转换失败
        }

        // 计算网络掩码
        uint32_t mask = (prefixA == 0) ? 0 : (~0 << (32 - prefixA));
        mask = htonl(mask);  // 转换为网络字节序

        // 检查B是否在A的网段内
        return (addrA.s_addr & mask) == (addrB.s_addr & mask);
    }

    // 如果A和B都是CIDR格式，检查A的网段是否包含B的网段
    if (isA_CIDR && isB_CIDR) {
        // 解析两个网络地址和前缀
        std::string ipA = matchesA[1].str();
        int prefixA = std::stoi(matchesA[2].str());

        std::string ipB = matchesB[1].str();
        int prefixB = std::stoi(matchesB[2].str());

        // A的前缀必须小于等于B的前缀才可能包含B
        if (prefixA > prefixB) {
            return false;
        }

        // 转换为网络字节序的整数
        struct in_addr addrA, addrB;
        if (inet_pton(AF_INET, ipA.c_str(), &addrA) != 1 ||
            inet_pton(AF_INET, ipB.c_str(), &addrB) != 1) {
            return false;  // 转换失败
        }

        // 计算A的网络掩码
        uint32_t maskA = (prefixA == 0) ? 0 : (~0 << (32 - prefixA));
        maskA = htonl(maskA);  // 转换为网络字节序

        // 检查B的网络地址是否在A的网段内
        return (addrA.s_addr & maskA) == (addrB.s_addr & maskA);
    }

    return false;
}

// 判断端口范围A是否包含端口范围B
bool isPortRangeContained(const std::string& portRangeA, const std::string& portRangeB) {
    // 如果A是"Anywhere"，它包含任何端口范围
    if (portRangeA == "Anywhere") {
        return true;
    }

    // 如果B是"Anywhere"但A不是，则A不可能包含B
    if (portRangeB == "Anywhere" && portRangeA != "Anywhere") {
        return false;
    }

    // 解析端口范围，格式可能是单个端口"80"或范围"1024:2048"
    // 可能含有协议后缀如"/tcp"
    auto parsePortRange = [](const std::string& range) -> std::pair<int, int> {
        // 移除协议后缀（如果有）
        std::string portPart = range;
        size_t slashPos = range.find('/');
        if (slashPos != std::string::npos) {
            portPart = range.substr(0, slashPos);
        }

        size_t colonPos = portPart.find(':');
        if (colonPos == std::string::npos) {
            // 单个端口
            int port = std::stoi(portPart);
            return { port, port };
        }
        else {
            // 端口范围
            int start = std::stoi(portPart.substr(0, colonPos));
            int end = std::stoi(portPart.substr(colonPos + 1));
            return { start, end };
        }
        };

    try {
        // 解析两个端口范围
        auto rangeA = parsePortRange(portRangeA);
        auto rangeB = parsePortRange(portRangeB);

        // 检查A的范围是否包含B的范围
        return (rangeA.first <= rangeB.first && rangeA.second >= rangeB.second);
    }
    catch (const std::exception& e) {
        // 解析失败
        return false;
    }
}

// 判断规则A是否包含规则B（B是否是冗余的）
bool isRuleContained(const UfwRule& ruleA, const UfwRule& ruleB) {
    // 条件1: A的编号小于B的编号（A会先被执行）
    if (ruleA.number >= ruleB.number) {
        return false;
    }

    // 条件2: A和B的动作相同（都是ALLOW或都是DENY）
    if (ruleA.action != ruleB.action) {
        return false;
    }

    // 条件3: A和B的方向相同（都是IN或都是OUT）
    if (ruleA.direction != ruleB.direction) {
        return false;
    }

    // 条件4: A和B的IP类型相同（都是IPv4或都是IPv6）
    if (ruleA.is_v6 != ruleB.is_v6) {
        return false;
    }

    // 条件5: A的来源网络包含B的来源网络
    if (!isNetworkContained(ruleA.from_ip, ruleB.from_ip)) {
        return false;
    }

    // 条件6: A的目标网络包含B的目标网络
    if (!isNetworkContained(ruleA.to_ip, ruleB.to_ip)) {
        return false;
    }

    // 条件7: 端口范围检查
    // 检查目标端口
    if (ruleB.to_port.empty()) {
        // 如果B没有指定端口（即B匹配所有端口）
        if (!ruleA.to_port.empty()) {
            // 但A指定了特定端口，则A不能完全包含B
            return false;
        }
    }
    else {
        // B指定了端口
        if (ruleA.to_port.empty()) {
            // 如果A没有指定端口，视为A包含所有端口
            // 不需要进一步检查目标端口
        }
        else {
            // 两者都指定了端口，检查协议兼容性
            if (!ruleA.to_port_protocol.empty() && !ruleB.to_port_protocol.empty() &&
                ruleA.to_port_protocol != ruleB.to_port_protocol) {
                return false;
            }

            // 检查端口范围
            if (!isPortRangeContained(ruleA.to_port, ruleB.to_port)) {
                return false;
            }
        }
    }

    // 检查来源端口
    if (ruleB.from_port.empty()) {
        // 如果B没有指定端口（即B匹配所有端口）
        if (!ruleA.from_port.empty()) {
            // 但A指定了特定端口，则A不能完全包含B
            return false;
        }
    }
    else {
        // B指定了端口
        if (ruleA.from_port.empty()) {
            // 如果A没有指定端口，视为A包含所有端口
            // 不需要进一步检查来源端口
        }
        else {
            // 两者都指定了端口，检查协议兼容性
            if (!ruleA.from_port_protocol.empty() && !ruleB.from_port_protocol.empty() &&
                ruleA.from_port_protocol != ruleB.from_port_protocol) {
                return false;
            }

            // 检查端口范围
            if (!isPortRangeContained(ruleA.from_port, ruleB.from_port)) {
                return false;
            }
        }
    }

    // 条件8: 协议检查
    // 注意：主要的协议检查已经在端口检查时处理了
    // 这部分只处理端口为空但协议被指定的罕见情况

    // 如果A的协议被指定而B的协议没被指定，B更宽泛，A不能包含B
    if (ruleA.to_port.empty() && ruleB.to_port.empty() &&
        !ruleA.to_port_protocol.empty() && ruleB.to_port_protocol.empty()) {
        return false;
    }

    if (ruleA.from_port.empty() && ruleB.from_port.empty() &&
        !ruleA.from_port_protocol.empty() && ruleB.from_port_protocol.empty()) {
        return false;
    }

    // 所有条件都满足，规则A包含规则B
    return true;
}

// 查找所有冗余规则（被其他规则包含的规则）
std::vector<UfwRule> findRedundantRules(const std::vector<UfwRule>& rules) {
    std::vector<UfwRule> redundantRules;
    std::vector<bool> isRedundant(rules.size(), false);  // 跟踪规则是否冗余

    for (size_t i = 0; i < rules.size(); ++i) {
        if (isRedundant[i]) {
            continue;  // 如果已经知道规则是冗余的，跳过它
        }

        for (size_t j = 0; j < rules.size(); ++j) {
            if (i != j && !isRedundant[j] && isRuleContained(rules[j], rules[i])) {
                // 找到了一个被包含的规则（冗余规则）
                redundantRules.push_back(rules[i]);
                isRedundant[i] = true;
                break;  // 一旦找到一个包含当前规则的规则，就不需要继续检查了
            }
        }
    }

    return redundantRules;
}

// 打印冗余规则及包含它们的规则
void printRedundantRules(const std::vector<UfwRule>& rules) {
    for (size_t i = 0; i < rules.size(); ++i) {
        for (size_t j = 0; j < rules.size(); ++j) {
            if (i != j && isRuleContained(rules[j], rules[i])) {
                std::cout << "规则 [" << rules[i].number << "] 是冗余的，被规则 ["
                    << rules[j].number << "] 包含" << std::endl;

                std::cout << "规则 [" << rules[j].number << "]: ";
                rules[j].print();

                std::cout << "规则 [" << rules[i].number << "]: ";
                rules[i].print();

                std::cout << std::endl;
                break;  // 一旦找到一个包含当前规则的规则，就不需要继续检查了
            }
        }
    }
}
