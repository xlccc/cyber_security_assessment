﻿#include"utils.h"
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