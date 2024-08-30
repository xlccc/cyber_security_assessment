#include"utils.h"
#include <iostream>

//获取当前时间，字符串表示
std::string getCurrentTimestamp() {
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
    ss << std::put_time(&timestamp, "%Y-%m-%d %X");
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
    std::cout << "Original data (" << fromEncoding << "): " << input << std::endl;
    std::cout << "Converted data (UTF-8): " << output << std::endl;

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

    std::cout << "Original data (" << detectedEncoding << "): " << input << std::endl;
    std::cout << "Converted data (UTF-8): " << output << std::endl;

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

    // 设置sys.path
    PyObject* sys = PyImport_ImportModule("sys");
    PyObject* sys_path = PyObject_GetAttrString(sys, "path");
    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/scan/scripts"));
    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/scan"));
    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src"));
}
void finalizePython()
{
    // 终止Python解释器
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