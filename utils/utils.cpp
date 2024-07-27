#include"utils.h"

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