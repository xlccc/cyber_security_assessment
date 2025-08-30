#include"execute_win.h"
#include <filesystem>  // C++17 及以上版本
#include <ctime>
const char B64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


// 编码转换函数
std::string convertEncoding(const std::string& input, const std::string& fromEncoding, const std::string& toEncoding) {
    // 打开 iconv 转换描述符
    iconv_t cd = iconv_open(toEncoding.c_str(), fromEncoding.c_str());
    if (cd == (iconv_t)-1) {
        throw std::runtime_error("Failed to open iconv");
    }

    // 输入缓冲区
    size_t inbytesleft = input.size();
    char* inbuf = const_cast<char*>(input.data());

    // 输出缓冲区（预留足够的空间）
    size_t outbytesleft = inbytesleft * 4; // UTF-8 最多占用 4 字节
    std::string output(outbytesleft, '\0');
    char* outbuf = &output[0];

    // 执行编码转换
    if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) == (size_t)-1) {
        iconv_close(cd);
        throw std::runtime_error("Failed to convert encoding");
    }

    // 关闭 iconv 转换描述符
    iconv_close(cd);

    // 调整输出大小
    output.resize(output.size() - outbytesleft);
    return output;
}





// UTF-8 转 UTF-16LE原始字节
std::string utf8ToUtf16Le(const std::string& utf8Str) {
    iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
    size_t inBytesLeft = utf8Str.size();
    size_t outBytesLeft = (inBytesLeft + 1) * 4;
    char* inBuf = const_cast<char*>(utf8Str.c_str());
    std::string outBuf(outBytesLeft, '\0');
    char* outPtr = &outBuf[0];

    iconv(cd, &inBuf, &inBytesLeft, &outPtr, &outBytesLeft);
    iconv_close(cd);
    outBuf.resize(outBuf.size() - outBytesLeft);

    return outBuf;
}

// 标准Base64编码函数
std::string base64Encode(const std::string& binData) {
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(binData.c_str());
    unsigned int in_len = binData.size();
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += B64Table[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++)
            ret += B64Table[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }
    return ret;

}

// 封装完整调用远程 PowerShell 脚本
std::string executeRemotePSScript(const std::string& localScriptPath) {
    // 读取本地脚本内容（UTF-8）
    std::ifstream ifs(localScriptPath, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("Cannot open local script file.");
    }
    std::string scriptContent((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    // 去除UTF-8 BOM（如果有）
    if (scriptContent.size() >= 3 &&
        static_cast<unsigned char>(scriptContent[0]) == 0xEF &&
        static_cast<unsigned char>(scriptContent[1]) == 0xBB &&
        static_cast<unsigned char>(scriptContent[2]) == 0xBF) {
        scriptContent = scriptContent.substr(3);
    }

    // 转换UTF-8至UTF-16LE
    std::string utf16LeData = utf8ToUtf16Le(scriptContent);

    // Base64编码UTF-16LE字节
    std::string base64Encoded = base64Encode(utf16LeData);

    // 拼接最终远程执行命令
    std::string psCmd = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + base64Encoded;
    return psCmd;
}

// 提取脚本执行结果的最后一行
std::string extractResultCode(const std::string& output) {
    std::istringstream stream(output);
    std::string line, lastLine;

    while (std::getline(stream, line)) {
        if (!line.empty()) {
            lastLine = line; // 更新最后一行
        }
    }

    return lastLine; 
}
