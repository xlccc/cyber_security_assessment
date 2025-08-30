#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iconv.h>
#include <stdexcept>
// 编码转换函数
std::string convertEncoding(const std::string& input, const std::string& fromEncoding, const std::string& toEncoding);
// UTF-8 转 UTF-16LE原始字节
std::string utf8ToUtf16Le(const std::string& utf8Str);
//标准Base64编码函数
extern const char B64Table[];

std::string base64Encode(const std::string& binData);
std::string executeRemotePSScript(const std::string& localScriptPath);


std::string extractResultCode(const std::string& output);
