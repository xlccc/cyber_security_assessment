#pragma once

#include <libssh/libssh.h>
#include <string>
#include <fstream>
#include<tuple>

class SSHClient {
private:
    ssh_session session;  // 维护 SSH 会话（长连接）
    ssh_channel channel = nullptr;;  // 维护可复用的 SSH 交互通道

  
   

public:
    struct ScriptResult {
        std::string output;
        int exitCode;
    };
    // **构造函数：建立 SSH 连接**
    SSHClient(const std::string& ip, int port, const std::string& username, const std::string& password);

    // **执行命令，支持长连接**
    std::string executeCommand(const std::string& command);
    
    std::string executeBat(const char* filename);
    std::string secondStep(const std::string filename);
   // bool uploadFileToCDrive(const std::string& localFilePath, const std::string& remoteFilePath);

    // **析构函数：确保断开连接**
    ~SSHClient();
};

