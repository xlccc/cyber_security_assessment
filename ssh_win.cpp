#include "ssh_win.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <fcntl.h>
#include <string.h>


// 构造函数：建立 SSH 连接
SSHClient::SSHClient(const std::string& ip, int port, const std::string& username, const std::string& password) {
    session = ssh_new();
    if (!session) {
        throw std::runtime_error("[ERROR] Failed to create SSH session.");
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    // 连接服务器
    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        throw std::runtime_error("[ERROR] SSH connect failed: " + std::string(ssh_get_error(session)));
    }

    // 认证
    if (ssh_userauth_password(session, nullptr, password.c_str()) != SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        throw std::runtime_error("[ERROR] SSH authentication failed: " + std::string(ssh_get_error(session)));
    }

    std::cout << "[INFO] SSH connection established successfully.\n";

   
}


std::string SSHClient::executeCommand(const std::string& command) {
    if (!session) {
        throw std::runtime_error("Session not initialized.");
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == nullptr) {
        throw std::runtime_error("Failed to create SSH channel.");
    }

    // 打开 session channel
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        throw std::runtime_error("Failed to open SSH channel session.");
    }

    // 执行命令
    if (ssh_channel_request_exec(channel, command.c_str()) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        throw std::runtime_error("Failed to execute command over SSH channel.");
    }

    // 读取输出
    std::string result;
    char buffer[256];
    int nbytes;

    // 循环读取数据直到结束
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        result.append(buffer, nbytes);
    }

    // 关闭和释放 channel
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return result;
}

std::string SSHClient::executeBat(const char* filename) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Failed to create channel\n");
        return "Error: Failed to create channel";
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Failed to open session\n");
        ssh_channel_free(channel);
        return "Error: Failed to open session";
    }

    std::string filenameStr(filename); // 将const char*转换为std::string
    std::string command = "curl -o C:\\Scripts\\" + filenameStr + " http://192.168.0.129:8081/getScript?file=" + filenameStr;

    if (ssh_channel_request_exec(channel, command.c_str()) != SSH_OK) { // 转回const char*
        fprintf(stderr, "Failed to get script\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return "Error: Failed to get script";
    }

    

    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return secondStep(filenameStr);
}

//执行脚本的第二部，用于开启通道执行脚本
std::string SSHClient::secondStep(std::string filename) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Failed to create channel\n");
        return "Error: Failed to create channel";
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Failed to open session\n");
        ssh_channel_free(channel);
        return "Error: Failed to open session";
    }

    const std::string command = "cmd /c \"C:\\Scripts\\" + filename + "\"";

    if (ssh_channel_request_exec(channel, command.c_str()) != SSH_OK) { // 转回const char*
        std::string err = ssh_get_error(session);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        std::cout << "Error: Command failed - " + err << std::endl;
        return "Error: Command failed - " + err;
    }

    char buffer[256];
    int nbytes;
    char last_line[256] = "";

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0';
        // 安全地复制字符串，避免缓冲区溢出
        strncpy(last_line, buffer, sizeof(last_line) - 1);
        last_line[sizeof(last_line) - 1] = '\0';
    }

    int exit_status = ssh_channel_get_exit_status(channel);
    std::string res = std::to_string(exit_status) + ":" + last_line;

    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return res;
}

//bool SSHClient::uploadFileToCDrive(const std::string& localFilePath, const std::string& remoteFilePath) {
//    // 替换反斜杠为正斜杠
//    std::string formattedPath = remoteFilePath;
//    std::replace(formattedPath.begin(), formattedPath.end(), '\\', '/');
//
//    // 提取文件名
//    std::string fileName = formattedPath.substr(formattedPath.find_last_of('/') + 1);
//
//    ssh_scp scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, formattedPath.c_str());
//    if (scp == nullptr) {
//        std::cerr << "无法创建SCP会话：" << ssh_get_error(session) << std::endl;
//        return false;
//    }
//
//    if (ssh_scp_init(scp) != SSH_OK) {
//        std::cerr << "SCP会话初始化失败：" << ssh_get_error(session) << std::endl;
//        ssh_scp_free(scp);
//        return false;
//    }
//
//    // 打开本地文件
//    std::ifstream file(localFilePath, std::ios::binary);
//    if (!file.is_open()) {
//        std::cerr << "无法打开本地文件：" << localFilePath << std::endl;
//        ssh_scp_close(scp);
//        ssh_scp_free(scp);
//        return false;
//    }
//
//    // 计算文件大小
//    file.seekg(0, std::ios::end);
//    size_t fileSize = file.tellg();
//    file.seekg(0, std::ios::beg);
//
//    // 推送文件元数据（仅使用文件名）
//    if (ssh_scp_push_file(scp, fileName.c_str(), fileSize, 0644) != SSH_OK) {
//        std::cerr << "无法上传文件元数据：" << ssh_get_error(session) << std::endl;
//        file.close();
//        ssh_scp_close(scp);
//        ssh_scp_free(scp);
//        return false;
//    }
//
//    // 推送文件内容
//    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
//    if (ssh_scp_write(scp, content.c_str(), content.size()) != SSH_OK) {
//        std::cerr << "文件上传失败：" << ssh_get_error(session) << std::endl;
//        file.close();
//        ssh_scp_close(scp);
//        ssh_scp_free(scp);
//        return false;
//    }
//
//    file.close();
//    ssh_scp_close(scp);
//    ssh_scp_free(scp);
//
//    std::cout << "文件成功上传到目标位置：" << formattedPath << std::endl;
//    return true;
////}



// **析构函数：确保断开连接**
SSHClient::~SSHClient() {
    
    if (session) {
        ssh_disconnect(session);
        ssh_free(session);
    }

}
