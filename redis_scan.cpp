#include "redis_scan.h"
#include "Command_Excute.h"
#include <sstream>
#include <vector>

std::string check_redis_unauthorized(const std::string& ssh_user,
    const std::string& ssh_pass,
    const std::string& redis_pass,
    const std::string& host) {
    std::string result;
    ssh_session session;

    // 建立SSH连接
    session = ssh_new();
    if (session == nullptr) {
        return "SSH会话创建失败";
    }

    // 设置SSH连接参数，使用传入的host
    ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, ssh_user.c_str());

    // 连接SSH
    if (ssh_connect(session) != SSH_OK) {
        result = "SSH连接失败: " + std::string(ssh_get_error(session));
        ssh_free(session);
        return result;
    }

    // SSH密码认证
    if (ssh_userauth_password(session, nullptr, ssh_pass.c_str()) != SSH_AUTH_SUCCESS) {
        result = "SSH认证失败: " + std::string(ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return result;
    }

    // 构建Redis命令
    std::string redis_cmd = redis_pass.empty() ? "redis-cli" : "redis-cli -a " + redis_pass;

    // Redis连接测试
    std::string ping_result = execute_commands(session, redis_cmd + " ping");
    if (ping_result.find("PONG") == std::string::npos) {
        ssh_disconnect(session);
        ssh_free(session);
        return "Redis连接失败: " + ping_result;
    }

    result = "Redis安全检查结果:\n\n";

    // 分类执行检查并添加描述性文本
    // 基本配置检查
    result += "绑定地址配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET bind") + "";

    result += "保护模式状态:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET protected-mode") + "";

    result += "密码配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET requirepass") + "";

    result += "端口配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET port") + "";

    // 补充SSL端口和协议检查
    result += "SSL端口配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET tls-port") + "";

    result += "SSL协议配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET tls-protocols") + "";

    // 日志相关配置
    result += "日志文件配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET logfile") + "";

    result += "日志级别配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET loglevel") + "";

    // 超时配置
    result += "连接超时配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET timeout") + "";

    // ACL相关配置
    result += "ACL文件配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET aclfile") + "";

    result += "ACL日志长度:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET acllog-max-len") + "";

    // 尝试获取ACL用户列表
    result += "ACL用户列表:\n" +
        execute_commands(session, redis_cmd + " ACL LIST") + "";

    // 最大连接数配置
    result += "最大连接数配置:\n" +
        execute_commands(session, redis_cmd + " CONFIG GET maxclients") + "";

    // 当前连接信息
    result += "当前连接的客户端:\n" +
        execute_commands(session, redis_cmd + " CLIENT LIST") + "\n";

    // 服务器详细信息
    result += "服务器详细信息:\n" +
        execute_commands(session, redis_cmd + " INFO") + "";


    // 清理SSH连接
    ssh_disconnect(session);
    ssh_free(session);

    return result;
}

//#include "redis_scan.h"
//#include "Command_Excute.h"
//#include <sstream>
//#include <vector>
//
//std::string check_redis_unauthorized(const std::string& ssh_user,
//    const std::string& ssh_pass,
//    const std::string& redis_pass) {
//    std::string result;
//    ssh_session session;
//
//    // 建立SSH连接
//    session = ssh_new();
//    if (session == nullptr) {
//        return "SSH会话创建失败";
//    }
//
//    // 设置SSH连接参数
//    ssh_options_set(session, SSH_OPTIONS_HOST, "192.168.1.10");
//    ssh_options_set(session, SSH_OPTIONS_USER, ssh_user.c_str());
//
//    // 连接SSH
//    if (ssh_connect(session) != SSH_OK) {
//        result = "SSH连接失败: " + std::string(ssh_get_error(session));
//        ssh_free(session);
//        return result;
//    }
//
//    // SSH密码认证
//    if (ssh_userauth_password(session, nullptr, ssh_pass.c_str()) != SSH_AUTH_SUCCESS) {
//        result = "SSH认证失败: " + std::string(ssh_get_error(session));
//        ssh_disconnect(session);
//        ssh_free(session);
//        return result;
//    }
//
//    // 构建Redis命令
//    std::string redis_cmd = redis_pass.empty() ? "redis-cli" : "redis-cli -a " + redis_pass;
//
//    // 执行Redis安全检查
//    std::vector<std::string> check_commands = {
//        "ping",
//        "CONFIG GET bind",
//        "CONFIG GET protected-mode",
//        "CONFIG GET requirepass",
//        "CONFIG GET port",
//        "CONFIG GET maxclients",
//        "INFO",
//        "CLIENT LIST"
//    };
//
//    // 执行检查并收集结果
//    result = "Redis安全检查结果:\n\n";
//    for (const auto& cmd : check_commands) {
//        result += "执行命令: " + cmd + "\n";
//        result += execute_commands(session, redis_cmd + " " + cmd);
//        result += "\n-------------------\n";
//    }
//
//    // 清理SSH连接
//    ssh_disconnect(session);
//    ssh_free(session);
//
//    return result;
//}

//
//std::string check_redis_unauthorized(const std::string& ssh_user,
//    const std::string& ssh_pass,
//    const std::string& redis_user,
//    const std::string& redis_pass) {
//    
//    std::string result;
//    ssh_session session;
//
//    // 建立SSH连接
//    session = ssh_new();
//    if (session == nullptr) {
//        return "SSH会话创建失败";
//    }
//
//    // 设置SSH连接参数
//    ssh_options_set(session, SSH_OPTIONS_HOST, "192.168.1.9");
//    ssh_options_set(session, SSH_OPTIONS_USER, ssh_user.c_str());
//
//    // 连接SSH
//    if (ssh_connect(session) != SSH_OK) {
//        result = "SSH连接失败: " + std::string(ssh_get_error(session));
//        ssh_free(session);
//        return result;
//    }
//
//    // SSH密码认证
//    if (ssh_userauth_password(session, nullptr, ssh_pass.c_str()) != SSH_AUTH_SUCCESS) {
//        result = "SSH认证失败: " + std::string(ssh_get_error(session));
//        ssh_disconnect(session);
//        ssh_free(session);
//        return result;
//    }
//
//    // 构建Redis检查命令
//    std::string redis_cmd;
//    if (redis_user == "null" || redis_pass.empty()) {
//        redis_cmd = "redis-cli";
//    }
//    else {
//        redis_cmd = "redis-cli -a " + redis_pass;
//    }
//
//    // 执行Redis安全检查
//    std::vector<std::string> check_commands = {
//        "ping",
//        "CONFIG GET bind",
//        "CONFIG GET protected-mode",
//        "CONFIG GET requirepass",
//        "CONFIG GET port",
//        "CONFIG GET maxclients",
//        "INFO",
//        "CLIENT LIST"
//    };
//
//    // 执行检查并收集结果
//    result = "Redis安全检查结果:\n\n";
//    for (const auto& cmd : check_commands) {
//        result += "执行命令: " + cmd + "\n";
//        result += execute_commands(session, redis_cmd + " " + cmd);
//        result += "\n-------------------\n";
//    }
//
//    // 清理SSH连接
//    ssh_disconnect(session);
//    ssh_free(session);
//
//    return result;
//}