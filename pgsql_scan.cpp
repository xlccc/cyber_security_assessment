#include "pgsql_scan.h"
#include "Command_Excute.h"
#include <sstream>
#include <vector>

std::string check_pgsql_unauthorized(const std::string& ssh_user,
    const std::string& ssh_pass,
    const std::string& pg_user,
    const std::string& pg_pass,
    const std::string& host,
    const std::string& port) {

    std::string result;
    ssh_session session;

    // 建立SSH连接
    session = ssh_new();
    if (session == nullptr) {
        return "SSH会话创建失败";
    }

    // 设置SSH连接参数
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

    // 构建PostgreSQL命令
    std::string psql_cmd = "PGPASSWORD='" + pg_pass + "' psql -U " + pg_user +
        " -h localhost -p " + port + " -d postgres -t -A -c ";

    // 测试PostgreSQL连接
    std::string test_result = execute_commands(session, psql_cmd + "'SELECT version();'");
    if (test_result.empty() || test_result.find("ERROR") != std::string::npos) {
        ssh_disconnect(session);
        ssh_free(session);
        return "PostgreSQL连接失败: " + test_result;
    }

    result = "PostgreSQL安全检查结果:\n\n";

    // 版本信息
    result += "PostgreSQL版本信息:\n" +
        execute_commands(session, psql_cmd + "'SELECT version();'") + "\n";

    // 用户和权限信息
    result += "用户角色信息:\n" +
        execute_commands(session, psql_cmd + "'SELECT oid,rolname,rolpassword,rolsuper,rolcanlogin,rolvaliduntil,rolcreaterole,rolcreatedb,rolinherit FROM pg_authid;'") + "\n";

    result += "角色成员关系:\n" +
        execute_commands(session, psql_cmd + "'SELECT r.rolname AS role_name, ARRAY(SELECT b.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) WHERE m.member = r.oid) as memberof FROM pg_catalog.pg_roles r;'") + "\n";

    // 网络配置
    result += "监听地址配置:\n" +
        execute_commands(session, psql_cmd + "'SHOW listen_addresses;'") + "\n";

    // SSL配置
    result += "SSL最低协议版本:\n" +
        execute_commands(session, psql_cmd + "'SHOW ssl_min_protocol_version;'") + "\n";

    // 日志配置
    result += "日志收集器状态:\n" +
        execute_commands(session, psql_cmd + "'SHOW logging_collector;'") + "\n";

    result += "日志最低消息级别:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_min_messages;'") + "\n";

    result += "日志目录:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_directory;'") + "\n";

    result += "日志文件名:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_filename;'") + "\n";

    result += "日志语句配置:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_statement;'") + "\n";

    result += "连接日志:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_connections;'") + "\n";

    result += "断开连接日志:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_disconnections;'") + "\n";

    result += "日志行前缀:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_line_prefix;'") + "\n";

    result += "日志目标:\n" +
        execute_commands(session, psql_cmd + "'SHOW log_destination;'") + "\n";

    // 插件信息
    result += "已加载插件:\n" +
        execute_commands(session, psql_cmd + "'SHOW shared_preload_libraries;'") + "\n";

    // 连接限制
    result += "最大连接数:\n" +
        execute_commands(session, psql_cmd + "'SHOW max_connections;'") + "\n";

    // 超时设置
    result += "语句超时设置:\n" +
        execute_commands(session, psql_cmd + "'SHOW statement_timeout;'") + "\n";

    result += "空闲会话超时:\n" +
        execute_commands(session, psql_cmd + "'SHOW idle_session_timeout;'") + "\n";

    // 认证配置
    result += "密码加密方式:\n" +
        execute_commands(session, psql_cmd + "'SHOW password_encryption;'") + "\n";

    // 当前活动连接
    result += "当前活动连接:\n" +
        execute_commands(session, psql_cmd + "'SELECT datname, usename, client_addr, client_port, backend_start, state FROM pg_stat_activity;'") + "\n";

    // 清理SSH连接
    ssh_disconnect(session);
    ssh_free(session);
    return result;
}