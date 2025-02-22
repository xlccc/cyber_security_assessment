#ifndef MYSQL_SCAN_H
#define MYSQL_SCAN_H

#include <string>
#include <vector>
#include <memory>
#include "mysql_connection_pool.h"
#include <iostream>
// MySQL default users
const std::vector<std::string> DEFAULT_USERS = {
    "root", "mysql.session", "mysql.sys",
    "mysql.infoschema", "debian-sys-maint"
};

// Structures to hold MySQL information
struct VariableGlobal {
    std::string key;
    std::string value;
};

struct Plugin {
    std::string name;
    std::string status;
    std::string type;
    std::string library;
    std::string license;
};

struct UserInfo {
    std::string user;
    std::string host;
    std::string authentication_string;
    std::string plugin;
    std::string ssl_type;
    std::string account_locked;
    std::string password_lifetime;
    std::string password_expired;
    std::string password_last_changed;
    std::string privileges;
    bool is_super_user;
};

struct DatabaseInfo {
    std::string name;
    std::string size;
    std::string table_count;
};

struct Role {
    std::string user;
    std::string role;
};

struct LogInfo {
    std::string error_log;
    std::string general_log;
    std::string general_log_file;
    std::string bin_log;
    std::string slow_query_log;
    std::string slow_query_log_file;
};

class MySQLScanner {
public:
    explicit MySQLScanner(std::shared_ptr<ConnectionPool> pool);

    // Main scanning function
    void scanAll();

    // Individual scan functions
    void scanBasicInfo();           // 版本、数据目录、连接ID
    void scanUsers();               // 用户信息
    void scanRoles();              // 角色信息
    void scanPasswordPolicies();    // 密码策略
    void scanPasswordLifetime();    // 密码过期
    void scanLockingPolicies();     // 失败锁定
    void scanTimeoutPolicies();     // 超时策略
    void scanLogSettings();         // 日志设置

private:
    // 类型检查函数
    template <typename T>
    bool getValueFromRow(mysqlx::Row& row, int index, T& value) {
        try {
            value = row[index].get<T>();
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Error getting value at index " << index << ": " << e.what() << std::endl;
            return false;
        }
    }
    std::shared_ptr<ConnectionPool> pool_;
    std::shared_ptr<mysqlx::Session> getConnection();
    bool isDefaultUser(const std::string& username);
    bool isSuperUser(const std::string& grants);
    std::string formatSize(double size_in_mb);

    // Helper function to execute queries
    template<typename T>
    std::vector<T> executeQuery(const std::string& query);
};

#endif // MYSQL_SCAN_H