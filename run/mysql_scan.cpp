#include "mysql_scan.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>

// 构造函数
MySQLScanner::MySQLScanner(std::shared_ptr<ConnectionPool> pool)
    : pool_(pool) {}

// 获取连接
std::shared_ptr<mysqlx::Session> MySQLScanner::getConnection() {
    return pool_->getConnection();
}

// 判断是否为系统自带默认账户
bool MySQLScanner::isDefaultUser(const std::string& username) {
    return std::find(DEFAULT_USERS.begin(), DEFAULT_USERS.end(), username) != DEFAULT_USERS.end();
}

// 判断是否为超级管理员
bool MySQLScanner::isSuperUser(const std::string& grants) {
    return (grants.find("GRANT ALL PRIVILEGES ON *.*") != std::string::npos) ||
        (grants.find("GRANT SUPER") != std::string::npos);
}

// 格式化大小（可选）
std::string MySQLScanner::formatSize(double size_in_mb) {
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (size_in_mb >= 1024) {
        ss << (size_in_mb / 1024) << " GB";
    }
    else {
        ss << size_in_mb << " MB";
    }
    return ss.str();
}

// 总体扫描入口保持不变
void MySQLScanner::scanAll() {
    std::cout << "\n=== MySQL Security Scan Report ===\n\n";
    try {
        scanBasicInfo();
        scanUsers();
        scanRoles();
        scanPasswordPolicies();
        scanPasswordLifetime();
        scanLockingPolicies();
        scanTimeoutPolicies();
        scanLogSettings();
    }
    catch (const std::exception& e) {
        std::cerr << "Error during scan: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanBasicInfo() {
    auto conn = getConnection();
    try {
        std::cout << "=== Basic Information ===\n";

        // 1) MySQL Version (字符串类型)
        {
            auto result = conn->sql("SELECT VERSION()").execute();
            auto row = result.fetchOne();
            std::string version;
            if (!getValueFromRow<std::string>(row, 0, version)) {
                version = "Unknown";
            }
            std::cout << "MySQL Version: " << version << "\n";
        }

        // 2) Data directory (字符串类型)
        {
            auto result = conn->sql("SHOW VARIABLES LIKE 'datadir'").execute();
            auto row = result.fetchOne();
            std::string datadir;
            if (!getValueFromRow<std::string>(row, 1, datadir)) {
                datadir = "Unknown";
            }
            std::cout << "Data Directory: " << datadir << "\n";
        }

        // 3) Connection ID (整数类型)
        {
            auto result = conn->sql("SELECT CONNECTION_ID()").execute();
            auto row = result.fetchOne();
            int64_t connId = 0;  // 使用 int64_t 防止溢出
            if (!getValueFromRow<int64_t>(row, 0, connId)) {
                connId = -1;
            }
            std::cout << "Connection ID: " << connId << "\n\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning basic info: " << e.what() << std::endl;
    }
}



void MySQLScanner::scanUsers() {
    auto conn = getConnection();
    try {
        std::cout << "=== User Information ===\n";
        auto result = conn->sql(
            "SELECT user, host, "
            "COALESCE(authentication_string, '') as auth_string, "
            "COALESCE(plugin, '') as plugin, "
            "COALESCE(ssl_type, '') as ssl_type, "
            "COALESCE(account_locked, '') as account_locked, "
            "CAST(COALESCE(password_lifetime, -1) AS SIGNED) as lifetime, "  // 转换为有符号整数
            "COALESCE(password_expired, '') as password_expired, "
            "COALESCE(CAST(password_last_changed AS CHAR), '') as last_changed "  // 日期转字符串
            "FROM mysql.user"
        ).execute();

        for (auto row : result) {
            std::string username, host, authString, plugin, sslType, accountLocked;
            std::string passwordExpired, lastChanged;
            int64_t lifetime;

            if (!getValueFromRow<std::string>(row, 0, username)) username = "N/A";
            if (!getValueFromRow<std::string>(row, 1, host)) host = "%";
            if (!getValueFromRow<std::string>(row, 2, authString)) authString = "N/A";
            if (!getValueFromRow<std::string>(row, 3, plugin)) plugin = "N/A";
            if (!getValueFromRow<std::string>(row, 4, sslType)) sslType = "N/A";
            if (!getValueFromRow<std::string>(row, 5, accountLocked)) accountLocked = "N/A";
            if (!getValueFromRow<int64_t>(row, 6, lifetime)) lifetime = -1;
            if (!getValueFromRow<std::string>(row, 7, passwordExpired)) passwordExpired = "N/A";
            if (!getValueFromRow<std::string>(row, 8, lastChanged)) lastChanged = "N/A";

            std::cout << "\nUser: " << username
                << (isDefaultUser(username) ? " (Default Account)" : "")
                << "\n";
            std::cout << "Host: " << host << "\n";
            std::cout << "Plugin: " << plugin << "\n";
            std::cout << "SSL Type: " << sslType << "\n";
            std::cout << "Account Locked: " << accountLocked << "\n";
            std::cout << "Password Lifetime: " << (lifetime < 0 ? "N/A" : std::to_string(lifetime)) << "\n";
            std::cout << "Password Expired: " << passwordExpired << "\n";
            std::cout << "Password Last Changed: " << lastChanged << "\n";

            try {
                std::string query = "SHOW GRANTS FOR '" + username + "'@'" + host + "'";
                auto grantsRes = conn->sql(query).execute();
                std::cout << "Privileges:\n";
                std::string grant_str;
                for (auto grantRow : grantsRes) {
                    if (!getValueFromRow<std::string>(grantRow, 0, grant_str)) {
                        grant_str = "N/A";
                    }
                    std::cout << "  " << grant_str << "\n";
                }
                if (isSuperUser(grant_str)) {
                    std::cout << "Role: Super Administrator\n";
                }
                else {
                    std::cout << "Role: Regular User\n";
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error getting privileges: " << e.what() << std::endl;
            }
            std::cout << std::string(50, '-') << "\n";
        }
        std::cout << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning users: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanRoles() {
    auto conn = getConnection();
    try {
        std::cout << "=== Role Information ===\n";
        auto result = conn->sql(
            "SELECT COALESCE(USER, '') as user, "
            "COALESCE(DEFAULT_ROLE_USER, '') as role_user "
            "FROM mysql.default_roles"
        ).execute();

        bool hasRoles = false;
        for (auto row : result) {
            hasRoles = true;
            std::string user, role;
            if (!getValueFromRow<std::string>(row, 0, user)) user = "N/A";
            if (!getValueFromRow<std::string>(row, 1, role)) role = "N/A";

            std::cout << "User: " << user
                << " -> Role: " << role << "\n";
        }

        if (!hasRoles) {
            std::cout << "No role assignments found (this may be normal in pre-8.0 versions)\n";
        }
        std::cout << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning roles: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanPasswordPolicies() {
    auto conn = getConnection();
    try {
        std::cout << "=== Password Policies ===\n";
        auto result = conn->sql(
            "SHOW VARIABLES LIKE 'validate_password%'"
        ).execute();

        bool hasPasswordValidation = false;
        for (auto row : result) {
            hasPasswordValidation = true;
            std::string varName, varValue;
            if (!getValueFromRow<std::string>(row, 0, varName)) varName = "N/A";
            if (!getValueFromRow<std::string>(row, 1, varValue)) varValue = "N/A";

            std::cout << std::setw(40) << varName
                << ": " << varValue << "\n";
        }

        if (!hasPasswordValidation) {
            std::cout << "Password validation plugin is not installed\n";
        }
        std::cout << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning password policies: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanLockingPolicies() {
    auto conn = getConnection();
    try {
        std::cout << "=== Account Locking Policies ===\n";
        auto result = conn->sql(
            "SHOW VARIABLES LIKE '%connection_control%'"
        ).execute();

        bool hasLockingPolicy = false;
        for (auto row : result) {
            hasLockingPolicy = true;
            std::string varName, varValue;
            if (!getValueFromRow<std::string>(row, 0, varName)) varName = "N/A";
            if (!getValueFromRow<std::string>(row, 1, varValue)) varValue = "N/A";

            std::cout << std::setw(40) << varName
                << ": " << varValue << "\n";
        }

        if (!hasLockingPolicy) {
            std::cout << "Connection control plugin is not installed\n";
        }
        std::cout << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning locking policies: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanLogSettings() {
    auto conn = getConnection();
    try {
        std::cout << "=== Log Settings ===\n";

        // Helper lambda for getting variable values
        auto getVariable = [&](const std::string& varName) -> std::string {
            auto result = conn->sql("SHOW VARIABLES LIKE ?").bind(varName).execute();
            auto row = result.fetchOne();
            std::string val;
            if (!getValueFromRow<std::string>(row, 1, val)) {
                return "N/A";
            }
            return val;
            };

        std::cout << "Error Log: " << getVariable("log_error") << "\n";
        std::cout << "General Log Enabled: " << getVariable("general_log") << "\n";
        std::cout << "General Log File: " << getVariable("general_log_file") << "\n";
        std::cout << "Binary Log Enabled: " << getVariable("log_bin") << "\n";
        std::cout << "Slow Query Log Enabled: " << getVariable("slow_query_log") << "\n";
        std::cout << "Slow Query Log File: " << getVariable("slow_query_log_file") << "\n\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning log settings: " << e.what() << std::endl;
    }
}



void MySQLScanner::scanPasswordLifetime() {
    auto conn = getConnection();
    try {
        std::cout << "=== Password Lifetime Settings ===\n";
        auto result = conn->sql(
            "SELECT @@default_password_lifetime as lifetime"
        ).execute();

        auto row = result.fetchOne();
        int64_t lifetime;
        if (!getValueFromRow<int64_t>(row, 0, lifetime)) {
            lifetime = 0;
        }
        std::cout << "Default Password Lifetime (days): "
            << lifetime << "\n\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning password lifetime: " << e.what() << std::endl;
    }
}

void MySQLScanner::scanTimeoutPolicies() {
    auto conn = getConnection();
    try {
        std::cout << "=== Timeout Policies ===\n";
        // 超时值通常是整数类型
        {
            auto result = conn->sql(
                "SELECT @@connect_timeout as timeout"
            ).execute();
            auto row = result.fetchOne();
            int64_t timeoutVal;
            if (!getValueFromRow<int64_t>(row, 0, timeoutVal)) {
                timeoutVal = -1;
            }
            std::cout << "Connection Timeout: "
                << (timeoutVal < 0 ? "N/A" : std::to_string(timeoutVal))
                << " seconds\n";
        }

        {
            auto result = conn->sql(
                "SELECT @@wait_timeout as timeout"
            ).execute();
            auto row = result.fetchOne();
            int64_t waitVal;
            if (!getValueFromRow<int64_t>(row, 0, waitVal)) {
                waitVal = -1;
            }
            std::cout << "Wait Timeout: "
                << (waitVal < 0 ? "N/A" : std::to_string(waitVal))
                << " seconds\n\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning timeout policies: " << e.what() << std::endl;
    }
}