#ifndef MYSQL_CONNECTION_POOL_H
#define MYSQL_CONNECTION_POOL_H

#include <mysqlx/xdevapi.h>
#include <queue>
#include <mutex>
#include <memory>
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <thread>
#include "utils/CommonDefs.h"

// 线程局部存储声明
namespace ConnectionPoolInternal {
    extern thread_local std::string current_thread_db;
}

// 数据库配置结构体
struct DatabaseConfig {
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
    std::string schema;        // 系统数据库（system_db）
    size_t initial_size;
    size_t max_size;
    std::chrono::seconds connection_timeout;
    int max_retries;       // 最大重试次数
    std::chrono::milliseconds retry_delay; // 重试延迟

    // 构造函数，提供默认值
    DatabaseConfig(
        std::string host_ = CONFIG.getDbHost(),
        uint16_t port_ = CONFIG.getDbPort(),
        std::string user_ = CONFIG.getDbUser(),
        std::string password_ = CONFIG.getDbPassword(),
        std::string schema_ = CONFIG.getDbSchema(),
        size_t initial_size_ = 5,
        size_t max_size_ = 20,
        std::chrono::seconds connection_timeout_ = std::chrono::seconds(30),
        int max_retries_ = 3,
        std::chrono::milliseconds retry_delay_ = std::chrono::milliseconds(500)
    ) : host(host_), port(port_), user(user_), password(password_),
        schema(schema_), initial_size(initial_size_), max_size(max_size_),
        connection_timeout(connection_timeout_), max_retries(max_retries_),
        retry_delay(retry_delay_) {
    }
};

class ConnectionPool {
public:
    // 设置当前线程使用的数据库
    static void setThreadDatabase(const std::string& db_name) {
        ConnectionPoolInternal::current_thread_db = db_name;
    }

    // 构造函数，接收配置参数
    explicit ConnectionPool(const DatabaseConfig& config)
        : config_(config), currentSize_(0), bad_conn_count_(0) {
        // 初始化连接池
        for (size_t i = 0; i < config_.initial_size; ++i) {
            try {
                addConnection();
            }
            catch (const std::exception& e) {
                std::cerr << "初始化连接失败: " << e.what() << std::endl;
                // 继续尝试初始化其他连接
            }
        }

        if (connections_.empty()) {
            std::cerr << "警告: 无法初始化任何数据库连接" << std::endl;
        }
    }

    // 获取配置对象
    const DatabaseConfig& getDatabaseConfig() const {
        return config_;
    }

    ~ConnectionPool() {
        // 清理所有连接
        std::lock_guard<std::mutex> lock(mutex_);
        while (!connections_.empty()) {
            connections_.pop();
        }
    }

    std::shared_ptr<mysqlx::Session> getConnection() {
        std::lock_guard<std::mutex> lock(mutex_);

        // 如果连接池为空且未达到最大连接数，添加新连接
        if (connections_.empty() && currentSize_ < config_.max_size) {
            try {
                addConnection();
            }
            catch (const std::exception& e) {
                std::cerr << "创建新连接失败: " << e.what() << std::endl;
            }
        }

        // 如果连接池仍为空，抛出异常
        if (connections_.empty()) {
            throw std::runtime_error("连接池中没有可用连接");
        }

        auto conn = std::move(connections_.front());
        connections_.pop();

        // 验证连接是否有效，并实现重试机制
        for (int retry = 0; retry <= config_.max_retries; ++retry) {
            try {
                // 尝试执行简单查询来验证连接
                conn->sql("SELECT 1").execute();
                // 连接有效，重置错误计数
                bad_conn_count_ = 0;
                break;
            }
            catch (const mysqlx::Error& err) {
                std::cerr << "MySQL验证错误 (尝试 " << retry + 1 << "/" << config_.max_retries + 1
                    << "): " << err.what() << std::endl;

                // 检查是否是SSL错误
                if (std::string(err.what()).find("SSL routines") != std::string::npos &&
                    retry < config_.max_retries) {
                    // 这是SSL错误，等待后重试
                    std::this_thread::sleep_for(config_.retry_delay);
                    continue;
                }

                // 最后一次尝试或非SSL错误，创建新连接
                bad_conn_count_++;
                try {
                    conn = createConnection();
                }
                catch (const std::exception& e) {
                    std::cerr << "重新创建连接失败: " << e.what() << std::endl;
                    if (retry == config_.max_retries) {
                        throw std::runtime_error("无法建立有效的数据库连接");
                    }
                }
            }
            catch (const std::exception& e) {
                std::cerr << "验证连接时出现标准异常: " << e.what() << std::endl;
                bad_conn_count_++;

                if (retry == config_.max_retries) {
                    try {
                        conn = createConnection();
                    }
                    catch (...) {
                        throw std::runtime_error("无法建立有效的数据库连接");
                    }
                }
            }
            catch (...) {
                std::cerr << "验证连接时出现未知异常" << std::endl;
                bad_conn_count_++;

                if (retry == config_.max_retries) {
                    try {
                        conn = createConnection();
                    }
                    catch (...) {
                        throw std::runtime_error("无法建立有效的数据库连接");
                    }
                }
            }
        }

        // 自动切换到线程级数据库
        if (!ConnectionPoolInternal::current_thread_db.empty()) {
            try {
                conn->sql("USE " + ConnectionPoolInternal::current_thread_db).execute();
            }
            catch (const std::exception& e) {
                std::cerr << "数据库切换失败: " << e.what() << std::endl;
                throw;
            }
        }

        // 如果错误计数过高，清理连接池
        if (bad_conn_count_ > 3) {
            cleanupConnections();
            bad_conn_count_ = 0;
        }

        return std::shared_ptr<mysqlx::Session>(conn.release(),
            [this](mysqlx::Session* session) {
                if (session != nullptr) {
                    this->returnConnection(std::unique_ptr<mysqlx::Session>(session));
                }
            });
    }

    bool initializeUserSchema(const std::string& user_schema) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto sys_conn = createConnection();

        try {
            // ===== 1. 初始化设置 =====
            sys_conn->sql("CREATE DATABASE IF NOT EXISTS `" + user_schema + "`").execute();
            sys_conn->sql("USE template_db").execute();
            sys_conn->sql("SET FOREIGN_KEY_CHECKS=0").execute();

            // ===== 2. 获取所有表 =====
            auto tables = sys_conn->sql("SHOW TABLES").execute();
            std::vector<std::string> table_names;
            for (auto table : tables.fetchAll()) {
                table_names.push_back(table[0].get<std::string>());
            }

            // ===== 3. 清理可能存在的表 =====
            sys_conn->sql("USE " + user_schema).execute();
            for (const auto& table_name : table_names) {
                try {
                    sys_conn->sql("DROP TABLE IF EXISTS `" + table_name + "`").execute();
                }
                catch (const mysqlx::Error& e) {
                    std::cerr << "[WARN] Failed to drop table " << table_name
                        << " in " << user_schema << ": " << e.what() << std::endl;
                }
            }

            // ===== 4. 复制表结构 =====
            sys_conn->sql("USE template_db").execute();
            for (const auto& table_name : table_names) {
                // 获取原表定义
                auto create_row = sys_conn->sql("SHOW CREATE TABLE `" + table_name + "`")
                    .execute()
                    .fetchOne();
                std::string create_stmt = create_row[1].get<std::string>();

                // ===== 关键修改1：确保外键约束名称唯一 =====
                std::string new_create = create_stmt;

                // 替换所有外键约束名称，添加用户schema前缀
                size_t fk_pos = 0;
                while ((fk_pos = new_create.find("CONSTRAINT `", fk_pos)) != std::string::npos) {
                    size_t end_pos = new_create.find("`", fk_pos + 12);
                    if (end_pos != std::string::npos) {
                        std::string old_name = new_create.substr(fk_pos + 12, end_pos - (fk_pos + 12));
                        std::string new_name = user_schema + "_" + old_name;
                        new_create.replace(fk_pos + 12, old_name.length(), new_name);
                    }
                    fk_pos += 12;
                }

                // ===== 关键修改2：替换所有外键引用 =====
                // 替换所有引用template_db的地方
                size_t ref_pos = 0;
                while ((ref_pos = new_create.find("REFERENCES `template_db`", ref_pos)) != std::string::npos) {
                    new_create.replace(ref_pos, 13, "REFERENCES `" + user_schema + "`");
                    ref_pos += user_schema.length() + 1;
                }

                // 替换所有引用template_db.表名的地方
                ref_pos = 0;
                while ((ref_pos = new_create.find("REFERENCES `template_db`.`", ref_pos)) != std::string::npos) {
                    new_create.replace(ref_pos, 13, "REFERENCES `" + user_schema + "`.");
                    ref_pos += user_schema.length() + 1;
                }

                // ===== 关键修改3：使用唯一临时表名 =====
                std::string temp_table = "temp_" + table_name + "_" + std::to_string(std::time(nullptr));

                // 替换CREATE TABLE语句中的表名
                size_t create_pos = new_create.find("CREATE TABLE ");
                if (create_pos != std::string::npos) {
                    size_t table_name_start = new_create.find('`', create_pos);
                    size_t table_name_end = new_create.find('`', table_name_start + 1);

                    if (table_name_start != std::string::npos && table_name_end != std::string::npos) {
                        new_create.replace(
                            table_name_start,
                            table_name_end - table_name_start + 1,
                            "`" + temp_table + "`"
                        );
                    }
                }

                // ===== 5. 安全创建流程 =====
                try {
                    // 删除可能存在的临时表
                    sys_conn->sql("DROP TABLE IF EXISTS `" + temp_table + "`").execute();

                    // 创建临时表
                    sys_conn->sql(new_create).execute();

                    // 复制数据
                    sys_conn->sql("INSERT INTO `" + temp_table + "` SELECT * FROM `template_db`.`" + table_name + "`")
                        .execute();

                    // 移动到用户数据库
                    sys_conn->sql("RENAME TABLE `" + temp_table + "` TO `" + user_schema + "`.`" + table_name + "`")
                        .execute();

                 /*   std::cout << "[SUCCESS] Copied table: " << table_name << std::endl;*/
                }
                catch (const mysqlx::Error& e) {
                    std::cerr << "[ERROR] Failed to copy table " << table_name << ": " << e.what() << std::endl;
                    // 尝试清理临时表
                    try {
                        sys_conn->sql("DROP TABLE IF EXISTS `" + temp_table + "`").execute();
                    }
                    catch (...) {}
                    throw;
                }
            }

            // ===== 6. 重建外键关系 =====
            sys_conn->sql("USE " + user_schema).execute();
            for (const auto& table_name : table_names) {
                // 获取该表的所有外键
                auto fks = sys_conn->sql(
                    "SELECT CONSTRAINT_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, "
                    "REFERENCED_COLUMN_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE "
                    "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND "
                    "REFERENCED_TABLE_SCHEMA IS NOT NULL")
                    .bind(user_schema, table_name)
                    .execute();

                for (auto fk : fks.fetchAll()) {
                    std::string constraint_name = fk[0].get<std::string>();
                    std::string column = fk[1].get<std::string>();
                    std::string ref_table = fk[2].get<std::string>();
                    std::string ref_column = fk[3].get<std::string>();

                    try {
                        // 删除旧外键
                        sys_conn->sql("ALTER TABLE `" + table_name + "` DROP FOREIGN KEY `" + constraint_name + "`")
                            .execute();

                        // 创建新外键（指向用户自己的数据库）
                        sys_conn->sql(
                            "ALTER TABLE `" + table_name + "` "
                            "ADD CONSTRAINT `" + constraint_name + "` "
                            "FOREIGN KEY (`" + column + "`) "
                            "REFERENCES `" + ref_table + "` (`" + ref_column + "`) "
                            "ON DELETE " + (constraint_name.find("_null_") != std::string::npos ? "SET NULL" : "CASCADE") + " "
                            "ON UPDATE CASCADE")
                            .execute();
                    }
                    catch (const mysqlx::Error& e) {
                        std::cerr << "[WARN] Failed to recreate foreign key for table "
                            << table_name << ": " << e.what() << std::endl;
                    }
                }
            }

            // ===== 7. 完成操作 =====
            sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute();
            return true;
        }
        catch (const mysqlx::Error& e) {
            try { sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute(); }
            catch (...) {}
            std::cerr << "[ERROR] Database error: " << e.what() << std::endl;
            return false;
        }
        catch (const std::exception& e) {
            try { sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute(); }
            catch (...) {}
            std::cerr << "[ERROR] System error: " << e.what() << std::endl;
            return false;
        }
    }

    bool initializeAdminDatabase() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto sys_conn = createConnection();
        const std::string admin_db = "admin_db";

        try {
            // ===== 1. 检查 admin_db 是否存在 =====
            bool admin_db_exists = false;
            try {
                // 查询 information_schema 来检查数据库是否存在
                auto result = sys_conn->sql(
                    "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '" + admin_db + "'"
                ).execute();

                admin_db_exists = result.count() > 0;

                if (admin_db_exists) {
                    std::cout << "[INFO] Skipping admin database initialization" << std::endl;
                    return true; // 数据库已存在，直接返回
                }
               
            }
            catch (const mysqlx::Error& e) {
                std::cerr << "[ERROR] Failed to check if admin database exists: " << e.what() << std::endl;
                throw;
            }

            // ===== 2. 创建 admin_db =====
            sys_conn->sql("CREATE DATABASE `" + admin_db + "`").execute();
        

            // ===== 3. 初始化设置 =====
            sys_conn->sql("USE template_db").execute();
            sys_conn->sql("SET FOREIGN_KEY_CHECKS=0").execute();

            // ===== 4. 获取所有表 =====
            auto tables = sys_conn->sql("SHOW TABLES").execute();
            std::vector<std::string> table_names;
            for (auto table : tables.fetchAll()) {
                table_names.push_back(table[0].get<std::string>());
            }

            // ===== 5. 复制表结构和数据 =====
            for (const auto& table_name : table_names) {
                try {
                    // 创建表结构
                    sys_conn->sql("CREATE TABLE `" + admin_db + "`.`" + table_name +
                        "` LIKE `template_db`.`" + table_name + "`").execute();

                    // 复制数据
                    sys_conn->sql("INSERT INTO `" + admin_db + "`.`" + table_name +
                        "` SELECT * FROM `template_db`.`" + table_name + "`").execute();

                   /* std::cout << "[SUCCESS] Copied table: " << table_name << std::endl;*/
                }
                catch (const mysqlx::Error& e) {
                    std::cerr << "[ERROR] Failed to copy table " << table_name << ": " << e.what() << std::endl;
                    throw;
                }
            }

            // ===== 6. 修复外键约束 =====
            sys_conn->sql("USE " + admin_db).execute();

            // 修复 host_cpe 表的外键
            try {
                sys_conn->sql("ALTER TABLE `host_cpe` DROP FOREIGN KEY `host_cpe_ibfk_1`").execute();
            }
            catch (...) {} // 忽略错误，可能不存在

            sys_conn->sql(
                "ALTER TABLE `host_cpe` "
                "ADD CONSTRAINT `host_cpe_ibfk_1` "
                "FOREIGN KEY (`shr_id`) "
                "REFERENCES `scan_host_result` (`id`) "
                "ON DELETE CASCADE ON UPDATE RESTRICT").execute();

            // 修复其他外键约束...
            // 这里需要添加修复其他表外键的代码

            // ===== 7. 完成操作 =====
            sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute();
            std::cout << "[SUCCESS] Admin database initialized successfully" << std::endl;
            return true;
        }
        catch (const mysqlx::Error& e) {
            try {
                if (sys_conn) {
                    sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute();
                }
            }
            catch (...) {}
            std::cerr << "[ERROR] Database error: " << e.what() << std::endl;
            return false;
        }
        catch (const std::exception& e) {
            try {
                if (sys_conn) {
                    sys_conn->sql("SET FOREIGN_KEY_CHECKS=1").execute();
                }
            }
            catch (...) {}
            std::cerr << "[ERROR] System error: " << e.what() << std::endl;
            return false;
        }
    }

private:
    DatabaseConfig config_;  // 存储配置信息
    std::queue<std::unique_ptr<mysqlx::Session>> connections_;
    std::mutex mutex_;
    size_t currentSize_;
    int bad_conn_count_; // 跟踪连接失败的次数

    std::unique_ptr<mysqlx::Session> createConnection() {
        for (int retry = 0; retry <= config_.max_retries; ++retry) {
            try {
                return std::make_unique<mysqlx::Session>(
                    mysqlx::SessionOption::HOST, config_.host,
                    mysqlx::SessionOption::PORT, config_.port,
                    mysqlx::SessionOption::USER, config_.user,
                    mysqlx::SessionOption::PWD, config_.password,
                    mysqlx::SessionOption::DB, config_.schema, // 固定使用系统数据库
                    mysqlx::SessionOption::CONNECT_TIMEOUT,
                    static_cast<int>(config_.connection_timeout.count())
                );
            }
            catch (const mysqlx::Error& e) {
                std::cerr << "创建连接失败 (尝试 " << retry + 1 << "/" << config_.max_retries + 1
                    << "): " << e.what() << std::endl;

                // 如果不是最后一次尝试，等待后重试
                if (retry < config_.max_retries) {
                    std::this_thread::sleep_for(config_.retry_delay);
                }
                else {
                    throw std::runtime_error("创建MySQL连接失败: " + std::string(e.what()));
                }
            }
        }
        throw std::runtime_error("超过最大重试次数，无法创建数据库连接");
    }

    void addConnection() {
        connections_.push(createConnection());
        ++currentSize_;
        std::cout << "已添加新连接，当前连接数: " << currentSize_ << std::endl;
    }

    void returnConnection(std::unique_ptr<mysqlx::Session> conn) {
        if (conn == nullptr) return;
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            // 关键修改点2：归还前重置为系统数据库
            conn->sql("USE " + config_.schema).execute();

            // 验证连接是否有效
            conn->sql("SELECT 1").execute();
            connections_.push(std::move(conn));
        }
        catch (const std::exception& e) {
            std::cerr << "返回无效连接: " << e.what() << std::endl;
            // 如果连接无效，创建新连接替代
            try {
                connections_.push(createConnection());
            }
            catch (const std::exception& e) {
                std::cerr << "无法替换无效连接: " << e.what() << std::endl;
                --currentSize_; // 减少连接计数
            }
        }
    }

    // 清理连接池中可能的无效连接
    void cleanupConnections() {
        std::cout << "执行连接池清理..." << std::endl;
        size_t originalSize = connections_.size();

        std::queue<std::unique_ptr<mysqlx::Session>> validConnections;

        // 检查所有现有连接
        while (!connections_.empty()) {
            auto conn = std::move(connections_.front());
            connections_.pop();

            try {
                conn->sql("SELECT 1").execute();
                validConnections.push(std::move(conn));
            }
            catch (...) {
                --currentSize_; // 减少无效连接计数
            }
        }

        // 将有效连接放回池中
        connections_ = std::move(validConnections);

        std::cout << "连接池清理完成: 从 " << originalSize << " 减少到 " << connections_.size() << " 个连接" << std::endl;

        // 确保连接池至少有一个连接
        while (connections_.empty() && currentSize_ < config_.max_size) {
            try {
                addConnection();
            }
            catch (...) {
                break; // 如果无法添加连接，跳出循环
            }
        }
    }
};

#endif // MYSQL_CONNECTION_POOL_H