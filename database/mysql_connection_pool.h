#ifndef MYSQL_CONNECTION_POOL_H
#define MYSQL_CONNECTION_POOL_H

#include <mysqlx/xdevapi.h>
#include <queue>
#include <mutex>
#include <memory>
#include <chrono>
#include <stdexcept>

class ConnectionPool {
public:
    // 简化的构造函数，不需要传入配置
    ConnectionPool() : currentSize_(0) {
        // 初始化连接池
        for (size_t i = 0; i < initial_size_; ++i) {
            addConnection();
        }
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

        if (connections_.empty() && currentSize_ < max_size_) {
            addConnection();
        }

        if (connections_.empty()) {
            throw std::runtime_error("No available connections in the pool");
        }

        auto conn = std::move(connections_.front());
        connections_.pop();

        // 验证连接是否有效
        try {
            conn->sql("SELECT 1").execute();
        }
        catch (...) {
            // 连接无效，创建新连接
            conn = createConnection();
        }

        return std::shared_ptr<mysqlx::Session>(conn.release(),
            [this](mysqlx::Session* session) {
                if (session != nullptr) {
                    this->returnConnection(std::unique_ptr<mysqlx::Session>(session));
                }
            });
    }

private:
    // 数据库连接配置，写死在私有成员中
    const std::string host_ = "10.9.130.193";  // 数据库主机
    const uint16_t port_ = 33060;          // X Protocol默认端口
    const std::string user_ = "root";      // 数据库用户名
    const std::string password_ = "Navicat822!"; // 数据库密码
    const std::string schema_ = "test_db";  // 数据库名
    const size_t initial_size_ = 2;        // 初始连接数
    const size_t max_size_ = 20;           // 最大连接数
    const std::chrono::seconds connection_timeout_{ 30 }; // 连接超时时间

    // 其他私有成员
    std::queue<std::unique_ptr<mysqlx::Session>> connections_;
    std::mutex mutex_;
    size_t currentSize_;

    std::unique_ptr<mysqlx::Session> createConnection() {
        try {
            return std::make_unique<mysqlx::Session>(
                mysqlx::SessionOption::HOST, host_,
                mysqlx::SessionOption::PORT, port_,
                mysqlx::SessionOption::USER, user_,
                mysqlx::SessionOption::PWD, password_,
                mysqlx::SessionOption::DB, schema_
            );
        }
        catch (const mysqlx::Error& e) {
            throw std::runtime_error("Failed to create MySQL connection: " + std::string(e.what()));
        }
    }

    void addConnection() {
        connections_.push(createConnection());
        ++currentSize_;
    }

    void returnConnection(std::unique_ptr<mysqlx::Session> conn) {
        if (conn == nullptr) return;

        std::lock_guard<std::mutex> lock(mutex_);
        try {
            // 验证连接是否还有效
            conn->sql("SELECT 1").execute();
            connections_.push(std::move(conn));
        }
        catch (...) {
            // 如果连接无效，创建新连接
            connections_.push(createConnection());
        }
    }
};

#endif // MYSQL_CONNECTION_POOL_H