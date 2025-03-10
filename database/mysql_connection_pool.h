

#ifndef MYSQL_CONNECTION_POOL_H
#define MYSQL_CONNECTION_POOL_H

#include <mysqlx/xdevapi.h>
#include <queue>
#include <mutex>
#include <memory>
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <thread> // 添加用于sleep操作

// 数据库配置结构体
struct DBConfig {
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
    std::string schema;
    size_t initial_size;
    size_t max_size;
    std::chrono::seconds connection_timeout;
    int max_retries;       // 最大重试次数
    std::chrono::milliseconds retry_delay; // 重试延迟

    // 构造函数，提供默认值
    DBConfig(
        std::string host_ = "10.9.130.51",
        uint16_t port_ = 33060,
        std::string user_ = "root",
        std::string password_ = "ComplexPassword123!",
        std::string schema_ = "",
        size_t initial_size_ = 5,
        size_t max_size_ = 20,
        std::chrono::seconds connection_timeout_ = std::chrono::seconds(30),
        int max_retries_ = 3,
        std::chrono::milliseconds retry_delay_ = std::chrono::milliseconds(500)
    ) : host(host_), port(port_), user(user_), password(password_),
        schema(schema_), initial_size(initial_size_), max_size(max_size_),
        connection_timeout(connection_timeout_), max_retries(max_retries_),
        retry_delay(retry_delay_) {}
};

class ConnectionPool {
public:
    // 构造函数，接收配置参数
    explicit ConnectionPool(const DBConfig& config)
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

        if (connections_.empty()) {
            std::cerr << "警告: 无法初始化任何数据库连接" << std::endl;
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

private:
    DBConfig config_;  // 存储配置信息
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
                    mysqlx::SessionOption::DB, config_.schema,
                    // 添加连接超时选项
                    mysqlx::SessionOption::CONNECT_TIMEOUT, static_cast<int>(config_.connection_timeout.count())
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
            // 验证连接是否有效
            conn->sql("SELECT 1").execute();
            connections_.push(std::move(conn));
            //std::cout << "连接已返回池中，当前可用连接: " << connections_.size() << std::endl;
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