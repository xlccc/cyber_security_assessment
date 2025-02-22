#ifndef MYSQL_CONNECTION_POOL_H
#define MYSQL_CONNECTION_POOL_H

#include <mysqlx/xdevapi.h>
#include <queue>
#include <mutex>
#include <memory>
#include <chrono>
#include <stdexcept>

// ���ݿ����ýṹ��
struct DBConfig {
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
    std::string schema;
    size_t initial_size;
    size_t max_size;
    std::chrono::seconds connection_timeout;

    // ���캯�����ṩĬ��ֵ
    DBConfig(
        std::string host_ = "localhost",
        uint16_t port_ = 33060,
        std::string user_ = "root",
        std::string password_ = "",
        std::string schema_ = "",
        size_t initial_size_ = 2,
        size_t max_size_ = 20,
        std::chrono::seconds connection_timeout_ = std::chrono::seconds(30)
    ) : host(host_), port(port_), user(user_), password(password_),
        schema(schema_), initial_size(initial_size_), max_size(max_size_),
        connection_timeout(connection_timeout_) {}
};

class ConnectionPool {
public:
    // �޸Ĺ��캯�����������ò���
    explicit ConnectionPool(const DBConfig& config)
        : config_(config), currentSize_(0) {
        // ��ʼ�����ӳ�
        for (size_t i = 0; i < config_.initial_size; ++i) {
            addConnection();
        }
    }

    ~ConnectionPool() {
        // ������������
        std::lock_guard<std::mutex> lock(mutex_);
        while (!connections_.empty()) {
            connections_.pop();
        }
    }

    std::shared_ptr<mysqlx::Session> getConnection() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connections_.empty() && currentSize_ < config_.max_size) {
            addConnection();
        }
        if (connections_.empty()) {
            throw std::runtime_error("No available connections in the pool");
        }
        auto conn = std::move(connections_.front());
        connections_.pop();

        // ��֤�����Ƿ���Ч
        try {
            conn->sql("SELECT 1").execute();
        }
        catch (...) {
            // ������Ч������������
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
    DBConfig config_;  // 存储配置信息
    std::queue<std::unique_ptr<mysqlx::Session>> connections_;
    std::mutex mutex_;
    size_t currentSize_;

    std::unique_ptr<mysqlx::Session> createConnection() {
        try {
            return std::make_unique<mysqlx::Session>(
                mysqlx::SessionOption::HOST, config_.host,
                mysqlx::SessionOption::PORT, config_.port,
                mysqlx::SessionOption::USER, config_.user,
                mysqlx::SessionOption::PWD, config_.password,
                mysqlx::SessionOption::DB, config_.schema
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
            // ��֤�����Ƿ���Ч
            conn->sql("SELECT 1").execute();
            connections_.push(std::move(conn));
        }
        catch (...) {
            // ���������Ч������������
            connections_.push(createConnection());
        }
    }
};

#endif // MYSQL_CONNECTION_POOL_H