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
    // �򻯵Ĺ��캯��������Ҫ��������
    ConnectionPool() : currentSize_(0) {
        // ��ʼ�����ӳ�
        for (size_t i = 0; i < initial_size_; ++i) {
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

        if (connections_.empty() && currentSize_ < max_size_) {
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
    // ���ݿ��������ã�д����˽�г�Ա��
    const std::string host_ = "10.9.130.61";  // ���ݿ�����
    const uint16_t port_ = 33060;          // X ProtocolĬ�϶˿�
    const std::string user_ = "root";      // ���ݿ��û���
    const std::string password_ = "ComplexPassword123!"; // ���ݿ�����
    const std::string schema_ = "test_db";  // ���ݿ���
    const size_t initial_size_ = 2;        // ��ʼ������
    const size_t max_size_ = 20;           // ���������
    const std::chrono::seconds connection_timeout_{ 30 }; // ���ӳ�ʱʱ��

    // ����˽�г�Ա
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