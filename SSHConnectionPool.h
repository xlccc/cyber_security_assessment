#pragma once
#include <libssh/libssh.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <stdexcept>
#include <vector>
#include <string>

class SSHConnectionPool {
public:
    struct SSHConnection {
        ssh_session session;
        bool inUse;
        int id; // 唯一标识每个ssh连接

        SSHConnection() : session(nullptr), inUse(false) {}
    };

    SSHConnectionPool(const std::string& host, const std::string& username,
        const std::string& password, size_t poolSize)
        : m_host(host), m_username(username), m_password(password),
        m_poolSize(poolSize), m_shutdown(false) {
        initializePool();
    }

    ~SSHConnectionPool() {
        shutdown();
    }

    // Get a connection from the pool
    ssh_session acquireConnection() {
        std::unique_lock<std::mutex> lock(m_mutex);

        m_condition.wait(lock, [this] {
            return !m_availableConnections.empty() || m_shutdown;
            });

        if (m_shutdown) {
            throw std::runtime_error("Connection pool is shutting down");
        }

        size_t index = m_availableConnections.front();
        m_availableConnections.pop();
        m_connections[index].inUse = true;

        return m_connections[index].session;
    }

    // Return a connection to the pool
    void releaseConnection(ssh_session session) {
        std::unique_lock<std::mutex> lock(m_mutex);

        for (size_t i = 0; i < m_connections.size(); ++i) {
            if (m_connections[i].session == session) {
                m_connections[i].inUse = false;
                m_availableConnections.push(i);
                break;
            }
        }

        m_condition.notify_one();
    }

    void shutdown() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_shutdown = true;

        // Clean up all connections
        for (auto& conn : m_connections) {
            if (conn.session) {
                ssh_disconnect(conn.session);
                ssh_free(conn.session);
                conn.session = nullptr;
            }
        }

        m_condition.notify_all();
    }

    int getConnectionID(ssh_session session) {
        std::unique_lock<std::mutex> lock(m_mutex);

        for (const auto& conn : m_connections) {
            if (conn.session == session) {
                return conn.id;
            }
        }

        throw std::runtime_error("Session not found in connection pool");
    }

private:
    void initializePool() {
        m_connections.resize(m_poolSize);

        for (size_t i = 0; i < m_poolSize; ++i) {
            ssh_session session = createSSHSession();
            if (!session) {
                throw std::runtime_error("Failed to create SSH session");
            }

            m_connections[i].session = session;
            m_connections[i].inUse = false;
            m_connections[i].id = static_cast<int>(i); // 为每个连接分配唯一编号
            m_availableConnections.push(i);
        }
    }

    ssh_session createSSHSession() {
        ssh_session session = ssh_new();
        if (session == nullptr) {
            return nullptr;
        }

        ssh_options_set(session, SSH_OPTIONS_HOST, m_host.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, m_username.c_str());

        if (ssh_connect(session) != SSH_OK) {
            ssh_free(session);
            return nullptr;
        }

        if (ssh_userauth_password(session, nullptr, m_password.c_str()) != SSH_AUTH_SUCCESS) {
            ssh_disconnect(session);
            ssh_free(session);
            return nullptr;
        }

        return session;
    }

    std::string m_host;
    std::string m_username;
    std::string m_password;
    size_t m_poolSize;
    bool m_shutdown;

    std::vector<SSHConnection> m_connections;
    std::queue<size_t> m_availableConnections;
    std::mutex m_mutex;
    std::condition_variable m_condition;
};

// Helper class for RAII-style connection management
class SSHConnectionGuard {
public:
    SSHConnectionGuard(SSHConnectionPool& pool)
        : m_pool(pool), m_session(pool.acquireConnection()), m_connectionID(-1) {
        // Find the connection ID
        m_connectionID = pool.getConnectionID(m_session);
    }

    ~SSHConnectionGuard() {
        m_pool.releaseConnection(m_session);
    }

    ssh_session get() const { return m_session; }
    int getConnectionID() const { return m_connectionID; } // Get the connection ID
    
    /*
    SSHConnectionGuard(SSHConnectionPool& pool)
        : m_pool(pool), m_session(pool.acquireConnection()) {}

    ~SSHConnectionGuard() {
        m_pool.releaseConnection(m_session);
    }

    ssh_session get() const { return m_session; }
    */

private:
    SSHConnectionPool& m_pool;
    ssh_session m_session;
    int m_connectionID;
};