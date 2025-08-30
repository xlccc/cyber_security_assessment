#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <curl/curl.h>

// 邮件配置结构体
struct SmtpConfig {
    std::string smtp_server;
    int smtp_port;
    std::string smtp_username;
    std::string smtp_password;
    std::string email_sender;
    bool use_tls;

    // 构造函数
    SmtpConfig(
        std::string smtp_server_ = CONFIG.getSmtpHost(),
        int smtp_port_ = CONFIG.getSmtpPort(),
        std::string smtp_username_ = CONFIG.getSmtpUsername(),
        std::string smtp_password_ = CONFIG.getSmtpPassword(),
        std::string email_sender_ = CONFIG.getSmtpFromAddress(),
        bool use_tls_ = CONFIG.getSmtpUseTls()
    ) :smtp_server(smtp_server_), smtp_port(smtp_port_),
        smtp_username(smtp_username_), smtp_password(smtp_password_),
        email_sender(email_sender_),use_tls(use_tls_) {
    }
};

class EmailService {
    public:
        static size_t payload_source(void* ptr, size_t size, size_t nmemb, void* userp) {
            std::string* payload = (std::string*)userp;
            size_t payload_size = payload->size();
            if (size * nmemb < 1)
                return 0;

            if (payload_size) {
                size_t len = std::min(size * nmemb, payload_size);
                memcpy(ptr, payload->c_str(), len);
                payload->erase(0, len);
                return len;
            }
            return 0;
        }

        static bool sendVerificationEmail(const std::string& to_email,
            const std::string& verification_code,
            const SmtpConfig& config) {
            try {
                std::string smtp_server = config.smtp_server; // QQ邮箱SMTP服务器
                std::string username = config.smtp_username; // 你的邮箱地址
                std::string auth_code = config.smtp_password; // 授权码
                std::string from = config.email_sender; // 发件人
                std::string to = to_email; // 收件人
                std::string cc; // 抄送（可选）

                // 邮件内容
                std::string payload_text = createEmailContent(to_email, config.email_sender,verification_code);

                // 初始化 libcurl
                CURL* curl = curl_easy_init();
                if (!curl) {
                    std::cerr << "CURL initialization failed" << std::endl;
                    return 1;
                }

                // 设置 SMTP 参数
                curl_easy_setopt(curl, CURLOPT_URL, smtp_server.c_str());
                curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
                curl_easy_setopt(curl, CURLOPT_PASSWORD, auth_code.c_str());
                curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from.c_str());

                // 设置收件人和抄送人
                struct curl_slist* recipients = NULL;
                recipients = curl_slist_append(recipients, to.c_str());
                if (!cc.empty()) {
                    recipients = curl_slist_append(recipients, cc.c_str());
                }
                curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

                // 设置邮件内容
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
                curl_easy_setopt(curl, CURLOPT_READDATA, &payload_text);
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

                // 启用 SSL
                curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // 仅用于测试，生产环境中建议启用
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // 仅用于测试

                // 调试信息（可选）
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

                // 执行发送
                CURLcode res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                }
                else {
                    std::cout << "Email sent successfully!" << std::endl;
                }

                // 清理
                curl_slist_free_all(recipients);
                curl_easy_cleanup(curl);

                return true;
            }
            catch (const std::exception& e) {
                std::cerr << "✗ SMTP邮件发送异常: " << e.what() << std::endl;
                return false;
            }
        }

    private:

        // 初始化 OpenSSL
        static void initializeSSL() {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
        }

        // 创建 SSL 上下文
        static SSL_CTX* createSSLContext() {
            const SSL_METHOD* method = SSLv23_client_method();
            SSL_CTX* ctx = SSL_CTX_new(method);
            if (!ctx) {
                std::cerr << "✗ 无法创建 SSL 上下文" << std::endl;
                return nullptr;
            }

            // 简化证书验证（生产环境应验证）
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
            return ctx;
        }

        // 获取 SSL 错误信息
        static std::string getSSLError() {
            unsigned long err = ERR_get_error();
            return ERR_error_string(err, nullptr);
        }

        // SMTP 协议处理
        static bool smtpProtocol(void* connection, bool isSSL,
            const SmtpConfig& config,
            const std::string& to_email,
            const std::string& verification_code) {
            std::string response;

            // 接收服务器欢迎消息
            if (!readResponse(connection, isSSL, response) ||
                !checkResponse(response, 220))
            {
                return false;
            }

            // EHLO 命令
            std::string ehlo = "EHLO localhost\r\n";
            if (!sendCommand(connection, isSSL, ehlo) ||
                !readResponse(connection, isSSL, response) ||
                !checkResponse(response, 250))
            {
                return false;
            }

            // STARTTLS 处理（非隐式 TLS）
            if (!config.use_tls && config.smtp_port == 587) {
                std::string starttls = "STARTTLS\r\n";
                if (!sendCommand(connection, isSSL, starttls) ||
                    !readResponse(connection, isSSL, response) ||
                    !checkResponse(response, 220))
                {
                    return false;
                }

                // 升级到 TLS 连接
                SSL* ssl = upgradeToTLS(connection);
                if (!ssl) return false;

                // 更新连接类型
                connection = ssl;
                isSSL = true;

                // 重新发送 EHLO
                if (!sendCommand(connection, isSSL, ehlo) ||
                    !readResponse(connection, isSSL, response) ||
                    !checkResponse(response, 250))
                {
                    return false;
                }
            }

            // 认证流程
            if (!config.smtp_username.empty()) {
                // AUTH LOGIN
                std::string auth = "AUTH LOGIN\r\n";
                if (!sendCommand(connection, isSSL, auth) ||
                    !readResponse(connection, isSSL, response) ||
                    !checkResponse(response, 334))
                {
                    return false;
                }

                // 用户名
                if (!sendCommand(connection, isSSL, base64Encode(config.smtp_username) + "\r\n") ||
                    !readResponse(connection, isSSL, response) ||
                    !checkResponse(response, 334))
                {
                    return false;
                }

                // 密码
                if (!sendCommand(connection, isSSL, base64Encode(config.smtp_password) + "\r\n") ||
                    !readResponse(connection, isSSL, response) ||
                    !checkResponse(response, 235))
                {
                    return false;
                }
            }

            // 邮件发送流程
            std::string mailFrom = "MAIL FROM: <" + config.email_sender + ">\r\n";
            if (!sendCommand(connection, isSSL, mailFrom) ||
                !readResponse(connection, isSSL, response) ||
                !checkResponse(response, 250))
            {
                return false;
            }

            std::string rcptTo = "RCPT TO: <" + to_email + ">\r\n";
            if (!sendCommand(connection, isSSL, rcptTo) ||
                !readResponse(connection, isSSL, response) ||
                !checkResponse(response, 250))
            {
                return false;
            }

            // DATA 命令
            if (!sendCommand(connection, isSSL, "DATA\r\n") ||
                !readResponse(connection, isSSL, response) ||
                !checkResponse(response, 354))
            {
                return false;
            }

            // 邮件内容
            std::string emailContent = createEmailContent(to_email, config.email_sender, verification_code);
            if (!sendCommand(connection, isSSL, emailContent) ||
                !sendCommand(connection, isSSL, "\r\n.\r\n") ||
                !readResponse(connection, isSSL, response) ||
                !checkResponse(response, 250))
            {
                return false;
            }

            // 退出
            sendCommand(connection, isSSL, "QUIT\r\n");
            return true;
        }

        // 升级到 TLS 连接
        static SSL* upgradeToTLS(void* sockfd) {
            SSL_CTX* ctx = createSSLContext();
            if (!ctx) return nullptr;

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, *(int*)sockfd);

            if (SSL_connect(ssl) != 1) {
                std::cerr << "✗ STARTTLS 升级失败: " << getSSLError() << std::endl;
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return nullptr;
            }

            return ssl;
        }

        // 发送命令到服务器
        static bool sendCommand(void* connection, bool isSSL, const std::string& command) {
            if (isSSL) {
                return SSL_write((SSL*)connection, command.c_str(), command.length()) > 0;
            }
            else {
                return send(*(int*)connection, command.c_str(), command.length(), 0) > 0;
            }
        }

        // 读取服务器响应
        static bool readResponse(void* connection, bool isSSL, std::string& response) {
            char buffer[1024];
            response.clear();

            while (true) {
                int bytesRead;
                if (isSSL) {
                    bytesRead = SSL_read((SSL*)connection, buffer, sizeof(buffer) - 1);
                }
                else {
                    bytesRead = recv(*(int*)connection, buffer, sizeof(buffer) - 1, 0);
                }

                if (bytesRead <= 0) return false;

                buffer[bytesRead] = '\0';
                response += buffer;

                // 检查是否包含终止序列
                if (response.find("\r\n") != std::string::npos) {
                    // 检查多行响应是否结束
                    if (response.length() >= 5 && response[3] == '-') continue;
                    break;
                }
            }

            return true;
        }

        // 检查响应码
        static bool checkResponse(const std::string& response, int expectedCode) {
            if (response.length() < 3) return false;

            int code = std::stoi(response.substr(0, 3));
            if (code != expectedCode) {
                std::cerr << "SMTP 错误响应: " << response;
                return false;
            }
            return true;
        }


    // 创建验证码邮件内容
    static std::string createEmailContent(const std::string& to_email,
        const std::string& from_email,
        const std::string& verification_code) {
        std::stringstream ss;

        // 邮件头部
        ss << "From: " << from_email << "\r\n"
            << "To: " << to_email << "\r\n"
            << "Subject: =?UTF-8?B?" << base64Encode("您的账户验证码") << "?=\r\n"
            << "Content-Type: text/plain; charset=utf-8\r\n"
            << "Content-Transfer-Encoding: 8bit\r\n"
            << "Date: " << getCurrentDateTime() << "\r\n"
            << "MIME-Version: 1.0\r\n"
            << "\r\n";  // 头部结束标志

        // 邮件正文
        ss << "尊敬的用户：\r\n\r\n"
            << "您的安全验证码是：\r\n"
            << "─────────────────\r\n"
            << "  " << verification_code << "\r\n"
            << "─────────────────\r\n\r\n"
            << "请注意：\r\n"
            << "• 此验证码将于 10 分钟后失效\r\n"
            << "• 请勿向任何人提供此验证码\r\n"
            << "• 官方人员不会索取此验证码\r\n\r\n"
            << "如非本人操作，请忽略此邮件。\r\n\r\n"
            << "系统自动发送，请勿回复。\r\n";

        return ss.str();
    }

    // 获取当前时间
    static std::string getCurrentDateTime() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%a, %d %b %Y %H:%M:%S %z");
        return ss.str();
    }

    // Base64 编码
    static std::string base64Encode(const std::string& input) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        for (unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }
};