#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <string>
#include <stdexcept>
#include <sodium.h>  // 使用 libsodium 替代 bcrypt

class SecurityUtils {
public:
    static std::string bcrypt_hash(const std::string& password, int rounds = 12) {
        // 初始化 libsodium（安全调用，多次初始化无害）
        if (sodium_init() < 0) {
            throw std::runtime_error("无法初始化libsodium");
        }

        // 选择与bcrypt安全等级相似的Argon2id算法参数
        const auto opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
        auto memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

        // 动态调整内存限制（根据参数rounds）
        memlimit = (size_t)(memlimit * (1 + rounds / 10.0));

        char hash[crypto_pwhash_STRBYTES];  // 存储哈希结果

        // 生成密码哈希（argon2id算法）
        if (crypto_pwhash_str(hash,
            password.c_str(),
            password.length(),
            opslimit,
            memlimit) != 0) {
            throw std::runtime_error("密码哈希失败：内存不足");
        }

        return std::string(hash);
    }

    static bool bcrypt_verify(const std::string& password, const std::string& hash) {
        // 初始化 libsodium
        if (sodium_init() < 0) {
            return false;
        }

        // 验证密码是否匹配哈希
        return crypto_pwhash_str_verify(hash.c_str(),
            password.c_str(),
            password.length()) == 0;
    }
};

#endif // SECURITY_UTILS_H