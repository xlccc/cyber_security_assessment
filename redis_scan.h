#ifndef REDIS_SECURITY_CHECK_H
#define REDIS_SECURITY_CHECK_H

#include <string>
#include <libssh/libssh.h>

// 添加host参数
std::string check_redis_unauthorized(const std::string& ssh_user,
    const std::string& ssh_pass,
    const std::string& redis_pass,
    const std::string& host);

#endif // REDIS_SECURITY_CHECK_H