#ifndef PGSQL_SECURITY_CHECK_H
#define PGSQL_SECURITY_CHECK_H
#include <string>
#include <libssh/libssh.h>

std::string check_pgsql_unauthorized(const std::string& ssh_user,
    const std::string& ssh_pass,
    const std::string& pg_user,
    const std::string& pg_pass,
    const std::string& host,
    const std::string& port = "5432");

#endif // PGSQL_SECURITY_CHECK_H