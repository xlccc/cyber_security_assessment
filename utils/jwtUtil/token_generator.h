#ifndef TOKEN_GENERATOR_H
#define TOKEN_GENERATOR_H

#include <jwt-cpp/jwt.h>
#include <string>
#include <chrono>

std::string generateToken(int user_id, const std::string& username, std::chrono::seconds ttl = std::chrono::hours(1));
bool verifyToken(const std::string& token);

#endif // TOKEN_GENERATOR_H