#include "token_generator.h"
#include <stdexcept>

std::string secret = "nobodyknowssecret";
std::string issuer = "cyber_security_group";

std::string generateToken(int user_id, const std::string& username, std::chrono::seconds ttl) {
    const std::string secret = std::getenv("JWT_SECRET") ? std::getenv("JWT_SECRET") : secret;
    auto now = std::chrono::system_clock::now();
    auto expire = now + ttl;

    auto token = jwt::create()
        .set_issuer(issuer)
        .set_subject(username)
        .set_payload_claim("user_id", jwt::claim(std::to_string(user_id)))
        .set_issued_at(now)
        .set_expires_at(expire)
        .sign(jwt::algorithm::hs256{ secret });

    return token;
}

bool verifyToken(const std::string& token) {
    const std::string secret = std::getenv("JWT_SECRET") ? std::getenv("JWT_SECRET") : secret;

    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{ secret })
            .with_issuer(issuer)
            .leeway(60); // 60 秒宽限期
        verifier.verify(decoded);
        return true;
    }
    catch (const std::exception& e) {
        return false;
    }
}