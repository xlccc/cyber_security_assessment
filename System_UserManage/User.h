#include<string>

struct User {
    int user_id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string role;
    std::string account_status;
    std::string schema_name;
   /* std::string last_login;*/
};