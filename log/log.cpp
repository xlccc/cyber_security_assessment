#include"log.h"

//定义全局日志变量
std::shared_ptr<spdlog::logger> system_logger;
std::shared_ptr<spdlog::logger> user_logger;
std::shared_ptr<spdlog::logger> console;

// 获取日志路径
std::string get_log_path(const std::string& log_type) {
    fs::path log_dir("logs");
    if (!fs::exists(log_dir)) {
        fs::create_directory(log_dir);
    }
    return (log_dir / (log_type + ".log")).string();
}

//初始化日志系统
void init_logs() {
    try {
        // 配置控制台日志
        console = spdlog::stdout_color_mt("console");
        console->set_pattern("%^[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v%$");

        // 配置系统运维日志（轮转日志，每个文件最大5MB，最多保留3个文件）
        system_logger = spdlog::rotating_logger_mt("system_logger", get_log_path("system"), 1024 * 1024 * 5, 3);
        system_logger->set_pattern("[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v");

        // 配置用户活动日志（轮转日志）
        user_logger = spdlog::rotating_logger_mt("user_logger", get_log_path("user"), 1024 * 1024 * 5, 3);
        user_logger->set_pattern("[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v");

        // 设置日志级别
        spdlog::set_level(spdlog::level::info);

        // 示例日志
        system_logger->info("System logging initialized.");
        user_logger->info("User activity logging initialized.");
        console->info("Logging initialized.");

        // 确保日志初始化成功
        if (!system_logger || !user_logger || !console) {
            std::cerr << "Log initialization failed: Unable to create one or more loggers!" << std::endl;
            exit(1);  // 退出程序
        }
    }
    catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        exit(1);  // 退出程序
    }
}